#!/usr/bin/env python3
"""NiceTunnel - small tunnels for two servers.

Author: Arsham Smoke
License: MIT (see LICENSE)

Type 1: reverse TCP tunnel (roles "server" and "client")
  server  runs on the machine users connect to (e.g. the Iran server).
          It listens on a "bridge" port for the tunnel client and on one or
          more public ports for end users.
  client  runs on the other machine (e.g. the outside server). It dials the
          server's bridge port, so only the server needs an open inbound port.

  Flow for every user connection:
    user -> server:PUBLIC_PORT
    server --(control channel)--> client : "NEW <id> <target_port>"
    client opens  target_host:target_port  and a fresh data connection to the
    server's bridge port; the server pairs it with the waiting user connection
    and bytes are relayed both ways.

  Authentication is an HMAC-SHA256 challenge/response with a shared token, so
  the token itself never crosses the wire. Traffic is NOT encrypted by the
  tunnel; carry already-encrypted protocols (TLS, VLESS, Trojan, SSH, ...).

Type 2: spoof tunnel (roles "spoof-entry" and "spoof-exit", plus the helpers
        "spoof-test" and "spoof-check")
  A UDP pipe between two servers. Each tunnel packet is a hand-built IPv4
  packet (UDP, TCP-SYN or ICMP) whose SOURCE address is taken from a list you
  choose instead of the server's own address. It only works when the hosting
  providers on the path let such packets out; "spoof-test" finds that out.
  Packets are authenticated (HMAC) and replay-protected but NOT encrypted:
  carry something that encrypts itself, such as WireGuard.

Standard library only. Python 3.8+. The spoof tunnel needs root (raw sockets).
"""
import argparse
import asyncio
import collections
import ctypes
import functools
import hashlib
import hmac
import ipaddress
import itertools
import logging
import os
import random
import re
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

VERSION = "1.2.0"
log = logging.getLogger("nicetunnel")

HANDSHAKE_TIMEOUT = 10   # seconds to finish an auth handshake
PING_INTERVAL = 10       # server -> client heartbeat period
DEAD_AFTER = 35          # control channel silent for this long = dead
CONNECT_WAIT = 10        # how long a user waits for the client's data link
TARGET_TIMEOUT = 5       # client -> local target connect timeout
HALF_CLOSE_WAIT = 120    # after one side finishes, wait this long for the other
BUF = 65536


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def sign(token, *parts):
    msg = ":".join(parts).encode()
    return hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()


def close(writer):
    try:
        writer.close()
    except Exception:
        pass


def tune(writer):
    """TCP_NODELAY + keepalive so dead peers are noticed."""
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, val in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
            if hasattr(socket, name):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), val)
    except OSError:
        pass


async def pump(reader, writer):
    """Copy reader -> writer. Returns True on a clean EOF, False on error."""
    clean = True
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        clean = False
    if clean:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass
    return clean


async def relay(r1, w1, r2, w2):
    """Bidirectional copy between (r1,w1) and (r2,w2); closes both at the end."""
    t1 = asyncio.ensure_future(pump(r1, w2))
    t2 = asyncio.ensure_future(pump(r2, w1))
    try:
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        # A clean EOF on one side is a half-close: let the other direction finish.
        # An error on either side means the connection is gone: stop right away.
        if pending and all(t.result() for t in done):
            await asyncio.wait(pending, timeout=HALF_CLOSE_WAIT)
    finally:
        for t in (t1, t2):
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
        close(w1)
        close(w2)


def parse_ports(text):
    """'443,8443:8080' -> [(443, 443), (8443, 8080)]  (public:target)"""
    out = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        pub, _, tgt = item.partition(":")
        pub, tgt = int(pub), int(tgt or pub)
        for p in (pub, tgt):
            if not 1 <= p <= 65535:
                raise argparse.ArgumentTypeError("port out of range: %d" % p)
        out.append((pub, tgt))
    if not out:
        raise argparse.ArgumentTypeError("no ports given")
    return out


# --------------------------------------------------------------------------
# server side
# --------------------------------------------------------------------------
class Server:
    def __init__(self, token):
        self.token = token
        self.control = None            # StreamWriter of the active tunnel client
        self.ctrl_lock = asyncio.Lock()
        self.pending = {}              # conn id -> Future[(reader, writer)]
        self.ids = itertools.count(1)

    async def send_ctrl(self, writer, data):
        async with self.ctrl_lock:
            writer.write(data)
            await writer.drain()

    async def on_bridge(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            tune(writer)
            nonce = secrets.token_hex(16)
            writer.write((nonce + "\n").encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), HANDSHAKE_TIMEOUT)
            parts = line.decode(errors="replace").split()

            if (len(parts) == 2 and parts[0] == "CTRL"
                    and hmac.compare_digest(parts[1], sign(self.token, nonce, "ctrl"))):
                await self.run_control(reader, writer)
                return

            if (len(parts) == 3 and parts[0] == "DATA"
                    and hmac.compare_digest(parts[2], sign(self.token, nonce, "data", parts[1]))):
                fut = self.pending.pop(parts[1], None)
                if fut is not None and not fut.done():
                    fut.set_result((reader, writer))
                    return  # the waiting user handler now owns this connection

            log.warning("rejected bridge connection from %s", peer)
        except Exception as exc:
            log.debug("bridge connection from %s failed: %r", peer, exc)
        close(writer)

    async def run_control(self, reader, writer):
        if self.control is not None:
            close(self.control)  # a new client replaces a stale one
        self.control = writer
        await self.send_ctrl(writer, b"OK\n")
        log.info("tunnel client connected")

        async def pinger():
            try:
                while True:
                    await asyncio.sleep(PING_INTERVAL)
                    await self.send_ctrl(writer, b"PING\n")
            except Exception:
                pass

        ping_task = asyncio.ensure_future(pinger())
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), DEAD_AFTER)
                if not line:
                    break
                msg = line.split()
                if len(msg) == 2 and msg[0] == b"FAIL":
                    fut = self.pending.pop(msg[1].decode(errors="replace"), None)
                    if fut is not None and not fut.done():
                        fut.set_exception(ConnectionError("target unreachable on client side"))
                # PONG and anything else just prove the client is alive
        except Exception:
            pass
        finally:
            ping_task.cancel()
            if self.control is writer:
                self.control = None
            close(writer)
            log.info("tunnel client disconnected")

    async def on_user(self, target_port, reader, writer):
        ctrl = self.control
        if ctrl is None:
            close(writer)  # no tunnel up: refuse immediately
            return
        tune(writer)
        cid = str(next(self.ids))
        fut = asyncio.get_event_loop().create_future()
        self.pending[cid] = fut
        try:
            await self.send_ctrl(ctrl, ("NEW %s %d\n" % (cid, target_port)).encode())
            bridge_reader, bridge_writer = await asyncio.wait_for(fut, CONNECT_WAIT)
        except Exception as exc:
            self.pending.pop(cid, None)
            log.debug("user connection %s dropped: %r", cid, exc)
            close(writer)
            return
        await relay(reader, writer, bridge_reader, bridge_writer)


async def run_server(args):
    srv = Server(args.token)
    servers = [await asyncio.start_server(srv.on_bridge, args.bind, args.bridge, backlog=512)]
    log.info("bridge listening on %s:%d", args.bind, args.bridge)
    for pub, tgt in args.ports:
        handler = functools.partial(srv.on_user, tgt)
        servers.append(await asyncio.start_server(handler, args.public_bind, pub, backlog=512))
        log.info("public port %s:%d -> client target port %d", args.public_bind, pub, tgt)
    await asyncio.gather(*(s.serve_forever() for s in servers))


# --------------------------------------------------------------------------
# client side
# --------------------------------------------------------------------------
_tasks = set()


def spawn(coro):
    task = asyncio.ensure_future(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task


async def open_bridge(args, role, *extra):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(args.server, args.bridge), HANDSHAKE_TIMEOUT)
    try:
        tune(writer)
        nonce = (await asyncio.wait_for(reader.readline(), HANDSHAKE_TIMEOUT)).decode().strip()
        if not nonce:
            raise ConnectionError("server closed the connection")
        sig = sign(args.token, nonce, role.lower(), *extra)
        writer.write((" ".join([role] + list(extra) + [sig]) + "\n").encode())
        await writer.drain()
    except Exception:
        close(writer)
        raise
    return reader, writer


async def client_session(args):
    """One control-channel lifetime. Returns True if authentication succeeded."""
    reader, writer = await open_bridge(args, "CTRL")
    lock = asyncio.Lock()

    async def send(data):
        async with lock:
            writer.write(data)
            await writer.drain()

    async def handle_new(cid, port):
        try:
            t_reader, t_writer = await asyncio.wait_for(
                asyncio.open_connection(args.target_host, port), TARGET_TIMEOUT)
        except Exception as exc:
            log.warning("target %s:%d unreachable: %s", args.target_host, port, exc)
            try:
                await send(("FAIL %s\n" % cid).encode())
            except Exception:
                pass
            return
        tune(t_writer)
        try:
            b_reader, b_writer = await open_bridge(args, "DATA", cid)
        except Exception as exc:
            log.warning("could not open data link: %s", exc)
            close(t_writer)
            return
        await relay(t_reader, t_writer, b_reader, b_writer)

    authed = False
    try:
        ok = await asyncio.wait_for(reader.readline(), HANDSHAKE_TIMEOUT)
        if ok.strip() != b"OK":
            raise ConnectionError("server rejected authentication (check the token)")
        authed = True
        log.info("connected to %s:%d", args.server, args.bridge)
        while True:
            line = await asyncio.wait_for(reader.readline(), DEAD_AFTER)
            if not line:
                break
            msg = line.split()
            if not msg:
                continue
            if msg[0] == b"PING":
                await send(b"PONG\n")
            elif msg[0] == b"NEW" and len(msg) == 3:
                try:
                    port = int(msg[2])
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    spawn(handle_new(msg[1].decode(errors="replace"), port))
    finally:
        close(writer)
    return authed


async def run_client(args):
    delay = 1
    while True:
        try:
            authed = await client_session(args)
            if authed:
                delay = 1
            log.warning("control connection lost, retrying in %ds", delay)
        except asyncio.TimeoutError:
            log.warning("timed out talking to %s:%d, retrying in %ds", args.server, args.bridge, delay)
        except Exception as exc:
            log.warning("%s, retrying in %ds", exc, delay)
        await asyncio.sleep(delay)
        delay = min(delay * 2, 15)


# --------------------------------------------------------------------------
# spoof tunnel
# --------------------------------------------------------------------------
# entry  (usually the Iran server): listens on a local UDP port, wraps every
#        datagram and sends it to the exit server.
# exit   (usually the foreign server): unwraps the datagrams and forwards
#        them to a UDP service (e.g. WireGuard); replies travel back the same way.
# Every packet one side sends carries a source address picked, round-robin,
# from that side's spoof list; the other side finds the packets by destination
# port (or ICMP) with a kernel packet filter, so the real source never matters.

TRANSPORTS = ("udp", "tcp", "icmp")
IP_PROTO = {"udp": 17, "tcp": 6, "icmp": 1}
TCP_FLAGS = {"syn": 0x02, "ack": 0x18}        # "ack" = PSH+ACK
ETH_P_IP = 0x0800
PACKET_HOST = 0
SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)
MAX_SPOOF_IPS = 65536
MAX_SESSIONS = 1024
SESSION_IDLE = 180        # seconds without traffic before a session is dropped
PING_EVERY = 10
PEER_DEAD_AFTER = 35
STATS_EVERY = 60
TEST_MAX_PACKETS = 30000
PROBE_MAGIC = b"NTPROBE1"

WIRE_VERSION = 1
T_DATA, T_PING, T_PONG = 1, 2, 3
HDR = struct.Struct("!BBBIQ")     # version, sender role, type, session id, counter
TAG_LEN = 16
OVERHEAD = HDR.size + TAG_LEN


class Throttle:
    """Lets a log line through at most once every `every` seconds."""

    def __init__(self, every=10):
        self.every = every
        self.last = None

    def ok(self):
        now = time.monotonic()
        if self.last is None or now - self.last >= self.every:
            self.last = now
            return True
        return False


def csum(data):
    """Internet checksum (RFC 1071)."""
    if len(data) & 1:
        data += b"\x00"
    total = sum(memoryview(data).cast("H"))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    total = ~total & 0xFFFF
    if sys.byteorder == "little":
        total = ((total & 0xFF) << 8) | (total >> 8)
    return total


def build_packet(transport, src, dst, sport, dport, payload, icmp_type=8, ident=0, seq=0, tcp_flags=0x02):
    """Build one IPv4 packet. src/dst are 4-byte packed addresses.
    The kernel fills in the IP header checksum and total length when we send."""
    if transport == "udp":
        ulen = 8 + len(payload)
        pseudo = src + dst + struct.pack("!BBH", 0, 17, ulen)
        head = struct.pack("!HHHH", sport, dport, ulen, 0)
        c = csum(pseudo + head + payload) or 0xFFFF
        l4 = struct.pack("!HHHH", sport, dport, ulen, c) + payload
    elif transport == "tcp":
        seq_no = random.getrandbits(32)
        ack_no = random.getrandbits(32) if tcp_flags & 0x10 else 0
        head = struct.pack("!HHIIBBHHH", sport, dport, seq_no, ack_no, 5 << 4, tcp_flags, 65535, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(head) + len(payload))
        c = csum(pseudo + head + payload)
        l4 = head[:16] + struct.pack("!H", c) + head[18:] + payload
    else:
        head = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq & 0xFFFF)
        c = csum(head + payload)
        l4 = struct.pack("!BBHHH", icmp_type, 0, c, ident, seq & 0xFFFF) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), random.getrandbits(16), 0, 64,
                     IP_PROTO[transport], 0, src, dst)
    return ip + l4


def parse_ip(pkt):
    """Read an IPv4 packet -> (proto, src, dport, payload, icmp_type), or None.
    Fragments other than the first are ignored."""
    n = len(pkt)
    if n < 28 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 15) * 4
    total = (pkt[2] << 8) | pkt[3]
    if ihl < 20 or total < ihl + 8 or total > n:
        return None
    if ((pkt[6] << 8) | pkt[7]) & 0x1FFF:
        return None
    proto, src = pkt[9], bytes(pkt[12:16])
    l4 = pkt[ihl:total]
    if proto == 17:
        ulen = (l4[4] << 8) | l4[5]
        return 17, src, (l4[2] << 8) | l4[3], bytes(l4[8:max(8, min(ulen, len(l4)))]), 0
    if proto == 6:
        if len(l4) < 20:
            return None
        off = (l4[12] >> 4) * 4
        if off < 20 or off > len(l4):
            return None
        return 6, src, (l4[2] << 8) | l4[3], bytes(l4[off:]), 0
    if proto == 1:
        return 1, src, 0, bytes(l4[8:]), l4[0]
    return None


def parse_spoof_ips(text, _nested=False):
    """'1.2.3.4, 10.0.0.0/24, 5.5.5.1-5.5.5.9, 7.7.7.1-9, @file' -> [4-byte addresses]"""
    out = []
    for item in re.split(r"[,\s]+", text.strip()):
        if not item:
            continue
        if item.startswith("@"):
            if _nested:
                raise ValueError("an address file cannot include another file")
            with open(item[1:]) as fh:
                out.extend(int.from_bytes(a, "big") for a in parse_spoof_ips(fh.read(), True))
        elif "/" in item:
            net = ipaddress.IPv4Network(item, strict=False)
            if net.num_addresses > MAX_SPOOF_IPS:
                raise ValueError("%s is too large (limit %d addresses)" % (item, MAX_SPOOF_IPS))
            out.extend(int(h) for h in (list(net.hosts()) or [net.network_address]))
        elif "-" in item:
            first, _, last = item.partition("-")
            lo = int(ipaddress.IPv4Address(first))
            hi = int(ipaddress.IPv4Address(last if "." in last else first.rsplit(".", 1)[0] + "." + last))
            if hi < lo:
                raise ValueError("bad range: " + item)
            if hi - lo + 1 > MAX_SPOOF_IPS:
                raise ValueError("%s is too large (limit %d addresses)" % (item, MAX_SPOOF_IPS))
            out.extend(range(lo, hi + 1))
        else:
            out.append(int(ipaddress.IPv4Address(item)))
        if len(out) > MAX_SPOOF_IPS:
            raise ValueError("too many addresses (limit %d)" % MAX_SPOOF_IPS)
    if not out:
        raise ValueError("no addresses given")
    return [v.to_bytes(4, "big") for v in out]


class ReplayWindow:
    """Rejects packets whose counter was already seen. Counter = epoch<<32 | seq;
    the sender picks a new random epoch at every start."""
    SIZE = 4096

    def __init__(self):
        self.epochs = collections.OrderedDict()      # epoch -> [highest seq, bitmap]

    def fresh(self, counter):
        epoch, seq = counter >> 32, counter & 0xFFFFFFFF
        st = self.epochs.get(epoch)
        if st is None:
            self.epochs[epoch] = [seq, 1]
            while len(self.epochs) > 8:
                self.epochs.popitem(last=False)
            return True
        self.epochs.move_to_end(epoch)
        high, bits = st
        if seq > high:
            shift = seq - high
            st[1] = (((bits << shift) | 1) & ((1 << self.SIZE) - 1)) if shift < self.SIZE else 1
            st[0] = seq
            return True
        back = high - seq
        if back >= self.SIZE or (bits >> back) & 1:
            return False
        st[1] = bits | (1 << back)
        return True


class Wire:
    """Wraps/unwraps tunnel messages: header + 16-byte HMAC tag + payload."""

    def __init__(self, token, role):
        self.key = hmac.digest(token.encode(), b"nicetunnel/spoof/v1", "sha256")
        self.role = role
        self.epoch = secrets.randbits(32)
        self.n = 0
        self.window = ReplayWindow()

    def seal(self, mtype, session, payload=b""):
        self.n += 1
        if self.n > 0xFFFFFFFF:
            self.epoch, self.n = secrets.randbits(32), 1
        hdr = HDR.pack(WIRE_VERSION, self.role, mtype, session, (self.epoch << 32) | self.n)
        return hdr + hmac.digest(self.key, hdr + payload, "sha256")[:TAG_LEN] + payload

    def open(self, data):
        """-> (type, session, payload) or None for anything not from the other side."""
        if len(data) < OVERHEAD:
            return None
        hdr, tag, payload = data[:HDR.size], data[HDR.size:OVERHEAD], data[OVERHEAD:]
        version, role, mtype, session, counter = HDR.unpack(hdr)
        if version != WIRE_VERSION or role == self.role:
            return None
        if not hmac.compare_digest(tag, hmac.digest(self.key, hdr + payload, "sha256")[:TAG_LEN]):
            return None
        if not self.window.fresh(counter):
            return None
        return mtype, session, payload


class RawSender:
    """Sends hand-built IPv4 packets to one peer with a rotating source address."""

    def __init__(self, transport, peer, spoofs, sport, dport, tcp_flags=0x02, icmp_type=8):
        self.transport, self.peer = transport, peer
        self.dst = socket.inet_aton(peer)
        self.spoofs = spoofs
        self.i = random.randrange(len(spoofs))
        self.sport, self.dport = sport, dport
        self.tcp_flags, self.icmp_type = tcp_flags, icmp_type
        self.ident = random.getrandbits(16)
        self.seq = 0
        self.errors = Throttle(10)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.sock.setblocking(False)

    def send(self, payload):
        src = self.spoofs[self.i]
        self.i = (self.i + 1) % len(self.spoofs)
        self.send_from(src, payload)

    def send_from(self, src, payload):
        self.seq += 1
        pkt = build_packet(self.transport, src, self.dst, self.sport, self.dport, payload,
                           self.icmp_type, self.ident, self.seq, self.tcp_flags)
        try:
            self.sock.sendto(pkt, (self.peer, 0))
        except (BlockingIOError, InterruptedError):
            pass                                  # send buffer full: drop, like any UDP path
        except OSError as exc:
            if self.errors.ok():
                log.warning("cannot send to %s: %s", self.peer, exc)

    def close(self):
        self.sock.close()


def bpf_program(proto, port):
    """Classic BPF over an IPv4 packet: this protocol (and destination port, if any)."""
    def ins(code, jt, jf, k):
        return struct.pack("HBBI", code, jt, jf, k)
    if port is None:
        prog = [ins(0x30, 0, 0, 9),               # ldb [9]            protocol
                ins(0x15, 0, 1, proto),           # jeq proto
                ins(0x06, 0, 0, 0xFFFF),          # accept
                ins(0x06, 0, 0, 0)]               # reject
    else:
        prog = [ins(0x30, 0, 0, 9),               # ldb [9]            protocol
                ins(0x15, 0, 6, proto),           # jeq proto, else reject
                ins(0x28, 0, 0, 6),               # ldh [6]            flags + fragment offset
                ins(0x45, 4, 0, 0x1FFF),          # jset: not a first fragment -> reject
                ins(0xB1, 0, 0, 0),               # ldxb 4*([0]&0xf)   header length
                ins(0x48, 0, 0, 2),               # ldh [x+2]          destination port
                ins(0x15, 0, 1, port),            # jeq port
                ins(0x06, 0, 0, 0xFFFF),          # accept
                ins(0x06, 0, 0, 0)]               # reject
    return b"".join(prog)


def attach_filter(sock, prog):
    buf = ctypes.create_string_buffer(prog, len(prog))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                    struct.pack("@HP", len(prog) // 8, ctypes.addressof(buf)))


def open_capture(transport, port, mode="auto"):
    """Socket that receives incoming packets of one transport (and port).
    "packet" mode taps the network card before the kernel's source-address check,
    so spoofed sources are not dropped by rp_filter; "raw" is the fallback.
    -> (socket, "packet" | "raw")"""
    proto = IP_PROTO[transport]
    prog = bpf_program(proto, None if transport == "icmp" else port)
    sock, kind = None, None
    if mode in ("auto", "packet"):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
            kind = "packet"
        except (OSError, AttributeError) as exc:
            if mode == "packet":
                raise
            log.warning("packet capture is not available (%s); using a raw socket instead", exc)
    if sock is None:
        sock, kind = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto), "raw"
    try:
        attach_filter(sock, prog)
    except (OSError, ValueError, struct.error) as exc:
        log.debug("kernel packet filter unavailable (%s); filtering in user space", exc)
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    return sock, kind


def udp_sink(port):
    """Binds the tunnel's UDP port so the kernel does not answer the tunnel's
    packets with ICMP 'port unreachable'. Nothing is ever read from it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        sock.bind(("0.0.0.0", port))
        return sock
    except OSError as exc:
        sock.close()
        log.info("udp port %d is used by another program (%s)", port, exc)
        return None


def run_quiet(cmd):
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode
    except (OSError, subprocess.SubprocessError):
        return 127


def tweak_file(path, value, what):
    """Writes a kernel setting; returns a function that puts the old value back, or None."""
    try:
        with open(path) as fh:
            old = fh.read().strip()
        if old == value:
            return None
        with open(path, "w") as fh:
            fh.write(value)
    except OSError as exc:
        log.warning("could not change %s (%s)", what, exc)
        return None
    log.info("%s: set to %s while this runs (it is restored when it stops)", what, value)

    def undo():
        try:
            with open(path, "w") as fh:
                fh.write(old)
        except OSError:
            pass
    return undo


def drop_tcp_rst(port):
    """Hides the kernel's RST replies to tunnel packets. Returns an undo function or None."""
    if not shutil.which("iptables"):
        return None
    rule = ["OUTPUT", "-p", "tcp", "--sport", str(port), "--tcp-flags", "RST", "RST", "-j", "DROP"]
    if run_quiet(["iptables", "-C"] + rule) == 0:
        return None
    if run_quiet(["iptables", "-I"] + rule) != 0:
        log.info("could not add a firewall rule that hides TCP RST replies (harmless)")
        return None
    return lambda: run_quiet(["iptables", "-D"] + rule)


def warn_rp_filter():
    bad = []
    for name in ("all", "default"):
        try:
            with open("/proc/sys/net/ipv4/conf/%s/rp_filter" % name) as fh:
                if fh.read().strip() == "1":
                    bad.append(name)
        except OSError:
            pass
    if bad:
        log.warning("rp_filter is strict on this server and the packet tap is not in use, so the "
                    "kernel may drop spoofed packets. Fix: sysctl -w net.ipv4.conf.all.rp_filter=0 "
                    "net.ipv4.conf.default.rp_filter=0")


class Sess:
    __slots__ = ("sid", "addr", "sock", "last")

    def __init__(self, sid, addr=None, sock=None):
        self.sid, self.addr, self.sock, self.last = sid, addr, sock, time.monotonic()


class SpoofNode:
    ROLE = 0            # role byte in every message: 0 = entry, 1 = exit
    ICMP_SEND = 8       # entry sends echo requests, exit sends echo replies

    def __init__(self, args):
        self.args = args
        self.wire = Wire(args.token, self.ROLE)
        self.sender = RawSender(args.send, args.peer, parse_spoof_ips(args.spoof_ip), args.port,
                                args.peer_port, TCP_FLAGS[args.tcp_flags], self.ICMP_SEND)
        self.cap, self.cap_mode = open_capture(args.recv, args.port, args.capture)
        self.sink = udp_sink(args.port) if args.recv == "udp" else None
        self.undo = []
        self.loop = None
        self.hk = None
        self.sent = self.received = 0
        self.last_rx = None
        self.size_log = Throttle(10)

    # -- life cycle ---------------------------------------------------------
    def start(self, loop):
        self.loop = loop
        if self.args.recv == "icmp" and self.ROLE == 1:     # exit receives echo requests
            self.undo.append(tweak_file("/proc/sys/net/ipv4/icmp_echo_ignore_all", "1", "answering ping"))
        if self.args.recv == "tcp":
            self.undo.append(drop_tcp_rst(self.args.port))
        if self.cap_mode == "raw":
            warn_rp_filter()
        loop.add_reader(self.cap.fileno(), self.on_capture)
        self.hk = asyncio.ensure_future(self.housekeeping())
        log.info("%s up: sending %s to %s (%d source address(es)), receiving %s on %s (%s capture)",
                 self.NAME, self.args.send, self.args.peer, len(self.sender.spoofs),
                 self.args.recv, "port %d" % self.args.port if self.args.recv != "icmp" else "ICMP",
                 self.cap_mode)

    def close(self):
        if self.hk:
            self.hk.cancel()
        if self.loop:
            try:
                self.loop.remove_reader(self.cap.fileno())
            except Exception:
                pass
        for fn in reversed(self.undo):
            if fn:
                try:
                    fn()
                except Exception:
                    pass
        self.cap.close()
        self.sender.close()
        if self.sink:
            self.sink.close()

    # -- plumbing -----------------------------------------------------------
    def send_msg(self, mtype, sid, payload=b""):
        self.sender.send(self.wire.seal(mtype, sid, payload))
        self.sent += 1

    def too_big(self, data):
        if len(data) <= self.args.max_payload:
            return False
        if self.size_log.ok():
            log.warning("dropped a %d-byte datagram (limit %d). Lower the MTU of the program "
                        "using the tunnel (WireGuard: MTU = 1280).", len(data), self.args.max_payload)
        return True

    def on_capture(self):
        want = IP_PROTO[self.args.recv]
        for _ in range(256):
            try:
                data, addr = self.cap.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                log.debug("capture error: %s", exc)
                return
            if self.cap_mode == "packet" and addr[2] != PACKET_HOST:
                continue                                     # our own packets, broadcasts, ...
            pkt = parse_ip(data)
            if pkt is None:
                continue
            proto, _src, dport, payload, itype = pkt
            if proto != want or (proto == 1 and itype not in (0, 8)):
                continue
            if proto != 1 and dport != self.args.port:
                continue
            msg = self.wire.open(payload)
            if msg is None:
                continue
            self.received += 1
            self.last_rx = time.monotonic()
            self.on_message(*msg)

    async def housekeeping(self):
        last_stats, sent0, recv0 = time.monotonic(), 0, 0
        while True:
            await asyncio.sleep(1)
            now = time.monotonic()
            try:
                self.tick(now)
            except Exception as exc:
                log.debug("housekeeping: %r", exc)
            if now - last_stats >= STATS_EVERY:
                if self.sent != sent0 or self.received != recv0:
                    log.info("last minute: sent %d packets, received %d packets",
                             self.sent - sent0, self.received - recv0)
                last_stats, sent0, recv0 = now, self.sent, self.received

    def tick(self, now):
        pass


class SpoofEntry(SpoofNode):
    ROLE = 0
    ICMP_SEND = 8
    NAME = "entry"

    def __init__(self, args):
        super().__init__(args)
        self.local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local.setblocking(False)
        self.local.bind((args.listen_bind, args.listen_port))
        self.by_addr, self.by_id = {}, {}
        self.started = time.monotonic()
        self.up = False
        self.warned = False
        self.last_pong = 0.0
        self.last_ping = 0.0

    def start(self, loop):
        super().start(loop)
        loop.add_reader(self.local.fileno(), self.on_local)
        log.info("entry: apps send UDP to %s:%d", self.args.listen_bind, self.args.listen_port)

    def close(self):
        try:
            self.loop.remove_reader(self.local.fileno())
        except Exception:
            pass
        self.local.close()
        super().close()

    def on_local(self):
        for _ in range(256):
            try:
                data, addr = self.local.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            if self.too_big(data):
                continue
            s = self.by_addr.get(addr)
            if s is None:
                if len(self.by_addr) >= MAX_SESSIONS:
                    continue
                sid = random.getrandbits(32)
                while sid in self.by_id:
                    sid = random.getrandbits(32)
                s = self.by_addr[addr] = self.by_id[sid] = Sess(sid, addr=addr)
                log.debug("new session %08x from %s:%d", sid, addr[0], addr[1])
            s.last = time.monotonic()
            self.send_msg(T_DATA, s.sid, data)

    def on_message(self, mtype, sid, payload):
        if mtype == T_DATA:
            s = self.by_id.get(sid)
            if s is not None:
                s.last = time.monotonic()
                try:
                    self.local.sendto(payload, s.addr)
                except OSError:
                    pass
        elif mtype == T_PONG:
            self.last_pong = time.monotonic()
            if not self.up:
                self.up = True
                log.info("the other server answered: the spoof tunnel is working")

    def tick(self, now):
        if now - self.last_ping >= PING_EVERY:
            self.last_ping = now
            self.send_msg(T_PING, 0, b"nt")
        if self.up and now - self.last_pong > PEER_DEAD_AFTER:
            self.up = False
            log.warning("no answer from the other server for %ds", PEER_DEAD_AFTER)
        elif not self.up and not self.warned and now - self.started > PEER_DEAD_AFTER and self.last_pong == 0.0:
            self.warned = True
            log.warning("no answer from the other server yet. Check: same token on both servers, "
                        "the spoof addresses (use the Spoof tester), and the firewall of both providers")
        for sid, s in list(self.by_id.items()):
            if now - s.last > SESSION_IDLE:
                del self.by_id[sid]
                self.by_addr.pop(s.addr, None)


class SpoofExit(SpoofNode):
    ROLE = 1
    ICMP_SEND = 0
    NAME = "exit"

    def __init__(self, args):
        super().__init__(args)
        host, _, port = args.forward.rpartition(":")
        self.target = (socket.gethostbyname(host or "127.0.0.1"), int(port))
        self.sessions = {}
        self.seen_peer = False
        self.limit_log = Throttle(10)

    def start(self, loop):
        super().start(loop)
        log.info("exit: forwarding to udp %s:%d", *self.target)

    def close(self):
        for s in self.sessions.values():
            try:
                self.loop.remove_reader(s.sock.fileno())
            except Exception:
                pass
            s.sock.close()
        self.sessions.clear()
        super().close()

    def on_message(self, mtype, sid, payload):
        if not self.seen_peer:
            self.seen_peer = True
            log.info("receiving authenticated packets from the other server")
        if mtype == T_PING:
            self.send_msg(T_PONG, sid, payload)
        elif mtype == T_DATA:
            s = self.sessions.get(sid)
            if s is None:
                if len(self.sessions) >= MAX_SESSIONS:
                    if self.limit_log.ok():
                        log.warning("too many sessions (%d); ignoring new ones", MAX_SESSIONS)
                    return
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect(self.target)
                s = self.sessions[sid] = Sess(sid, sock=sock)
                self.loop.add_reader(sock.fileno(), self.on_target, s)
                log.debug("new session %08x", sid)
            s.last = time.monotonic()
            try:
                s.sock.send(payload)
            except OSError:
                pass                                     # target not listening yet

    def on_target(self, s):
        for _ in range(64):
            try:
                data = s.sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return                                   # ICMP "refused" from the target
            if self.too_big(data):
                continue
            s.last = time.monotonic()
            self.send_msg(T_DATA, s.sid, data)

    def tick(self, now):
        for sid, s in list(self.sessions.items()):
            if now - s.last > SESSION_IDLE:
                try:
                    self.loop.remove_reader(s.sock.fileno())
                except Exception:
                    pass
                s.sock.close()
                del self.sessions[sid]
        if self.seen_peer and self.last_rx is not None and now - self.last_rx > 2 * PEER_DEAD_AFTER:
            self.seen_peer = False
            log.warning("no packets from the other server for %ds", 2 * PEER_DEAD_AFTER)


async def run_spoof(args):
    node = (SpoofEntry if args.role == "spoof-entry" else SpoofExit)(args)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, ValueError):
            pass
    try:
        node.start(loop)
        await stop.wait()
    finally:
        node.close()


# -- spoof tester -------------------------------------------------------------
def local_ip_towards(peer):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((peer, 9))
        return socket.inet_aton(s.getsockname()[0])
    finally:
        s.close()


def test_send(args):
    spoofs = parse_spoof_ips(args.spoof_ip)
    total = (len(spoofs) + 1) * args.count
    if total > TEST_MAX_PACKETS:
        sys.exit("error: that would be %d test packets (limit %d). Use fewer addresses or --count 1."
                 % (total, TEST_MAX_PACKETS))
    sender = RawSender(args.transport, args.peer, spoofs, args.port, args.port, TCP_FLAGS[args.tcp_flags], 8)
    run_id = random.getrandbits(32)
    real = local_ip_towards(args.peer)
    delay = 1.0 / args.rate
    print("Sending %d test packets to %s (%s, port %d): %d address(es) x %d, plus %d normal ones..."
          % (total, args.peer, args.transport, args.port, len(spoofs), args.count, args.count))
    sys.stdout.flush()
    for src, kind in [(real, 0)] + [(ip, 1) for ip in spoofs]:
        for k in range(args.count):
            sender.send_from(src, PROBE_MAGIC + struct.pack("!IHHB", run_id, args.count, k, kind) + bytes(24))
            time.sleep(delay)
    sender.close()
    print("Done. Now read the result on the receiving server.")
    return 0


def test_recv(args):
    cap, mode = open_capture(args.transport, args.port, args.capture)
    sink = udp_sink(args.port) if args.transport == "udp" else None
    undo = []
    if args.transport == "icmp":
        undo.append(tweak_file("/proc/sys/net/ipv4/icmp_echo_ignore_all", "1", "answering ping"))
    if args.transport == "tcp":
        undo.append(drop_tcp_rst(args.port))
    seen = {}                                        # source ip -> [kind, per-ip count, {k}]
    print("Waiting %d seconds for test packets (%s, port %s)..." %
          (args.seconds, args.transport, args.port if args.transport != "icmp" else "-"))
    sys.stdout.flush()
    deadline = time.monotonic() + args.seconds
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select([cap], [], [], min(left, 0.5))
            if not ready:
                continue
            for _ in range(512):
                try:
                    data, addr = cap.recvfrom(65535)
                except (BlockingIOError, InterruptedError):
                    break
                if mode == "packet" and addr[2] != PACKET_HOST:
                    continue
                pkt = parse_ip(data)
                if pkt is None:
                    continue
                proto, src, dport, payload, itype = pkt
                if proto != IP_PROTO[args.transport] or (proto == 1 and itype != 8):
                    continue
                if proto != 1 and dport != args.port:
                    continue
                if not payload.startswith(PROBE_MAGIC) or len(payload) < len(PROBE_MAGIC) + 9:
                    continue
                _run, per_ip, k, kind = struct.unpack_from("!IHHB", payload, len(PROBE_MAGIC))
                rec = seen.setdefault(socket.inet_ntoa(src), [kind, per_ip, set()])
                rec[2].add(k)
    finally:
        for fn in reversed(undo):
            if fn:
                fn()
        cap.close()
        if sink:
            sink.close()

    real = {ip: r for ip, r in seen.items() if r[0] == 0}
    spoofed = {ip: r for ip, r in seen.items() if r[0] == 1}
    print()
    if real:
        ip, r = next(iter(real.items()))
        print("Normal packets (real source %s): %d of %d arrived -> the network path works." % (ip, len(r[2]), r[1]))
    else:
        print("Normal packets (real source address): none arrived.")
    print("Spoofed source addresses that arrived: %d" % len(spoofed))
    order = sorted(spoofed.items(), key=lambda kv: (-len(kv[1][2]), socket.inet_aton(kv[0])))
    for ip, r in order[:40]:
        print("   %-16s %d of %d" % (ip, len(r[2]), r[1]))
    if len(order) > 40:
        print("   ... and %d more" % (len(order) - 40))
    if spoofed:
        good = [ip for ip, _ in order]
        print()
        print("Working addresses (copy this list into the other server's tunnel settings):")
        print(",".join(good) if len(good) <= 40 else "(%d addresses, see the saved file)" % len(good))
        if args.out:
            try:
                with open(args.out, "w") as fh:
                    fh.write("\n".join(good) + "\n")
                print("Saved to %s  (use it as @%s)" % (args.out, args.out))
            except OSError as exc:
                print("Could not save %s: %s" % (args.out, exc))
    elif real:
        print()
        print("Normal packets arrive but spoofed ones do not: the hosting provider (or a router on the way)")
        print("blocks spoofed source addresses. The spoof tunnel cannot work on this path.")
    else:
        print()
        print("Nothing arrived. Possible reasons: the sender was not running during this time, the port or")
        print("transport differs between the two servers, a firewall (also the provider's panel) blocks it,")
        print("or the path is cut.")
    return 0


def run_spoof_test(args):
    return test_send(args) if args.mode == "send" else test_recv(args)


def run_spoof_check(args):
    if args.ips is not None:
        try:
            print(len(parse_spoof_ips(args.ips)))
        except (ValueError, OSError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        return 0
    problems = []
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW).close()
    except OSError as exc:
        problems.append("cannot send raw packets (%s)" % exc)
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)).close()
    except (OSError, AttributeError) as exc:
        try:
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP).close()
        except OSError as exc2:
            problems.append("cannot capture packets (%s / %s)" % (exc, exc2))
    if problems:
        print("; ".join(problems))
        return 1
    print("ok")
    return 0


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def add_spoof_args(sp):
    sp.add_argument("--peer", required=True, help="real IPv4 address of the other server")
    sp.add_argument("--spoof-ip", required=True,
                    help="source addresses for the packets THIS server sends: 1.2.3.4, 10.0.0.0/24, "
                         "5.5.5.1-5.5.5.9, @file (comma separated)")
    sp.add_argument("--transport", choices=TRANSPORTS, default="udp",
                    help="packet type in both directions (default udp)")
    sp.add_argument("--send", choices=TRANSPORTS, help="packet type this server sends (default: --transport)")
    sp.add_argument("--recv", choices=TRANSPORTS, help="packet type this server receives (default: --transport)")
    sp.add_argument("--port", type=int, default=4500, help="port this server receives tunnel packets on")
    sp.add_argument("--peer-port", type=int, help="port the other server receives on (default: --port)")
    sp.add_argument("--tcp-flags", choices=sorted(TCP_FLAGS), default="syn", help="flags for tcp packets")
    sp.add_argument("--max-payload", type=int, default=1400, help="largest datagram to carry (default 1400)")
    sp.add_argument("--capture", choices=("auto", "packet", "raw"), default="auto")


def build_parser():
    p = argparse.ArgumentParser(description="NiceTunnel: reverse TCP tunnel and spoof tunnel")
    p.add_argument("--token", default=os.environ.get("NICETUNNEL_TOKEN"),
                   help="shared secret (or set NICETUNNEL_TOKEN); at least 16 characters")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version="NiceTunnel engine " + VERSION)
    sub = p.add_subparsers(dest="role", required=True)

    s = sub.add_parser("server", help="run on the machine users connect to")
    s.add_argument("--bridge", type=int, default=7000, help="tunnel port the client dials (default 7000)")
    s.add_argument("--ports", type=parse_ports, required=True,
                   help="public ports, e.g. 443,8443:8080 (public[:target-port-on-client-side])")
    s.add_argument("--bind", default="0.0.0.0", help="address for the bridge port")
    s.add_argument("--public-bind", default="0.0.0.0", help="address for the public ports")

    c = sub.add_parser("client", help="run on the other machine")
    c.add_argument("--server", required=True, help="IP or hostname of the tunnel server")
    c.add_argument("--bridge", type=int, default=7000, help="server bridge port (default 7000)")
    c.add_argument("--target-host", default="127.0.0.1",
                   help="where forwarded connections go on this machine (default 127.0.0.1)")

    e = sub.add_parser("spoof-entry", help="spoof tunnel, the side apps send UDP to")
    add_spoof_args(e)
    e.add_argument("--listen-port", type=int, required=True, help="UDP port apps send to")
    e.add_argument("--listen-bind", default="0.0.0.0")

    x = sub.add_parser("spoof-exit", help="spoof tunnel, the side that forwards to the UDP service")
    add_spoof_args(x)
    x.add_argument("--forward", default="127.0.0.1:51820", help="HOST:PORT of the UDP service")

    t = sub.add_parser("spoof-test", help="find out which spoofed source addresses get through")
    tsub = t.add_subparsers(dest="mode", required=True)
    tr = tsub.add_parser("recv", help="run this first, on the receiving server")
    ts = tsub.add_parser("send", help="then run this on the sending server")
    for sp in (tr, ts):
        sp.add_argument("--transport", choices=TRANSPORTS, default="udp")
        sp.add_argument("--port", type=int, default=4500)
        sp.add_argument("--capture", choices=("auto", "packet", "raw"), default="auto")
        sp.add_argument("--tcp-flags", choices=sorted(TCP_FLAGS), default="syn")
    tr.add_argument("--seconds", type=int, default=60)
    tr.add_argument("--out", help="save the working addresses to this file")
    ts.add_argument("--peer", required=True)
    ts.add_argument("--spoof-ip", required=True)
    ts.add_argument("--count", type=int, default=5, help="packets per address")
    ts.add_argument("--rate", type=int, default=200, help="packets per second (default 200)")

    k = sub.add_parser("spoof-check", help="helper for the menu")
    k.add_argument("--ips", help="validate a spoof address list and print how many it contains")
    k.add_argument("--raw", action="store_true", help="check that this server can use raw sockets")
    return p


def check_spoof_args(args):
    """Fills in defaults and returns an error text, or None."""
    for name in ("port", "peer_port", "listen_port"):
        v = getattr(args, name, None)
        if v is not None and not 1 <= v <= 65535:
            return "--%s must be 1-65535" % name.replace("_", "-")
    if args.role in ("spoof-entry", "spoof-exit"):
        args.send = args.send or args.transport
        args.recv = args.recv or args.transport
        args.peer_port = args.peer_port or args.port
        try:
            socket.inet_aton(args.peer)
            if args.peer.count(".") != 3:
                raise OSError
            parse_spoof_ips(args.spoof_ip)
        except (OSError, ValueError) as exc:
            return "bad --peer or --spoof-ip: %s" % (exc or "peer must be an IPv4 address")
        if args.role == "spoof-entry" and args.recv == "udp" and args.listen_port == args.port:
            return "--listen-port and --port must differ when the tunnel uses udp"
        if args.role == "spoof-exit":
            host, _, port = args.forward.rpartition(":")
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                return "--forward must look like HOST:PORT"
    return None


def main():
    args = build_parser().parse_args()
    if args.role == "spoof-check":
        sys.exit(run_spoof_check(args))
    needs_token = args.role in ("server", "client", "spoof-entry", "spoof-exit")
    if needs_token and (not args.token or len(args.token) < 16):
        sys.exit("error: a token of at least 16 characters is required (--token or NICETUNNEL_TOKEN)")
    problem = check_spoof_args(args)
    if problem:
        sys.exit("error: " + problem)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    if args.role == "spoof-test":
        try:
            sys.exit(run_spoof_test(args))
        except KeyboardInterrupt:
            sys.exit(130)
        except PermissionError:
            sys.exit("error: the spoof tester needs root (raw sockets). Run it as root.")
        except OSError as exc:
            sys.exit("error: %s" % exc)
    runners = {"server": run_server, "client": run_client,
              "spoof-entry": run_spoof, "spoof-exit": run_spoof}
    try:
        asyncio.run(runners[args.role](args))
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("error: the spoof tunnel needs root (raw sockets). Run it as root.")


if __name__ == "__main__":
    main()
