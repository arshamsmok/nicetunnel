#!/usr/bin/env python3
"""NiceTunnel - a small reverse TCP tunnel.

Author: Arsham Smoke
License: MIT (see LICENSE)

Two roles:
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

Standard library only. Python 3.8+.
"""
import argparse
import asyncio
import functools
import hashlib
import hmac
import itertools
import logging
import os
import secrets
import socket
import sys

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
# entry point
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="Minimal reverse TCP tunnel")
    p.add_argument("--token", default=os.environ.get("NICETUNNEL_TOKEN"),
                   help="shared secret (or set NICETUNNEL_TOKEN); at least 16 characters")
    p.add_argument("-v", "--verbose", action="store_true")
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
    return p


def main():
    args = build_parser().parse_args()
    if not args.token or len(args.token) < 16:
        sys.exit("error: a token of at least 16 characters is required (--token or NICETUNNEL_TOKEN)")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")
    runner = run_server if args.role == "server" else run_client
    try:
        asyncio.run(runner(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
