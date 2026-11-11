#!/usr/bin/env python3
"""NiceTunnel web panel - create, connect and manage SPOOF tunnels from a browser.

Runs on ONE server (the one you manage from). It manages the reverse TCP and
spoof tunnel slots of that server, using the same slot files and systemd units as the
"nicetunnel" menu, so a tunnel made here also shows up in the menu and vice versa.
To control the other server too, run the panel there as well.

Usage (as root):
  python3 nicetunnel_panel.py set-password          # first time
  python3 nicetunnel_panel.py serve [--bind 127.0.0.1] [--port 8787]

Keep it on 127.0.0.1 and open it through an SSH tunnel:
  ssh -L 8787:127.0.0.1:8787 root@SERVER_IP   then open http://127.0.0.1:8787

Scope: reverse TCP tunnels, SPOOF tunnels and the spoof tester of THIS server.

Standard library only. Python 3.8+.
"""
import argparse
import getpass
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

APP_DIR = os.environ.get("NICETUNNEL_APP_DIR", "/opt/nicetunnel")
CONF_DIR = os.environ.get("NICETUNNEL_CONF_DIR", "/etc/nicetunnel")
PANEL_CONF = os.path.join(CONF_DIR, "panel.json")
ENGINE = os.path.join(APP_DIR, "nicetunnel.py")
MAX_SLOT = 10
SESSION_TTL = 12 * 3600
LOGIN_FAILS_MAX = 5
TRANSPORTS = ("udp", "tcp", "icmp")

sessions = {}   # session id -> expiry time
sess_owner = {}  # session id -> "admin" or "tok:<token id>"
# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, universal_newlines=True)
        return p.returncode, p.stdout
    except Exception as exc:
        return 1, str(exc)


def hash_password(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    return salt.hex() + "$" + dk.hex()


def check_password(pw, stored):
    try:
        salt_hex, _ = stored.split("$", 1)
        return hmac.compare_digest(hash_password(pw, bytes.fromhex(salt_hex)), stored)
    except Exception:
        return False


def load_panel_conf():
    try:
        with open(PANEL_CONF) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_panel_conf(conf):
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    tmp = PANEL_CONF + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(conf, fh)
    os.replace(tmp, PANEL_CONF)


def valid_ipv4(text):
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv4Address)
    except ValueError:
        return False


def valid_port(v):
    return isinstance(v, int) and 1 <= v <= 65535


def valid_spoof_list(text):
    """Accepts 1.2.3.4, 10.0.0.0/28, 5.5.5.1-5.5.5.9 separated by commas."""
    items = [x for x in text.split(",") if x]
    if not items or len(items) > 50:
        return False
    for item in items:
        try:
            if "/" in item:
                ipaddress.IPv4Network(item, strict=False)
            elif "-" in item:
                first, _, last = item.partition("-")
                lo = int(ipaddress.IPv4Address(first))
                hi = int(ipaddress.IPv4Address(last if "." in last else first.rsplit(".", 1)[0] + "." + last))
                if hi < lo or hi - lo > 65535:
                    return False
            else:
                ipaddress.IPv4Address(item)
        except ValueError:
            return False
    return True


def slot_file(n):
    return os.path.join(CONF_DIR, "slot%d.env" % n)


def read_env(path):
    data = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                data[k] = v.strip('"')
    return data


def list_slots(spoof_only=False):
    """Returns every slot the panel can manage, tagged with its TYPE.

    Reverse slots written by nicetunnel.sh carry TYPE=tcp, spoof slots TYPE=spoof.
    Older slot files with no TYPE are treated as reverse tunnels.
    """
    out = []
    for n in range(1, MAX_SLOT + 1):
        if not os.path.exists(slot_file(n)):
            continue
        try:
            env = read_env(slot_file(n))
        except OSError:
            continue
        kind = env.get("TYPE") or "tcp"
        if spoof_only and kind != "spoof":
            continue
        _, st = run(["systemctl", "is-active", "nicetunnel@%d" % n])
        state = st.strip() or "unknown"
        if kind == "spoof":
            out.append({
                "slot": n, "kind": "spoof",
                "role": env.get("ROLE", ""),
                "side": "Iran (entry)" if env.get("ROLE") == "server" else "Foreign (exit)",
                "transport": env.get("TRANSPORT", ""),
                "port": env.get("TPORT", ""),
                "peer": env.get("PEER_IP", ""),
                "spoof_ips": env.get("SPOOF_IPS", ""),
                "listen_port": env.get("LISTEN_PORT", ""),
                "forward": env.get("FORWARD", ""),
                "state": state,
            })
        else:
            out.append({
                "slot": n, "kind": "reverse",
                "role": env.get("ROLE", ""),
                "side": "Iran (server)" if env.get("ROLE") == "server" else "Foreign (client)",
                "bridge": env.get("BRIDGE", ""),
                "ports": env.get("PORTS", ""),
                "server_ip": env.get("SERVER_IP", ""),
                "target_host": env.get("TARGET_HOST", ""),
                "state": state,
            })
    return out


def list_spoof_slots():
    return list_slots(spoof_only=True)


def first_free_slot():
    for n in range(1, MAX_SLOT + 1):
        if not os.path.exists(slot_file(n)):
            return n
    return None


def valid_slot(n):
    return isinstance(n, int) and 1 <= n <= MAX_SLOT and os.path.exists(slot_file(n))


def write_spoof_slot(n, p):
    """Same file format as the menu's spoof slots, so the menu understands it."""
    if p["role"] == "server":
        args = "spoof-entry --peer %s --spoof-ip %s --transport %s --port %d --listen-port %d" % (
            p["peer"], p["spoof_ips"], p["transport"], p["port"], p["listen_port"])
    else:
        args = "spoof-exit --peer %s --spoof-ip %s --transport %s --port %d --forward %s" % (
            p["peer"], p["spoof_ips"], p["transport"], p["port"], p["forward"])
    body = (
        "TYPE=spoof\n"
        "ROLE=%(role)s\nTRANSPORT=%(transport)s\nTPORT=%(port)d\nPEER_IP=%(peer)s\n"
        "SPOOF_IPS=%(spoof_ips)s\nLISTEN_PORT=%(listen_port)s\nFORWARD=%(forward)s\n"
        "NICETUNNEL_TOKEN=%(token)s\nRT_ARGS=\"%(args)s\"\n"
    ) % dict(p, args=args)
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    fd = os.open(slot_file(n), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)


def write_reverse_slot(n, p):
    """Same file format as nicetunnel.sh write_slot(), so the menu understands it."""
    if p["role"] == "server":
        args = "server --bridge %s --ports %s" % (p["bridge"], p["ports"])
    else:
        args = "client --server %s --bridge %s --target-host %s" % (
            p["server_ip"], p["bridge"], p["target_host"])
    body = (
        "TYPE=tcp\n"
        "ROLE=%(role)s\nBRIDGE=%(bridge)s\nPORTS=%(ports)s\n"
        "SERVER_IP=%(server_ip)s\nTARGET_HOST=%(target_host)s\n"
        "NICETUNNEL_TOKEN=%(token)s\nRT_ARGS=\"%(args)s\"\n"
    ) % dict(p, args=args)
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    fd = os.open(slot_file(n), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)


def validate_spoof(d):
    """Returns (clean_dict, error). Input comes from the browser, so check everything."""
    role = d.get("role")
    if role not in ("server", "client"):
        return None, "role must be Iran or Foreign"
    transport = d.get("transport", "udp")
    if transport not in TRANSPORTS:
        return None, "transport must be udp, tcp or icmp"
    peer = str(d.get("peer", "")).strip()
    if not valid_ipv4(peer):
        return None, "peer must be an IPv4 address of the other server"
    spoof_ips = re.sub(r"\s+", "", str(d.get("spoof_ips", "")))
    if not valid_spoof_list(spoof_ips):
        return None, "spoof source addresses are not valid (e.g. 10.0.0.0/28 or 1.2.3.4)"
    try:
        port = int(d.get("port", 4500))
    except (TypeError, ValueError):
        return None, "tunnel port must be a number"
    if not valid_port(port):
        return None, "tunnel port must be 1-65535"
    token = str(d.get("token", "")).strip() or secrets.token_hex(16)
    if len(token) < 16 or not re.fullmatch(r"[A-Za-z0-9._~+=-]+", token):
        return None, "token must be at least 16 characters (letters, digits, . _ ~ + = -)"
    clean = {"role": role, "transport": transport, "peer": peer, "spoof_ips": spoof_ips,
             "port": port, "token": token, "listen_port": 0, "forward": ""}
    if role == "server":
        try:
            lp = int(d.get("listen_port", 0))
        except (TypeError, ValueError):
            return None, "listen port must be a number"
        if not valid_port(lp):
            return None, "listen port (UDP port your apps send to) must be 1-65535"
        if transport == "udp" and lp == port:
            return None, "listen port and tunnel port must differ when using udp"
        clean["listen_port"] = lp
    else:
        fwd = str(d.get("forward", "127.0.0.1:51820")).strip()
        host, _, fport = fwd.rpartition(":")
        if not fport.isdigit() or not valid_port(int(fport)) or not host:
            return None, "forward must look like HOST:PORT (e.g. 127.0.0.1:51820)"
        clean["forward"] = fwd
    return clean, None


def valid_host(text):
    if not text or len(text) > 253:
        return False
    if valid_ipv4(text):
        return True
    return re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", text) is not None


def valid_ports_list(text):
    """Comma list of ports or ranges: 80,443,2000-2010."""
    items = [x for x in text.split(",") if x]
    if not items or len(items) > 100:
        return False
    for it in items:
        a, _, b = it.partition("-")
        if not a.isdigit() or (b and not b.isdigit()):
            return False
        lo = int(a)
        hi = int(b) if b else lo
        if not (valid_port(lo) and valid_port(hi)) or hi < lo:
            return False
    return True


def validate_reverse(d):
    """Returns (clean_dict, error) for a reverse TCP tunnel."""
    role = d.get("role")
    if role not in ("server", "client"):
        return None, "role must be Iran (server) or Foreign (client)"
    try:
        bridge = int(d.get("bridge", 7000))
    except (TypeError, ValueError):
        return None, "bridge port must be a number"
    if not valid_port(bridge):
        return None, "bridge port must be 1-65535"
    token = str(d.get("token", "")).strip() or secrets.token_hex(16)
    if len(token) < 16 or not re.fullmatch(r"[A-Za-z0-9._~+=-]+", token):
        return None, "token must be at least 16 characters (letters, digits, . _ ~ + = -)"
    clean = {"role": role, "bridge": bridge, "ports": "", "server_ip": "",
             "target_host": "", "token": token}
    if role == "server":
        ports = re.sub(r"\s+", "", str(d.get("ports", "")))
        if not valid_ports_list(ports):
            return None, "ports must look like 80,443,2000-2010"
        clean["ports"] = ports
    else:
        sip = str(d.get("server_ip", "")).strip()
        if not valid_ipv4(sip):
            return None, "Iran server must be an IPv4 address"
        th = str(d.get("target_host", "127.0.0.1")).strip() or "127.0.0.1"
        if not valid_host(th):
            return None, "target host is not valid"
        clean["server_ip"] = sip
        clean["target_host"] = th
    return clean, None


# --------------------------------------------------------------------------
# web page
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# spoof tester (runs the engine's spoof-test in the background)
# --------------------------------------------------------------------------
tester_lock = threading.Lock()
tester = {"title": "", "log": "", "running": False, "code": None}


def tester_reader(proc):
    for line in proc.stdout:
        with tester_lock:
            tester["log"] += line
    proc.wait()
    with tester_lock:
        tester["running"] = False
        tester["code"] = proc.returncode


def tester_start(title, engine_args):
    with tester_lock:
        if tester["running"]:
            return False, "a test is already running"
        if not os.path.exists(ENGINE):
            return False, "engine not found: %s" % ENGINE
        proc = subprocess.Popen([sys.executable, ENGINE] + engine_args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        tester.update(title=title, log="", running=True, code=None)
    threading.Thread(target=tester_reader, args=(proc,), daemon=True).start()
    return True, None


def validate_test(kind, d):
    """Returns (engine_args, error) for a spoof-test run."""
    transport = d.get("transport", "udp")
    if transport not in TRANSPORTS:
        return None, "transport must be udp, tcp or icmp"
    try:
        port = int(d.get("port", 4500))
    except (TypeError, ValueError):
        return None, "port must be a number"
    if not valid_port(port):
        return None, "port must be 1-65535"
    if kind == "recv":
        try:
            secs = int(d.get("seconds", 60))
        except (TypeError, ValueError):
            return None, "seconds must be a number"
        if not 5 <= secs <= 300:
            return None, "seconds must be 5-300"
        return ["spoof-test", "recv", "--transport", transport, "--port", str(port),
                "--seconds", str(secs)], None
    peer = str(d.get("peer", "")).strip()
    if not valid_ipv4(peer):
        return None, "peer must be an IPv4 address of the other server"
    spoof = re.sub(r"\s+", "", str(d.get("spoof_ips", "")))
    if not valid_spoof_list(spoof):
        return None, "spoof source addresses are not valid (e.g. 10.0.0.0/28 or 1.2.3.4)"
    try:
        count = int(d.get("count", 5))
    except (TypeError, ValueError):
        return None, "packets per address must be a number"
    if not 1 <= count <= 10:
        return None, "packets per address must be 1-10"
    return ["spoof-test", "send", "--peer", peer, "--spoof-ip", spoof, "--transport", transport,
            "--port", str(port), "--count", str(count)], None


# --------------------------------------------------------------------------
# web page
# --------------------------------------------------------------------------
PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NiceTunnel Panel</title>
<style>
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{font-family:system-ui,Segoe UI,sans-serif;color:#e8ecff;background:#070b1a;overflow-x:hidden}
#bg{position:fixed;inset:0;z-index:-2;background:
 radial-gradient(60vw 60vw at 15% 10%,rgba(99,102,241,.55),transparent 60%),
 radial-gradient(50vw 50vw at 90% 20%,rgba(236,72,153,.40),transparent 60%),
 radial-gradient(55vw 55vw at 70% 100%,rgba(20,184,166,.45),transparent 60%),
 radial-gradient(40vw 40vw at 0% 100%,rgba(56,189,248,.35),transparent 60%),#070b1a;
 animation:drift 18s ease-in-out infinite alternate}
@keyframes drift{from{filter:hue-rotate(0deg) saturate(1)}to{filter:hue-rotate(35deg) saturate(1.25)}}
#grid{position:fixed;inset:0;z-index:-1;opacity:.25;
 background-image:linear-gradient(rgba(255,255,255,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.08) 1px,transparent 1px);
 background-size:46px 46px;mask-image:radial-gradient(circle at 50% 40%,#000,transparent 75%);-webkit-mask-image:radial-gradient(circle at 50% 40%,#000,transparent 75%)}
.glass{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);border-radius:16px;
 backdrop-filter:blur(18px) saturate(140%);-webkit-backdrop-filter:blur(18px) saturate(140%);box-shadow:0 8px 32px rgba(0,0,0,.35)}
#shell{display:flex;min-height:100vh;gap:16px;padding:16px}
#side{width:230px;flex:none;padding:18px 12px;display:flex;flex-direction:column;gap:6px;position:sticky;top:16px;height:calc(100vh - 32px)}
.brand{font-weight:700;font-size:18px;padding:6px 10px 14px;letter-spacing:.3px}
.brand small{display:block;font-weight:400;font-size:11px;color:#9aa6d6}
.nav{display:flex;align-items:center;gap:10px;padding:11px 12px;border-radius:12px;cursor:pointer;color:#c9d2ff;border:1px solid transparent;transition:.2s;user-select:none}
.nav:hover{background:rgba(255,255,255,.09)}
.nav.on{background:linear-gradient(135deg,rgba(99,102,241,.55),rgba(56,189,248,.35));border-color:rgba(255,255,255,.25);color:#fff}
.nav i{font-style:normal;width:20px;text-align:center}
.sp{flex:1}
#main{flex:1;min-width:0;display:flex;flex-direction:column;gap:16px}
#top{padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
#top h1{margin:0;font-size:19px}
.page{display:none;flex-direction:column;gap:16px}.page.on{display:flex}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}
.card{padding:16px}
.card .k{font-size:12px;color:#9aa6d6;text-transform:uppercase;letter-spacing:.8px}
.card .v{font-size:28px;font-weight:700;margin:6px 0}
.card .s{font-size:12px;color:#b8c2ee}
.bar{height:7px;border-radius:6px;background:rgba(255,255,255,.12);overflow:hidden;margin-top:8px}
.bar b{display:block;height:100%;width:0;background:linear-gradient(90deg,#38bdf8,#818cf8,#ec4899);transition:width .6s}
canvas{width:100%;height:90px;display:block}
.sec{padding:18px}.sec h2{margin:0 0 12px;font-size:16px}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{padding:10px 8px;text-align:left;border-bottom:1px solid rgba(255,255,255,.1)}
th{color:#9aa6d6;font-weight:500;font-size:12px;text-transform:uppercase}
input,select,button{font:inherit;color:#fff;background:rgba(255,255,255,.09);border:1px solid rgba(255,255,255,.22);border-radius:10px;padding:9px 11px;outline:none}
input:focus,select:focus{border-color:#818cf8;box-shadow:0 0 0 3px rgba(129,140,248,.25)}
select option{color:#111}
input::placeholder{color:#7f8bb8}
button{cursor:pointer;transition:.15s}button:hover{background:rgba(255,255,255,.18)}
button.ok{background:linear-gradient(135deg,#6366f1,#06b6d4);border-color:transparent;font-weight:600}
button.danger{background:rgba(244,63,94,.25);border-color:rgba(244,63,94,.6)}
button.sm{padding:5px 9px;font-size:12px;margin:1px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
.row>div{display:flex;flex-direction:column;min-width:200px;flex:1}
label{font-size:12px;color:#aab4e6;margin-bottom:4px}
pre{background:rgba(0,0,0,.45);border-radius:10px;padding:12px;overflow:auto;max-height:340px;font-size:12px;margin:0;white-space:pre-wrap}
.msg{padding:10px 12px;border-radius:10px;margin-bottom:10px}.good{background:rgba(16,185,129,.25)}.bad{background:rgba(244,63,94,.25)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:#888}
.active .dot{background:#34d399;box-shadow:0 0 8px #34d399}.inactive .dot,.failed .dot{background:#f43f5e}
.active{color:#6ee7b7}.inactive,.failed{color:#fda4af}
code{background:rgba(0,0,0,.4);padding:2px 6px;border-radius:6px;word-break:break-all}
#login{max-width:400px;margin:12vh auto;padding:28px}#login h1{margin-top:0}#login .row>div{min-width:100%}
.hide{display:none!important}
/* v3: glass polish */
body{background:#050815}
.glass{background:linear-gradient(145deg,rgba(255,255,255,.15),rgba(255,255,255,.04));border:1px solid rgba(255,255,255,.2);border-radius:20px;box-shadow:0 12px 40px rgba(0,0,0,.42),inset 0 1px 0 rgba(255,255,255,.28)}
#side{background:linear-gradient(170deg,rgba(255,255,255,.13),rgba(255,255,255,.03))}
.brand{font-size:21px;background:linear-gradient(90deg,#fff,#a5b4fc,#f0abfc);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand small{-webkit-text-fill-color:#9aa6d6}
.nav{border-radius:14px;transition:all .25s cubic-bezier(.2,.8,.2,1)}
.nav:hover{background:rgba(255,255,255,.12);transform:translateX(-3px)}
#shell[dir=rtl] .nav:hover{transform:translateX(3px)}
.nav.on{box-shadow:0 8px 24px rgba(99,102,241,.38),inset 0 1px 0 rgba(255,255,255,.3)}
#top{background:linear-gradient(145deg,rgba(255,255,255,.14),rgba(255,255,255,.04))}
#top h1{font-size:21px;letter-spacing:.2px}
.card{transition:transform .25s,box-shadow .25s}
.card:hover{transform:translateY(-3px);box-shadow:0 18px 46px rgba(0,0,0,.5)}
.card .v{background:linear-gradient(90deg,#fff,#c7d2fe);-webkit-background-clip:text;background-clip:text;color:transparent}
.sec h2{font-size:17px;letter-spacing:.2px}
input,select{background:rgba(255,255,255,.08);border-radius:12px;backdrop-filter:blur(8px)}
button{background:linear-gradient(180deg,rgba(255,255,255,.22),rgba(255,255,255,.06));border:1px solid rgba(255,255,255,.28);box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 4px 14px rgba(0,0,0,.25);transition:transform .15s,box-shadow .2s,background .2s;border-radius:12px}
button:hover{transform:translateY(-1px);box-shadow:inset 0 1px 0 rgba(255,255,255,.4),0 8px 22px rgba(0,0,0,.3)}
button:active{transform:scale(.97)}
button.ok{background:linear-gradient(135deg,rgba(99,102,241,.92),rgba(6,182,212,.85));border-color:rgba(255,255,255,.2);box-shadow:0 6px 18px rgba(99,102,241,.45),inset 0 1px 0 rgba(255,255,255,.4)}
button.bad,button.danger{background:linear-gradient(135deg,rgba(244,63,94,.6),rgba(190,18,60,.5));border-color:rgba(244,63,94,.6)}
button.warn{background:linear-gradient(135deg,rgba(245,158,11,.65),rgba(234,88,12,.5));border-color:rgba(251,191,36,.5)}
button.sm{border-radius:9px;padding:5px 10px}
table{border-spacing:0}
tr:hover td{background:rgba(255,255,255,.045)}
td,th{padding:11px 9px}
pre{border:1px solid rgba(255,255,255,.08)}
.lang{padding:6px 14px;font-size:13px;margin-inline-start:10px}
#login{max-width:420px;padding:32px}
#login h1{background:linear-gradient(90deg,#fff,#a5b4fc,#f0abfc);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block}
#login .lang{margin:0 0 14px;display:block}
#login input{padding:11px 13px;font-size:15px}
#login button.ok{width:100%;padding:11px;font-size:15px}
@media(max-width:820px){#shell{flex-direction:column}#side{width:auto;height:auto;position:static;flex-direction:row;flex-wrap:wrap}.brand,.sp{display:none}}
/* v4: header logo, footer, sub-tabs */
.logo{width:34px;height:34px;flex:none;filter:drop-shadow(0 4px 12px rgba(99,102,241,.55))}
.hdr{display:flex;align-items:center;gap:11px}
.hdr .nm{font-weight:700;font-size:17px;letter-spacing:.3px;background:linear-gradient(90deg,#fff,#a5b4fc,#f0abfc);-webkit-background-clip:text;background-clip:text;color:transparent}
.hdr .vv{font-size:11px;color:#9aa6d6;padding:2px 7px;border:1px solid rgba(255,255,255,.22);border-radius:999px}
#foot{padding:12px 20px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;font-size:12px;color:#9aa6d6}
#foot a{color:#a5b4fc;text-decoration:none}
.tabs{display:flex;gap:8px;flex-wrap:wrap}
.tab{padding:8px 15px;border-radius:999px;cursor:pointer;font-size:13px;color:#c9d2ff;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);transition:.2s;user-select:none}
.tab:hover{background:rgba(255,255,255,.14)}
.tab.on{background:linear-gradient(135deg,rgba(99,102,241,.75),rgba(6,182,212,.6));border-color:rgba(255,255,255,.3);color:#fff;box-shadow:0 6px 18px rgba(99,102,241,.35)}
.sub{display:none}.sub.on{display:block}
</style>
<body>
<div id="bg"></div><div id="grid"></div>
<div id="app">Loading...</div>
<script>
window.onerror=(m,u,l)=>{document.getElementById("app").textContent="JS error: "+m+" line "+l;};
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lang = localStorage.getItem('nt_lang') || 'en';
const FA = {'Reverse tunnel':'تونل معکوس','Spoof tunnel':'تونل اسپوف','Settings':'تنظیمات','Account':'حساب کاربری','Language':'زبان','Apply':'اعمال','Save changes':'ذخیره تغییرات','Saved':'ذخیره شد','Current password':'رمز فعلی','New password (empty = keep)':'رمز جدید (خالی = بدون تغییر)','Changing the password logs out every other browser session.':'با تغییر رمز، سایر مرورگرها از پنل خارج می‌شوند.','Reverse TCP tunnels on this server':'تونل‌های معکوس TCP این سرور','Create reverse tunnel':'ساخت تونل معکوس','Iran (server: listens, forwards ports)':'ایران (سرور: گوش می‌دهد و پورت‌ها را منتقل می‌کند)','Foreign (client: connects to Iran)':'خارج (کلاینت: به ایران وصل می‌شود)','Bridge port (both sides)':'پورت پل (هر دو سر)','Ports to forward':'پورت‌های انتقالی','Iran server real IP':'آی‌پی واقعی سرور ایران','Kind':'نوع','No tunnel yet. Open Create to add one.':'هنوز تونلی نیست. از بخش ساخت یکی بسازید.','Tunnel created. Token (copy it to the other server):':'تونل ساخته شد. توکن را به سرور مقابل منتقل کنید:','Total restarts':'مجموع ری‌استارت','Active':'فعال','Down':'قطع','Memory used':'حافظه مصرفی','Logout':'خروج','Dashboard':'داشبورد','Tunnels':'تونل‌ها','Create':'ساخت','Monitoring':'پایش','Spoof tester':'تست اسپوف','Access tokens':'توکن‌های دسترسی','Logs':'لاگ‌ها','Logout':'خروج','Login':'ورود','Save password':'ذخیره رمز','Password or access token':'رمز یا توکن دسترسی','Create admin password (min 8 chars)':'ساخت رمز مدیر (حداقل ۸ کاراکتر)','Username':'نام کاربری','Password':'رمز عبور','CPU':'پردازنده','Memory':'حافظه','Disk':'دیسک','Uptime':'مدت روشنی','CPU history':'تاریخچه پردازنده','Network download':'دریافت شبکه','Network upload':'ارسال شبکه','Tunnel status':'وضعیت تونل‌ها','Tunnel monitor':'پایش تونل‌ها','(auto refresh 3s)':'(نوسازی خودکار هر ۳ ثانیه)','Spoof tunnels on this server':'تونل‌های اسپوف این سرور','Create spoof tunnel':'ساخت تونل اسپوف','Create and connect':'ساخت و اتصال','Create token':'ساخت توکن','Person name':'نام شخص','Connect':'اتصال','Restart':'ری‌استارت','Stop':'توقف','Start':'شروع','Delete':'حذف','Revoke':'بستن','Enable':'فعال‌سازی','Pause':'توقف موقت','Resume':'ادامه','Slot':'اسلات','Side':'سمت','Type:port':'نوع:پورت','Other server':'سرور مقابل','Other server real IP':'آی‌پی واقعی سرور مقابل','Source IPs':'آی‌پی‌های جعلی','Ports':'پورت‌ها','State':'وضعیت','Start test':'شروع تست','Refresh result':'بروزرسانی نتیجه','Mode':'حالت','Packet type':'نوع بسته','Port':'پورت','Logs':'لاگ‌ها','This server is':'این سرور است','Tunnel port (both sides)':'پورت تونل (هر دو سر)','Listen UDP port (apps send here)':'پورت UDP ورودی (برنامه‌ها اینجا می‌فرستند)','Forward to HOST:PORT':'ارسال به HOST:PORT','Fake source IPs (from Spoof tester)':'آی‌پی‌های جعلی (از تست اسپوف)','Token (empty = generate)':'توکن (خالی = ساخت خودکار)','Listen seconds (5-300)':'مدت گوش دادن (۵ تا ۳۰۰ ثانیه)','Fake source IPs to test':'آی‌پی‌های جعلی برای تست','Packets per address (1-10)':'تعداد بسته برای هر آدرس (۱ تا ۱۰)','Receive (run first)':'دریافت (اول اجرا شود)','Send (run second)':'ارسال (دوم اجرا شود)','Iran (entry: apps send UDP here)':'ایران (ورودی: برنامه‌ها UDP را اینجا می‌فرستند)','Foreign (exit: forwards to a UDP service)':'خارج (خروجی: به سرویس UDP وصل می‌کند)','active':'فعال','inactive':'غیرفعال','failed':'خطا','revoked':'بسته‌شده','paused':'متوقف','No tokens yet.':'هنوز توکنی نیست.','No spoof tunnel yet. Open Create to add one.':'هنوز تونلی نیست. از بخش ساخت یکی بسازید.','Open Tunnels and click Logs on a tunnel.':'از بخش تونل‌ها روی لاگ یک تونل بزنید.','No test run yet.':'هنوز تستی اجرا نشده.','Give each person their own token. They log in with it in the Password field. Revoke a token to cut off that person immediately.':'برای هر نفر یک توکن جدا بسازید. با آن در فیلد رمز وارد می‌شود. با بستن توکن، دسترسی آن شخص فوراً قطع می‌شود.','Run Receive on the receiving server first, then Send on the sending server, with the same packet type and port. Copy the fake source IPs that arrived into "Create".':'اول Receive را روی سرور دریافت‌کننده و بعد Send را روی سرور ارسال‌کننده با همان نوع بسته و پورت اجرا کنید. آی‌پی‌های جعلی که رسیدند را در بخش ساخت کپی کنید.'};
document.documentElement.lang = lang; document.documentElement.dir = lang==='fa' ? 'rtl' : 'ltr';
function tr(root){
  if(lang!=='fa' || !root) return;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); let n;
  while((n = w.nextNode())){ const t = n.nodeValue.trim(); if(t && FA[t]) n.nodeValue = n.nodeValue.replace(t, FA[t]); }
  root.querySelectorAll('input[placeholder]').forEach(i => { const v=i.getAttribute('placeholder'); if(FA[v]) i.setAttribute('placeholder', FA[v]); });
}
function toggleLang(){ localStorage.setItem('nt_lang', lang==='fa' ? 'en' : 'fa'); location.reload(); }
function langBtn(){ return `<button class="lang" onclick="toggleLang()">${lang==='fa' ? 'English' : 'فارسی'}</button>`; }
setInterval(() => tr(document.body), 700);
let state = {logged: false, needSetup: false}, page = 'dash', hist = {cpu:[],rx:[],tx:[]}, timer = null, tTimer = null, cur = 'list', logSlot = 0;
function msg(t, ok){ const m=$('#msg'); if(m){ m.className='msg '+(ok?'good':'bad'); m.textContent=t; } else alert(t); }
async function api(path, body){
  const r = await fetch(path, {method: body===undefined?'GET':'POST', headers:{'Content-Type':'application/json'},
    body: body===undefined?undefined:JSON.stringify(body), credentials:'same-origin'});
  let j = {}; try { j = await r.json(); } catch(e){}
  if(!r.ok) throw new Error(j.error || ('HTTP '+r.status));
  return j;
}
const fmtB = n => { const u=['B','KB','MB','GB','TB']; let i=0; n=+n||0; while(n>=1024&&i<4){n/=1024;i++;} return n.toFixed(i?1:0)+' '+u[i]; };
const fmtUp = s => { s=Math.floor(s); const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return (d?d+'d ':'')+h+'h '+m+'m'; };

function loginView(){
  $('#app').innerHTML = `<div id="login" class="glass"><h1>NiceTunnel Panel</h1>${langBtn()}<div id="msg"></div>
  <div class="row"><div><label>Username</label><input id="un" value="admin" autocomplete="username"></div>
  <div><label>${state.needSetup?'Create owner password (min 8 chars)':'Password'}</label>
  <div style="position:relative"><input id="pw" type="password" style="padding-right:44px">
  <button type="button" id="pwtog" style="position:absolute;right:3px;top:3px;padding:7px 10px;background:transparent;border:none;box-shadow:none;font-size:15px">&#128065;</button></div></div>
  <div><button class="ok" id="go">${state.needSetup?'Save password':'Login'}</button></div></div></div>`;
  $('#go').onclick = async () => { try {
      await api(state.needSetup ? '/api/setup' : '/api/login', {username:$('#un').value,password:$('#pw').value});
      await load(); } catch(e){ msg(e.message,false); } };
  $('#pw').onkeydown = e => { if(e.key==='Enter') $('#go').click(); };
  $('#pwtog').onclick = () => { const p=$('#pw'); p.type = p.type==='password' ? 'text' : 'password'; p.focus(); };
}
const PAGES = [['dash','&#9673;','Dashboard'],['rev','&#8646;','Reverse tunnel'],['spoof','&#9889;','Spoof tunnel'],['set','&#9881;','Settings']];
const LOGO = '<svg class="logo" viewBox="0 0 48 48" fill="none"><defs><linearGradient id="lg" x1="0" y1="0" x2="48" y2="48"><stop stop-color="#818cf8"/><stop offset=".5" stop-color="#38bdf8"/><stop offset="1" stop-color="#f0abfc"/></linearGradient></defs><path d="M6 24h36" stroke="url(#lg)" stroke-width="3" stroke-linecap="round" opacity=".5"/><circle cx="13" cy="24" r="7" stroke="url(#lg)" stroke-width="3.5"/><circle cx="35" cy="24" r="7" stroke="url(#lg)" stroke-width="3.5"/><path d="M16 10h16M16 38h16" stroke="url(#lg)" stroke-width="2.5" stroke-linecap="round" opacity=".75"/></svg>';
function shell(){
  const nm = state.username || 'admin';
  $('#app').innerHTML = `<div id="shell"><div id="side" class="glass">
    <div class="brand" style="display:flex;align-items:center;gap:10px;padding:2px 6px 16px">${LOGO}<div><div style="font-size:15px;-webkit-text-fill-color:#fff;background:none;color:#fff">NiceTunnel</div><small style="-webkit-text-fill-color:#9aa6d6">v1.3.0</small></div></div>
    ${PAGES.map(p=>`<div class="nav" data-p="${p[0]}"><i>${p[1]}</i><span>${p[2]}</span></div>`).join('')}
    <div class="sp"></div><div class="nav" id="lo"><i>&#10162;</i><span>Logout</span></div></div>
  <div id="main"><div id="top" class="glass"><div class="hdr">${LOGO}<span class="nm">NiceTunnel</span><span class="vv">v1.3.0</span><h1 id="ttl" style="margin:0 0 0 6px"></h1></div>
    <div style="display:flex;align-items:center;gap:10px"><span id="host" style="color:#9aa6d6;font-size:12px"></span>${langBtn()}</div></div><div id="msg"></div>
  <div class="page" id="p-dash">
    <div class="cards">
      <div class="card glass"><div class="k">CPU</div><div class="v" id="cpu">-</div><div class="bar"><b id="cpub"></b></div><div class="s" id="load"></div></div>
      <div class="card glass"><div class="k">Memory</div><div class="v" id="mem">-</div><div class="bar"><b id="memb"></b></div><div class="s" id="memt"></div></div>
      <div class="card glass"><div class="k">Disk</div><div class="v" id="disk">-</div><div class="bar"><b id="diskb"></b></div><div class="s" id="diskt"></div></div>
      <div class="card glass"><div class="k">Uptime</div><div class="v" id="up">-</div><div class="s" id="tuns"></div></div>
    </div>
    <div class="cards">
      <div class="card glass"><div class="k">Network download</div><div class="v" id="rx">-</div><canvas id="crx"></canvas><div class="s" id="rxt"></div></div>
      <div class="card glass"><div class="k">Network upload</div><div class="v" id="tx">-</div><canvas id="ctx"></canvas><div class="s" id="txt"></div></div>
      <div class="card glass"><div class="k">CPU history</div><div class="v">&nbsp;</div><canvas id="ccpu"></canvas></div>
    </div>
    <div class="sec glass"><h2>Tunnel status</h2><div id="mon"></div></div>
  </div>
  <div class="page" id="p-rev">
    <div class="sec glass"><h2>Reverse TCP tunnels on this server</h2><div id="revtbl"></div></div>
    <div class="sec glass"><h2>Create reverse tunnel</h2><div class="row">
      <div><label>This server is</label><select id="rrole">
        <option value="server">Iran (server: listens, forwards ports)</option>
        <option value="client">Foreign (client: connects to Iran)</option></select></div>
      <div><label>Bridge port (both sides)</label><input id="rbridge" value="7000"></div>
      <div id="rports"><label>Ports to forward</label><input id="rport" placeholder="80,443,2000-2010"></div>
      <div id="rsip" class="hide"><label>Iran server real IP</label><input id="rserver" placeholder="203.0.113.5"></div>
      <div id="rth" class="hide"><label>Forward to HOST:PORT</label><input id="rtarget" value="127.0.0.1:80" placeholder="127.0.0.1:80"></div>
      <div><label>Token (empty = generate)</label><input id="rtoken" placeholder="min 16 chars"></div>
    </div><p><button class="ok" id="rcreate">Create and connect</button></p><div id="rnew"></div></div>
  </div>
  <div class="page" id="p-spoof">
    <div class="tabs">
      <div class="tab on" data-t="list">Tunnels</div><div class="tab" data-t="new">Create</div>
      <div class="tab" data-t="mon">Monitoring</div><div class="tab" data-t="test">Spoof tester</div>
      <div class="tab" data-t="logs">Logs</div>
    </div>
    <div class="sub on" id="s-list"><div class="sec glass"><h2>Spoof tunnels on this server</h2><div id="tbl"></div></div></div>
    <div class="sub" id="s-new"><div class="sec glass"><h2>Create spoof tunnel</h2><div class="row">
      <div><label>This server is</label><select id="role">
        <option value="server">Iran (entry: apps send UDP here)</option>
        <option value="client">Foreign (exit: forwards to a UDP service)</option></select></div>
      <div><label>Other server real IP</label><input id="peer" placeholder="203.0.113.5"></div>
      <div><label>Packet type</label><select id="transport"><option>udp</option><option>tcp</option><option>icmp</option></select></div>
      <div><label>Tunnel port (both sides)</label><input id="port" value="4500"></div>
      <div><label>Fake source IPs (from Spoof tester)</label><input id="spoof_ips" placeholder="10.0.0.0/28 or 1.2.3.4,5.5.5.1-5.5.5.9"></div>
      <div id="lp"><label>Listen UDP port (apps send here)</label><input id="listen_port" value="51820"></div>
      <div id="fw" class="hide"><label>Forward to HOST:PORT</label><input id="forward" value="127.0.0.1:51820"></div>
      <div><label>Token (empty = generate)</label><input id="token" placeholder="min 16 chars"></div>
    </div><p><button class="ok" id="create">Create and connect</button></p><div id="newtoken"></div></div></div>
    <div class="sub" id="s-mon"><div class="cards" id="mcards"></div><div class="sec glass"><h2>Tunnel monitor <small style="color:#9aa6d6;font-weight:400">(auto refresh 3s)</small></h2><div id="mtun"></div></div></div>
    <div class="sub" id="s-test"><div class="sec glass"><h2>Spoof tester</h2>
      <p style="color:#b8c2ee;font-size:14px">Run <b>Receive</b> on the receiving server first, then <b>Send</b> on the sending server, with the same packet type and port. Copy the fake source IPs that arrived into "Create".</p>
      <div class="row">
        <div><label>Mode</label><select id="tmode"><option value="recv">Receive (run first)</option><option value="send">Send (run second)</option></select></div>
        <div><label>Packet type</label><select id="ttr"><option>udp</option><option>tcp</option><option>icmp</option></select></div>
        <div><label>Port</label><input id="tport" value="4500"></div>
        <div class="trecv"><label>Listen seconds (5-300)</label><input id="tsec" value="60"></div>
        <div class="tsend hide"><label>Other server real IP</label><input id="tpeer" placeholder="203.0.113.5"></div>
        <div class="tsend hide"><label>Fake source IPs to test</label><input id="tspoof" placeholder="10.0.0.0/28"></div>
        <div class="tsend hide"><label>Packets per address (1-10)</label><input id="tcount" value="5"></div>
      </div><p><button class="ok" id="tstart">Start test</button> <button id="tref">Refresh result</button></p>
      <pre id="tbox">No test run yet.</pre></div></div>
    <div class="sub" id="s-logs"><div class="sec glass"><h2>Logs</h2><pre id="logbox">Open Tunnels and click Logs on a tunnel.</pre></div></div>
  </div>
  <div class="page" id="p-set">
    <div class="sec glass"><h2>Account</h2><div class="row">
      <div><label>Username</label><input id="sun" value="${esc(nm)}"></div>
      <div><label>Current password</label><input id="scur" type="password"></div>
      <div><label>New password (empty = keep)</label><input id="snew" type="password" placeholder="min 8 chars"></div>
    </div><p><button class="ok" id="ssave">Save changes</button></p>
    <p style="color:#9aa6d6;font-size:12px">Changing the password logs out every other browser session.</p></div>
    <div class="sec glass"><h2>Language</h2><div class="row" style="align-items:center"><div style="max-width:260px"><select id="slang"><option value="en">English</option><option value="fa">فارسی</option></select></div>
      <div><button id="slanggo">Apply</button></div></div></div>
  </div>
  <div id="foot" class="glass"><span>NiceTunnel v1.3.0 · Spoof &amp; Reverse panel</span><span>By <b style="color:#c7d2fe">arshamsmok</b></span></div>
  </div></div>`;
  document.querySelectorAll('.nav[data-p]').forEach(e=>e.onclick=()=>go(e.dataset.p));
  document.querySelectorAll('.tab').forEach(e=>e.onclick=()=>sub(e.dataset.t));
  $('#lo').onclick = logout;
  $('#role').onchange = () => { const s=$('#role').value==='server'; $('#lp').classList.toggle('hide',!s); $('#fw').classList.toggle('hide',s); };
  $('#rrole').onchange = () => { const s=$('#rrole').value==='server';
    $('#rports').classList.toggle('hide',!s); $('#rsip').classList.toggle('hide',s); $('#rth').classList.toggle('hide',s); };
  $('#create').onclick = create; $('#rcreate').onclick = createRev; $('#ssave').onclick = saveAccount;
  $('#slang').value = lang; $('#slanggo').onclick = () => { if($('#slang').value!==lang){ localStorage.setItem('nt_lang',$('#slang').value); location.reload(); } };
  $('#tmode').onchange = tmodeView; $('#tstart').onclick = tstart; $('#tref').onclick = tstatus;
  if(lang==='fa') tr($('#app'));
}
function sub(t){
  cur = t;
  document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('on', e.dataset.t===t));
  document.querySelectorAll('.sub').forEach(e=>e.classList.toggle('on', e.id==='s-'+t));
  if(t==='mon') monitor();
  if(t==='logs' && logSlot) logs(logSlot);
}
function go(p){
  page = p;
  document.querySelectorAll('.page').forEach(e=>e.classList.toggle('on', e.id==='p-'+p));
  document.querySelectorAll('.nav[data-p]').forEach(e=>e.classList.toggle('on', e.dataset.p===p));
  $('#ttl').textContent = PAGES.filter(x=>x[0]===p)[0][2];
  refresh();
}
function spark(id, arr, color){
  const c=$(id); if(!c) return; const w=c.width=c.clientWidth*2, h=c.height=180, x=c.getContext('2d');
  x.clearRect(0,0,w,h); if(arr.length<2) return;
  const mx=Math.max(...arr,1), st=w/(arr.length-1);
  x.beginPath(); arr.forEach((v,i)=>{ const y=h-8-(v/mx)*(h-20); i?x.lineTo(i*st,y):x.moveTo(0,y); });
  x.strokeStyle=color; x.lineWidth=4; x.lineJoin='round'; x.stroke();
  x.lineTo(w,h); x.lineTo(0,h); x.closePath(); x.fillStyle=color+'33'; x.fill();
}
function push(a,v){ a.push(v); if(a.length>60) a.shift(); }
function bar(id,p){ $(id).style.width=Math.max(0,Math.min(100,p))+'%'; }
function slotTable(slots, full){
  if(!slots.length) return '<p style="color:#b8c2ee">No tunnel yet. Open Create to add one.</p>';
  return `<table><tr><th>Slot</th><th>Kind</th><th>Side</th><th>Type:port</th><th>Other server</th><th>Source IPs</th><th>Ports</th><th>State</th>${full?'<th></th>':''}</tr>`+
  slots.map(s => s.kind==='reverse' ? `<tr><td>${s.slot}</td><td>reverse</td><td>${esc(s.side)}</td><td>tcp:${esc(s.bridge)}</td><td>${esc(s.server_ip||'-')}</td><td>-</td>
   <td>${s.role==='server'?'listen '+esc(s.ports):'forward '+esc(s.target_host)}</td>
   <td class="${esc(s.state)}"><span class="dot"></span>${esc(s.state)}</td>
   ${full?rowBtns(s.slot):''}</tr>` : `<tr><td>${s.slot}</td><td>spoof</td><td>${esc(s.side)}</td><td>${esc(s.transport)}:${esc(s.port)}</td><td>${esc(s.peer)}</td><td>${esc(s.spoof_ips)}</td>
   <td>${s.role==='server'?'listen UDP '+esc(s.listen_port):'forward '+esc(s.forward)}</td>
   <td class="${esc(s.state)}"><span class="dot"></span>${esc(s.state)}</td>
   ${full?rowBtns(s.slot):''}</tr>`).join('')+'</table>';
}
function rowBtns(n){ return `<td><button class="sm ok" onclick="act(${n},'start')">Connect</button><button class="sm" onclick="act(${n},'restart')">Restart</button><button class="sm" onclick="act(${n},'stop')">Stop</button><button class="sm" onclick="logs(${n})">Logs</button><button class="sm danger" onclick="del(${n})">Delete</button></td>`; }
async function refresh(){
  try {
    const [st, sl] = await Promise.all([api('/api/stats'), api('/api/slots')]);
    push(hist.cpu, st.cpu); push(hist.rx, st.rx_rate); push(hist.tx, st.tx_rate);
    $('#host').textContent = st.hostname + ' · ' + st.ip;
    $('#cpu').textContent = st.cpu.toFixed(0)+'%'; bar('#cpub', st.cpu); $('#load').textContent = 'load '+st.load.join(' / ');
    $('#mem').textContent = st.mem_pct.toFixed(0)+'%'; bar('#memb', st.mem_pct); $('#memt').textContent = fmtB(st.mem_used)+' / '+fmtB(st.mem_total);
    $('#disk').textContent = st.disk_pct.toFixed(0)+'%'; bar('#diskb', st.disk_pct); $('#diskt').textContent = fmtB(st.disk_used)+' / '+fmtB(st.disk_total);
    $('#up').textContent = fmtUp(st.uptime);
    const act = sl.slots.filter(s=>s.state==='active').length; $('#tuns').textContent = act+' of '+sl.slots.length+' tunnels active';
    $('#rx').textContent = fmtB(st.rx_rate)+'/s'; $('#rxt').textContent = 'total '+fmtB(st.rx_total);
    $('#tx').textContent = fmtB(st.tx_rate)+'/s'; $('#txt').textContent = 'total '+fmtB(st.tx_total);
    spark('#crx', hist.rx, '#38bdf8'); spark('#ctx', hist.tx, '#ec4899'); spark('#ccpu', hist.cpu, '#818cf8');
    $('#mon').innerHTML = slotTable(sl.slots, false);
    $('#revtbl').innerHTML = slotTable(sl.slots.filter(s=>s.kind==='reverse'), true);
    $('#tbl').innerHTML = slotTable(sl.slots.filter(s=>s.kind==='spoof'), true);
  } catch(e){ if(/login|auth|401/i.test(e.message)) load(); else msg(e.message,false); }
}
async function monitor(){
  try {
    const r = await api('/api/monitor'), t = r.tunnels;
    const up = t.filter(x=>x.state==='active').length, bad = t.length-up;
    const rs = t.reduce((a,x)=>a+(+x.restarts||0),0);
    $('#mcards').innerHTML = `<div class="card glass"><div class="k">Active</div><div class="v active">${up}</div></div>
      <div class="card glass"><div class="k">Down</div><div class="v ${bad?'failed':''}">${bad}</div></div>
      <div class="card glass"><div class="k">Total restarts</div><div class="v">${rs}</div></div>
      <div class="card glass"><div class="k">Memory used</div><div class="v">${fmtB(t.reduce((a,x)=>a+x.mem,0))}</div></div>`;
    $('#mtun').innerHTML = t.length ? t.map(x=>`<div style="margin-bottom:14px;padding:12px;border-radius:12px;background:rgba(0,0,0,.25)">
      <b>#${x.slot}</b> ${esc(x.side)} · ${esc(x.transport)}:${esc(x.port)} ↔ ${esc(x.peer)}
      <span class="${esc(x.state)}" style="float:right"><span class="dot"></span>${esc(x.state)}</span>
      <div class="s" style="color:#b8c2ee;font-size:12px;margin:6px 0">PID ${esc(x.pid)} · restarts ${esc(x.restarts)} · mem ${fmtB(x.mem)}${x.since?' · since '+esc(x.since):''}</div>
      <pre style="max-height:90px">${esc(x.last||'(no logs)')}</pre></div>`).join('') : '<p>No spoof tunnel yet.</p>';
  } catch(e){ msg(e.message,false); }
}
function tmodeView(){ const s=$('#tmode').value==='send';
  document.querySelectorAll('.tsend').forEach(e=>e.classList.toggle('hide',!s));
  document.querySelectorAll('.trecv').forEach(e=>e.classList.toggle('hide',s)); }
async function tstart(){
  const m=$('#tmode').value;
  const body={transport:$('#ttr').value, port:$('#tport').value, seconds:$('#tsec').value,
    peer:$('#tpeer').value.trim(), spoof_ips:$('#tspoof').value, count:$('#tcount').value};
  try { await api('/api/test/'+m, body); msg('Test started', true); tstatus(); } catch(e){ msg(e.message,false); } }
async function tstatus(){
  clearTimeout(tTimer);
  try { const r = await api('/api/test/status');
    const state = r.running ? 'running...' : (r.state || 'idle');
    $('#tbox').textContent = (r.title ? '['+r.title+'] ' : '') + state + '\n' + (r.log || '');
    if (r.running) tTimer = setTimeout(tstatus, 2000);
  } catch(e){ msg(e.message,false); } }
async function load(){
  clearInterval(timer);
  try { state = await api('/api/state');
    if(!state.logged){ loginView(); return; }
    shell(); go(page); timer = setInterval(()=>{ refresh(); if(page==='spoof' && cur==='mon') monitor(); }, 3000);
  } catch(e){ loginView(); msg(e.message,false); }
}
async function act(n, a){ try { const r = await api(`/api/slot/${n}/${a}`, {}); msg(`Tunnel ${n}: ${r.state}`, true); refresh(); } catch(e){ msg(e.message,false);} }
async function del(n){ if(!confirm('Delete tunnel '+n+'?')) return; try { await api(`/api/slot/${n}/delete`, {}); refresh(); } catch(e){ msg(e.message,false);} }
async function logs(n){ try { const r = await api(`/api/slot/${n}/logs`); logSlot = n; go('spoof'); sub('logs'); $('#logbox').textContent = r.logs || '(no logs)'; } catch(e){ msg(e.message,false);} }
async function create(){
  const body = {role:$('#role').value, peer:$('#peer').value.trim(), transport:$('#transport').value,
    port:$('#port').value, spoof_ips:$('#spoof_ips').value, listen_port:$('#listen_port').value,
    forward:$('#forward').value, token:$('#token').value.trim()};
  try { const r = await api('/api/spoof', body);
    $('#newtoken').innerHTML = `<div class="msg good">Tunnel ${r.slot} created. Token (copy it to the other server):<br><code>${esc(r.token)}</code></div>`;
    refresh(); } catch(e){ msg(e.message,false); } }
async function createRev(){
  const body = {role:$('#rrole').value, bridge:$('#rbridge').value, ports:$('#rport').value,
    server_ip:$('#rserver').value.trim(), target_host:$('#rtarget').value.trim(), token:$('#rtoken').value.trim()};
  try { const r = await api('/api/reverse', body);
    $('#rnew').innerHTML = `<div class="msg good">Tunnel ${r.slot} created. Token (copy it to the other server):<br><code>${esc(r.token)}</code></div>`;
    refresh(); } catch(e){ msg(e.message,false); } }
async function saveAccount(){
  try { await api('/api/account', {current:$('#scur').value, username:$('#sun').value.trim(), password:$('#snew').value});
    msg('Saved', true); $('#scur').value=''; $('#snew').value=''; } catch(e){ msg(e.message,false); } }
async function logout(){ await api('/api/logout', {}); state.logged=false; load(); }
load();
</script></body></html>
"""


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
SESSION_RE = re.compile(r"nt_session=([0-9a-f]{64})")



_net = {"t": 0.0, "rx": 0, "tx": 0}
_cpu = {"idle": 0, "total": 0}


def collect_stats():
    st = {}
    try:
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        idle, total = v[3] + (v[4] if len(v) > 4 else 0), sum(v)
        di, dt = idle - _cpu["idle"], total - _cpu["total"]
        st["cpu"] = round(100.0 * (1 - di / dt), 1) if dt > 0 and _cpu["total"] else 0.0
        _cpu["idle"], _cpu["total"] = idle, total
    except Exception:
        st["cpu"] = 0.0
    try:
        st["load"] = ["%.2f" % x for x in os.getloadavg()]
    except Exception:
        st["load"] = ["0", "0", "0"]
    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                mem[k] = int(rest.split()[0]) * 1024
    except Exception:
        pass
    mt = mem.get("MemTotal", 0)
    mu = mt - mem.get("MemAvailable", 0)
    st.update(mem_total=mt, mem_used=mu, mem_pct=(100.0 * mu / mt) if mt else 0.0)
    try:
        du = shutil.disk_usage("/")
        st.update(disk_total=du.total, disk_used=du.used, disk_pct=100.0 * du.used / du.total)
    except Exception:
        st.update(disk_total=0, disk_used=0, disk_pct=0.0)
    try:
        with open("/proc/uptime") as f:
            st["uptime"] = float(f.read().split()[0])
    except Exception:
        st["uptime"] = 0
    rx = tx = 0
    try:
        with open("/proc/net/dev") as f:
            for line in list(f)[2:]:
                name, _, rest = line.partition(":")
                if name.strip() == "lo":
                    continue
                c = rest.split()
                rx += int(c[0])
                tx += int(c[8])
    except Exception:
        pass
    now = time.time()
    dt = now - _net["t"]
    if _net["t"] and dt > 0:
        st["rx_rate"] = max(0, (rx - _net["rx"]) / dt)
        st["tx_rate"] = max(0, (tx - _net["tx"]) / dt)
    else:
        st["rx_rate"] = st["tx_rate"] = 0
    _net.update(t=now, rx=rx, tx=tx)
    st.update(rx_total=rx, tx_total=tx)
    st["hostname"] = socket.gethostname()
    st["ip"] = public_ip_guess()
    return st



def collect_monitor():
    out = []
    for sl in list_spoof_slots():
        n = sl["slot"]
        _, o = run(["systemctl", "show", "nicetunnel@%d" % n, "-p",
                    "ActiveState,NRestarts,MemoryCurrent,ActiveEnterTimestamp,MainPID"])
        p = dict(l.split("=", 1) for l in o.splitlines() if "=" in l)
        mem = p.get("MemoryCurrent", "")
        sl["restarts"] = p.get("NRestarts", "0")
        sl["since"] = p.get("ActiveEnterTimestamp", "") if sl["state"] == "active" else ""
        sl["mem"] = int(mem) if mem.isdigit() else 0
        sl["pid"] = p.get("MainPID", "0")
        _, lg = run(["journalctl", "-u", "nicetunnel@%d" % n, "-n", "4", "--no-pager", "-o", "cat"])
        sl["last"] = lg.strip()[-400:]
        out.append(sl)
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NiceTunnelPanel"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200, headers=None):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n > 65536:
            raise ValueError("request too large")
        data = json.loads(self.rfile.read(n) if n else b"{}")
        if not isinstance(data, dict):
            raise ValueError("bad JSON")
        return data

    def session_id(self):
        m = SESSION_RE.search(self.headers.get("Cookie", ""))
        return m.group(1) if m else None

    def session_ok(self):
        sid = self.session_id()
        if not sid:
            return False
        with lock:
            exp = sessions.get(sid)
            own = sess_owner.get(sid, "")
            if exp and exp > time.time():
                return True
            sessions.pop(sid, None)
            sess_owner.pop(sid, None)
        return False

    def require_admin(self):
        if not self.require_login():
            return False
        if sess_owner.get(self.session_id()) != "admin":
            self.send_json({"error": "admin only"}, 403)
            return False
        return True

    def require_login(self):
        if not self.session_ok():
            self.send_json({"error": "login required"}, 401)
            return False
        return True

    def same_origin_ok(self):
        origin = self.headers.get("Origin")
        return not origin or urlparse(origin).netloc == self.headers.get("Host", "")

    # -- GET -----------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            data = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/state":
            conf = load_panel_conf()
            logged = self.session_ok()
            role = "admin" if sess_owner.get(self.session_id()) == "admin" else "user"
            return self.send_json({"logged": logged, "role": role, "needSetup": "password" not in conf,
                                   "username": conf.get("username", "admin") if logged else ""})
        if path == "/api/slots":
            if not self.require_login():
                return
            return self.send_json({"slots": list_slots()})
        if path == "/api/stats":
            if not self.require_login():
                return
            return self.send_json(collect_stats())
        if path == "/api/monitor":
            if not self.require_login():
                return
            return self.send_json({"tunnels": collect_monitor()})
        if path == "/api/test/status":
            if not self.require_login():
                return
            with tester_lock:
                return self.send_json(dict(tester))
        m = re.fullmatch(r"/api/slot/(\d+)/logs", path)
        if m:
            if not self.require_login():
                return
            n = int(m.group(1))
            if not valid_slot(n):
                return self.send_json({"error": "no such tunnel"}, 404)
            _, out = run(["journalctl", "-u", "nicetunnel@%d" % n, "-n", "80", "--no-pager"])
            return self.send_json({"logs": out})
        self.send_json({"error": "not found"}, 404)

    # -- POST ----------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        if not self.same_origin_ok():
            return self.send_json({"error": "cross-site request refused"}, 403)
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "bad request body"}, 400)

        if path == "/api/setup":
            conf = load_panel_conf()
            if "password" in conf:
                return self.send_json({"error": "already set up"}, 400)
            pw = str(body.get("password", ""))
            if len(pw) < 8:
                return self.send_json({"error": "password must be at least 8 characters"}, 400)
            conf["password"] = hash_password(pw)
            conf["username"] = str(body.get("username", "admin")).strip() or "admin"
            save_panel_conf(conf)
            return self.send_json({"ok": True})

        if path == "/api/login":
            ip = self.client_address[0]
            with lock:
                cnt, first = fails.get(ip, [0, time.time()])
                if time.time() - first > 900:
                    cnt, first = 0, time.time()
                if cnt >= LOGIN_FAILS_MAX:
                    return self.send_json({"error": "too many attempts, wait 15 minutes"}, 429)
            conf = load_panel_conf()
            pw = str(body.get("password", ""))
            owner = None
            # Only the owner account (username + password) can log in.
            # Access tokens alone never grant panel access.
            if conf.get("password") and hmac.compare_digest(
                    str(body.get("username", "")), conf.get("username", "admin")) and check_password(pw, conf["password"]):
                owner = "admin"
            if not owner:
                with lock:
                    fails[ip] = [cnt + 1, first]
                time.sleep(1)
                return self.send_json({"error": "wrong username or password"}, 401)
            sid = secrets.token_hex(32)
            with lock:
                fails.pop(ip, None)
                sessions[sid] = time.time() + SESSION_TTL
                sess_owner[sid] = owner
            return self.send_json({"ok": True}, headers=[(
                "Set-Cookie", "nt_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                % (sid, SESSION_TTL))])

        if path == "/api/logout":
            sid = self.session_id()
            if sid:
                with lock:
                    sessions.pop(sid, None)
                    sess_owner.pop(sid, None)
            return self.send_json({"ok": True}, headers=[(
                "Set-Cookie", "nt_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])

        if not self.require_login():
            return

        if path in ("/api/test/recv", "/api/test/send"):
            kind = path.rsplit("/", 1)[1]
            args, err = validate_test(kind, body)
            if err:
                return self.send_json({"error": err}, 400)
            title = "Receive test" if kind == "recv" else "Send test"
            ok, err = tester_start(title, args)
            if not ok:
                return self.send_json({"error": err}, 409)
            return self.send_json({"ok": True})

        if path == "/api/account":
            conf = load_panel_conf()
            cur = str(body.get("current", ""))
            if not conf.get("password") or not check_password(cur, conf["password"]):
                time.sleep(1)
                return self.send_json({"error": "current password is wrong"}, 403)
            nu = str(body.get("username", "")).strip()
            npw = str(body.get("password", ""))
            if nu:
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", nu):
                    return self.send_json({"error": "username: 1-32 letters, digits . _ -"}, 400)
                conf["username"] = nu
            if npw:
                if len(npw) < 8:
                    return self.send_json({"error": "password must be at least 8 characters"}, 400)
                conf["password"] = hash_password(npw)
            save_panel_conf(conf)
            if npw:
                keep = self.session_id()
                with lock:
                    for s in list(sessions):
                        if s != keep:
                            sessions.pop(s, None)
                            sess_owner.pop(s, None)
            return self.send_json({"ok": True, "username": conf.get("username", "admin")})

        if path == "/api/reverse":
            clean, err = validate_reverse(body)
            if err:
                return self.send_json({"error": err}, 400)
            n = first_free_slot()
            if n is None:
                return self.send_json({"error": "no free slot (max %d)" % MAX_SLOT}, 400)
            write_reverse_slot(n, clean)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "nicetunnel@%d" % n])
            code, out = run(["systemctl", "restart", "nicetunnel@%d" % n])
            if code != 0:
                return self.send_json({"error": "saved but could not start: " + out.strip()[-300:],
                                       "slot": n, "token": clean["token"]}, 500)
            return self.send_json({"ok": True, "slot": n, "token": clean["token"]})

        if path == "/api/spoof":
            clean, err = validate_spoof(body)
            if err:
                return self.send_json({"error": err}, 400)
            n = first_free_slot()
            if n is None:
                return self.send_json({"error": "no free slot (max %d)" % MAX_SLOT}, 400)
            write_spoof_slot(n, clean)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "nicetunnel@%d" % n])
            code, out = run(["systemctl", "restart", "nicetunnel@%d" % n])
            if code != 0:
                return self.send_json({"error": "saved but could not start: " + out.strip()[-300:],
                                       "slot": n, "token": clean["token"]}, 500)
            return self.send_json({"ok": True, "slot": n, "token": clean["token"]})

        m = re.fullmatch(r"/api/slot/(\d+)/(start|stop|restart|delete)", path)
        if m:
            n, action = int(m.group(1)), m.group(2)
            if not valid_slot(n):
                return self.send_json({"error": "no such tunnel"}, 404)
            unit = "nicetunnel@%d" % n
            if action == "delete":
                run(["systemctl", "disable", "--now", unit])
                try:
                    os.remove(slot_file(n))
                except OSError:
                    pass
                return self.send_json({"ok": True, "state": "deleted"})
            run(["systemctl", action, unit])
            time.sleep(1)
            _, st = run(["systemctl", "is-active", unit])
            return self.send_json({"ok": True, "state": st.strip()})

        self.send_json({"error": "not found"}, 404)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_set_password(_args):
    pw = getpass.getpass("New panel password (min 8 chars): ")
    if len(pw) < 8 or pw != getpass.getpass("Repeat: "):
        sys.exit("error: passwords do not match or are too short")
    conf = load_panel_conf()
    old = conf.get("username", "admin")
    user = input("Username [%s]: " % old).strip() or old
    conf["username"] = user
    conf["password"] = hash_password(pw)
    save_panel_conf(conf)
    print("Saved. Username: %s" % user)


UNIT_PATH = "/etc/systemd/system/nicetunnel-panel.service"
PANEL_PORT = 8787


def public_ip_guess():
    try:
        out = subprocess.run(["hostname", "-I"], stdout=subprocess.PIPE,
                             universal_newlines=True).stdout.split()
        for ip in out:
            if ":" not in ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "SERVER_IP"


def cmd_install(args):
    """Installs and starts the panel as a systemd service, then prints how to open it."""
    if os.geteuid() != 0:
        sys.exit("error: run as root")
    if not os.path.exists(ENGINE):
        sys.exit("error: %s not found. Install NiceTunnel first." % ENGINE)
    here = os.path.abspath(__file__)
    target = os.path.join(APP_DIR, "nicetunnel_panel.py")
    if here != target:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(here, "rb") as src, open(target + ".new", "wb") as dst:
            dst.write(src.read())
        os.chmod(target + ".new", 0o755)
        os.replace(target + ".new", target)
    conf = load_panel_conf()
    if "port" not in conf:
        conf["port"] = random.randint(20000, 60000)
        save_panel_conf(conf)
    port = int(conf["port"])
    if "password" not in conf:
        print("Set the panel password (min 8 characters):")
        cmd_set_password(args)
    unit = (
        "[Unit]\nDescription=NiceTunnel Spoof Panel\nAfter=network-online.target\n"
        "Wants=network-online.target\n\n[Service]\n"
        "ExecStart=%s %s serve --bind 0.0.0.0 --port %d\nRestart=always\nRestartSec=3\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    ) % (sys.executable, target, port)
    with open(UNIT_PATH, "w") as f:
        f.write(unit)
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "--now", "nicetunnel-panel"])
    subprocess.run(["systemctl", "restart", "nicetunnel-panel"])
    if shutil.which("ufw"):
        subprocess.run(["ufw", "allow", "%d/tcp" % port], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("")
    print("Panel installed.")
    print("  URL:      http://%s:%d" % (public_ip_guess(), port))
    print("  Username: %s" % load_panel_conf().get("username", "admin"))
    print("  Password: the one you set.")
    print("Open TCP port %d in your provider firewall if the page does not load." % port)


def cmd_uninstall(_args):
    if os.geteuid() != 0:
        sys.exit("error: run as root")
    subprocess.run(["systemctl", "disable", "--now", "nicetunnel-panel"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(UNIT_PATH):
        os.remove(UNIT_PATH)
    subprocess.run(["systemctl", "daemon-reload"])
    print("Panel service removed.")


RAW_URL = "https://raw.githubusercontent.com/arshamsmok/nicetunnel/main/nicetunnel_panel.py"


def cmd_update(_args):
    """Download the newest panel file from GitHub and restart the service."""
    import urllib.request
    if os.geteuid() != 0:
        sys.exit("error: run as root")
    data = urllib.request.urlopen(RAW_URL, timeout=30).read()
    if b"def main" not in data:
        sys.exit("error: downloaded file looks wrong")
    target = os.path.join(APP_DIR, "nicetunnel_panel.py")
    with open(target + ".new", "wb") as f:
        f.write(data)
    os.chmod(target + ".new", 0o755)
    os.replace(target + ".new", target)
    subprocess.run(["systemctl", "restart", "nicetunnel-panel"])
    print("Panel updated and restarted.")


def cmd_serve(args):
    if os.geteuid() != 0:
        sys.exit("error: run as root (the panel manages systemd services)")
    if not os.path.exists(ENGINE):
        sys.exit("error: %s not found. Install NiceTunnel first." % ENGINE)
    if "password" not in load_panel_conf():
        sys.exit("error: set a password first: python3 %s set-password" % sys.argv[0])
    srv = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    print("NiceTunnel panel on http://%s:%d  " % (args.bind, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    p = argparse.ArgumentParser(description="NiceTunnel web panel for spoof tunnels")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password", help="set or change the panel password").set_defaults(func=cmd_set_password)
    sub.add_parser("install", help="install and start the panel service").set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="remove the panel service").set_defaults(func=cmd_uninstall)
    sub.add_parser("update", help="download the latest panel and restart").set_defaults(func=cmd_update)
    s = sub.add_parser("serve", help="run the web panel")
    s.add_argument("--bind", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_serve)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
