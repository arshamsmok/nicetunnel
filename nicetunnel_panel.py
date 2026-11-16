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

lock = threading.Lock()
fails = {}      # client ip -> [count, first_time]
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


def pw_problem(pw):
    """Returns an error text if the password is weak, else None."""
    if len(pw) < 10:
        return "password must be at least 10 characters"
    if not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw):
        return "password needs lower and upper case letters"
    if not re.search(r"\d", pw):
        return "password needs a digit"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "password needs a symbol like ! @ # $"
    return None


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
 .seg-bar{display:inline-flex;gap:4px;padding:4px;border-radius:12px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);align-self:flex-start}
 .seg{padding:8px 18px;border-radius:9px;border:0;background:none;color:#c9d2ff;cursor:pointer;font-size:13px;font-family:inherit}
 .seg.on{background:linear-gradient(135deg,#4f46e5,#0891b2);color:#fff}
 .tsec{display:none;flex-direction:column;gap:16px}.tsec.on{display:flex}
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
/* v5: flat dark look */
#bg,#grid{display:none}
body{background:#0a0d14!important}
#shell{gap:0;padding:0;flex-wrap:wrap;align-content:flex-start}
.glass{backdrop-filter:none!important;-webkit-backdrop-filter:none!important;box-shadow:none!important;background:#10141f!important;border:1px solid #232a3a!important;border-radius:0!important}
#side{width:230px;top:0;height:100vh;border-width:0 0 0 1px!important;border-top:0!important;padding:16px 14px}
#shell[dir=ltr] #side{border-width:0 1px 0 0!important}
#top{border-width:0 0 1px 0!important;padding:12px 24px}
#foot{border-width:1px 0 0 0!important;justify-content:center;gap:20px;color:#8b93a7}
#main{flex:1;min-width:0;display:flex;flex-direction:column;min-height:100vh}
#main>.glass:not(#top):not(#foot),.card{border-radius:14px!important;background:#10141f!important;border:1px solid #232a3a!important}
.logo{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:12px;background:#4f78f5;color:#fff;font-weight:700;font-size:16px;filter:none}
.hdr .nm{background:none;-webkit-text-fill-color:#fff;color:#fff;font-size:17px}
.hdr .vv{border:0;padding:0;color:#8b93a7}
.nav{border-radius:10px;color:#9aa3b8}
.nav:hover{transform:none!important;background:#171c29}
.nav.on{background:#18233f!important;border-color:transparent!important;box-shadow:none!important;color:#fff}
#login{border-radius:14px!important}
.tab.on{background:#18233f;box-shadow:none;border-color:#2c3a5e}
/* v6: compact minimal */
body{font-size:13px}
#side{width:200px;padding:12px 10px}
.brand{font-size:16px;padding:4px 8px 10px}
.brand small{font-size:10px}
.nav{padding:8px 10px;font-size:13px;gap:8px}
#top{padding:10px 18px}
#top h1{font-size:16px}
#main{gap:12px}
.page{gap:12px}
.sec{padding:14px}
.sec h2{font-size:14px;margin-bottom:10px}
.card{padding:12px}
.card .v{font-size:22px;margin:4px 0}
.card .k{font-size:11px}
th{font-size:11px}
td,th{padding:7px 8px}
table{font-size:13px}
input,select,button{padding:7px 9px;font-size:13px}
button.ok{padding:8px 16px}
label{font-size:11px;margin-bottom:3px}
.row{gap:10px}
.row>div{min-width:160px}
pre{font-size:11px;padding:10px;max-height:260px}
.tab{padding:6px 12px;font-size:12px}
.logo{width:32px;height:32px;font-size:14px;border-radius:10px}
.hdr .nm{font-size:15px}
#foot{padding:10px 16px;font-size:11px}
/* v7: neon pro */
body{background:#070a12!important;background-image:radial-gradient(900px 500px at 85% -10%,rgba(99,102,241,.18),transparent 60%),radial-gradient(700px 400px at -10% 110%,rgba(6,182,212,.14),transparent 60%)!important}
#side{background:linear-gradient(180deg,#0c1120,#080b15)!important;border-right:1px solid #1b2440!important}
#main>.glass:not(#top):not(#foot),.card{background:linear-gradient(160deg,#10162a,#0b0f1c)!important;border:1px solid #1f2a4a!important;box-shadow:0 6px 24px rgba(0,0,0,.35),inset 0 1px 0 rgba(255,255,255,.04)!important;transition:border-color .2s,transform .2s}
.card:hover{border-color:#3b5bdb!important;transform:translateY(-2px)}
.logo{background:linear-gradient(135deg,#6366f1,#06b6d4)!important;box-shadow:0 0 16px rgba(99,102,241,.55)}
.nav{transition:all .18s}
.nav:hover{background:#121a33!important;color:#fff;padding-inline-start:14px}
.nav.on{background:linear-gradient(90deg,rgba(99,102,241,.28),rgba(6,182,212,.08))!important;border-inline-start:3px solid #22d3ee!important;color:#fff}
#top{background:rgba(10,14,26,.75)!important;backdrop-filter:blur(10px);border-bottom:1px solid #1b2440!important}
.card .v{background:linear-gradient(90deg,#fff,#7dd3fc);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.bar{background:#151c33!important;border-radius:99px;overflow:hidden}
.bar b{background:linear-gradient(90deg,#6366f1,#22d3ee)!important;box-shadow:0 0 10px rgba(34,211,238,.6);border-radius:99px}
input,select{background:#0a0f1d!important;border:1px solid #243056!important;border-radius:10px!important;transition:border-color .2s,box-shadow .2s}
input:focus,select:focus{outline:0;border-color:#22d3ee!important;box-shadow:0 0 0 3px rgba(34,211,238,.15)}
button{border-radius:10px!important;transition:transform .15s,box-shadow .2s,filter .2s}
button:hover{transform:translateY(-1px);filter:brightness(1.12)}
button.ok{background:linear-gradient(135deg,#6366f1,#06b6d4)!important;border:0!important;color:#fff;box-shadow:0 4px 16px rgba(99,102,241,.4)}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(99,102,241,.08)}
th{color:#7f8fb8;text-transform:uppercase;letter-spacing:.05em}
pre{background:#060912!important;border:1px solid #1b2440;border-radius:10px;color:#9be7c4}
.tab.on{background:linear-gradient(135deg,#4f46e5,#0891b2)!important;border-color:transparent!important;color:#fff}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:#26335c;border-radius:9px}
.page{animation:ntfade .3s ease}
@keyframes ntfade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
/* v8: icons, theme, map */
.nav i{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;flex:none}
.nav i svg,.ibtn svg,.card .ic svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.ibtn{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;padding:0;background:#121a33;border:1px solid #243056;color:#cbd5f5}
.ibtn:hover{color:#22d3ee}
.mapsvg{width:100%;height:auto;display:block}
.mline{fill:none;stroke-width:3;opacity:.9}
.mline.flow{stroke-dasharray:6 8;animation:mflow 1s linear infinite}
@keyframes mflow{to{stroke-dashoffset:-14}}
.mhub{filter:drop-shadow(0 0 10px #6366f1)}
.mapsvg .ml{fill:#e2e8ff;font-size:14px;font-weight:600}
.mapsvg .ms{fill:#94a3b8;font-size:12px}
.mapsvg .mt{fill:#94a3b8;font-size:16px}
html[data-theme=light] body{background:#eef2fb!important;background-image:none!important;color:#1c2340}
html[data-theme=light] #bg,html[data-theme=light] #grid{display:none}
html[data-theme=light] #side,html[data-theme=light] #top,html[data-theme=light] .glass,html[data-theme=light] .card,html[data-theme=light] #main>.glass:not(#top):not(#foot){background:#fff!important;border-color:#dfe5f3!important;box-shadow:0 2px 10px rgba(30,40,80,.06)!important;color:#1c2340}
html[data-theme=light] .nav{color:#4a5578}
html[data-theme=light] .nav:hover{background:#eef2ff!important}
html[data-theme=light] .nav.on{color:#1c2340;background:linear-gradient(90deg,rgba(99,102,241,.14),rgba(6,182,212,.04))!important}
html[data-theme=light] .card .v{-webkit-text-fill-color:#1c2340;background:none}
html[data-theme=light] .bar{background:#e4e9f5!important}
html[data-theme=light] input,html[data-theme=light] select{background:#f5f7fc!important;color:#1c2340;border-color:#d5ddef!important}
html[data-theme=light] th{color:#5c6789}
html[data-theme=light] pre{background:#f4f6fb!important;color:#1c4d3a}
html[data-theme=light] .ibtn{background:#fff;border-color:#d5ddef;color:#4a5578}
html[data-theme=light] .mapsvg .ml{fill:#1c2340}
html[data-theme=light] .mapsvg .ms,html[data-theme=light] .mapsvg .mt{fill:#5c6789}
html[data-theme=light] [style*="b8c2ee"],html[data-theme=light] [style*="9aa6d6"]{color:#5c6789!important}
/* v9: login page look */
#login.glass{max-width:380px;margin:0 auto;padding:30px 26px;border-radius:18px;background:rgba(12,18,38,.78);border:1px solid rgba(250,204,21,.18);box-shadow:0 20px 60px rgba(0,0,0,.45)}
#login h1{font-size:20px;margin:14px 0 4px;color:#fde68a;letter-spacing:.3px}
#login .ok{background:linear-gradient(90deg,#facc15,#eab308);color:#1a1405;font-weight:700;border:none;border-radius:12px;padding:12px}
#login input{border-radius:12px}
.tgbar{position:fixed;top:14px;left:14px;display:flex;gap:8px;z-index:5}
.tgbar a{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;border-radius:999px;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.35);color:#7dd3fc;text-decoration:none;font-size:12px}
.tgbar a:hover{background:rgba(56,189,248,.22)}
/* v4: NiceTunnel navy+gold dashboard */
:root{--bg0:#050d18;--bg1:#081a2e;--st1:#0e2036;--st2:#14294a;--ln:#1d3a62;--gold:#e9c46a;--gold2:#f4d58a;--teal:#34d0c3;--tx:#eef2f7;--tx2:#a9b8cc}
body{background:linear-gradient(180deg,var(--bg0),var(--bg1) 420px,#07162a)!important;color:var(--tx)}
#bg,#grid{display:none!important}
#shell{gap:0!important;padding:0!important}
#side{width:84px!important;padding:12px 8px!important;align-items:stretch;gap:4px!important;background:#07121f!important;border:0!important;border-inline-end:1px solid var(--ln)!important;border-radius:0!important;box-shadow:none!important}
#side .brand{justify-content:center;padding:4px 0 14px!important}#side .brand>div{display:none}
#side .nav{flex-direction:column;justify-content:center;gap:5px;padding:10px 4px!important;font-size:11px!important;text-align:center;border-radius:12px!important;color:var(--tx2)!important;border:1px solid transparent!important;position:relative}
#side .nav:hover{background:var(--st1)!important;color:var(--tx)!important;padding-inline-start:4px!important;transform:none!important}
#side .nav.on{background:var(--st1)!important;color:var(--gold2)!important;border:1px solid var(--ln)!important;box-shadow:none!important}
#side .nav.on::after{content:'';position:absolute;inset-inline-end:-9px;top:20%;bottom:20%;width:3px;border-radius:3px;background:var(--gold)}
#side .nav i{width:22px;height:22px}#side .nav i svg{width:21px;height:21px}
#main{padding:0 22px 18px!important;gap:14px!important}
#top{margin:0 -22px!important;padding:12px 22px!important;border-radius:0!important;background:rgba(7,18,31,.85)!important;border:0!important;border-bottom:1px solid var(--ln)!important;box-shadow:none!important;backdrop-filter:blur(8px);position:sticky;top:0;z-index:20}
#top .hdr svg,#top .hdr .nm,#top .hdr .vv{display:none}
#top h1{font-size:18px!important;font-weight:700;color:var(--tx);background:none!important;-webkit-text-fill-color:var(--tx)!important}
#main>.glass:not(#top):not(#foot),.card,.sec{background:linear-gradient(180deg,var(--st1),#0b1a2d)!important;border:1px solid var(--ln)!important;border-radius:16px!important;box-shadow:0 1px 0 rgba(255,255,255,.04) inset!important}
.card:hover{border-color:#2a4f82!important;transform:none!important}
.card .k,.k{color:var(--tx2)!important;font-size:12px;letter-spacing:.04em}
.card .v,.v{color:var(--tx)!important;font-weight:700;font-variant-numeric:tabular-nums}
.card .s{color:#97a9c0!important}
.sec h2{font-size:15px!important;padding-bottom:10px;margin-bottom:12px;border-bottom:1px solid var(--ln);color:var(--tx)!important;background:none!important;-webkit-text-fill-color:var(--tx)!important}
.bar{background:#0a1624!important;height:6px!important;border-radius:6px!important}
.bar b{background:linear-gradient(90deg,var(--teal),var(--gold))!important;border-radius:6px!important}
button,.btn{background:var(--st2)!important;border:1px solid var(--ln)!important;color:var(--tx)!important;border-radius:9px!important;box-shadow:none!important}
button:hover{border-color:var(--gold)!important}
button.ok,button.primary{background:linear-gradient(180deg,var(--gold2),var(--gold))!important;color:#1b1303!important;border:0!important;font-weight:700}
input,select,textarea{background:#0a1624!important;border:1px solid var(--ln)!important;color:var(--tx)!important;border-radius:9px!important}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--gold)!important;box-shadow:0 0 0 3px rgba(233,196,106,.15)!important}
label{color:var(--tx2)!important}
.tabs{border-bottom:1px solid var(--ln);gap:4px}
.tab{border-radius:9px 9px 0 0!important;color:var(--tx2)!important;background:none!important;border:0!important}
.tab.on{color:var(--gold2)!important;box-shadow:inset 0 -2px 0 var(--gold)!important}
table{border-collapse:collapse}th{color:var(--tx2)!important;font-weight:600;font-size:12px;background:#0a1624!important}
td,th{border-bottom:1px solid #16304f!important}tr:hover td{background:rgba(52,208,195,.04)}
#foot{background:none!important;border:0!important;box-shadow:none!important;justify-content:center;gap:10px;color:#6f86a3!important;font-size:12px}
@media(max-width:820px){#side{width:auto!important;flex-direction:row!important;overflow-x:auto;padding:6px!important;border-inline-end:0!important;border-bottom:1px solid var(--ln)!important}#side .nav{flex:1;min-width:64px}#side .nav.on::after{display:none}#main{padding:0 12px 14px!important}#top{margin:0 -12px!important;padding:10px 12px!important}}

 /* v5: login centered */
 body{min-height:100vh}
 .lwrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;box-sizing:border-box;
  background:radial-gradient(1.5px 1.5px at 12% 18%,#fff8 50%,transparent 51%),radial-gradient(1.5px 1.5px at 78% 12%,#fff7 50%,transparent 51%),radial-gradient(1px 1px at 40% 30%,#fff6 50%,transparent 51%),radial-gradient(1.5px 1.5px at 88% 40%,#fde68a99 50%,transparent 51%),radial-gradient(1px 1px at 22% 70%,#fff6 50%,transparent 51%),radial-gradient(ellipse at 50% 100%,rgba(250,204,21,.12),transparent 60%)}
 #login.glass{margin:0 auto;width:100%;max-width:380px}
 #login svg{filter:drop-shadow(0 0 14px rgba(250,204,21,.35))}
 #login .ltitle{font-size:34px;font-weight:800;margin:10px 0 2px;text-align:center;display:block;background:linear-gradient(90deg,#fff7d6,#facc15 55%,#f59e0b);-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent}
 #login .lsub{text-align:center;color:#9aa6d6;font-size:13px;margin-bottom:18px}

 /* v5: settings */
 .sset{padding:6px 20px}.sset h2{padding:14px 0 6px;margin:0}
 .srow{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 0;border-top:1px solid rgba(255,255,255,.07);flex-wrap:wrap}
 .srow .st{flex:1 1 220px;min-width:0}.srow .st b{display:block;font-size:14px;margin-bottom:3px}
 .srow .st p{margin:0;color:#9aa6d6;font-size:12px;line-height:1.7}
 .srow input{flex:0 1 260px;min-width:160px}
 .segm{display:inline-flex;padding:3px;border-radius:10px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1)}
 .segm button{border:0;background:none;color:#c9d2ff;padding:7px 14px;border-radius:8px;font-size:13px;cursor:pointer;font-family:inherit;box-shadow:none}
 .segm button.on{background:#facc15;color:#1a1405;font-weight:700}
 .scode{direction:ltr;background:rgba(0,0,0,.3);padding:7px 10px;border-radius:8px;font-size:12px;color:#fde68a;word-break:break-all;max-width:100%}
 .sbtn{padding:8px 14px;border-radius:10px;border:1px solid rgba(250,204,21,.4);color:#fde68a;text-decoration:none;font-size:13px}
 .lowmo *{animation:none!important;transition:none!important}

 /* v6: fields */
 #login .row{flex-direction:column;align-items:stretch;gap:16px}
 #login .row>div{min-width:100%;gap:7px}
 #login label{font-size:13px;font-weight:600;color:#c9d2ff;margin:0 2px}
 #login input{height:48px;box-sizing:border-box;width:100%;padding:0 16px;font-size:15px;background:#0a1226!important;border:1px solid #2a3866!important;border-radius:14px!important;color:#fff}
 #login input:focus{border-color:#facc15!important;box-shadow:0 0 0 3px rgba(250,204,21,.18)}
 #login #pw{padding-inline-end:48px}
 #login .ok{height:50px;margin-top:6px;font-size:16px}
 #login .ltitle{font-size:32px;line-height:1.3}
 #login .segm{margin:6px auto 18px!important}
 .srow input,.srow select{height:42px;box-sizing:border-box;padding:0 14px;font-size:14px;border-radius:12px!important;background:#0a1226!important;border:1px solid #2a3866!important}
 .srow input:focus,.srow select:focus{border-color:#facc15!important;box-shadow:0 0 0 3px rgba(250,204,21,.15)}
 .srow{padding:18px 0;gap:14px 20px}
 .srow .st p{margin-top:4px}
 .srow>input,.srow>select{flex:0 1 280px;width:280px;max-width:100%}
 @media(max-width:560px){.srow>input,.srow>select{flex:1 1 100%;width:100%}}
 .sset h2{padding:16px 0 10px;font-size:16px}
 .sset .sbtns{display:flex;gap:10px;flex-wrap:wrap;padding:16px 0 10px}
 .sbtn,.sset button{min-height:40px}

/* v7: buttons + live badge */
button{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.16);box-shadow:none;border-radius:10px;padding:9px 16px;font-size:13px;font-weight:500}
button:hover{background:rgba(255,255,255,.1);transform:none;box-shadow:none;border-color:rgba(255,255,255,.3)}
button.ok{background:linear-gradient(180deg,#f3d27a,#e2b550);color:#1b1608;border-color:transparent;font-weight:700;box-shadow:0 2px 10px rgba(226,181,80,.25)}
button.ok:hover{background:linear-gradient(180deg,#f7dc8e,#e8bf5c)}
button.bad,button.danger{background:rgba(244,63,94,.12);color:#fda4af;border-color:rgba(244,63,94,.45)}
.live{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:999px;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.4);color:#38bdf8;font-size:12px;font-weight:600}
.live i{width:7px;height:7px;border-radius:50%;background:#38bdf8;box-shadow:0 0 8px #38bdf8;animation:lv 1.6s infinite}
.live.off{color:#f87171;background:rgba(248,113,113,.12);border-color:rgba(248,113,113,.4)}
.live.off i{background:#f87171;box-shadow:0 0 8px #f87171;animation:none}
@keyframes lv{50%{opacity:.35}}
/* v10: NiceTunnel night-tunnel login */
html body .nl{position:fixed;inset:0;overflow:auto;z-index:20;color:#eef2f7;-webkit-overflow-scrolling:touch;
 background:radial-gradient(70% 45% at 50% 100%,rgba(233,196,106,.10),transparent 70%),linear-gradient(180deg,#040a16 0%,#071426 48%,#0b2038 80%,#0a1a2e 100%)}
.nl *{box-sizing:border-box}
.nl-stars{position:absolute;inset:0;pointer-events:none;
 background-image:radial-gradient(1.4px 1.4px at 8% 14%,#fff 50%,transparent 51%),radial-gradient(1px 1px at 17% 38%,#fff9 50%,transparent 51%),radial-gradient(1.6px 1.6px at 29% 9%,#fff 50%,transparent 51%),radial-gradient(1px 1px at 41% 27%,#fff8 50%,transparent 51%),radial-gradient(1.4px 1.4px at 56% 12%,#fff 50%,transparent 51%),radial-gradient(1px 1px at 66% 33%,#fff8 50%,transparent 51%),radial-gradient(1.6px 1.6px at 79% 8%,#fde68a 50%,transparent 51%),radial-gradient(1px 1px at 88% 29%,#fff9 50%,transparent 51%),radial-gradient(1.4px 1.4px at 94% 16%,#fff 50%,transparent 51%),radial-gradient(1px 1px at 5% 52%,#fff7 50%,transparent 51%),radial-gradient(1px 1px at 96% 55%,#fff7 50%,transparent 51%),radial-gradient(1.2px 1.2px at 48% 46%,#fff6 50%,transparent 51%)}
.nl-stars.b{background-image:radial-gradient(1.2px 1.2px at 13% 24%,#fff 50%,transparent 51%),radial-gradient(1.4px 1.4px at 35% 19%,#fde68a 50%,transparent 51%),radial-gradient(1px 1px at 52% 36%,#fff 50%,transparent 51%),radial-gradient(1.4px 1.4px at 72% 21%,#fff 50%,transparent 51%),radial-gradient(1px 1px at 84% 44%,#fff 50%,transparent 51%),radial-gradient(1.2px 1.2px at 22% 58%,#fff 50%,transparent 51%);animation:nltw 3.6s ease-in-out infinite}
@keyframes nltw{0%,100%{opacity:.25}50%{opacity:1}}
.nl-top{position:absolute;top:0;left:0;right:0;z-index:3;display:flex;justify-content:space-between;align-items:center;gap:10px;padding:16px 18px}
.nl-brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:16px;letter-spacing:.3px;color:#fff;direction:ltr}
.nl-brand svg{filter:drop-shadow(0 0 10px rgba(233,196,106,.35))}
.nl-chips{display:flex;gap:8px;align-items:center}
html body .nl a.nl-chip{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:34px;height:34px;padding:0 13px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid rgba(233,196,106,.28);color:#d6deec;text-decoration:none;font-size:12.5px;transition:.2s}
html body .nl a.nl-chip:hover{background:rgba(233,196,106,.12);border-color:rgba(233,196,106,.6);color:#f4d58a}
.nl svg{fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.nl-chip svg{width:16px;height:16px}
.nl-main{position:relative;z-index:2;min-height:100%;display:flex;align-items:center;justify-content:center;padding:84px 16px 240px}
.nl-card{width:100%;max-width:400px;padding:34px 26px 24px;border-radius:24px;background:rgba(9,20,38,.80);border:1px solid rgba(233,196,106,.22);
 box-shadow:0 24px 70px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.07);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);animation:nlin .6s cubic-bezier(.2,.8,.2,1) both}
@keyframes nlin{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.nl-title{margin:0;text-align:center;font-size:42px;line-height:1.35;font-weight:800;letter-spacing:.3px;background:linear-gradient(90deg,#fff3c9,#f4d58a 45%,#e0a93a);-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent;filter:drop-shadow(0 4px 22px rgba(233,196,106,.25))}
.nl-sub{text-align:center;color:#a9b8cc;font-size:13.5px;margin:2px 0 22px}
.nl-seg{display:flex;gap:4px;padding:4px;margin-bottom:20px;border-radius:14px;background:rgba(255,255,255,.035);border:1px solid #1d3a62}
html body .nl .nl-seg button{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;height:40px;padding:0 10px;border-radius:10px!important;border:1px solid transparent!important;background:transparent!important;color:#a9b8cc;font-size:13px;box-shadow:none!important;transform:none!important}
html body .nl .nl-seg button.on{background:#14294a!important;border-color:#2a4a7a!important;color:#f4d58a}
.nl-seg svg{width:15px;height:15px}
.nl-f{margin-bottom:15px}
.nl-f label{display:block;margin:0 2px 7px;font-size:13px;font-weight:600;color:#c3cee0}
.nl-in{position:relative}
.nl-ic{position:absolute;top:0;bottom:0;inset-inline-start:15px;display:flex;align-items:center;color:#6f86a8;pointer-events:none}
.nl-ic svg{width:18px;height:18px}
html body .nl .nl-in input{width:100%;height:52px;padding:0 46px;font-size:15px;color:#fff!important;background:#07111f!important;border:1px solid #1d3a62!important;border-radius:14px!important;outline:none;backdrop-filter:none;transition:border-color .2s,box-shadow .2s}
html body .nl .nl-in input:focus{border-color:#e9c46a!important;box-shadow:0 0 0 3px rgba(233,196,106,.16)}
html body .nl .nl-in input:-webkit-autofill{-webkit-box-shadow:0 0 0 60px #07111f inset!important;-webkit-text-fill-color:#fff}
html body .nl button.nl-eye{position:absolute;top:0;bottom:0;inset-inline-end:6px;width:40px;margin:auto 0;height:40px;padding:0;display:flex;align-items:center;justify-content:center;background:transparent!important;border:0!important;box-shadow:none!important;color:#6f86a8;transform:none!important}
html body .nl button.nl-eye:hover{color:#f4d58a}
.nl-eye svg{width:18px;height:18px}
.nl-hint{font-size:12px;color:#a9b8cc;margin:-4px 2px 14px;line-height:1.9}
html body .nl button.nl-go{width:100%;height:52px;margin-top:8px;border:0!important;border-radius:14px!important;font-size:16px;font-weight:800;color:#1a1405;background:linear-gradient(180deg,#f3d98d,#dfb653)!important;box-shadow:0 10px 28px rgba(233,196,106,.28),inset 0 1px 0 rgba(255,255,255,.5)!important;transition:filter .2s,transform .15s}
html body .nl button.nl-go:hover{filter:brightness(1.06);transform:translateY(-1px)!important}
html body .nl button.nl-go:active{transform:scale(.98)!important}
.nl #msg:empty{display:none}
.nl #msg{margin-bottom:14px;font-size:13px}
.nl-foot{margin-top:20px;text-align:center;font-size:12px;color:#6f86a8}
.nl-foot a{color:#e9c46a;text-decoration:none;border-bottom:1px solid rgba(233,196,106,.35)}
.nl-scene{position:fixed;left:0;right:0;bottom:0;height:min(38vh,330px);min-height:210px;z-index:1;pointer-events:none}
.nl-scene svg{width:100%;height:100%;display:block;stroke:none;stroke-width:0}
.nl-scene svg .k{stroke-width:3;fill:none;stroke-linecap:round}
.nl-dash{stroke-dasharray:14 18;animation:nlflow 1s linear infinite}
@keyframes nlflow{to{stroke-dashoffset:-32}}
.nl-pulse{transform-box:fill-box;transform-origin:center;animation:nlp 2.4s ease-out infinite}
@keyframes nlp{0%{transform:scale(.6);opacity:.9}100%{transform:scale(2.6);opacity:0}}
.lowmo .nl-pk,.lowmo .nl-dash,.lowmo .nl-pulse,.lowmo .nl-stars.b{display:none;animation:none}
@media(prefers-reduced-motion:reduce){.nl-pk{display:none}.nl-dash,.nl-pulse,.nl-stars.b,.nl-card{animation:none}}
@media(max-width:420px){.nl-title{font-size:36px}.nl-card{padding:28px 20px 20px}.nl-main{padding-top:76px}}
/* v10b: slim, refined */
html body .nl{font-family:Vazirmatn,"IRANSans","Segoe UI",Tahoma,system-ui,sans-serif;font-weight:400}
html body .nl button,html body .nl input{font-family:inherit}
html body .nl .nl-card{max-width:370px;padding:30px 24px 20px;border-radius:20px;border:1px solid rgba(233,196,106,.13);background:rgba(8,18,35,.82)}
html body .nl .nl-title{font-size:38px;font-weight:700;letter-spacing:0}
html body .nl .nl-sub{font-size:12.5px;font-weight:400;color:#9fb0c8;margin-bottom:20px}
html body .nl .nl-seg{padding:3px;gap:3px;border-radius:11px;border:1px solid rgba(60,100,160,.35);background:rgba(255,255,255,.02);margin-bottom:18px}
html body .nl .nl-seg button{height:34px;font-size:12.5px;font-weight:400;border-radius:8px!important}
html body .nl .nl-seg button.on{background:#10233f!important;border-color:rgba(70,110,170,.45)!important;color:#f4d58a}
html body .nl .nl-seg svg{width:13px;height:13px;stroke-width:1.5}
html body .nl .nl-f label{font-size:12px;font-weight:400;color:#a9b8cc}
html body .nl .nl-in input{height:44px;font-size:14px;font-weight:400;border:1px solid rgba(60,100,160,.4)!important;border-radius:11px!important;background:#06101e!important}
html body .nl .nl-ic svg,html body .nl .nl-eye svg{width:16px;height:16px;stroke-width:1.5}
html body .nl button.nl-go{height:44px;font-size:14.5px;font-weight:600;border-radius:11px!important;color:#14110a!important;-webkit-text-fill-color:#14110a;background:#e9c46a!important;box-shadow:0 6px 18px rgba(233,196,106,.2)!important}
html body .nl .nl-foot{font-size:11.5px;margin-top:16px}
html body .nl a.nl-chip{height:30px;font-size:12px;border-color:rgba(233,196,106,.2)}
html body .nl .nl-chip svg{width:14px;height:14px;stroke-width:1.6}
/* v11: NiceTunnel dashboard */
html:not([data-theme=light]) body{background:linear-gradient(180deg,#040a16,#08172b 60%,#071426)!important;color:#e6ecf6}
html:not([data-theme=light]) .glass{background:rgba(10,22,40,.78)!important;border:1px solid rgba(233,196,106,.12)!important;border-radius:16px!important;box-shadow:0 10px 30px rgba(0,0,0,.35)!important;-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
html:not([data-theme=light]) #side{background:rgba(6,14,28,.92)!important}
html:not([data-theme=light]) .nav{color:#aab8cf;border-radius:11px!important;font-size:13.5px}
html:not([data-theme=light]) .nav.on{background:rgba(233,196,106,.10)!important;border-color:rgba(233,196,106,.28)!important;color:#f4d58a;box-shadow:none!important}
html:not([data-theme=light]) .nav:hover{background:rgba(255,255,255,.05)!important;transform:none!important}
html:not([data-theme=light]) .hdr .nm{background:linear-gradient(90deg,#fff3c9,#e9c46a)!important;-webkit-background-clip:text!important;background-clip:text!important}
html:not([data-theme=light]) .card .v{background:none!important;-webkit-text-fill-color:#fff;color:#fff}
#p-dash{gap:12px}
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.dc,.dpanel{background:linear-gradient(160deg,rgba(14,30,54,.94),rgba(8,18,34,.94));border:1px solid rgba(233,196,106,.12);border-radius:16px;color:#e6ecf6;box-shadow:0 8px 26px rgba(0,0,0,.28)}
.dc{padding:14px 16px;overflow:hidden}
.dk{display:flex;align-items:center;gap:7px;font-size:12px;color:#8fa2bf;font-weight:400}
.dk svg{width:14px;height:14px;fill:none;stroke:#e9c46a;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}
.dv{font-size:30px;font-weight:600;margin:6px 0 4px;color:#fff;line-height:1.15}
.dv small{font-size:12.5px;color:#8fa2bf;font-weight:400;margin-inline-start:6px}
.dc canvas{width:100%;height:32px;display:block}
.ds{font-size:11.5px;color:#8fa2bf;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ds .bd{color:#f0707a}
.dseg{display:flex;gap:3px;height:4px;margin-top:12px}.dseg i{display:block;border-radius:3px}
.dm{display:flex;align-items:center;gap:8px;font-size:11.5px;color:#8fa2bf;margin:8px 0}
.dm span:first-child{width:34px}.dm span:last-child{width:34px;text-align:end;color:#e6ecf6}
.dm em{flex:1;height:4px;border-radius:3px;background:#0e2038;overflow:hidden;display:block}
.dm b{display:block;height:100%;background:linear-gradient(90deg,#34d0c3,#e9c46a);border-radius:3px}
.dpanel{overflow:hidden}
.dph{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.05)}
.dph h3{margin:0;font-size:14.5px;font-weight:600;color:#fff}
.dph p{margin:3px 0 0;font-size:11.5px;color:#8fa2bf}
.dleg{display:flex;gap:12px;font-size:11px;color:#8fa2bf;white-space:nowrap}
.dleg i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-inline-end:5px}
#map{overflow-x:auto;direction:ltr;-webkit-overflow-scrolling:touch}
#map svg{display:block}
#map text{font-family:inherit}
.dn{fill:#fff;font-size:12px;font-weight:600}.dn2{fill:#8fa2bf;font-size:10.5px}.dpl{fill:#dbe5f5;font-size:10.5px}
.mdash{stroke-dasharray:2 14;stroke-linecap:round;animation:dflow 1.1s linear infinite}
@keyframes dflow{to{stroke-dashoffset:-16}}
.lowmo .mdash{animation:none}
@media(prefers-reduced-motion:reduce){.mdash{animation:none}}
.dtwo{display:grid;grid-template-columns:1.5fr 1fr;gap:12px}
@media(max-width:820px){.dtwo{grid-template-columns:1fr}}
html body button.dlink{height:28px;padding:0 12px;font-size:12px;font-weight:400;color:#cfd8e8;background:transparent!important;border:1px solid rgba(233,196,106,.25)!important;border-radius:9px!important;box-shadow:none!important;transform:none!important}
html body button.dlink:hover{color:#f4d58a;border-color:rgba(233,196,106,.6)!important}
.tr{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.05);cursor:pointer}
.tr:last-child{border-bottom:0}.tr:hover{background:rgba(255,255,255,.03)}
.tb{width:3px;align-self:stretch;min-height:30px;border-radius:2px;background:#6b7a93}
.tb.active{background:#34d0c3}.tb.failed{background:#f0707a}
.tm{flex:1;min-width:0}
.tm b{display:block;font-size:13.5px;font-weight:600;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tm span{display:block;font-size:11.5px;color:#8fa2bf;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:3px;direction:ltr;text-align:start}
.tg{display:inline-block;font-size:10.5px;padding:1px 8px;border-radius:999px;border:1px solid rgba(233,196,106,.25);color:#e9c46a;margin-inline-start:8px;font-weight:400;vertical-align:middle}
.tp{flex:none;font-size:11.5px;padding:3px 11px;border-radius:999px;border:1px solid #2a3b57;color:#8fa2bf}
.tp.active{color:#34d0c3;border-color:rgba(52,208,195,.4);background:rgba(52,208,195,.08)}
.tp.failed{color:#f0707a;border-color:rgba(240,112,122,.4);background:rgba(240,112,122,.08)}
.wr{display:flex;align-items:center;gap:10px;padding:12px 16px;font-size:12.5px;color:#cfd8e8;border-bottom:1px solid rgba(255,255,255,.05)}
.wr:last-child{border-bottom:0}
.wr i{flex:none;width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:rgba(240,112,122,.12);color:#f0707a;font-style:normal;font-size:14px}
.wr i.g{background:rgba(52,208,195,.12);color:#34d0c3}.wr i.y{background:rgba(233,196,106,.12);color:#e9c46a}
.wr span{flex:1;min-width:0}
.dempty{padding:26px 16px;text-align:center;color:#8fa2bf;font-size:12.5px}

.tm b,.tm span{direction:ltr;text-align:left}
#shell[dir=rtl] .tm b,#shell[dir=rtl] .tm span{text-align:right}
#shell[dir=rtl] .tg{margin-inline-start:0;margin-inline-end:8px}
@media(max-width:820px){
 html:not([data-theme=light]){background:#040a16}
 #shell{display:flex!important;flex-direction:row!important;padding:0!important;gap:0!important}
 #side{position:sticky!important;top:0!important;bottom:auto!important;width:68px!important;height:100vh!important;flex:none!important;flex-direction:column!important;flex-wrap:nowrap!important;justify-content:flex-start!important;overflow-y:auto!important;overflow-x:hidden!important;padding:12px 6px!important;gap:4px!important;border-radius:0!important;border-style:solid!important;border-width:0 0 0 1px!important;border-color:rgba(233,196,106,.14)!important}
 #shell[dir=ltr] #side{border-width:0 1px 0 0!important}
 #side .brand{display:flex!important;justify-content:center;padding:2px 0 12px!important}
 #side .brand>div{display:none!important}
 #side .sp{display:block!important;flex:1}
 #side .nav{flex:none!important;flex-direction:column;gap:4px;padding:9px 2px!important;font-size:10px!important;text-align:center;min-width:0!important}
 #side .nav.on::after{display:none!important}
 #main{flex:1;min-width:0;padding:10px}
 #top{margin-bottom:10px}
}
.lgbar{display:flex;gap:8px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid rgba(255,255,255,.05);align-items:center}
html body .lgbar select,html body .lgbar input{height:34px;background:#06101e!important;border:1px solid rgba(60,100,160,.4)!important;border-radius:9px!important;color:#e6ecf6!important;padding:0 10px;font-size:12.5px;font-family:inherit}
.lgbar input{flex:1;min-width:120px}
.lgseg{display:flex;gap:3px;padding:3px;border:1px solid rgba(60,100,160,.35);border-radius:10px}
html body .lgseg button{height:26px;padding:0 10px;font-size:12px;border:0!important;border-radius:7px!important;background:transparent!important;color:#8fa2bf;box-shadow:none!important;transform:none!important}
html body .lgseg button.on{background:#10233f!important;color:#f4d58a}
.lg{max-height:64vh;min-height:260px;overflow:auto;padding:12px 16px;font:12px/1.75 ui-monospace,Menlo,Consolas,monospace;color:#cfd8e8;direction:ltr;text-align:left;background:#050d18}
.lg div{white-space:pre-wrap;overflow-wrap:anywhere;border-bottom:1px solid rgba(255,255,255,.03)}
.lg .e{color:#f0707a}.lg .w{color:#e9c46a}.lg .o{color:#34d0c3}.lg .t,.lg span.t{color:#6f86a8}
@media(max-width:560px){.dgrid{grid-template-columns:1fr 1fr;gap:10px}.dc{padding:12px 13px}.dv{font-size:25px}.dph{padding:12px 13px}.tr{padding:11px 13px}}
/* v12: settings page - side sub-nav + refined toggles */
.set-wrap{display:flex;gap:18px;align-items:flex-start}
.set-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:18px}
.set-nav{position:sticky;top:16px;width:178px;flex:none;display:flex;flex-direction:column;gap:3px;padding:2px}
.set-nav .nav{font-size:13px}
@media(max-width:820px){.set-wrap{flex-direction:column}.set-nav{position:static;width:100%;flex-direction:row;flex-wrap:wrap;overflow-x:auto}}
.segm button.on{background:#facc15!important;color:#1a1405!important;font-weight:700!important}
.sset input[type=checkbox]{appearance:none;-webkit-appearance:none;width:38px;height:22px;min-width:38px;border-radius:999px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18);position:relative;cursor:pointer;vertical-align:middle;transition:.15s;margin:0}
.sset input[type=checkbox]::after{content:'';position:absolute;top:2px;inset-inline-start:2px;width:16px;height:16px;border-radius:50%;background:#aab4d6;transition:.15s}
.sset input[type=checkbox]:checked{background:var(--gold);border-color:var(--gold)}
.sset input[type=checkbox]:checked::after{inset-inline-start:18px;background:#1a1405}
.sset label{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:#c9d2ff;cursor:pointer}

/* v13: network tuning */
.nhint{color:var(--tx2);font-size:12.5px;line-height:1.9;margin:2px 0 14px}
.nbadge{font-size:11px;font-weight:600;padding:3px 10px;border-radius:999px;margin-inline-start:8px;vertical-align:middle;background:rgba(255,255,255,.07);color:var(--tx2);border:1px solid rgba(255,255,255,.1)}
.nbadge.on{background:rgba(52,208,195,.12);color:#34d0c3;border-color:rgba(52,208,195,.35)}
.nprof{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.pcard{cursor:pointer;padding:14px 15px;border-radius:14px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.03);transition:.18s;position:relative}
.pcard:hover{border-color:rgba(250,204,21,.4);transform:translateY(-1px)}
.pcard.sel{border-color:var(--gold);background:linear-gradient(160deg,rgba(250,204,21,.12),rgba(250,204,21,.02));box-shadow:0 8px 24px rgba(250,204,21,.08)}
.pcard b{display:flex;align-items:center;gap:8px;font-size:14px;color:var(--tx)}
.pcard p{margin:6px 0 0;font-size:12px;line-height:1.8;color:var(--tx2)}
.pcard .pa{font-size:10px;padding:2px 8px;border-radius:999px;background:rgba(52,208,195,.14);color:#34d0c3}
.ntable{border:1px solid rgba(255,255,255,.08);border-radius:12px;overflow:hidden;margin-bottom:14px}
.nrow{display:grid;grid-template-columns:1.6fr 1fr 1fr;gap:8px;padding:9px 14px;font-size:12px;align-items:center;border-top:1px solid rgba(255,255,255,.05)}
.nrow:first-child{border-top:0;background:rgba(255,255,255,.04);color:var(--tx2);font-weight:600}
.nrow code{direction:ltr;text-align:start;font-size:11.5px;color:var(--tx);overflow-wrap:anywhere}
.nrow .nv{direction:ltr;text-align:start;display:flex;align-items:center;gap:7px;color:var(--tx2);font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.nrow .nv i{width:7px;height:7px;border-radius:50%;flex:none;background:#6b7280}
.nrow .nv.ok i{background:#34d0c3;box-shadow:0 0 8px #34d0c3}
.nact{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.nkern{margin-inline-start:auto;font-size:11px;color:var(--tx2);direction:ltr}
@media(max-width:560px){.nprof{grid-template-columns:1fr}.nrow{grid-template-columns:1fr 1fr}.nrow code{grid-column:1/-1}}
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
FA['Logs']='لاگ';
document.documentElement.lang = lang; document.documentElement.dir = lang==='fa' ? 'rtl' : 'ltr';
function tr(root){
  if(lang!=='fa' || !root) return;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); let n;
  while((n = w.nextNode())){ const t = n.nodeValue.trim(); if(t && FA[t]) n.nodeValue = n.nodeValue.replace(t, FA[t]); }
  root.querySelectorAll('input[placeholder]').forEach(i => { const v=i.getAttribute('placeholder'); if(FA[v]) i.setAttribute('placeholder', FA[v]); });
}
const L=(en,fa)=>lang==='fa'?fa:en;
const TZS=[['Asia/Tehran','ایران · Iran'],['Europe/Istanbul','ترکیه · Türkiye'],['Asia/Dubai','امارات · UAE'],['Asia/Baghdad','عراق · Iraq'],['Asia/Kabul','افغانستان · Afghanistan'],['Asia/Baku','آذربایجان · Azerbaijan'],['Asia/Karachi','پاکستان · Pakistan'],['Asia/Kolkata','هند · India'],['Asia/Riyadh','عربستان · Saudi Arabia'],['Europe/London','انگلیس · UK'],['Europe/Berlin','آلمان · Germany'],['Europe/Paris','فرانسه · France'],['Europe/Amsterdam','هلند · Netherlands'],['Europe/Moscow','روسیه · Russia'],['America/New_York','آمریکا شرق · US East'],['America/Los_Angeles','آمریکا غرب · US West'],['America/Toronto','کانادا · Canada'],['Asia/Tokyo','ژاپن · Japan'],['Asia/Singapore','سنگاپور · Singapore'],['Asia/Shanghai','چین · China'],['Australia/Sydney','استرالیا · Australia'],['UTC','UTC']];
function nowStr(){ const cal=localStorage.getItem('nt_cal')||(lang==='fa'?'persian':'gregory'), tz=localStorage.getItem('nt_tz')||'Asia/Tehran';
  try{ return new Intl.DateTimeFormat((cal==='persian'?'fa-IR-u-ca-persian':'en-GB'),{calendar:cal,timeZone:tz,year:'numeric',month:'long',day:'numeric',weekday:'long',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date()); }catch(e){ return new Date().toString(); } }
function fdate(ts){ if(!ts) return '-'; const cal=localStorage.getItem('nt_cal')||(lang==='fa'?'persian':'gregory'), tz=localStorage.getItem('nt_tz')||'Asia/Tehran';
  try{ return new Intl.DateTimeFormat((cal==='persian'?'fa-IR-u-ca-persian':'en-GB'),{calendar:cal,timeZone:tz,dateStyle:'medium',timeStyle:'short'}).format(new Date(ts*1000)); }catch(e){ return new Date(ts*1000).toLocaleString(); } }
function toggleLang(){ localStorage.setItem('nt_lang', lang==='fa' ? 'en' : 'fa'); location.reload(); }
function langBtn(){ return `<button class="lang" onclick="toggleLang()">${lang==='fa' ? 'English' : 'فارسی'}</button>`; }
function applyTheme(){ document.documentElement.dataset.theme = localStorage.getItem('nt_theme') || 'dark'; }
function toggleTheme(){ localStorage.setItem('nt_theme', document.documentElement.dataset.theme==='light' ? 'dark' : 'light'); applyTheme(); const b=$('#thbtn'); if(b) b.innerHTML = themeIcon(); }
function themeIcon(){ return document.documentElement.dataset.theme==='light' ? IC.moon : IC.sun; }
function themeBtn(){ return `<button class="ibtn" id="thbtn" title="Theme" onclick="toggleTheme()">${themeIcon()}</button>`; }
applyTheme();
setInterval(() => tr(document.body), 700);
let state = {logged: false, needSetup: false}, page = 'dash', hist = {cpu:[],rx:[],tx:[]}, timer = null, tTimer = null, cur = 'list', logSlot = 0;
function msg(t, ok){ const m=$('#msg'); if(m){ m.className='msg '+(ok?'good':'bad'); m.textContent=t; } else alert(t); }
const BASE = location.pathname.replace(/\/+$/,'');
async function api(path, body){
  const r = await fetch(BASE+path, {method: body===undefined?'GET':'POST', headers:{'Content-Type':'application/json'},
    body: body===undefined?undefined:JSON.stringify(body), credentials:'same-origin'});
  let j = {}; try { j = await r.json(); } catch(e){}
  if(!r.ok) throw new Error(j.error || ('HTTP '+r.status));
  return j;
}
const fmtB = n => { const u=['B','KB','MB','GB','TB']; let i=0; n=+n||0; while(n>=1024&&i<4){n/=1024;i++;} return n.toFixed(i?1:0)+' '+u[i]; };
const fmtUp = s => { s=Math.floor(s); const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return (d?d+'d ':'')+h+'h '+m+'m'; };

function lmode(m){ window._lm=m; document.querySelectorAll('#lsw button').forEach(b=>{b.classList.toggle('on',b.dataset.m===m);b.onclick=()=>lmode(b.dataset.m);});
  if(!$('#pw')) return; $('#fun').classList.toggle('hide',m==='link'); $('#fpw').classList.toggle('hide',m==='link'); $('#lkbox').classList.toggle('hide',m!=='link');
  if(m==='link'){ const o=new URLSearchParams(location.search).get('otl'); if(o) $('#lk').value=o; } }
function loginView(){
  const lg=s=>'<svg viewBox="0 0 64 64" width="'+s+'" height="'+s+'"><defs><linearGradient id="ntl'+s+'" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fde68a"/><stop offset="1" stop-color="#d97706"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="16" fill="#0b1226" stroke="url(#ntl'+s+')" stroke-width="2.5"/><path d="M12 52V32a20 20 0 0 1 40 0v20" fill="none" stroke="url(#ntl'+s+')" stroke-width="4" stroke-linecap="round"/><path d="M20 52V33a12 12 0 0 1 24 0v19" fill="none" stroke="url(#ntl'+s+')" stroke-width="3" stroke-linecap="round" opacity=".7"/><path d="M27 52V34a5 5 0 0 1 10 0v18z" fill="url(#ntl'+s+')" opacity=".9"/><path d="M6 52h52" stroke="url(#ntl'+s+')" stroke-width="3" stroke-linecap="round"/></svg>';
  const ICK='<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>';
  const ICU='<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>';
  const ICL='<svg viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>';
  const ICE='<svg viewBox="0 0 24 24"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
  const ICT='<svg viewBox="0 0 24 24"><path d="M21 4L3 11l6 2 2 6 3-4 5 3z"/></svg>';
  const TUN='M1250 194 C700 206 300 198 -50 208';
  const node=x=>'<g transform="translate('+x+',100)"><line class="k" x1="0" y1="0" x2="0" y2="102" stroke="#8a7340" opacity=".8"/><path class="k" d="M-22 0V-16a22 22 0 0 1 44 0V0" stroke="url(#ntGold)"/><path class="k" d="M-14 0V-15a14 14 0 0 1 28 0V0" stroke="url(#ntGold)" opacity=".7"/><path d="M-6 0V-14a6 6 0 0 1 12 0V0z" fill="url(#ntGold)" opacity=".9"/><circle class="nl-pulse" cx="0" cy="102" r="7" fill="#34d0c3" style="animation-delay:'+(x%3)*0.6+'s"/><circle cx="0" cy="102" r="5" fill="#34d0c3"/></g>';
  const scene='<svg viewBox="0 0 1200 320" preserveAspectRatio="xMidYMax slice" aria-hidden="true"><defs><linearGradient id="ntGround" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0b1c33"/><stop offset="1" stop-color="#050d18"/></linearGradient><linearGradient id="ntGold" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f4d58a"/><stop offset="1" stop-color="#d9a441"/></linearGradient><linearGradient id="ntTun" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#34d0c3"/><stop offset="1" stop-color="#1b9aa8"/></linearGradient><filter id="ntGlow" x="-20%" y="-200%" width="140%" height="500%"><feGaussianBlur stdDeviation="5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>'
    +'<path d="M0 98 C150 66 260 74 380 88 C520 104 640 60 800 74 C960 88 1080 64 1200 84 L1200 101 L0 101Z" fill="#0b1a30"/>'
    +'<rect y="100" width="1200" height="220" fill="url(#ntGround)"/>'
    +'<line x1="0" y1="100" x2="1200" y2="100" stroke="#e9c46a" stroke-width="2.2" opacity=".9" filter="url(#ntGlow)"/>'
    +'<g stroke="#ffffff" stroke-opacity=".05"><line x1="0" y1="140" x2="1200" y2="140"/><line x1="0" y1="255" x2="1200" y2="255"/><line x1="0" y1="298" x2="1200" y2="298"/></g>'
    +node(150)+node(450)+node(600)+node(750)+node(1050)
    +'<path d="M-50 208 C300 198 700 206 1250 194" fill="none" stroke="#34d0c3" stroke-opacity=".10" stroke-width="30" stroke-linecap="round"/>'
    +'<path d="M-50 208 C300 198 700 206 1250 194" fill="none" stroke="#34d0c3" stroke-opacity=".30" stroke-width="14" stroke-linecap="round"/>'
    +'<path d="M-50 208 C300 198 700 206 1250 194" fill="none" stroke="url(#ntTun)" stroke-width="6" stroke-linecap="round" filter="url(#ntGlow)"/>'
    +'<path class="nl-dash" d="M-50 208 C300 198 700 206 1250 194" fill="none" stroke="#e8fffd" stroke-opacity=".75" stroke-width="2" stroke-linecap="round"/>'
    +[0,2,4].map(d=>'<g class="nl-pk" filter="url(#ntGlow)"><polygon points="16,0 -8,-9 -8,9" fill="#bffaf4"/><animateMotion dur="6s" begin="'+d+'s" repeatCount="indefinite" rotate="auto" path="'+TUN+'"/></g>').join('')
    +'</svg>';
  const ok = state.needSetup;
  $('#app').innerHTML = `<div class="nl"><div class="nl-stars"></div><div class="nl-stars b"></div>
  <div class="nl-top"><div class="nl-brand">${lg(34)}<span>NiceTunnel</span></div>
   <div class="nl-chips"><a class="nl-chip" href="https://t.me/DarkCore_Vpn" target="_blank" rel="noopener" title="Telegram">${ICT}</a><a class="nl-chip" href="#" id="ltheme" title="Theme">${themeIcon()}</a><a class="nl-chip" href="#" id="llang">${lang==='fa'?'English':'فارسی'}</a></div></div>
  <div class="nl-main"><div class="nl-card">
   <h1 class="nl-title">${L('NiceTunnel','نایس‌تانل')}</h1>
   <div class="nl-sub">${ok?L('Create your admin password','ساخت رمز مدیر'):L('Secure paths. Stable connections.','مسیر امن، اتصال پایدار.')}</div>
   ${ok?'':`<div class="nl-seg" id="lsw"><button type="button" data-m="pw">${ICK}${L('Password','رمز عبور')}</button><button type="button" data-m="link">${ICL}${L('One-time link','لینک یک‌بارمصرف')}</button></div>`}
   <div id="msg"></div>
   <div class="nl-f" id="fun"><label for="un">${L('Username','نام کاربری')}</label><div class="nl-in"><span class="nl-ic">${ICU}</span><input id="un" value="admin" autocomplete="username" autocapitalize="off" spellcheck="false"></div></div>
   <div class="nl-f" id="fpw"><label for="pw">${ok?L('Create admin password','ساخت رمز مدیر'):L('Admin password','رمز مدیر')}</label><div class="nl-in"><span class="nl-ic">${ICK}</span><input id="pw" type="password" autocomplete="${ok?'new-password':'current-password'}"><button type="button" id="pwtog" class="nl-eye" aria-label="Show password">${ICE}</button></div></div>
   <div id="pwhint" class="nl-hint" style="display:${ok?'block':'none'}"></div>
   <div class="nl-f hide" id="lkbox"><label for="lk">${L('One-time link or code','لینک یا کد یک‌بارمصرف')}</label><div class="nl-in"><span class="nl-ic">${ICL}</span><input id="lk" dir="ltr" autocomplete="off"></div></div>
   <button class="nl-go" id="go" type="button">${ok?L('Save password','ذخیره رمز'):L('Login','ورود')}</button>
   <div class="nl-foot">© NiceTunnel · <a href="https://t.me/DarkCore_Vpn" target="_blank" rel="noopener">@DarkCore_Vpn</a></div>
  </div></div>
  <div class="nl-scene">${scene}</div></div>`;
  $('#ltheme').onclick=e=>{e.preventDefault();toggleTheme();$('#ltheme').innerHTML=themeIcon();};
  $('#llang').onclick=e=>{e.preventDefault();toggleLang();};
  if(!state.needSetup){ lmode(new URLSearchParams(location.search).get('otl')?'link':'pw'); }
  if(state.needSetup) $('#pw').oninput = () => { const v=$('#pw').value, ok=(c,t)=>(c?'✓ ':'✗ ')+t;
    $('#pwhint').innerHTML=[ok(v.length>=10,'10+ chars'),ok(/[a-z]/.test(v)&&/[A-Z]/.test(v),'Aa'),ok(/\d/.test(v),'0-9'),ok(/[^A-Za-z0-9]/.test(v),'!@#')].join(' &nbsp; '); };
  $('#go').onclick = async () => { try {
      if(!state.needSetup && window._lm==='link'){ let v=$('#lk').value.trim(); const m=v.match(/otl=([^&\s]+)/); if(m) v=m[1];
        await api('/api/login',{link:v}); history.replaceState(null,'',BASE+'/'); await load(); return; }
      await api(state.needSetup ? '/api/setup' : '/api/login', {username:$('#un').value,password:$('#pw').value});
      await load(); } catch(e){ msg(e.message,false); } };
  $('#pw').onkeydown = e => { if(e.key==='Enter') $('#go').click(); };
  $('#pwtog').onclick = () => { const p=$('#pw'); p.type = p.type==='password' ? 'text' : 'password'; p.focus(); };
}
const IC={dash:'<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/></svg>',rev:'<svg viewBox="0 0 24 24"><path d="M4 7h13l-3-3M20 17H7l3 3"/></svg>',spoof:'<svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>',set:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1"/></svg>',out:'<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',sun:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',moon:'<svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'};
const ICSH='<svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>',
  ICTG='<svg viewBox="0 0 24 24"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>',
  ICUS='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
  ICBK='<svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>',
  ICAP='<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.4-.3-.4-.5-.8-.5-1.3 0-1.1.9-2 2-2h2.3A4.7 4.7 0 0 0 22 10.7C22 5.9 17.5 2 12 2z"/><circle cx="7.5" cy="10.5" r="1.2"/><circle cx="12" cy="7" r="1.2"/><circle cx="16.5" cy="10.5" r="1.2"/></svg>';
IC.logs='<svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10"/></svg>';
const PAGES = [['dash',IC.dash,'Dashboard'],['tun',IC.rev,'Tunnels'],['logs',IC.logs,'Logs'],['set',IC.set,'Settings']];
  let tsel = 'rev';
const LOGO = '<svg viewBox="0 0 64 64" width="34" height="34"><defs><linearGradient id="ntg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fde68a"/><stop offset="1" stop-color="#d97706"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="16" fill="#0b1226" stroke="url(#ntg)" stroke-width="2.5"/><path d="M12 52V32a20 20 0 0 1 40 0v20" fill="none" stroke="url(#ntg)" stroke-width="4" stroke-linecap="round"/><path d="M20 52V33a12 12 0 0 1 24 0v19" fill="none" stroke="url(#ntg)" stroke-width="3" stroke-linecap="round" opacity=".7"/><path d="M27 52V34a5 5 0 0 1 10 0v18z" fill="url(#ntg)" opacity=".9"/><path d="M6 52h52" stroke="url(#ntg)" stroke-width="3" stroke-linecap="round"/></svg>';
function shell(){
  const nm = state.username || 'admin';
  $('#app').innerHTML = `<div id="shell"><div id="side" class="glass">
    <div class="brand" style="display:flex;align-items:center;gap:10px;padding:2px 6px 16px">${LOGO}<div><div style="font-size:15px;-webkit-text-fill-color:#fff;background:none;color:#fff">NiceTunnel</div><small style="-webkit-text-fill-color:#9aa6d6">v1.4.0</small></div></div>
    ${PAGES.map(p=>`<div class="nav" data-p="${p[0]}"><i>${p[1]}</i><span>${p[2]}</span></div>`).join('')}
    <div class="sp"></div><div class="nav" id="lo"><i>${IC.out}</i><span>Logout</span></div></div>
  <div id="main"><div id="top" class="glass"><div class="hdr">${LOGO}<span class="nm">NiceTunnel</span><span class="vv">v1.4.0</span><h1 id="ttl" style="margin:0 0 0 6px"></h1></div>
    <div style="display:flex;align-items:center;gap:10px"><span id="live" class="live"><i></i><b>${L("Online","آنلاین")}</b></span><span id="host" style="color:#9aa6d6;font-size:12px"></span>${themeBtn()}${langBtn()}</div></div><div id="msg"></div>
  <div class="page" id="p-dash">
    <div class="dgrid" id="dstats"></div>
    <div class="dpanel"><div class="dph"><div><h3>${L("Network map","نقشهٔ شبکه")}</h3><p>${L("Servers are wells, tunnels are channels. Click one to open it.","سرورها چاه‌اند و تونل‌ها کانال. برای باز کردن هرکدام روی آن کلیک کنید.")}</p></div><div class="dleg"><span><i style="background:#34d0c3"></i>${L("flowing","جاری")}</span><span><i style="background:#f0707a"></i>${L("broken","قطع")}</span><span><i style="background:#6b7a93"></i>${L("stopped","خاموش")}</span></div></div><div id="map"></div></div>
    <div class="dtwo">
      <div class="dpanel"><div class="dph"><h3>${L("Tunnels","تونل‌ها")}</h3><button class="dlink" onclick="go('tun')">${L("See all","همه")}</button></div><div id="dtun"></div></div>
      <div class="dpanel"><div class="dph"><h3>${L("Needs attention","نیازمند توجه")}</h3></div><div id="dwarn"></div></div>
    </div>
  </div>
  <div class="page" id="p-tun">
  <div class="seg-bar"><button class="seg" data-s="rev">Reverse</button><button class="seg" data-s="spoof">Spoof</button></div>
  <div class="tsec" id="t-rev">
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
  <div class="tsec" id="t-spoof">
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
  </div>
  <div class="page" id="p-logs">
    <div class="dpanel"><div class="dph"><div><h3>${L("Logs","لاگ‌ها")}</h3><p>${L("Live service logs of your tunnels, refreshed every few seconds.","لاگ زندهٔ سرویس تونل‌ها، هر چند ثانیه به‌روز می‌شود.")}</p></div><button class="dlink" id="lgcopy">${L("Copy","کپی")}</button></div>
    <div class="lgbar"><select id="lgsel"></select><input id="lgq" placeholder="${L("Filter…","فیلتر…")}"><div class="lgseg" id="lgl"><button data-l="all" class="on">${L("All","همه")}</button><button data-l="w">${L("Warnings","هشدار")}</button><button data-l="e">${L("Errors","خطا")}</button></div></div>
    <div class="lg" id="lgbox"></div></div>
  </div>
  <div class="page" id="p-set">
    <div class="set-wrap">
    <div class="set-nav" id="setnav">
      <div class="nav" data-anchor="sec-sec"><i>${ICSH}</i><span>${L('Security','امنیت')}</span></div>
      <div class="nav" data-anchor="sec-up"><i>${IC.set}</i><span>${L('Update','به‌روزرسانی')}</span></div>
      <div class="nav" data-anchor="sec-net"><i><svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg></i><span>${L('Network & speed','شبکه و سرعت')}</span></div>
      <div class="nav" data-anchor="sec-tg"><i>${ICTG}</i><span>${L('Telegram','تلگرام')}</span></div>
      <div class="nav" data-anchor="sec-usage"><i>${ICUS}</i><span>${L('Usage','مصرف')}</span></div>
      <div class="nav" data-anchor="sec-backup"><i>${ICBK}</i><span>${L('Backup','پشتیبان')}</span></div>
      <div class="nav" data-anchor="sec-app"><i>${ICAP}</i><span>${L('Appearance','ظاهر')}</span></div>
    </div>
    <div class="set-main">
    <div class="sec glass sset" id="sec-sec"><h2>${L('Security','امنیت')}</h2>
      <div class="srow"><div class="st"><b>${L('Username','نام کاربری')}</b><p>${L('Name used to sign in to the panel.','نامی که برای ورود به پنل استفاده می‌شود.')}</p></div><input id="sun" value="${esc(nm)}"></div>
      <div class="srow"><div class="st"><b>${L('Current password','رمز فعلی')}</b><p>${L('Required to confirm any change.','برای تأیید هر تغییری لازم است.')}</p></div><input id="scur" type="password"></div>
      <div class="srow"><div class="st"><b>${L('New password','رمز جدید')}</b><p>${L('Leave empty to keep the current one. Changing it logs out every other browser session.','خالی بگذارید تا رمز فعلی بماند. تغییرش، سایر مرورگرها را از پنل خارج می‌کند.')}</p></div><input id="snew" type="password" placeholder="10+ chars, Aa, 1, !"></div>
      <div class="srow"><div></div><button class="ok" id="ssave">${L('Save changes','ذخیره تغییرات')}</button></div>
      <div class="srow"><div class="st"><b>${L('One-time login link','لینک ورود یکبار مصرف')}</b><p>${L('Valid for 40 minutes, works once. Useful when you forget the password.','۴۰ دقیقه اعتبار دارد و فقط یک بار کار می‌کند.')}</p></div><button class="ok" id="otlbtn">${L('Generate link','ساخت لینک')}</button></div>
      <div id="otlout" class="hide" style="padding:8px 0"><code class="scode" id="otlurl" style="word-break:break-all;display:block;direction:ltr"></code><button id="otlcopy" style="margin-top:6px">${L('Copy','کپی')}</button> <small id="otlexp"></small></div>
      <div class="srow"><div class="st"><b>${L('Logged-in devices','دستگاه‌های واردشده')}</b><p>${L('Every active session with its device and IP.','هر نشست فعال با دستگاه و آی‌پی.')}</p></div><button id="devout">${L('Log out others','خروج بقیه')}</button></div>
      <div id="devs"></div>
    </div>
    <div class="sec glass sset" id="sec-up"><h2>${L('Update','به‌روزرسانی')}</h2>
      <div class="srow"><div class="st"><b>${L('Installed','نصب‌شده')}</b><p>NiceTunnel Panel</p></div><code class="scode">v1.4.0</code></div>
      <div class="srow"><div class="st"><b>${L('Panel address','آدرس پنل')}</b><p>${L('Secret path of this panel. Keep it private.','مسیر مخفی این پنل. آن را محرمانه نگه دارید.')}</p></div><code id="sinfo" class="scode"></code></div>
      <div class="srow"><div class="st"><b>${L('Creator','سازنده')}</b><p>Arsham Smok · آرشام اسموک</p></div></div>
    </div>
    <div class="sec glass sset" id="sec-net"><h2>${L('Network & speed','شبکه و سرعت')} <span class="nbadge" id="nbadge"></span></h2>
      <p class="nhint">${L('Tunes the Linux network stack (BBR, fq, big buffers) for faster, steadier transfers on long or lossy routes. Reversible at any time.','پشته‌ی شبکه‌ی لینوکس (BBR، fq، بافرهای بزرگ) را برای انتقال سریع‌تر و پایدارتر روی مسیرهای دور یا پرافت تنظیم می‌کند. هر لحظه قابل برگشت است.')}</p>
      <div class="nprof" id="nprof"></div>
      <div class="ntable" id="ntable"></div>
      <div class="nact"><button class="ok" id="napply">${L('Apply profile','اعمال پروفایل')}</button> <button id="nrevert">${L('Restore defaults','بازگشت به پیش‌فرض')}</button> <span class="nkern" id="nkern"></span></div>
    </div>
    <div class="sec glass sset" id="sec-tg"><h2>${L('Telegram bot','ربات تلگرام')}</h2>
      <div class="srow"><div class="st"><b>${L('Bot token','توکن ربات')}</b><p id="tgcur">${L('Get it from @BotFather.','از @BotFather بگیرید.')}</p></div><input id="tgtok" dir="ltr" placeholder="123456:ABC..." autocomplete="off"></div>
      <div class="srow"><div class="st"><b>Chat ID</b><p>${L('Your numeric ID (from @userinfobot) or a group ID.','آیدی عددی شما (از @userinfobot) یا گروه.')}</p></div><input id="tgchat" dir="ltr"></div>
      <div class="srow"><div class="st"><b>${L('API address (optional)','آدرس API (اختیاری)')}</b><p>${L('Mirror/proxy for Telegram if blocked. Default: api.telegram.org','اگر تلگرام فیلتر است، آدرس پروکسی/میرور. پیش‌فرض: api.telegram.org')}</p></div><input id="tgapi" dir="ltr" placeholder="https://api.telegram.org"></div>
      <div class="srow"><div class="st"><b>${L('Notify about','اعلان برای')}</b></div><div style="display:flex;gap:14px;flex-wrap:wrap"><label><input type="checkbox" class="tgev" value="tunnel"> ${L('Tunnel up/down/created/deleted','وصل/قطع/ساخت/حذف تونل')}</label><label><input type="checkbox" class="tgev" value="login"> ${L('Logins & failed logins','ورودها و ورود ناموفق')}</label><label><input type="checkbox" class="tgev" value="backup"> ${L('Backups','بکاپ‌ها')}</label></div></div>
      <div class="srow"><div></div><div><button class="ok" id="tgsave">${L('Save','ذخیره')}</button> <button id="tgtest">${L('Send test','ارسال تست')}</button> <button id="tgdel">${L('Remove','حذف')}</button></div></div>
    </div>
    <div class="sec glass sset" id="sec-usage"><h2>${L('Usage','مصرف')}</h2>
      <div class="srow"><div class="st"><b>${L('Now','اکنون')}</b></div><code class="scode" id="clock"></code></div>
      <div class="srow"><div class="st"><b>${L('Calendar','تقویم')}</b></div><div class="segm" id="sgcal"><button data-v="persian">${L('Jalali','شمسی')}</button><button data-v="gregory">${L('Gregorian','میلادی')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Time zone','منطقه زمانی')}</b></div><select id="stz">${TZS.map(z=>`<option value="${z[0]}">${z[1]}</option>`).join('')}</select></div>
    </div>
    <div class="sec glass sset" id="sec-backup"><h2>${L('Backup & restore','پشتیبان و بازیابی')}</h2>
      <div class="srow"><div class="st"><b>${L('Create backup now','بکاپ فوری')}</b><p>${L('Saves all tunnels. Include panel settings (password, Telegram) for a full copy. Sent to Telegram too, so you still have it if this server dies.','همه تونل‌ها ذخیره می‌شود. «کامل» شامل تنظیمات پنل (رمز، تلگرام) هم هست. به تلگرام هم ارسال می‌شود تا با از دست رفتن سرور، بکاپ را داشته باشید.')}</p></div><div><label><input type="checkbox" id="bkfull"> ${L('Full','کامل')}</label> <label><input type="checkbox" id="bktg" checked> Telegram</label> <button class="ok" id="bknow">${L('Backup','بکاپ')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Automatic backup','بکاپ خودکار')}</b><p>${L('Keeps the last 10 copies.','۱۰ نسخه آخر نگه داشته می‌شود.')}</p></div><div><label><input type="checkbox" id="abon"> ${L('On','فعال')}</label> ${L('every','هر')} <input id="abh" type="number" min="1" max="168" style="width:70px"> ${L('hours','ساعت')} <label><input type="checkbox" id="abfull"> ${L('Full','کامل')}</label> <button id="absave">${L('Save','ذخیره')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Restore from file','بازیابی از فایل')}</b><p>${L('On a new server: install the panel, upload the backup file here. Tunnels are rebuilt and started. Then update the OTHER server of each tunnel with this server\'s new IP.','روی سرور جدید: پنل را نصب کنید و فایل بکاپ را اینجا آپلود کنید. تونل‌ها ساخته و اجرا می‌شوند. سپس در سرور مقابل هر تونل، آی‌پی جدید این سرور را جایگزین کنید.')}</p></div><div><input type="file" id="bkfile" accept=".json"> <label><input type="checkbox" id="bkpanel"> ${L('Also panel settings','تنظیمات پنل هم')}</label> <button class="ok" id="bkrest">${L('Restore','بازیابی')}</button></div></div>
      <div id="bklist"></div>
    </div>
    <div class="sec glass sset" id="sec-app"><h2>${L('Appearance','ظاهر')}</h2>
      <div class="srow"><div class="st"><b>${L('Language','زبان')}</b><p>${L('Interface language.','زبان رابط کاربری.')}</p></div><div class="segm" id="sglang"><button data-v="fa">فارسی</button><button data-v="en">English</button></div></div>
      <div class="srow"><div class="st"><b>${L('Theme','تم')}</b><p>${L('Dark is the default look.','تم تاریک پیش‌فرض است.')}</p></div><div class="segm" id="sgtheme"><button data-v="dark">${L('Dark','تاریک')}</button><button data-v="light">${L('Light','روشن')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Motion','حرکت')}</b><p>${L('Reduced mode turns off animations on slow phones.','حالت کم‌مصرف، انیمیشن‌ها را روی گوشی‌های ضعیف خاموش می‌کند.')}</p></div><div class="segm" id="sgmotion"><button data-v="full">${L('Full','کامل')}</button><button data-v="low">${L('Reduced','کم‌مصرف')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Telegram channel','کانال تلگرام')}</b><p>${L('News, updates and support.','اخبار، به‌روزرسانی و پشتیبانی.')}</p></div><a class="sbtn" href="https://t.me/DarkCore_Vpn" target="_blank" rel="noopener">@DarkCore_Vpn</a></div>
    </div>
    </div>
    </div>
  </div>
  <div id="foot" class="glass"><span>NiceTunnel · by Arsham Smok</span><span>·</span><a href="https://t.me/DarkCore_Vpn" target="_blank" rel="noopener" style="color:var(--gold)">@DarkCore_Vpn</a></div>
  </div></div>`;
  document.querySelectorAll('.nav[data-p]').forEach(e=>e.onclick=()=>go(e.dataset.p));
  document.querySelectorAll('.seg').forEach(e=>e.onclick=()=>go(e.dataset.s));
  document.querySelectorAll('.tab').forEach(e=>e.onclick=()=>sub(e.dataset.t));
  $('#lo').onclick = logout;
  $('#role').onchange = () => { const s=$('#role').value==='server'; $('#lp').classList.toggle('hide',!s); $('#fw').classList.toggle('hide',s); };
  $('#rrole').onchange = () => { const s=$('#rrole').value==='server';
    $('#rports').classList.toggle('hide',!s); $('#rsip').classList.toggle('hide',s); $('#rth').classList.toggle('hide',s); };
  $('#create').onclick = create; $('#rcreate').onclick = createRev; $('#ssave').onclick = saveAccount;
  $('#sinfo').textContent = location.origin + (BASE||'/');
  const segSet=(id,cur,fn)=>{ const g=$(id); g.querySelectorAll('button').forEach(b=>{ b.classList.toggle('on',b.dataset.v===cur); b.onclick=()=>{ fn(b.dataset.v); g.querySelectorAll('button').forEach(x=>x.classList.toggle('on',x===b)); }; }); };
  segSet('#sglang',lang,v=>{ if(v!==lang){ localStorage.setItem('nt_lang',v); location.reload(); } });
  segSet('#sgtheme',document.documentElement.dataset.theme||'dark',v=>{ localStorage.setItem('nt_theme',v); applyTheme(); const t=$('#thbtn'); if(t) t.innerHTML=themeIcon(); });
  segSet('#sgmotion',localStorage.getItem('nt_motion')||'full',v=>{ localStorage.setItem('nt_motion',v); document.documentElement.classList.toggle('lowmo',v==='low'); });
  document.documentElement.classList.toggle('lowmo',localStorage.getItem('nt_motion')==='low');
  setupSetNav();
  setExtras();
  netTune();
  $('#tmode').onchange = tmodeView; $('#tstart').onclick = tstart; $('#tref').onclick = tstatus;
  if(lang==='fa') tr($('#app'));
}

async function netTune(){
  let T; try{ T=await api('/api/tune'); }catch(e){ return; }
  let sel=T.active||'balanced';
  const names={balanced:[L('Balanced','متعادل'),L('Safe for every server. Larger buffers, BBR and fq.','امن برای همه‌ی سرورها. بافر بزرگ‌تر، BBR و fq.')],
               turbo:[L('Turbo','توربو'),L('Maximum throughput for fast, distant links. Needs more RAM.','حداکثر توان عملیاتی برای لینک‌های سریع و دور. رم بیشتری مصرف می‌کند.')]};
  const draw=()=>{
    $('#nprof').innerHTML=Object.keys(names).map(k=>`<div class="pcard${k===sel?' sel':''}" data-k="${k}"><b>${k==='turbo'?'⚡':'🌿'} ${names[k][0]}${T.active===k?` <span class="pa">${L('Active','فعال')}</span>`:''}</b><p>${names[k][1]}</p></div>`).join('');
    $('#nprof').querySelectorAll('.pcard').forEach(c=>c.onclick=()=>{sel=c.dataset.k;draw();});
    const rows=T.profiles[sel]||[];
    $('#ntable').innerHTML=`<div class="nrow"><span>${L('Setting','تنظیم')}</span><span>${L('Recommended','پیشنهادی')}</span><span>${L('Current','فعلی')}</span></div>`+
      rows.map(r=>`<div class="nrow"><code>${esc(r.key)}</code><span class="nv">${esc(r.want)}</span><span class="nv${r.ok?' ok':''}"><i></i>${esc(r.cur)}</span></div>`).join('');
    const b=$('#nbadge'); b.textContent=T.active?(L('Active: ','فعال: ')+names[T.active][0]):L('Default','پیش‌فرض'); b.classList.toggle('on',!!T.active);
    $('#nkern').textContent='Linux '+T.kernel+' · '+(T.avail.join(', ')||'-');
  };
  draw();
  const reload=async()=>{ T=await api('/api/tune'); sel=T.active||sel; draw(); };
  $('#napply').onclick=async()=>{ const b=$('#napply'); b.disabled=true; try{ await api('/api/tune/apply',{profile:sel}); await reload(); alert(L('Applied and saved (survives reboot).','اعمال و ذخیره شد (بعد از ریبوت هم می‌ماند).')); }catch(e){ alert(e.message); } b.disabled=false; };
  $('#nrevert').onclick=async()=>{ if(!confirm(L('Restore previous network values?','مقادیر قبلی شبکه برگردانده شود؟'))) return; try{ await api('/api/tune/revert',{}); await reload(); }catch(e){ alert(e.message); } };
}
function setupSetNav(){
  const links = [...document.querySelectorAll('#setnav .nav[data-anchor]')];
  const secs = links.map(a=>document.getElementById(a.dataset.anchor)).filter(Boolean);
  links.forEach(a=>a.onclick=()=>{ const el=document.getElementById(a.dataset.anchor);
    if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); });
  if(!secs.length || !('IntersectionObserver' in window)) return;
  const io = new IntersectionObserver(entries=>{
    entries.forEach(e=>{ if(e.isIntersecting) links.forEach(a=>a.classList.toggle('on', a.dataset.anchor===e.target.id)); });
  }, {rootMargin:'-15% 0px -70% 0px', threshold:0});
  secs.forEach(s=>io.observe(s));
}
function sub(t){
  cur = t;
  document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('on', e.dataset.t===t));
  document.querySelectorAll('.sub').forEach(e=>e.classList.toggle('on', e.id==='s-'+t));
  if(t==='mon') monitor();
  if(t==='logs' && logSlot) logs(logSlot);
}
function go(p){
  if(p==='rev'||p==='spoof'){ tsel = p; p = 'tun'; }
  page = p;
  document.querySelectorAll('.tsec').forEach(e=>e.classList.toggle('on', e.id==='t-'+tsel));
  document.querySelectorAll('.seg').forEach(e=>e.classList.toggle('on', e.dataset.s===tsel));
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
function renderMap(st, slots){
  const el=$('#map'); if(!el) return;
  const peers={}; slots.forEach(s=>{ const ip=s.kind==='reverse'?s.server_ip:s.peer; if(!ip) return; (peers[ip]=peers[ip]||[]).push(s); });
  const keys=Object.keys(peers), W=800, H=260, X0=150, X1=650, mid=(X0+X1)/2;
  let g=`<svg viewBox="0 0 ${W} ${H}" class="mapsvg">`;
  if(!keys.length) g+=`<text x="${W/2}" y="${H/2+5}" text-anchor="middle" class="mt">No tunnel yet</text>`;
  keys.forEach((ip,i)=>{
    const list=peers[ip], y=keys.length===1?H/2:50+i*((H-100)/Math.max(1,keys.length-1));
    const up=list.filter(s=>s.state==='active').length, bad=list.some(s=>s.state==='failed');
    const col= up ? '#22c55e' : bad ? '#ef4444' : '#64748b';
    g+=`<path d="M${X0},${H/2} C${mid},${H/2} ${mid},${y} ${X1},${y}" stroke="${col}" class="mline ${up?'flow':''}"/>`;
    g+=`<circle cx="${X1}" cy="${y}" r="9" fill="${col}"/>`;
    g+=`<text x="${X1+18}" y="${y-4}" class="ml">${esc(ip)}</text><text x="${X1+18}" y="${y+12}" class="ms">${up}/${list.length} active</text>`;
  });
  g+=`<circle cx="${X0}" cy="${H/2}" r="16" fill="#6366f1" class="mhub"/>`;
  g+=`<text x="${X0}" y="${H/2+38}" text-anchor="middle" class="ml">${esc(st.hostname||'this server')}</text><text x="${X0}" y="${H/2+54}" text-anchor="middle" class="ms">${esc(st.ip||'')}</text>`;
  el.innerHTML=g+'</svg>';
}
const ICT2='<svg viewBox="0 0 24 24"><path d="M3 19V11a9 9 0 0 1 18 0v8M7 19v-8a5 5 0 0 1 10 0v8"/></svg>', ICS2='<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>', ICC2='<svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/></svg>';
const ICA='<svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>';
function fmtR(b){ const x=(+b||0)*8; if(x>=1e9) return [(x/1e9).toFixed(2),'Gbps']; if(x>=1e6) return [(x/1e6).toFixed(x>=1e8?0:1),'Mbps']; if(x>=1e3) return [(x/1e3).toFixed(0),'Kbps']; return [Math.round(x),'bps']; }
function peerOf(s){ return (s.kind==='reverse' ? (s.server_ip||s.target_host) : s.peer) || 'remote'; }
function stCls(s){ return s==='active'?'active':s==='failed'?'failed':'off'; }
function stTxt(s){ return s==='active'?L('Flowing','جاری'):s==='failed'?L('Broken','قطع'):(s==='inactive'||s==='unknown')?L('Stopped','خاموش'):esc(s); }
function slotProto(s){ return s.kind==='reverse' ? 'tcp:'+(s.bridge||'') : (s.transport||'spoof')+':'+(s.port||''); }
function slotDetail(s){
  if(s.kind==='reverse') return 'reverse '+slotProto(s)+' · '+(s.role==='server' ? 'listen '+(s.ports||'-') : 'forward '+(s.target_host||'-'));
  return 'spoof '+slotProto(s)+' · '+(s.role==='server' ? 'UDP '+(s.listen_port||'-') : '→ '+(s.forward||'-'))+(s.spoof_ips?' · src '+s.spoof_ips:'');
}
let _dsig='';
function dashRender(st, slots){
  if(!$('#dstats')) return;
  const act=slots.filter(s=>s.state==='active').length, bad=slots.filter(s=>s.state==='failed').length, off=slots.length-act-bad;
  const pm={}; slots.forEach(s=>{ const ip=peerOf(s); (pm[ip]=pm[ip]||[]).push(s); });
  const pk=Object.keys(pm), pon=pk.filter(ip=>pm[ip].some(s=>s.state==='active')).length, pbad=pk.filter(ip=>!pm[ip].some(s=>s.state==='active')&&pm[ip].some(s=>s.state==='failed')).length;
  const R=fmtR((st.rx_rate||0)+(st.tx_rate||0)), seg=(n,c)=>n?`<i style="flex:${n};background:${c}"></i>`:'';
  const mini=(k,p)=>`<div class="dm"><span>${k}</span><em><b style="width:${Math.max(0,Math.min(100,p||0))}%"></b></em><span>${(p||0).toFixed(0)}%</span></div>`;
  $('#dstats').innerHTML=`
   <div class="dc"><div class="dk">${ICA}${L('Throughput now','ترافیک همین حالا')}</div><div class="dv">${R[0]}<small>${R[1]}</small></div><canvas id="cth"></canvas><div class="ds"><bdi dir="ltr">↓ ${fmtB(st.rx_rate)}/s · ↑ ${fmtB(st.tx_rate)}/s</bdi></div></div>
   <div class="dc"><div class="dk">${ICT2}${L('Tunnels flowing','تونل‌های جاری')}</div><div class="dv">${act}<small>${L('of','از')} ${slots.length}</small></div><div class="dseg">${seg(act,'#34d0c3')}${seg(bad,'#f0707a')}${seg(off,'#6b7a93')}${slots.length?'':'<i style="flex:1;background:#1d2e4a"></i>'}</div><div class="ds">${bad?`<span class="bd">${bad} ${L('broken','قطع')}</span>`:(slots.length?L('All healthy','همه سالم'):L('No tunnel yet','هنوز تونلی نیست'))}</div></div>
   <div class="dc"><div class="dk">${ICS2}${L('Servers connected','سرورهای متصل')}</div><div class="dv">${pon}<small>${L('of','از')} ${pk.length}</small></div><div class="dseg">${seg(pon,'#34d0c3')}${seg(pbad,'#f0707a')}${seg(pk.length-pon-pbad,'#6b7a93')}${pk.length?'':'<i style="flex:1;background:#1d2e4a"></i>'}</div><div class="ds">${esc(st.hostname||'')} · ${esc(st.ip||'')}</div></div>
   <div class="dc"><div class="dk">${ICC2}${L('This server','این سرور')}</div>${mini('CPU',st.cpu)}${mini('RAM',st.mem_pct)}${mini('Disk',st.disk_pct)}<div class="ds">${L('Uptime','آپتایم')} ${fmtUp(st.uptime)}</div></div>`;
  spark('#cth', hist.rx.map((v,i)=>v+(hist.tx[i]||0)), '#34d0c3');
  const W=[];
  slots.filter(s=>s.state==='failed').forEach(s=>W.push(`<div class="wr"><i>!</i><span>${L('Tunnel','تونل')} #${s.slot} · ${esc(peerOf(s))} ${L('is broken','قطع است')}</span><button class="dlink" onclick="go('${s.kind==='reverse'?'rev':'spoof'}')">${L('Open','باز کردن')}</button></div>`));
  slots.filter(s=>s.state!=='active'&&s.state!=='failed').forEach(s=>W.push(`<div class="wr"><i class="y">•</i><span>${L('Tunnel','تونل')} #${s.slot} · ${esc(peerOf(s))} ${L('is stopped','خاموش است')}</span><button class="dlink" onclick="go('${s.kind==='reverse'?'rev':'spoof'}')">${L('Open','باز کردن')}</button></div>`));
  if((st.cpu||0)>85) W.push(`<div class="wr"><i class="y">%</i><span>${L('High CPU','پردازنده شلوغ است')} ${st.cpu.toFixed(0)}%</span></div>`);
  if((st.mem_pct||0)>90) W.push(`<div class="wr"><i class="y">%</i><span>${L('High memory','حافظه پر است')} ${st.mem_pct.toFixed(0)}%</span></div>`);
  if((st.disk_pct||0)>90) W.push(`<div class="wr"><i class="y">%</i><span>${L('Disk almost full','دیسک تقریباً پر است')} ${st.disk_pct.toFixed(0)}%</span></div>`);
  if(!W.length) W.push(slots.length ? `<div class="wr"><i class="g">✓</i><span>${L('Everything is on track: all tunnels are flowing.','همه‌چیز روبه‌راه است: همه تونل‌ها جاری‌اند.')}</span></div>` : `<div class="wr"><i class="g">+</i><span>${L('Create your first tunnel to get started.','اولین تونل خود را بسازید.')}</span><button class="dlink" onclick="go('rev')">${L('Create','ساخت')}</button></div>`);
  $('#dwarn').innerHTML=W.join('');
  const cw=($('#map')||{}).clientWidth||0, sig=lang+'|'+cw+'|'+(st.hostname||'')+'|'+JSON.stringify(slots.map(s=>[s.slot,s.state,peerOf(s),s.port,s.bridge]));
  if(sig===_dsig) return; _dsig=sig;
  dashMap(st, slots, pm, pk);
  $('#dtun').innerHTML = slots.length ? slots.map(s=>`<div class="tr" onclick="go('${s.kind==='reverse'?'rev':'spoof'}')"><i class="tb ${stCls(s.state)}"></i><div class="tm"><b>#${s.slot} · ${esc(st.hostname||L('This server','این سرور'))} ↔ ${esc(peerOf(s))}<em class="tg">${esc(s.side)}</em></b><span>${esc(slotDetail(s))}</span></div><div class="tp ${stCls(s.state)}">${stTxt(s.state)}</div></div>`).join('') : `<div class="dempty">${L('No tunnels yet. Create one from the Tunnels page.','هنوز تونلی نیست. از صفحه تونل‌ها یکی بسازید.')}<br><br><button class="dlink" onclick="go('rev')">${L('Create tunnel','ساخت تونل')}</button></div>`;
}
function dashMap(st, slots, pm, pk){
  const el=$('#map'); if(!el) return;
  const cw=Math.max(el.clientWidth||320,300), n=pk.length, W=Math.max(cw,(n+1)*150), H0=96, X0=Math.min(86,W*.15), XR=W-70;
  const px=i=>X0+(i+1)*((XR-X0)/Math.max(n,1));
  const rows=[]; pk.forEach((ip,i)=>pm[ip].forEach(s=>rows.push({s,i,ip})));
  const yy=j=>H0+48+j*40, H=H0+48+Math.max(rows.length,1)*40+16;
  const cut=(t,m)=>{t=String(t);return t.length>m?t.slice(0,m-1)+'…':t;};
  let g=`<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><defs><linearGradient id="dgd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0a1c33"/><stop offset="1" stop-color="#050d18"/></linearGradient><linearGradient id="dsk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#050b17"/><stop offset="1" stop-color="#112340"/></linearGradient></defs>`;
  g+=`<rect width="${W}" height="${H0}" fill="url(#dsk)"/><rect y="${H0}" width="${W}" height="${H-H0}" fill="url(#dgd)"/>`;
  for(let k=0;k<46;k++){ g+=`<circle cx="${((k*137.5)%W).toFixed(0)}" cy="${((k*61.8)%(H0-10)+4).toFixed(0)}" r="${k%5?0.8:1.3}" fill="#fff" opacity="${(0.25+(k%4)*0.18).toFixed(2)}"/>`; }
  g+=`<line x1="0" y1="${H0}" x2="${W}" y2="${H0}" stroke="#e9c46a" stroke-width="1.6" opacity=".9"/>`;
  const dT=rows.length?yy(rows.length-1):H0+22, dP=pk.map((ip,i)=>{ const js=rows.map((r,j)=>r.i===i?j:-1).filter(j=>j>=0); return js.length?yy(Math.max(...js)):H0+22; });
  g+=`<line x1="${X0}" y1="${H0}" x2="${X0}" y2="${dT}" stroke="#8a7340" stroke-width="2.5" stroke-linecap="round"/>`;
  pk.forEach((ip,i)=>{ g+=`<line x1="${px(i)}" y1="${H0}" x2="${px(i)}" y2="${dP[i]}" stroke="#8a7340" stroke-width="2.5" stroke-linecap="round"/>`; });
  rows.forEach((r,j)=>{
    const s=r.s, y=yy(j), xp=px(r.i), dx=(xp-X0)*.4, col=s.state==='active'?'#34d0c3':s.state==='failed'?'#f0707a':'#6b7a93';
    const d=`M${X0} ${y} C${X0+dx} ${y+12} ${xp-dx} ${y+12} ${xp} ${y}`, t='#'+s.slot+' · '+slotProto(s), pw=t.length*6.1+30, xm=(X0+xp)/2, ym=y+9;
    g+=`<g style="cursor:pointer" onclick="go('${s.kind==='reverse'?'rev':'spoof'}')"><path d="${d}" fill="none" stroke="transparent" stroke-width="22"/>`
     +`<path d="${d}" fill="none" stroke="${col}" stroke-opacity=".14" stroke-width="12" stroke-linecap="round"/>`
     +`<path d="${d}" fill="none" stroke="${col}" stroke-width="${s.state==='active'?4:3}" stroke-linecap="round" ${s.state==='active'?'':'stroke-dasharray="5 6" opacity=".8"'}/>`
     +(s.state==='active'?`<path class="mdash" d="${d}" fill="none" stroke="#e8fffd" stroke-opacity=".8" stroke-width="1.6"/>`:'')
     +`<circle cx="${X0}" cy="${y}" r="4" fill="${col}"/><circle cx="${xp}" cy="${y}" r="4" fill="${col}"/>`
     +`<rect x="${(xm-pw/2).toFixed(1)}" y="${ym-10}" width="${pw.toFixed(1)}" height="20" rx="10" fill="#0a1a30" stroke="${col}" stroke-opacity=".5"/><circle cx="${(xm-pw/2+12).toFixed(1)}" cy="${ym}" r="3" fill="${col}"/><text class="dpl" x="${(xm-pw/2+20).toFixed(1)}" y="${ym+3.6}">${esc(t)}</text></g>`;
  });
  if(!rows.length) g+=`<text class="dn2" x="${W/2}" y="${H0+50}" text-anchor="middle">${L('No tunnel yet','هنوز تونلی نیست')}</text>`;
  const node=(x,anc,name,sub,col)=>`<path d="M${x-9} ${H0} a9 9 0 0 1 18 0z" fill="#e9c46a"/><circle cx="${anc==='start'?x-6:x-(String(name).length*3.2+9)}" cy="${H0-34}" r="3" fill="${col}"/><text class="dn" x="${anc==='start'?x+2:x+4}" y="${H0-30}" text-anchor="${anc}">${esc(cut(name,24))}</text><text class="dn2" x="${anc==='start'?x-6:x}" y="${H0-16}" text-anchor="${anc}">${esc(cut(sub,34))}</text>`;
  g+=node(X0,'start',st.hostname||L('this server','همین سرور'),(st.ip||''),'#34d0c3');
  pk.forEach((ip,i)=>{ const l=pm[ip], col=l.some(s=>s.state==='active')?'#34d0c3':l.some(s=>s.state==='failed')?'#f0707a':'#6b7a93'; g+=node(px(i),'middle',ip,(l[0].role==='server'?L('Foreign','خارج'):L('Iran','ایران'))+' · '+l.length+' '+L('tunnel','تونل'),col); });
  el.innerHTML=g+'</svg>';
}
let _lgsig='', _lgl='all', _lgsel='all', _lgbusy=false;
async function logsPage(){
  if(!$('#lgbox')||_lgbusy) return; _lgbusy=true;
  try{
    const slots=window._slots||[], sel=$('#lgsel');
    const opts='<option value="all">'+L('All tunnels','همه تونل‌ها')+'</option>'+slots.map(x=>`<option value="${x.slot}">#${x.slot} · ${esc(peerOf(x))} · ${x.kind}</option>`).join('');
    if(sel.dataset.o!==opts){ sel.innerHTML=opts; sel.dataset.o=opts; sel.value=slots.some(x=>String(x.slot)===_lgsel)?_lgsel:'all'; }
    _lgsel=sel.value;
    const ids=_lgsel==='all'?slots.map(x=>x.slot):[+_lgsel];
    const res=await Promise.all(ids.map(n=>api('/api/slot/'+n+'/logs').then(r=>({n,t:r.logs||''})).catch(e=>({n,t:'error: '+e.message}))));
    let lines=[]; res.forEach(r=>r.t.split('\n').forEach(l=>{ if(l.trim()) lines.push({n:r.n,l}); }));
    const q=($('#lgq').value||'').trim().toLowerCase();
    const isE=t=>/error|fail|panic|fatal|traceback|refused|denied/i.test(t), isW=t=>/warn|retry|reconnect|timeout|timed out|lost|closed/i.test(t);
    lines=lines.filter(x=>(!q||x.l.toLowerCase().includes(q)) && (_lgl==='all'||(_lgl==='e'?isE(x.l):(isE(x.l)||isW(x.l)))));
    const html=lines.length ? lines.slice(-400).map(x=>{ const m=x.l.match(/^([A-Z][a-z]{2} +\d+ [\d:]{8}) (\S+) (.*)$/), c=isE(x.l)?'e':isW(x.l)?'w':/start|connect|listen|active|ready|established/i.test(x.l)?'o':'';
      return `<div class="${c}">${ids.length>1?'<span class="t">#'+x.n+'</span> ':''}${m?'<span class="t">'+esc(m[1])+'</span> '+esc(m[3]):esc(x.l)}</div>`; }).join('') : `<div class="t">${L('No log lines.','لاگی نیست.')}</div>`;
    if(html!==_lgsig){ const b=$('#lgbox'), near=b.scrollHeight-b.scrollTop-b.clientHeight<60; _lgsig=html; b.innerHTML=html; if(near) b.scrollTop=b.scrollHeight; }
  } finally { _lgbusy=false; }
}
document.addEventListener('input',e=>{ if(e.target.id==='lgq'){ _lgsig=''; logsPage(); } });
document.addEventListener('change',e=>{ if(e.target.id==='lgsel'){ _lgsel=e.target.value; _lgsig=''; logsPage(); } });
document.addEventListener('click',e=>{ const b=e.target.closest&&e.target.closest('#lgl button'); if(b){ _lgl=b.dataset.l; document.querySelectorAll('#lgl button').forEach(x=>x.classList.toggle('on',x===b)); _lgsig=''; logsPage(); return; }
  if(e.target.id==='lgcopy'){ const t=$('#lgbox').innerText; try{ navigator.clipboard.writeText(t).then(()=>msg(L('Copied','کپی شد'),true)); }catch(_){} } });
function rowBtns(n){ return `<td><button class="sm ok" onclick="act(${n},'start')">Connect</button><button class="sm" onclick="act(${n},'restart')">Restart</button><button class="sm" onclick="act(${n},'stop')">Stop</button><button class="sm" onclick="logs(${n})">Logs</button><button class="sm danger" onclick="del(${n})">Delete</button></td>`; }
async function refresh(){
  try {
    const [st, sl] = await Promise.all([api('/api/stats'), api('/api/slots')]);
    push(hist.cpu, st.cpu); push(hist.rx, st.rx_rate); push(hist.tx, st.tx_rate);
    const lv=$('#live'); if(lv){lv.classList.remove('off'); lv.querySelector('b').textContent=L('Online','آنلاین');}
    $('#host').textContent = st.hostname + ' · ' + st.ip;
    dashRender(st, sl.slots); window._slots=sl.slots; if(page==='logs') logsPage();
    $('#revtbl').innerHTML = slotTable(sl.slots.filter(s=>s.kind==='reverse'), true);
    $('#tbl').innerHTML = slotTable(sl.slots.filter(s=>s.kind==='spoof'), true);
  } catch(e){ const lv=$('#live'); if(lv){lv.classList.add('off'); lv.querySelector('b').textContent=L('Offline','آفلاین');} if(/login|auth|401/i.test(e.message)) load(); else msg(e.message,false); }
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
    shell(); go(page); timer = setInterval(()=>{ refresh(); if(page==='tun' && tsel==='spoof' && cur==='mon') monitor(); }, 3000);
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

async function setExtras(){
  const sv=(k,d)=>localStorage.getItem(k)||d;
  const clk=()=>{ const c=$('#clock'); if(c) c.textContent=nowStr(); }; clk(); if(window._ck) clearInterval(window._ck); window._ck=setInterval(clk,1000);
  $('#stz').value=sv('nt_tz','Asia/Tehran'); $('#stz').onchange=()=>{localStorage.setItem('nt_tz',$('#stz').value);clk();loadDevs();loadBk();};
  const g=$('#sgcal'), cc=sv('nt_cal',lang==='fa'?'persian':'gregory');
  g.querySelectorAll('button').forEach(b=>{b.classList.toggle('on',b.dataset.v===cc);b.onclick=()=>{localStorage.setItem('nt_cal',b.dataset.v);g.querySelectorAll('button').forEach(x=>x.classList.toggle('on',x===b));clk();loadDevs();loadBk();};});
  $('#otlbtn').onclick=async()=>{ try{ const r=await api('/api/otl/create',{}); $('#otlurl').textContent=location.origin+(BASE||'')+'/?otl='+r.token; $('#otlout').classList.remove('hide'); $('#otlexp').textContent=L('Expires: ','انقضا: ')+fdate(r.exp); }catch(e){alert(e.message);} };
  $('#otlcopy').onclick=()=>{ const t=$('#otlurl').textContent; (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).catch(()=>{const r=document.createRange();r.selectNode($('#otlurl'));getSelection().removeAllRanges();getSelection().addRange(r);}); };
  const loadDevs=async()=>{ try{ const r=await api('/api/devices'); $('#devs').innerHTML=r.devices.map(d=>`<div class="srow"><div class="st"><b>${esc(d.dev)}${d.me?' ('+L('this device','این دستگاه')+')':''}</b><p dir="ltr">${esc(d.ip)} · ${d.how==='link'?L('link','لینک'):L('password','رمز')} · ${fdate(d.t)}</p></div>${d.me?'':`<button data-id="${d.id}" class="rv">${L('Log out','خروج')}</button>`}</div>`).join('');
    document.querySelectorAll('#devs .rv').forEach(b=>b.onclick=async()=>{await api('/api/device/revoke',{id:b.dataset.id});loadDevs();}); }catch(e){} };
  $('#devout').onclick=async()=>{ await api('/api/device/revoke-others',{}); loadDevs(); }; loadDevs();
  // telegram
  try{ const t=await api('/api/tg'); $('#tgchat').value=t.chat; $('#tgapi').value=t.api; if(t.has) $('#tgcur').textContent=L('Saved: ','ذخیره‌شده: ')+t.masked+L(' (leave empty to keep)',' (خالی = بدون تغییر)');
    document.querySelectorAll('.tgev').forEach(c=>c.checked=t.events.includes(c.value)); }catch(e){}
  $('#tgsave').onclick=async()=>{ try{ await api('/api/tg/save',{token:$('#tgtok').value,chat:$('#tgchat').value,api:$('#tgapi').value,on:true,events:[...document.querySelectorAll('.tgev')].filter(c=>c.checked).map(c=>c.value)}); $('#tgtok').value=''; alert(L('Saved','ذخیره شد')); }catch(e){alert(e.message);} };
  $('#tgtest').onclick=async()=>{ try{ await api('/api/tg/test',{}); alert(L('Sent. Check Telegram.','ارسال شد. تلگرام را ببینید.')); }catch(e){alert(e.message);} };
  $('#tgdel').onclick=async()=>{ if(confirm(L('Remove Telegram settings?','تنظیمات تلگرام حذف شود؟'))){ await api('/api/tg/clear',{}); $('#tgchat').value='';$('#tgapi').value='';$('#tgcur').textContent=''; } };
  // backups
  const loadBk=async()=>{ try{ const r=await api('/api/backups'); $('#abon').checked=!!r.auto.on; $('#abh').value=r.auto.hours||24; $('#abfull').checked=!!r.auto.full;
    $('#bklist').innerHTML=r.list.map(b=>`<div class="srow"><div class="st"><b dir="ltr">${esc(b.name)}</b><p>${fdate(b.time)} · ${fmtB(b.size)}</p></div><div><a class="sbtn" href="${BASE}/api/backup/get?name=${encodeURIComponent(b.name)}" download>${L('Download','دانلود')}</a> <button class="br" data-n="${esc(b.name)}">${L('Restore','بازیابی')}</button> <button class="bd" data-n="${esc(b.name)}">${L('Delete','حذف')}</button></div></div>`).join('');
    document.querySelectorAll('#bklist .br').forEach(b=>b.onclick=()=>restore({name:b.dataset.n}));
    document.querySelectorAll('#bklist .bd').forEach(b=>b.onclick=async()=>{ if(confirm(L('Delete this backup?','این بکاپ حذف شود؟'))){await api('/api/backup/delete',{name:b.dataset.n});loadBk();} }); }catch(e){} };
  const restore=async(body)=>{ body.panel=$('#bkpanel').checked; try{ let r; try{ r=await api('/api/backup/restore',body); }catch(e){ if(e.message==='exists' && confirm(L('Some tunnels already exist and will be overwritten. Continue?','برخی تونل‌ها از قبل وجود دارند و بازنویسی می‌شوند. ادامه؟'))){ body.overwrite=true; r=await api('/api/backup/restore',body); } else if(e.message!=='exists') throw e; else return; }
    alert(L(r.restored+' tunnel(s) restored. Now set this server\'s new IP on the other side of each tunnel.',r.restored+' تونل بازیابی شد. حالا آی‌پی جدید این سرور را در سرور مقابل هر تونل وارد کنید.')); }catch(e){alert(e.message);} };
  $('#bknow').onclick=async()=>{ try{ const r=await api('/api/backup/create',{full:$('#bkfull').checked,telegram:$('#bktg').checked}); alert(L('Done: ','انجام شد: ')+r.slots+L(' tunnels',' تونل')+(r.sent?' · Telegram ✓':'')); loadBk(); }catch(e){alert(e.message);} };
  $('#absave').onclick=async()=>{ try{ await api('/api/backup/auto',{on:$('#abon').checked,hours:+$('#abh').value||24,full:$('#abfull').checked}); alert(L('Saved','ذخیره شد')); }catch(e){alert(e.message);} };
  $('#bkrest').onclick=()=>{ const f=$('#bkfile').files[0]; if(!f) return alert(L('Choose a file','فایل را انتخاب کنید')); const rd=new FileReader(); rd.onload=()=>{ let d; try{d=JSON.parse(rd.result);}catch(e){return alert('Invalid JSON');} restore({data:d}); }; rd.readAsText(f); };
  loadBk();
}
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




# --------------------------------------------------------------------------
# v5: one-time links, devices, Telegram, backups
# --------------------------------------------------------------------------
OTL_TTL = 40 * 60
BACKUP_DIR = os.path.join(CONF_DIR, "backups")
sess_info = {}   # session id -> {"ip","ua","t","how"}
APP_VERSION = "1.4.0"


def hash_tok(t):
    return hashlib.sha256(t.encode()).hexdigest()


def otl_create():
    conf = load_panel_conf()
    now = time.time()
    lst = [x for x in conf.get("otl", []) if x["exp"] > now][-4:]
    tok = secrets.token_urlsafe(24)
    lst.append({"h": hash_tok(tok), "exp": now + OTL_TTL, "t": now})
    conf["otl"] = lst
    save_panel_conf(conf)
    return tok, now + OTL_TTL


def otl_use(tok):
    """True if tok is a valid unused link token. Consumes it (single use)."""
    with lock:
        conf = load_panel_conf()
        now = time.time()
        h = hash_tok(tok)
        ok = False
        keep = []
        for x in conf.get("otl", []):
            if x["exp"] <= now:
                continue
            if hmac.compare_digest(x["h"], h):
                ok = True
                continue
            keep.append(x)
        conf["otl"] = keep
        save_panel_conf(conf)
        return ok


def device_name(ua):
    u = ua.lower()
    osn = "Android" if "android" in u else "iPhone" if "iphone" in u else "iPad" if "ipad" in u else \
        "Windows" if "windows" in u else "macOS" if "mac os" in u else "Linux" if "linux" in u else "Unknown OS"
    br = "Edge" if "edg/" in u else "Opera" if "opr/" in u else "Chrome" if "chrome" in u else \
        "Firefox" if "firefox" in u else "Safari" if "safari" in u else "Unknown browser"
    return "%s · %s" % (br, osn)


def host_label():
    try:
        return socket.gethostname()
    except Exception:
        return "server"


def tg_call(method, fields=None, files=None):
    """Calls the Telegram Bot API. Returns (ok, text). Never raises."""
    import urllib.request
    import uuid
    tg = load_panel_conf().get("tg", {})
    token = tg.get("token", "")
    if not token:
        return False, "no token"
    base = (tg.get("api") or "https://api.telegram.org").rstrip("/")
    url = "%s/bot%s/%s" % (base, token, method)
    try:
        if files:
            bd = uuid.uuid4().hex
            parts = []
            for k, v in (fields or {}).items():
                parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (bd, k, v)).encode())
            for k, (fn, data) in files.items():
                parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                              "Content-Type: application/json\r\n\r\n" % (bd, k, fn)).encode() + data + b"\r\n")
            parts.append(("--%s--\r\n" % bd).encode())
            req = urllib.request.Request(url, b"".join(parts), {"Content-Type": "multipart/form-data; boundary=" + bd})
        else:
            req = urllib.request.Request(url, json.dumps(fields or {}).encode(), {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return True, r.read().decode()[:300]
    except Exception as exc:
        return False, str(exc).replace(token, "***")[:200]


def tg_send(text, event=None):
    tg = load_panel_conf().get("tg", {})
    if not tg.get("token") or not tg.get("chat") or not tg.get("on", True):
        return
    if event and event not in tg.get("events", ["tunnel", "login", "backup"]):
        return
    threading.Thread(target=tg_call, args=("sendMessage", {"chat_id": tg["chat"], "text": text}), daemon=True).start()


def make_backup(full=False):
    """Backup = every tunnel slot file (+ tokens) and, if full, the panel settings."""
    slots = {}
    for n in range(1, MAX_SLOT + 1):
        if os.path.exists(slot_file(n)):
            try:
                with open(slot_file(n)) as fh:
                    slots[str(n)] = fh.read()
            except OSError:
                pass
    data = {"magic": "darkcore-backup", "v": 1, "created": int(time.time()), "host": host_label(),
            "ip": public_ip_guess(), "slots": slots}
    if full:
        data["panel"] = load_panel_conf()
    return data


ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=[^\r\n\x00]*$")


def check_backup(d):
    if not isinstance(d, dict) or d.get("magic") != "darkcore-backup" or not isinstance(d.get("slots"), dict):
        return "not a NiceTunnel backup file"
    for k, v in d["slots"].items():
        if not (k.isdigit() and 1 <= int(k) <= MAX_SLOT) or not isinstance(v, str) or len(v) > 8192:
            return "bad slot entry"
        for line in v.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not ENV_LINE.match(line):
                return "bad line in slot %s" % k
    return None


def save_backup_file(data, keep=10):
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    name = "darkcore-%s-%s.json" % (time.strftime("%Y%m%d-%H%M%S"), "full" if "panel" in data else "tunnels")
    p = os.path.join(BACKUP_DIR, name)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    files = sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith(".json"))
    for old in files[:-keep]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass
    return name


def list_backups():
    out = []
    try:
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith(".json"):
                st = os.stat(os.path.join(BACKUP_DIR, f))
                out.append({"name": f, "size": st.st_size, "time": int(st.st_mtime)})
    except OSError:
        pass
    return out


def restore_backup(d, with_panel=False):
    n_ok = 0
    for k, v in d["slots"].items():
        fd = os.open(slot_file(int(k)), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(v)
        n_ok += 1
    if with_panel and isinstance(d.get("panel"), dict):
        cur = load_panel_conf()
        new = dict(d["panel"])
        new["base"] = cur.get("base", new.get("base", ""))   # keep this server's secret path
        new["otl"] = []
        save_panel_conf(new)
    run(["systemctl", "daemon-reload"])
    for k in d["slots"]:
        run(["systemctl", "enable", "nicetunnel@%s" % k])
        run(["systemctl", "restart", "nicetunnel@%s" % k])
    return n_ok


# --------------------------------------------------------------------------
# network speed tuning (sysctl profiles)
# --------------------------------------------------------------------------
TUNE_FILE = "/etc/sysctl.d/99-nicetunnel.conf"
TUNE_MOD = "/etc/modules-load.d/nicetunnel.conf"
TUNE_PREV = os.path.join(CONF_DIR, "sysctl-prev.json")
_BASE_TUNE = [
    ("net.core.default_qdisc", "fq"),
    ("net.ipv4.tcp_congestion_control", "bbr"),
    ("net.ipv4.tcp_fastopen", "3"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.tcp_slow_start_after_idle", "0"),
    ("net.ipv4.tcp_no_metrics_save", "1"),
]
TUNE_PROFILES = {
    "balanced": _BASE_TUNE + [
        ("net.core.rmem_max", "33554432"), ("net.core.wmem_max", "33554432"),
        ("net.core.rmem_default", "1048576"), ("net.core.wmem_default", "1048576"),
        ("net.ipv4.tcp_rmem", "4096 131072 33554432"), ("net.ipv4.tcp_wmem", "4096 65536 33554432"),
        ("net.core.netdev_max_backlog", "16384"), ("net.core.somaxconn", "4096"),
        ("net.ipv4.tcp_notsent_lowat", "131072"),
    ],
    "turbo": _BASE_TUNE + [
        ("net.core.rmem_max", "67108864"), ("net.core.wmem_max", "67108864"),
        ("net.core.rmem_default", "4194304"), ("net.core.wmem_default", "4194304"),
        ("net.ipv4.tcp_rmem", "4096 262144 67108864"), ("net.ipv4.tcp_wmem", "4096 131072 67108864"),
        ("net.core.netdev_max_backlog", "32768"), ("net.core.somaxconn", "8192"),
        ("net.core.netdev_budget", "600"), ("net.ipv4.tcp_notsent_lowat", "131072"),
        ("net.ipv4.udp_rmem_min", "16384"), ("net.ipv4.udp_wmem_min", "16384"),
        ("net.ipv4.tcp_fin_timeout", "15"),
    ],
}


def sysctl_get(key):
    try:
        with open("/proc/sys/" + key.replace(".", "/")) as f:
            return " ".join(f.read().split())
    except Exception:
        return None


def tune_state():
    try:
        avail = open("/proc/sys/net/ipv4/tcp_available_congestion_control").read().split()
    except Exception:
        avail = []
    profiles = {}
    active = None
    for name, items in TUNE_PROFILES.items():
        rows = []
        for k, v in items:
            cur = sysctl_get(k)
            if cur is None:
                continue
            rows.append({"key": k, "want": v, "cur": cur, "ok": cur == v})
        profiles[name] = rows
        if rows and all(r["ok"] for r in rows):
            active = name
    return {"profiles": profiles, "active": active, "avail": avail, "bbr": "bbr" in avail or os.path.exists("/lib/modules"),
            "saved": os.path.exists(TUNE_FILE), "kernel": os.uname().release}


def tune_apply(name):
    items = TUNE_PROFILES.get(name)
    if not items:
        return False, "unknown profile"
    run(["modprobe", "tcp_bbr"])
    run(["modprobe", "sch_fq"])
    avail = sysctl_get("net.ipv4.tcp_available_congestion_control") or ""
    prev = {}
    if os.path.exists(TUNE_PREV):
        try:
            prev = json.load(open(TUNE_PREV))
        except Exception:
            prev = {}
    lines = ["# NiceTunnel speed profile: " + name]
    applied = 0
    for k, v in items:
        if sysctl_get(k) is None:
            continue
        if k == "net.ipv4.tcp_congestion_control" and "bbr" not in avail.split():
            continue
        prev.setdefault(k, sysctl_get(k))
        rc, _ = run(["sysctl", "-w", "%s=%s" % (k, v)])
        if rc == 0:
            lines.append("%s = %s" % (k, v))
            applied += 1
    try:
        os.makedirs(CONF_DIR, exist_ok=True)
        json.dump(prev, open(TUNE_PREV, "w"))
        os.makedirs(os.path.dirname(TUNE_FILE), exist_ok=True)
        open(TUNE_FILE, "w").write("\n".join(lines) + "\n")
        os.makedirs(os.path.dirname(TUNE_MOD), exist_ok=True)
        open(TUNE_MOD, "w").write("tcp_bbr\nsch_fq\n")
    except Exception as exc:
        return False, str(exc)
    return True, applied


def tune_revert():
    prev = {}
    try:
        prev = json.load(open(TUNE_PREV))
    except Exception:
        pass
    for k, v in prev.items():
        if v is not None:
            run(["sysctl", "-w", "%s=%s" % (k, v)])
    for f in (TUNE_FILE, TUNE_MOD, TUNE_PREV):
        try:
            os.remove(f)
        except OSError:
            pass
    return True


def background_loop():
    last = {}
    first = True
    while True:
        try:
            conf = load_panel_conf()
            cur = {}
            for sl in list_slots():
                cur[sl["slot"]] = sl["state"]
            if not first:
                for n, st in cur.items():
                    old = last.get(n)
                    if old is not None and old != st:
                        up = st == "active"
                        tg_send("%s تانل %d (%s) %s\nسرور: %s\nوضعیت: %s" % (
                            "🟢" if up else "🔴", n, "ریورس" if True else "", "وصل شد" if up else "قطع شد",
                            host_label(), st), "tunnel")
                for n in last:
                    if n not in cur:
                        tg_send("🗑 تانل %d حذف شد (%s)" % (n, host_label()), "tunnel")
                for n in cur:
                    if n not in last:
                        tg_send("➕ تانل %d ساخته شد (%s)" % (n, host_label()), "tunnel")
            last, first = cur, False
            ab = conf.get("autobackup", {})
            if ab.get("on") and time.time() - conf.get("ab_last", 0) >= ab.get("hours", 24) * 3600:
                data = make_backup(full=bool(ab.get("full")))
                name = save_backup_file(data)
                conf = load_panel_conf()
                conf["ab_last"] = int(time.time())
                save_panel_conf(conf)
                tg = conf.get("tg", {})
                if tg.get("token") and tg.get("chat") and "backup" in tg.get("events", ["backup"]):
                    tg_call("sendDocument", {"chat_id": tg["chat"], "caption": "💾 بکاپ خودکار %s" % host_label()},
                            {"document": (name, json.dumps(data).encode())})
        except Exception:
            pass
        time.sleep(15)


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


def route_path(raw):
    """Strips the secret base path; None means 404."""
    base = load_panel_conf().get("base", "")
    if not base:
        return raw
    if raw == base or raw == base + "/":
        return "/"
    if raw.startswith(base + "/api/"):
        return raw[len(base):]
    return None


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
        if n > 1048576:
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
        if not origin:
            return True
        return urlparse(origin).netloc.lower() == self.headers.get("Host", "").lower()

    # -- GET -----------------------------------------------------------------
    def do_GET(self):
        path = route_path(urlparse(self.path).path)
        if path is None:
            return self.send_json({"error": "not found"}, 404)
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
        if path == "/api/devices":
            if not self.require_login():
                return
            me = self.session_id()
            now = time.time()
            out = []
            for sid, exp in list(sessions.items()):
                if exp <= now:
                    continue
                inf = sess_info.get(sid, {})
                out.append({"id": sid[:12], "me": sid == me, "ip": inf.get("ip", "?"), "t": inf.get("t", 0),
                            "how": inf.get("how", "password"), "dev": device_name(inf.get("ua", ""))})
            out.sort(key=lambda x: -x["t"])
            return self.send_json({"devices": out})
        if path == "/api/tg":
            if not self.require_login():
                return
            tg = load_panel_conf().get("tg", {})
            t = tg.get("token", "")
            return self.send_json({"has": bool(t), "masked": (t[:4] + "…" + t[-4:]) if t else "", "chat": tg.get("chat", ""),
                                   "api": tg.get("api", ""), "on": tg.get("on", True),
                                   "events": tg.get("events", ["tunnel", "login", "backup"])})
        if path == "/api/tune":
            if not self.require_login():
                return
            return self.send_json(tune_state())
        if path == "/api/backups":
            if not self.require_login():
                return
            conf = load_panel_conf()
            return self.send_json({"list": list_backups(), "auto": conf.get("autobackup", {"on": False, "hours": 24, "full": False}),
                                   "last": conf.get("ab_last", 0)})
        if path == "/api/backup/get":
            if not self.require_login():
                return
            q = urlparse(self.path).query
            m2 = re.search(r"name=(darkcore-[0-9-]+-(?:full|tunnels)\.json)", q)
            if not m2:
                return self.send_json({"error": "bad name"}, 400)
            try:
                with open(os.path.join(BACKUP_DIR, m2.group(1)), "rb") as fh:
                    data = fh.read()
            except OSError:
                return self.send_json({"error": "not found"}, 404)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
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
        path = route_path(urlparse(self.path).path)
        if path is None:
            return self.send_json({"error": "not found"}, 404)
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
            if pw_problem(pw):
                return self.send_json({"error": pw_problem(pw)}, 400)
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
            how = "password"
            if body.get("link"):
                if otl_use(str(body["link"]).strip()[-80:]):
                    owner, how = "admin", "link"
            elif conf.get("password") and hmac.compare_digest(
                    str(body.get("username", "")), conf.get("username", "admin")) and check_password(pw, conf["password"]):
                owner = "admin"
            if not owner:
                with lock:
                    fails[ip] = [cnt + 1, first]
                time.sleep(1)
                tg_send("⚠️ تلاش ناموفق ورود به پنل %s\nIP: %s" % (host_label(), ip), "login")
                return self.send_json({"error": "wrong username or password" if how == "password" and not body.get("link") else "link is invalid, expired or already used"}, 401)
            sid = secrets.token_hex(32)
            with lock:
                fails.pop(ip, None)
                sessions[sid] = time.time() + SESSION_TTL
                sess_owner[sid] = owner
                sess_info[sid] = {"ip": ip, "ua": self.headers.get("User-Agent", "")[:200], "t": int(time.time()), "how": how}
            tg_send("🔐 ورود به پنل %s\nروش: %s\nIP: %s\nدستگاه: %s" % (
                host_label(), "لینک یکبار مصرف" if how == "link" else "رمز", ip, device_name(self.headers.get("User-Agent", ""))), "login")
            return self.send_json({"ok": True}, headers=[(
                "Set-Cookie", "nt_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d"
                % (sid, SESSION_TTL))])

        if path == "/api/logout":
            sid = self.session_id()
            if sid:
                with lock:
                    sessions.pop(sid, None)
                    sess_owner.pop(sid, None)
                    sess_info.pop(sid, None)
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
                if pw_problem(npw):
                    return self.send_json({"error": pw_problem(npw)}, 400)
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

        if path == "/api/otl/create":
            tok, exp = otl_create()
            return self.send_json({"token": tok, "exp": int(exp)})

        if path == "/api/device/revoke":
            sid = str(body.get("id", ""))
            for s_ in list(sessions):
                if s_[:12] == sid and s_ != self.session_id():
                    with lock:
                        sessions.pop(s_, None)
                        sess_owner.pop(s_, None)
                        sess_info.pop(s_, None)
            return self.send_json({"ok": True})

        if path == "/api/device/revoke-others":
            keep = self.session_id()
            with lock:
                for s_ in list(sessions):
                    if s_ != keep:
                        sessions.pop(s_, None)
                        sess_owner.pop(s_, None)
                        sess_info.pop(s_, None)
            return self.send_json({"ok": True})

        if path == "/api/tg/save":
            conf = load_panel_conf()
            tg = conf.get("tg", {})
            tok = str(body.get("token", "")).strip()
            if tok:
                if not re.fullmatch(r"\d{5,12}:[A-Za-z0-9_-]{30,60}", tok):
                    return self.send_json({"error": "token format is wrong"}, 400)
                tg["token"] = tok
            chat = str(body.get("chat", "")).strip()
            if chat and not re.fullmatch(r"-?\d{3,20}|@[A-Za-z0-9_]{4,40}", chat):
                return self.send_json({"error": "chat id must be a number like 123456789"}, 400)
            tg["chat"] = chat
            api = str(body.get("api", "")).strip()
            if api and not re.fullmatch(r"https?://[A-Za-z0-9.:/_-]{3,100}", api):
                return self.send_json({"error": "bad API address"}, 400)
            tg["api"] = api
            tg["on"] = bool(body.get("on", True))
            ev = [e for e in body.get("events", []) if e in ("tunnel", "login", "backup")]
            tg["events"] = ev
            conf["tg"] = tg
            save_panel_conf(conf)
            return self.send_json({"ok": True})

        if path == "/api/tg/test":
            tg = load_panel_conf().get("tg", {})
            ok, out = tg_call("sendMessage", {"chat_id": tg.get("chat", ""), "text": "✅ NiceTunnel Panel: اتصال تلگرام برقرار است\n" + host_label()})
            return self.send_json({"ok": ok, "detail": out}, 200 if ok else 400)

        if path == "/api/tg/clear":
            conf = load_panel_conf()
            conf.pop("tg", None)
            save_panel_conf(conf)
            return self.send_json({"ok": True})

        if path == "/api/tune/apply":
            if os.geteuid() != 0:
                return self.send_json({"error": "root required"}, 403)
            ok, info = tune_apply(str(body.get("profile", "")))
            return self.send_json({"ok": ok, "detail": info} if ok else {"error": str(info)}, 200 if ok else 400)

        if path == "/api/tune/revert":
            tune_revert()
            return self.send_json({"ok": True})

        if path == "/api/backup/create":
            data = make_backup(full=bool(body.get("full")))
            name = save_backup_file(data)
            tg = load_panel_conf().get("tg", {})
            sent = False
            if body.get("telegram") and tg.get("token") and tg.get("chat"):
                sent, _ = tg_call("sendDocument", {"chat_id": tg["chat"], "caption": "💾 بکاپ %s" % host_label()},
                                  {"document": (name, json.dumps(data).encode())})
            return self.send_json({"ok": True, "name": name, "sent": sent, "slots": len(data["slots"])})

        if path == "/api/backup/auto":
            conf = load_panel_conf()
            try:
                hrs = max(1, min(168, int(body.get("hours", 24))))
            except (TypeError, ValueError):
                hrs = 24
            conf["autobackup"] = {"on": bool(body.get("on")), "hours": hrs, "full": bool(body.get("full"))}
            save_panel_conf(conf)
            return self.send_json({"ok": True})

        if path == "/api/backup/delete":
            name = str(body.get("name", ""))
            if re.fullmatch(r"darkcore-[0-9-]+-(full|tunnels)\.json", name):
                try:
                    os.remove(os.path.join(BACKUP_DIR, name))
                except OSError:
                    pass
            return self.send_json({"ok": True})

        if path == "/api/backup/restore":
            d = body.get("data")
            if d is None:
                name = str(body.get("name", ""))
                if not re.fullmatch(r"darkcore-[0-9-]+-(full|tunnels)\.json", name):
                    return self.send_json({"error": "bad name"}, 400)
                try:
                    with open(os.path.join(BACKUP_DIR, name)) as fh:
                        d = json.load(fh)
                except Exception:
                    return self.send_json({"error": "backup not found"}, 404)
            err = check_backup(d)
            if err:
                return self.send_json({"error": err}, 400)
            if not body.get("overwrite") and any(os.path.exists(slot_file(int(k))) for k in d["slots"]):
                return self.send_json({"error": "exists", "need_confirm": True}, 409)
            n = restore_backup(d, with_panel=bool(body.get("panel")))
            tg_send("♻️ بکاپ روی %s برگردانده شد (%d تانل)" % (host_label(), n), "backup")
            return self.send_json({"ok": True, "restored": n})

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
    pw = getpass.getpass("New panel password (10+ chars, upper+lower, digit, symbol): ")
    if pw_problem(pw):
        sys.exit("error: " + pw_problem(pw))
    if pw != getpass.getpass("Repeat: "):
        sys.exit("error: passwords do not match")
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


def public_ip_detect():
    """Real public IPv4 (works behind NAT too); falls back to the local guess."""
    import urllib.request
    for u in ("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"):
        try:
            ip = urllib.request.urlopen(u, timeout=5).read().decode().strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip
        except Exception:
            pass
    return public_ip_guess()


def make_self_signed(host, cert, key):
    """Creates a self-signed cert valid for the IP/domain (+ local IPs). Installs openssl if missing."""
    if not shutil.which("openssl"):
        subprocess.run("apt-get update -qq && apt-get install -y -qq openssl", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sans = []
    for h in {host, public_ip_guess()}:
        if h and h != "SERVER_IP":
            sans.append(("IP:%s" if re.fullmatch(r"[\d.]+", h) else "DNS:%s") % h)
    sans.append("IP:127.0.0.1")
    os.makedirs(os.path.dirname(cert), exist_ok=True)
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-keyout", key, "-out", cert, "-subj", "/CN=%s" % host,
                        "-addext", "subjectAltName=" + ",".join(sans)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        return False
    os.chmod(key, 0o600)
    return True


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
        print("Set the panel password (10+ chars, upper+lower, digit, symbol):")
        cmd_set_password(args)
    conf = load_panel_conf()
    print("")
    print("How will you open the panel?")
    print("  1) Domain  (free Let's Encrypt HTTPS certificate)")
    print("  2) IP only (self-signed HTTPS, browser shows a warning once)")
    print("  3) Other   (my own certificate files)")
    print("  4) Plain HTTP (no encryption, not recommended)")
    choice = (input("Choose [1-4, default 2]: ").strip() or "2")
    host = public_ip_detect()
    scheme = "https"
    os.makedirs(CONF_DIR, exist_ok=True)
    cert, key = os.path.join(CONF_DIR, "panel.crt"), os.path.join(CONF_DIR, "panel.key")
    if choice == "1":
        host = input("Domain (must point to this server): ").strip()
        email = input("Email for Let's Encrypt (optional): ").strip()
        if not shutil.which("certbot"):
            subprocess.run("apt-get update -qq && apt-get install -y -qq certbot", shell=True)
        cmd = ["certbot", "certonly", "--standalone", "-d", host, "--non-interactive", "--agree-tos"]
        cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
        if subprocess.run(cmd).returncode != 0:
            sys.exit("error: certbot failed. Check DNS and that port 80 is free and open.")
        cert = "/etc/letsencrypt/live/%s/fullchain.pem" % host
        key = "/etc/letsencrypt/live/%s/privkey.pem" % host
        hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
        os.makedirs(hook_dir, exist_ok=True)
        with open(hook_dir + "/nicetunnel-panel.sh", "w") as f:
            f.write("#!/bin/sh\nsystemctl restart nicetunnel-panel\n")
        os.chmod(hook_dir + "/nicetunnel-panel.sh", 0o755)
    elif choice == "3":
        host = input("Domain or IP you will use: ").strip() or host
        cert = input("Path to certificate (fullchain.pem): ").strip()
        key = input("Path to private key: ").strip()
        if not (os.path.isfile(cert) and os.path.isfile(key)):
            sys.exit("error: certificate or key file not found")
    elif choice == "4":
        scheme = "http"
        cert = key = ""
    else:
        if not make_self_signed(host, cert, key):
            sys.exit("error: could not create certificate (apt install openssl)")
    if "base" not in conf:
        conf["base"] = "/k-" + secrets.token_hex(6)
    conf["host"], conf["scheme"] = host, scheme
    save_panel_conf(conf)
    tls_args = (" --cert %s --key %s" % (cert, key)) if scheme == "https" else ""
    unit = (
        "[Unit]\nDescription=NiceTunnel Spoof Panel\nAfter=network-online.target\n"
        "Wants=network-online.target\n\n[Service]\n"
        "ExecStart=%s %s serve --bind 0.0.0.0 --port %d%s\nRestart=always\nRestartSec=3\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    ) % (sys.executable, target, port, tls_args)
    with open(UNIT_PATH, "w") as f:
        f.write(unit)
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "--now", "nicetunnel-panel"])
    subprocess.run(["systemctl", "restart", "nicetunnel-panel"])
    if shutil.which("ufw"):
        subprocess.run(["ufw", "allow", "%d/tcp" % port], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("")
    print("Panel installed.")
    c = load_panel_conf()
    print("  URL:      %s://%s:%d%s/" % (c["scheme"], c["host"], port, c["base"]))
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
    if args.cert and args.key and not (os.path.isfile(args.cert) and os.path.isfile(args.key)):
        h = load_panel_conf().get("host") or public_ip_detect()
        if not make_self_signed(h, args.cert, args.key):
            sys.exit("error: certificate missing and could not be created")
    srv = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    if args.cert and args.key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=background_loop, daemon=True).start()
    print("NiceTunnel panel on %s:%d" % (args.bind, args.port))
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
    s.add_argument("--cert", default="")
    s.add_argument("--key", default="")
    s.set_defaults(func=cmd_serve)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
