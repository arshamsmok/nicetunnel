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
import smtplib
import base64
from email.message import EmailMessage
import concurrent.futures
import http.client
import ssl
import struct
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
from urllib.parse import parse_qs, urlparse

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
    for n in range(1, max_slots() + 1):
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
    for n in range(1, max_slots() + 1):
        if not os.path.exists(slot_file(n)):
            return n
    return None


def valid_slot(n):
    return isinstance(n, int) and 1 <= n <= max_slots() and os.path.exists(slot_file(n))


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
/* v14: settings - tab bar, calmer cards, finer controls */
#p-set .set-wrap{flex-direction:column;gap:14px}
#p-set .set-nav{position:sticky;top:8px;z-index:5;width:100%;flex-direction:row;gap:4px;padding:6px;overflow-x:auto;scrollbar-width:none;border-radius:16px;background:rgba(8,22,40,.92);border:1px solid var(--ln);backdrop-filter:blur(10px);box-shadow:0 8px 24px rgba(0,0,0,.28)}
#p-set .set-nav::-webkit-scrollbar{display:none}
#p-set .set-nav .nav{flex:none;flex-direction:row;gap:7px;padding:8px 14px!important;border-radius:11px!important;font-size:12.5px!important;font-weight:500;white-space:nowrap;color:var(--tx2);border:1px solid transparent!important;background:transparent!important;transition:.18s}
#p-set .set-nav .nav i,#p-set .set-nav .nav i svg{width:15px;height:15px}
#p-set .set-nav .nav:hover{color:var(--tx);background:rgba(255,255,255,.05)!important;padding-inline-start:14px!important}
#p-set .set-nav .nav.on{color:var(--gold2);background:linear-gradient(180deg,rgba(233,196,106,.16),rgba(233,196,106,.06))!important;border-color:rgba(233,196,106,.38)!important;font-weight:600}
#p-set .set-nav .nav.on::after{display:none}
#p-set .set-main{gap:14px}
#p-set .sset{padding:4px 22px 10px;scroll-margin-top:76px}
#p-set .sset h2{font-size:15px!important;font-weight:700;letter-spacing:0;padding:18px 0 14px;margin:0;border-bottom:0!important;display:flex;align-items:center;gap:8px}
#p-set .sset h2::before{content:'';width:3px;height:15px;border-radius:3px;background:var(--gold);flex:none}
#p-set .srow{padding:18px 0;gap:12px 18px;border-top:1px solid rgba(255,255,255,.06)}
#p-set .srow .st b{font-size:13.5px;font-weight:600;margin-bottom:5px;color:var(--tx)}
#p-set .srow .st p{font-size:12px;line-height:1.9;color:var(--tx2);opacity:.85}
#p-set .srow button,#p-set .sbtns button,#p-set .sbtn{min-height:38px;padding:0 18px;border-radius:11px!important;font-size:12.5px;display:inline-flex;align-items:center;justify-content:center;gap:7px;background:rgba(255,255,255,.035)!important;border:1px solid rgba(255,255,255,.14)!important;color:var(--tx)!important;transition:.18s}
#p-set .srow button:hover,#p-set .sbtns button:hover{background:rgba(233,196,106,.08)!important;border-color:rgba(233,196,106,.5)!important;color:var(--gold2)!important}
#p-set .srow button.ok,#p-set .sbtns button.ok{background:linear-gradient(180deg,var(--gold2),var(--gold))!important;color:#1b1303!important;border-color:transparent!important;box-shadow:0 4px 14px rgba(233,196,106,.22)!important}
#p-set .srow button.bad,#p-set .srow button.danger{background:rgba(244,63,94,.1)!important;color:#fda4af!important;border-color:rgba(244,63,94,.4)!important}
#p-set .srow button:disabled{opacity:.5;cursor:default}
#p-set .segm{padding:3px;border-radius:12px;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.1)}
#p-set .segm button{min-height:32px;padding:0 16px;border-radius:9px!important;background:transparent!important;border:0!important;color:var(--tx2)!important;font-size:12.5px}
#p-set .segm button.on{background:linear-gradient(180deg,var(--gold2),var(--gold))!important;color:#1b1303!important;font-weight:700;box-shadow:0 2px 8px rgba(233,196,106,.25)!important}
#p-set .srow input:not([type=checkbox]):not([type=radio]):not([type=file]),#p-set .srow select{height:40px;border-radius:11px!important;font-size:13px;background:rgba(0,0,0,.25)!important;border:1px solid var(--ln)!important;color:var(--tx)}
#p-set .srow input:not([type=checkbox]):focus,#p-set .srow select:focus{border-color:var(--gold)!important;box-shadow:0 0 0 3px rgba(233,196,106,.14)}
#p-set .scode{background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:8px 12px}
#p-set .nkern{unicode-bidi:isolate;direction:ltr;text-align:end;opacity:.7}
@media(max-width:560px){#p-set .sset{padding:2px 16px 8px}#p-set .srow{flex-direction:column;align-items:stretch}#p-set .srow>button,#p-set .srow>.segm{align-self:flex-start}}
/* v15: layout fixes, side flyout, splash, tunnel cards */
#main,.page,.sec,.glass,.row>div{min-width:0}
.sec table{display:block;overflow-x:auto;max-width:100%}
button,.sbtn{max-width:100%}
input,select{max-width:100%}
.seg-bar,#setnav{display:none!important}
.tabs{flex-wrap:nowrap!important;overflow-x:auto;scrollbar-width:none;gap:6px!important;border-bottom:1px solid rgba(255,255,255,.07)!important}
.tabs::-webkit-scrollbar{display:none}
.tab{flex:none;white-space:nowrap;padding:8px 14px!important;font-size:12.5px!important;border-radius:10px!important;border:1px solid transparent!important;background:transparent!important;color:#9fb0c8!important;box-shadow:none!important}
.tab.on{background:rgba(233,196,106,.12)!important;border-color:rgba(233,196,106,.32)!important;color:#f4d58a!important;box-shadow:none!important}
.sset{scroll-margin-top:12px}#p-set .sset{scroll-margin-top:12px}
@media(max-width:560px){#p-set .srow .st,.srow .st{flex:0 0 auto!important;width:100%}#p-set .srow>input,#p-set .srow>select,.srow>input,.srow>select{flex:0 0 auto!important;width:100%!important}}
.tcards{display:flex;flex-direction:column;gap:10px}
.tcard{border:1px solid rgba(233,196,106,.13);border-radius:14px;padding:12px 14px;background:rgba(255,255,255,.02)}
.tch{display:flex;align-items:center;gap:12px}
.tact{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,.06)}
.tact button.sm{height:32px;min-height:0;padding:0 14px;border-radius:9px!important;font-size:12.5px;margin:0}
.fly{position:fixed;z-index:60;min-width:190px;max-width:min(260px,72vw);padding:6px;border-radius:14px;background:rgba(7,16,30,.97);border:1px solid rgba(233,196,106,.22);box-shadow:0 18px 50px rgba(0,0,0,.55);display:none;flex-direction:column;gap:2px;max-height:calc(100vh - 24px);overflow:auto}
.fly.on{display:flex;animation:flyin .16s ease-out}
@keyframes flyin{from{opacity:0;transform:translateX(6px)}to{opacity:1;transform:none}}
.fly .fh{font-size:11px;color:#7f93b2;padding:6px 12px 4px}
html body .fly button{display:flex;align-items:center;gap:10px;width:100%;height:38px;padding:0 12px;border:0!important;border-radius:10px!important;background:transparent!important;color:#cdd7ea;font-size:13px;box-shadow:none!important;transform:none!important;text-align:start;white-space:nowrap}
.fly button svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round;flex:none}
html body .fly button:hover{background:rgba(255,255,255,.06)!important}
html body .fly button.on{background:rgba(233,196,106,.12)!important;color:#f4d58a}
#splash{position:fixed;inset:0;z-index:200;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;background:radial-gradient(60% 40% at 50% 62%,rgba(233,196,106,.14),transparent 70%),linear-gradient(180deg,#040a16,#071426 60%,#0a1a2e);transition:opacity .45s ease,visibility .45s}
#splash.out{opacity:0;visibility:hidden}
#splash .sl{animation:splin .8s cubic-bezier(.2,.8,.2,1) both;filter:drop-shadow(0 0 28px rgba(233,196,106,.45))}
#splash b{font-size:26px;font-weight:700;letter-spacing:.5px;background:linear-gradient(90deg,#fff3c9,#e9c46a);-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent;animation:splin .8s .1s cubic-bezier(.2,.8,.2,1) both}
#splash i{display:block;width:120px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,#34d0c3,transparent);animation:spline 1s ease-in-out infinite}
@keyframes splin{from{opacity:0;transform:scale(.7)}to{opacity:1;transform:none}}
@keyframes spline{0%,100%{opacity:.25;transform:scaleX(.5)}50%{opacity:1;transform:scaleX(1)}}
@media(max-width:560px){
 #top{flex-wrap:wrap!important;gap:8px 10px!important;padding:10px 12px!important}
 #top>div:last-child{flex-wrap:wrap;justify-content:flex-end;min-width:0}
 #host{display:none!important}
 #ttl{font-size:16px!important;margin:0!important}
 .hdr{min-width:0;flex-wrap:wrap}
}
.row{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))!important;gap:12px!important}
.row input,.row select{width:100%!important;box-sizing:border-box}
#p-set .set-wrap{align-items:stretch!important;width:100%}
#p-set .set-main{width:100%;max-width:100%;min-width:0}
#p-set .sset{max-width:100%;overflow:hidden}
.nact{min-width:0}.nkern{max-width:100%;overflow-wrap:anywhere}
input[type=file]{width:100%!important;max-width:100%!important;min-width:0!important;flex:1 1 100%!important}
/* v16: stats chips, details modal, servers, 2FA */
@media(min-width:1100px){.dgrid{grid-template-columns:repeat(3,1fr)}}
.mxs{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.mx{font-size:11px;padding:2px 9px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);color:#b9c6da;direction:ltr;white-space:nowrap}
.mx.good{color:#34d0c3;border-color:rgba(52,208,195,.3)}.mx.warn{color:#e9c46a;border-color:rgba(233,196,106,.35)}.mx.bad{color:#f0707a;border-color:rgba(240,112,122,.4)}
.dmo{position:fixed;inset:0;z-index:120;background:rgba(2,6,14,.72);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px);display:flex;align-items:flex-start;justify-content:center;padding:max(14px,env(safe-area-inset-top)) 12px 18px;overflow:auto}
.dmb{width:100%;max-width:640px;background:linear-gradient(160deg,#0d1d36,#07121f);border:1px solid rgba(233,196,106,.2);border-radius:18px;box-shadow:0 30px 80px rgba(0,0,0,.6);padding:0 0 14px;margin:auto 0;animation:nlin .25s ease-out both}
.dmh{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.06)}
.dmh b{font-size:15px;color:#fff}.dmh .tp{margin-inline-start:10px}
html body button.dmx{width:32px;height:32px;padding:0;border-radius:10px!important;background:transparent!important;border:1px solid rgba(233,196,106,.25)!important;color:#cdd7ea;box-shadow:none!important;transform:none!important}
#dmbody{padding:0 16px}
.dmsec{margin-top:16px}.dmsec h4{display:flex;align-items:center;gap:8px;margin:0 0 8px;font-size:13px;font-weight:600;color:#fff}
.dmsec h4 .lgd{margin-inline-start:auto;font-size:11px;color:#8fa2bf;font-weight:400}.dmsec h4 .lgd i{display:inline-block;width:8px;height:8px;border-radius:50%;margin:0 4px 0 8px}
.dgr{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:14px}
@media(max-width:560px){.dgr{grid-template-columns:repeat(2,1fr)}}
.dcell{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:10px 12px;min-width:0}
.dcell span{display:block;font-size:11px;color:#8fa2bf}.dcell b{display:block;margin-top:4px;font-size:14px;color:#fff;direction:ltr;text-align:start;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dcell small{display:block;margin-top:2px;font-size:11px;color:#8fa2bf;direction:ltr;text-align:start}
.dnote{font-size:12px;color:#8fa2bf;margin:10px 2px 0;line-height:1.7}
.dcv{width:100%;height:96px;display:block;border:1px solid rgba(255,255,255,.05);border-radius:12px;background:#050d18;margin-top:8px}
.evs{max-height:200px;overflow:auto;border:1px solid rgba(255,255,255,.05);border-radius:12px}
.ev{display:flex;align-items:center;gap:10px;padding:9px 12px;font-size:12.5px;color:#cfd8e8;border-bottom:1px solid rgba(255,255,255,.04)}
.ev:last-child{border-bottom:0}.ev span{flex:1;min-width:0}.ev small{color:#6f86a8;direction:ltr;white-space:nowrap}.ev .tb{min-height:16px;align-self:center;height:16px}
#dm details summary{cursor:pointer;font-size:13px;font-weight:600;color:#f4d58a;padding:4px 0}
.efg{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:10px}
.ef label{display:block;font-size:11.5px;color:#8fa2bf;margin-bottom:5px}
html body .ef input,html body .ef select{width:100%;height:38px;padding:0 10px;border-radius:10px!important;background:#06101e!important;border:1px solid rgba(60,100,160,.4)!important;color:#e6ecf6!important;font-size:13px}
.scard{border:1px solid rgba(233,196,106,.13);border-radius:14px;padding:12px 14px;margin:12px 14px;background:rgba(255,255,255,.02)}
.sch{display:flex;align-items:center;gap:12px}
.sdot{width:9px;height:9px;border-radius:50%;background:#6b7a93;flex:none}.sdot.on{background:#34d0c3;box-shadow:0 0 10px #34d0c3aa}.sdot.off{background:#f0707a}
.sgr{display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-top:10px;align-items:center}
@media(max-width:560px){.sgr{grid-template-columns:1fr}}
.sinfo{display:flex;flex-direction:column;gap:6px;font-size:12px;color:#8fa2bf}.sinfo span{display:flex;justify-content:space-between;gap:10px}.sinfo b{color:#e6ecf6;direction:ltr}
.srows{margin-top:10px;border-top:1px solid rgba(255,255,255,.06)}
.srows .tr{flex-wrap:wrap}
a.sm.lnk,a.dlink{display:inline-flex;align-items:center;height:32px;padding:0 14px;border-radius:9px;font-size:12.5px;text-decoration:none;color:#cfd8e8;border:1px solid rgba(233,196,106,.25)}
a.sm.lnk:hover,a.dlink:hover{color:#f4d58a;border-color:rgba(233,196,106,.6)}
.srvform{padding:14px;border-bottom:1px solid rgba(255,255,255,.06)}
.keybox,.tfabox{margin:12px 14px;padding:12px 14px;border:1px dashed rgba(233,196,106,.3);border-radius:12px;background:rgba(233,196,106,.04)}
#p-set .tfabox{margin:10px 0}
.keybox code,.tfabox code{display:block;direction:ltr;word-break:break-all;color:#f4d58a;font-size:13px;margin:6px 0}
.rcodes{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:6px;margin:10px 0}.rcodes code{margin:0;padding:6px 10px;background:#06101e;border-radius:8px;text-align:center;letter-spacing:1px}
.pa{padding:0 14px 14px}.pa p{font-size:12.5px;color:#8fa2bf;line-height:1.8}
.pa .row2{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
html body .pa input{height:38px;padding:0 10px;border-radius:10px!important;background:#06101e!important;border:1px solid rgba(60,100,160,.4)!important;color:#e6ecf6!important;font-size:13px;flex:1;min-width:140px}
/* v17: activity, switches */
.ar{display:flex;flex-wrap:wrap;gap:4px 12px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px;direction:ltr;text-align:left}
.ar b{color:#fff}.ar .t{color:#6f86a8}.ar .e{color:#f0707a}
.chk,.swrow{display:flex;align-items:center;gap:8px;font-size:12.5px;color:#b9c6da;margin-top:10px;line-height:1.7}
html body .chk input,html body .swrow input{width:auto;height:auto;min-width:0;flex:none}
.dmsec h4 .lgd{margin-inline-start:auto;font-size:11px;color:#8fa2bf;font-weight:400}
/* v18: alerts, access, viewer mode */
.alf{display:flex;gap:8px;flex-wrap:wrap;align-items:center;min-width:0;flex:1}
.alf input,.alf select{flex:1 1 130px;min-width:0}
.alevs{display:flex;gap:8px 16px;flex-wrap:wrap}
.alevs label{display:flex;align-items:center;gap:6px;font-size:12.5px;color:#b9c6da}
html body .alevs input,html body .alf .chk input{width:auto;height:auto;min-width:0;flex:none}
.vwr{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:13px}
.viewer .nav[data-p="set"],.viewer .nav[data-p="srv"],.viewer .tact,.viewer .adm,.viewer #lgmode,.viewer .seg-bar,.viewer #p-tun .tabs [data-t="new"],.viewer #p-tun .tabs [data-t="test"],.viewer .dlink[onclick*="srv"],.viewer #fly{display:none!important}
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
FA['Logs']='لاگ'; FA['Servers']='سرورها';
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

function lmode(m){ window._lm=m; if($('#fotp')&&m==='link') $('#fotp').classList.add('hide'); document.querySelectorAll('#lsw button').forEach(b=>{b.classList.toggle('on',b.dataset.m===m);b.onclick=()=>lmode(b.dataset.m);});
  if(!$('#pw')) return; $('#fun').classList.toggle('hide',m==='link'); $('#fpw').classList.toggle('hide',m==='link'); $('#lkbox').classList.toggle('hide',m!=='link');
  if(m==='link'){ const o=new URLSearchParams(location.search).get('otl'); if(o) $('#lk').value=o; } }
function loginView(){ window._sp=true;
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
   <div class="nl-f hide" id="fotp"><label for="otp">${L('Verification code','کد تأیید')}</label><div class="nl-in"><span class="nl-ic">${ICK}</span><input id="otp" dir="ltr" inputmode="numeric" autocomplete="one-time-code" maxlength="14"></div></div>
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
      const body={username:$('#un').value,password:$('#pw').value}; if(!state.needSetup && $('#fotp') && !$('#fotp').classList.contains('hide')) body.otp=$('#otp').value.trim();
      const rr=await apiX(state.needSetup ? '/api/setup' : '/api/login', body);
      if(rr.j.need_otp){ $('#fotp').classList.remove('hide'); $('#otp').focus(); msg(L('Enter the 6-digit code from your authenticator app, or a recovery code.','کد ۶ رقمی برنامه احراز هویت یا یک کد بازیابی را وارد کنید.'),true); return; }
      if(rr.s!==200) throw new Error(rr.j.error||'error');
      await load(); } catch(e){ msg(e.message,false); } };
  $('#pw').onkeydown = e => { if(e.key==='Enter') $('#go').click(); }; if($('#otp')) $('#otp').onkeydown = e => { if(e.key==='Enter') $('#go').click(); };
  $('#pwtog').onclick = () => { const p=$('#pw'); p.type = p.type==='password' ? 'text' : 'password'; p.focus(); };
}
const IC={dash:'<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/></svg>',rev:'<svg viewBox="0 0 24 24"><path d="M4 7h13l-3-3M20 17H7l3 3"/></svg>',spoof:'<svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>',set:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1L7 17M17 7l2.1-2.1"/></svg>',out:'<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',sun:'<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',moon:'<svg viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'};
const ICSH='<svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>',
  ICTG='<svg viewBox="0 0 24 24"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>',
  ICUS='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
  ICBK='<svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>',
  ICAP='<svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.4-.3-.4-.5-.8-.5-1.3 0-1.1.9-2 2-2h2.3A4.7 4.7 0 0 0 22 10.7C22 5.9 17.5 2 12 2z"/><circle cx="7.5" cy="10.5" r="1.2"/><circle cx="12" cy="7" r="1.2"/><circle cx="16.5" cy="10.5" r="1.2"/></svg>';
IC.srv='<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>';
IC.logs='<svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10"/></svg>';
const PAGES = [['dash',IC.dash,'Dashboard'],['srv',IC.srv,'Servers'],['tun',IC.rev,'Tunnels'],['logs',IC.logs,'Logs'],['set',IC.set,'Settings']];
  let tsel = 'rev';
const LOGO = '<svg viewBox="0 0 64 64" width="34" height="34"><defs><linearGradient id="ntg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fde68a"/><stop offset="1" stop-color="#d97706"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="16" fill="#0b1226" stroke="url(#ntg)" stroke-width="2.5"/><path d="M12 52V32a20 20 0 0 1 40 0v20" fill="none" stroke="url(#ntg)" stroke-width="4" stroke-linecap="round"/><path d="M20 52V33a12 12 0 0 1 24 0v19" fill="none" stroke="url(#ntg)" stroke-width="3" stroke-linecap="round" opacity=".7"/><path d="M27 52V34a5 5 0 0 1 10 0v18z" fill="url(#ntg)" opacity=".9"/><path d="M6 52h52" stroke="url(#ntg)" stroke-width="3" stroke-linecap="round"/></svg>';
function shell(){
  const nm = state.username || 'admin';
  $('#app').innerHTML = `<div id="shell"><div id="side" class="glass">
    <div class="brand" style="display:flex;align-items:center;gap:10px;padding:2px 6px 16px">${LOGO}<div><div style="font-size:15px;-webkit-text-fill-color:#fff;background:none;color:#fff">NiceTunnel</div><small style="-webkit-text-fill-color:#9aa6d6">v1.8.0</small></div></div>
    ${PAGES.map(p=>`<div class="nav" data-p="${p[0]}"><i>${p[1]}</i><span>${p[2]}</span></div>`).join('')}
    <div class="sp"></div><div class="nav" id="lo"><i>${IC.out}</i><span>Logout</span></div></div>
  <div id="fly" class="fly"></div><div id="main"><div id="top" class="glass"><div class="hdr">${LOGO}<span class="nm">NiceTunnel</span><span class="vv">v1.8.0</span><h1 id="ttl" style="margin:0 0 0 6px"></h1></div>
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
      <div><label>${L("Create on","ساخت روی")}</label><select id="rpair"><option value="">${L("This server only","فقط این سرور")}</option></select></div>
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
      <div><label>${L("Create on","ساخت روی")}</label><select id="spair"><option value="">${L("This server only","فقط این سرور")}</option></select></div>
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
  <div class="page" id="p-srv">
    <div class="dpanel"><div class="dph"><div><h3>${L("Servers","سرورها")}</h3><p>${L("Other NiceTunnel panels you manage from here.","پنل‌های دیگر نایس‌تانل که از اینجا مدیریت می‌کنید.")}</p></div><button class="dlink" id="srvadd">+ ${L("Add server","افزودن سرور")}</button></div>
      <div id="srvform" class="srvform hide"><div class="efg"><div class="ef"><label>${L("Name","نام")}</label><input id="srvname" placeholder="Frankfurt"></div><div class="ef"><label>${L("Panel address","آدرس پنل")}</label><input id="srvurl" dir="ltr" placeholder="https://1.2.3.4:45152/k-abc123"></div><div class="ef"><label>${L("API key","کلید API")}</label><input id="srvkey" dir="ltr" placeholder="nt_..." autocomplete="off"></div></div><div class="nact"><button class="ok" id="srvsave">${L("Connect","اتصال")}</button> <span id="srvmsg" class="dnote"></span></div><p class="dnote">${L("Create the key on the other panel under Servers → Connect this server.","کلید را روی پنل مقابل در بخش سرورها ← «اتصال این سرور» بسازید.")}</p></div>
      <div id="srvlist"></div></div>
    <div class="dpanel"><div class="dph"><div><h3>${L("Connect this server","اتصال این سرور")}</h3><p>${L("Let another NiceTunnel panel see and manage this server. The key allows stats, start/stop/restart and logs only.","به پنل دیگری اجازه دهید این سرور را ببیند و مدیریت کند. کلید فقط آمار، شروع/توقف/ری‌استارت و لاگ را اجازه می‌دهد.")}</p></div></div>
      <div class="pa"><p>${L("This panel's address:","آدرس این پنل:")}</p><code class="scode" id="srvaddr" style="direction:ltr;display:block;word-break:break-all"></code><div class="row2"><button class="sm" id="srvaddrcopy">${L("Copy","کپی")}</button></div>
        <div class="row2" style="margin-top:16px"><input id="keyname" placeholder="${L("Key name (e.g. main panel)","نام کلید (مثلاً پنل اصلی)")}"><button class="ok" id="keymake">${L("Create key","ساخت کلید")}</button></div>
        <div class="row2" style="margin-top:8px"><input id="keyips" dir="ltr" placeholder="${L("Allowed addresses (optional), e.g. 1.2.3.4","آدرس‌های مجاز (اختیاری)، مثلاً 1.2.3.4")}"></div>
        <label class="chk"><input type="checkbox" id="keyfull"> ${L("Allow creating and deleting tunnels (needed for one-click pairs). Only for a panel you fully trust.","اجازه ساخت و حذف تانل (برای ساخت یک‌کلیکی روی دو سرور). فقط برای پنلی که کاملاً به آن اعتماد دارید.")}</label>
        <div id="keynew" class="keybox hide"><p class="dnote" style="margin-top:0">${L("Copy this key now. It will not be shown again.","این کلید را همین حالا کپی کنید. دیگر نمایش داده نمی‌شود.")}</p><code id="keynewv"></code><button class="sm" id="keycopy">${L("Copy key","کپی کلید")}</button></div></div>
      <div id="keylist"></div></div>
  </div>
  <div class="page" id="p-logs">
    <div class="dpanel"><div class="dph"><div><h3>${L("Logs","لاگ‌ها")}</h3><p>${L("Live service logs of your tunnels, refreshed every few seconds.","لاگ زندهٔ سرویس تونل‌ها، هر چند ثانیه به‌روز می‌شود.")}</p></div><button class="dlink" id="lgcopy">${L("Copy","کپی")}</button></div>
    <div class="lgbar"><div class="lgseg" id="lgmode"><button data-m="svc" class="on">${L("Tunnel logs","لاگ تانل‌ها")}</button><button data-m="aud">${L("Activity","فعالیت‌ها")}</button></div><select id="lgsel"></select><input id="lgq" placeholder="${L("Filter…","فیلتر…")}"><div class="lgseg" id="lgl"><button data-l="all" class="on">${L("All","همه")}</button><button data-l="w">${L("Warnings","هشدار")}</button><button data-l="e">${L("Errors","خطا")}</button></div></div>
    <div class="lg" id="lgbox"></div></div>
  </div>
  <div class="page" id="p-set">
    <div class="set-wrap">
    <div class="set-nav" id="setnav">
      <div class="nav" data-anchor="sec-sec"><i>${ICSH}</i><span>${L('Security','امنیت')}</span></div>
      <div class="nav" data-anchor="sec-up"><i>${IC.set}</i><span>${L('About & update','درباره و به‌روزرسانی')}</span></div>
      <div class="nav" data-anchor="sec-net"><i><svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg></i><span>${L('Network & speed','شبکه و سرعت')}</span></div>
      <div class="nav" data-anchor="sec-tg"><i>${ICTG}</i><span>${L('Telegram','تلگرام')}</span></div>
      <div class="nav" data-anchor="sec-time"><i>${ICUS}</i><span>${L('Date & time','تاریخ و ساعت')}</span></div>
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
    <div class="sec glass sset" id="sec-2fa"><h2>${L('Two-factor login','ورود دو مرحله‌ای')}</h2>
      <div class="srow"><div class="st"><b>${L('Authenticator app (TOTP)','برنامه احراز هویت (TOTP)')}</b><p id="tfastate"></p></div><div><button class="ok" id="tfaon">${L('Enable','فعال‌سازی')}</button><button id="tfaoff" class="hide">${L('Disable','غیرفعال‌سازی')}</button></div></div>
      <div id="tfasetup" class="tfabox hide"><p class="dnote" style="margin-top:0">1. ${L('Add an account in Google Authenticator, Authy or any TOTP app using this key:','در Google Authenticator یا Authy یا هر برنامه TOTP با این کلید حساب اضافه کنید:')}</p><code id="tfakey"></code><div class="row2" style="display:flex;gap:8px;flex-wrap:wrap"><button class="sm" id="tfacopy">${L('Copy key','کپی کلید')}</button><a class="sm lnk" id="tfauri" href="#">${L('Open in authenticator app','باز کردن در برنامه')}</a></div><p class="dnote">2. ${L('Enter the 6-digit code it shows:','کد ۶ رقمی نمایش‌داده‌شده را وارد کنید:')}</p><div class="efg"><div class="ef"><input id="tfacode" inputmode="numeric" maxlength="6" dir="ltr" autocomplete="one-time-code"></div></div><div class="nact"><button class="ok" id="tfaconfirm">${L('Confirm & enable','تأیید و فعال‌سازی')}</button></div></div>
      <div id="tfacodes" class="tfabox hide"></div>
      <div id="tfadis" class="tfabox hide"><p class="dnote" style="margin-top:0">${L('Enter your password and a current code (or a recovery code) to turn it off.','برای خاموش کردن، رمز و یک کد فعلی (یا کد بازیابی) را وارد کنید.')}</p><div class="efg"><div class="ef"><label>${L('Password','رمز')}</label><input id="tfadpw" type="password"></div><div class="ef"><label>${L('Code','کد')}</label><input id="tfadcode" dir="ltr" maxlength="14"></div></div><div class="nact"><button class="ok" id="tfadisgo">${L('Turn off','خاموش کردن')}</button></div></div>
    </div>
    <div class="sec glass sset" id="sec-up"><h2>${L('About & update','درباره و به‌روزرسانی')}</h2>
      <div class="srow"><div class="st"><b>${L('Installed','نصب‌شده')}</b><p>NiceTunnel Panel</p></div><code class="scode">v1.8.0</code></div>
      <div class="srow"><div class="st"><b>${L('Panel address','آدرس پنل')}</b><p>${L('Secret path of this panel. Keep it private.','مسیر مخفی این پنل. آن را محرمانه نگه دارید.')}</p></div><code id="sinfo" class="scode"></code></div>
      <div class="srow"><div class="st"><b>${L('Creator','سازنده')}</b><p>Arsham Smok · آرشام اسموک</p></div></div>
      <div class="srow"><div class="st"><b>${L('Updates','به‌روزرسانی')}</b><p id="updst">${L('Check if a newer version is available.','بررسی کنید نسخه جدیدتری هست یا نه.')}</p></div><div><button id="updchk">${L('Check for updates','بررسی به‌روزرسانی')}</button> <button class="ok hide" id="updgo">${L('Update now','به‌روزرسانی')}</button></div></div>
    </div>
    <div class="sec glass sset" id="sec-net"><h2>${L('Network & speed','شبکه و سرعت')} <span class="nbadge" id="nbadge"></span></h2>
      <p class="nhint">${L('Tunes the Linux network stack (BBR, fq, big buffers) for faster, steadier transfers on long or lossy routes. Reversible at any time.','پشته‌ی شبکه‌ی لینوکس (BBR، fq، بافرهای بزرگ) را برای انتقال سریع‌تر و پایدارتر روی مسیرهای دور یا پرافت تنظیم می‌کند. هر لحظه قابل برگشت است.')}</p>
      <div class="nprof" id="nprof"></div>
      <div class="ntable" id="ntable"></div>
      <div class="nact"><button class="ok" id="napply">${L('Apply profile','اعمال پروفایل')}</button> <button id="nrevert">${L('Restore defaults','بازگشت به پیش‌فرض')}</button> <span class="nkern" id="nkern"></span></div>
    </div>
    <div class="sec glass sset" id="sec-dom"><h2>${L('Domain & SSL','دامنه و SSL')}</h2>
      <p class="nhint" id="domcur"></p>
      <div class="srow"><div class="st"><b>${L('Domain','دامنه')}</b><p>${L('Add an A record pointing to this server first. Port 80 must be free when issuing and renewing.','ابتدا یک A رکورد به IP همین سرور بسازید. پورت ۸۰ هنگام دریافت و تمدید گواهی باید آزاد باشد.')}</p></div><input id="domname" dir="ltr" placeholder="panel.example.com" autocomplete="off"></div>
      <div class="srow"><div class="st"><b>${L('Email','ایمیل')}</b><p>${L('Optional, for certificate expiry notices.','اختیاری، برای اطلاع از انقضای گواهی.')}</p></div><input id="domemail" dir="ltr" placeholder="you@example.com" autocomplete="off"></div>
      <div class="nact"><button class="ok" id="domgo">${L('Get SSL & switch','دریافت SSL و فعال‌سازی')}</button></div>
    </div>
    <div class="sec glass sset" id="sec-tg"><h2>${L('Telegram bot','ربات تلگرام')}</h2>
      <div class="srow"><div class="st"><b>${L('Bot token','توکن ربات')}</b><p id="tgcur">${L('Get it from @BotFather.','از @BotFather بگیرید.')}</p></div><input id="tgtok" dir="ltr" placeholder="123456:ABC..." autocomplete="off"></div>
      <div class="srow"><div class="st"><b>Chat ID</b><p>${L('Your numeric ID (from @userinfobot) or a group ID.','آیدی عددی شما (از @userinfobot) یا گروه.')}</p></div><input id="tgchat" dir="ltr"></div>
      <div class="srow"><div class="st"><b>${L('API address (optional)','آدرس API (اختیاری)')}</b><p>${L('Mirror/proxy for Telegram if blocked. Default: api.telegram.org','اگر تلگرام فیلتر است، آدرس پروکسی/میرور. پیش‌فرض: api.telegram.org')}</p></div><input id="tgapi" dir="ltr" placeholder="https://api.telegram.org"></div>
      <div class="srow"><div class="st"><b>${L('Proxy (optional)','پراکسی (اختیاری)')}</b><p>${L('If Telegram is blocked on this server: socks5://host:1080 or http://host:8080 (add user:pass@ if needed).','اگر تلگرام روی این سرور فیلتر است: socks5://host:1080 یا http://host:8080 (در صورت نیاز user:pass@ را اضافه کنید).')}</p></div><input id="tgproxy" dir="ltr" placeholder="socks5://host:1080" autocomplete="off"></div>
      <div class="srow"><div></div><div><button class="ok" id="tgsave">${L('Save','ذخیره')}</button> <button id="tgtest">${L('Send test','ارسال تست')}</button> <button id="tgdel">${L('Remove','حذف')}</button></div></div>
    </div>
    <div class="sec glass sset" id="sec-alerts"><h2>${L('Alerts','هشدارها')}</h2>
      <div class="srow"><div class="st"><b>${L('Notify about','اعلان برای')}</b><p>${L('Applies to Telegram, webhook and email.','برای تلگرام، وب‌هوک و ایمیل.')}</p></div><div class="alevs" id="alevs"></div></div>
      <div class="srow"><div class="st"><b>${L('Alert threshold','حد هشدار')}</b><p>${L('CPU, RAM and disk usage in percent.','مصرف CPU، رم و دیسک به درصد.')}</p></div><input id="alth" type="number" min="50" max="99" value="90"></div>
      <div class="srow"><div class="st"><b>Webhook</b><p>${L('Discord, Slack, or any address that accepts JSON.','دیسکورد، اسلک یا هر آدرسی که JSON می‌پذیرد.')}</p></div><div class="alf"><input id="whurl" dir="ltr" placeholder="https://..."><select id="whfmt"><option value="generic">JSON</option><option value="discord">Discord</option><option value="slack">Slack</option></select><label class="chk" style="margin:0"><input type="checkbox" id="whon"> ${L('On','فعال')}</label><button id="whtest">${L('Send test','ارسال تست')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Email','ایمیل')}</b><p>${L('Any SMTP server. Port 587 with STARTTLS or 465 with SSL.','هر سرور SMTP. پورت ۵۸۷ با STARTTLS یا ۴۶۵ با SSL.')}</p></div><div class="alf"><input id="emhost" dir="ltr" placeholder="smtp.example.com"><input id="emport" type="number" placeholder="587" style="max-width:90px"><select id="emsec"><option value="starttls">STARTTLS</option><option value="ssl">SSL</option><option value="none">${L('None','بدون')}</option></select><input id="emuser" dir="ltr" placeholder="${L('user','کاربر')}" autocomplete="off"><input id="empass" type="password" placeholder="${L('password','رمز')}" autocomplete="new-password"><input id="emfrom" dir="ltr" placeholder="from@example.com"><input id="emto" dir="ltr" placeholder="you@example.com"><label class="chk" style="margin:0"><input type="checkbox" id="emon"> ${L('On','فعال')}</label><button id="emtest">${L('Send test','ارسال تست')}</button></div></div>
      <div class="srow"><div></div><div><button class="ok" id="alsave">${L('Save','ذخیره')}</button> <span id="almsg" class="dnote"></span></div></div>
    </div>
    <div class="sec glass sset" id="sec-access"><h2>${L('Access','دسترسی')}</h2>
      <div class="srow"><div class="st"><b>${L('Allowed IP addresses','آی‌پی‌های مجاز')}</b><p>${L('Only these addresses can open the panel. Leave empty to allow everyone. Your address: ','فقط این آدرس‌ها می‌توانند پنل را باز کنند. خالی = همه. آدرس شما: ')}<code id="myip"></code></p></div><div class="alf"><input id="allowips" dir="ltr" placeholder="1.2.3.4, 10.0.0.0/8, fd00::/8"><button class="ok" id="allowsave">${L('Save','ذخیره')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Viewer accounts','حساب‌های بیننده')}</b><p>${L('See everything, change nothing. Good for teammates and checking from a phone.','همه‌چیز را می‌بینند ولی چیزی را تغییر نمی‌دهند. مناسب همکار یا مشاهده با گوشی.')}</p></div><div class="alf"><input id="vwname" placeholder="${L('name','نام')}" autocomplete="off"><input id="vwpass" type="password" placeholder="${L('password (8+)','رمز (حداقل ۸)')}" autocomplete="new-password"><button class="ok" id="vwadd">${L('Add','افزودن')}</button></div></div>
      <div id="vwlist"></div>
    </div>
    <div class="sec glass sset" id="sec-adv"><h2>${L('Advanced','پیشرفته')}</h2>
      <div class="srow"><div class="st"><b>${L('Tunnels on this server','تعداد تانل‌های این سرور')}</b><p>${L('Highest number of tunnels (1 to 100). Make sure the core supports it.','حداکثر تعداد تانل (۱ تا ۱۰۰). مطمئن شوید هسته آن را پشتیبانی می‌کند.')}</p></div><div class="alf"><input id="advmax" type="number" min="1" max="100" style="max-width:110px"><button class="ok" id="advsave">${L('Save','ذخیره')}</button></div></div>
      <div class="srow"><div class="st"><b>Prometheus</b><p>${L('Metrics for Grafana. Use an API key as the Bearer token.','آمار برای گرافانا. کلید API را به‌عنوان توکن Bearer بگذارید.')}</p></div><code class="scode" id="metricsurl" style="direction:ltr;word-break:break-all"></code></div>
      <div class="srow"><div class="st"><b>${L('Speed caps','سقف سرعت')}</b><p id="nftst"></p></div></div>
    </div>
    <div class="sec glass sset" id="sec-time"><h2>${L('Date & time','تاریخ و ساعت')}</h2>
      <div class="srow"><div class="st"><b>${L('Now','اکنون')}</b></div><code class="scode" id="clock"></code></div>
      <div class="srow"><div class="st"><b>${L('Calendar','تقویم')}</b></div><div class="segm" id="sgcal"><button data-v="persian">${L('Jalali','شمسی')}</button><button data-v="gregory">${L('Gregorian','میلادی')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Time zone','منطقه زمانی')}</b></div><select id="stz">${TZS.map(z=>`<option value="${z[0]}">${z[1]}</option>`).join('')}</select></div>
    </div>
    <div class="sec glass sset" id="sec-backup"><h2>${L('Backup & restore','پشتیبان و بازیابی')}</h2>
      <div class="srow"><div class="st"><b>${L('Create backup now','بکاپ فوری')}</b><p>${L('Saves all tunnels. Include panel settings (password, Telegram) for a full copy. Sent to Telegram too, so you still have it if this server dies.','همه تونل‌ها ذخیره می‌شود. «کامل» شامل تنظیمات پنل (رمز، تلگرام) هم هست. به تلگرام هم ارسال می‌شود تا با از دست رفتن سرور، بکاپ را داشته باشید.')}</p></div><div><label><input type="checkbox" id="bkfull"> ${L('Full','کامل')}</label> <label><input type="checkbox" id="bktg" checked> Telegram</label> <button class="ok" id="bknow">${L('Backup','بکاپ')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Automatic backup','بکاپ خودکار')}</b><p>${L('Keeps the last 10 copies.','۱۰ نسخه آخر نگه داشته می‌شود.')}</p></div><div><label><input type="checkbox" id="abon"> ${L('On','فعال')}</label> ${L('every','هر')} <input id="abh" type="number" min="1" max="168" style="width:70px"> ${L('hours','ساعت')} <label><input type="checkbox" id="abfull"> ${L('Full','کامل')}</label> <button id="absave">${L('Save','ذخیره')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Restore from file','بازیابی از فایل')}</b><p>${L('On a new server: install the panel, upload the backup file here. Tunnels are rebuilt and started. Then update the OTHER server of each tunnel with this server\'s new IP.','روی سرور جدید: پنل را نصب کنید و فایل بکاپ را اینجا آپلود کنید. تونل‌ها ساخته و اجرا می‌شوند. سپس در سرور مقابل هر تونل، آی‌پی جدید این سرور را جایگزین کنید.')}</p></div><div><input type="file" id="bkfile" accept=".json"> <label><input type="checkbox" id="bkpanel"> ${L('Also panel settings','تنظیمات پنل هم')}</label> <button class="ok" id="bkrest">${L('Restore','بازیابی')}</button></div></div>
      <div class="srow"><div class="st"><b>${L('Backup passphrase','رمز بکاپ')}</b><p id="bkpst"></p></div><div style="display:flex;gap:8px;flex-wrap:wrap"><input id="bkpass" type="password" autocomplete="new-password" placeholder="${L('8+ characters','حداقل ۸ کاراکتر')}"><button class="ok" id="bkpsave">${L('Save','ذخیره')}</button><button id="bkpclear" class="hide">${L('Turn off','خاموش')}</button></div></div>
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
  document.querySelectorAll('.nav[data-p]').forEach(e=>e.onclick=()=>navClick(e));
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
  netTune(); domainSet();
  $('#tmode').onchange = tmodeView; $('#tstart').onclick = tstart; $('#tref').onclick = tstatus;
  if(lang==='fa') tr($('#app'));
}

async function domainSet(){
  let D; try{ D=await api('/api/domain'); }catch(e){ return; }
  const cur=$('#domcur');
  cur.textContent=L('Server IP','آی‌پی سرور')+': '+D.ip+' — '+L('open as','آدرس فعلی')+': '+D.scheme+'://'+D.host;
  cur.style.direction='ltr'; cur.style.unicodeBidi='isolate';
  $('#domgo').onclick=async()=>{
    const d=$('#domname').value.trim(); if(!d) return msg(L('Enter a domain','دامنه را وارد کنید'));
    $('#domgo').disabled=true; msg(L('Requesting certificate, please wait…','در حال دریافت گواهی، کمی صبر کنید…'),true);
    try{ const r=await api('/api/domain/apply',{domain:d,email:$('#domemail').value.trim()});
      msg(L('Done. The panel restarts; open: ','انجام شد. پنل ری‌استارت می‌شود؛ آدرس جدید: ')+r.url,true);
      setTimeout(()=>{ location.href=r.url; },4000);
    }catch(e){ msg(e.message||String(e)); }
    $('#domgo').disabled=false;
  };
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
  page = p; if(p!=='tun'&&p!=='set') closeFly(); if(p==='set') tfaExtras(); if(p==='srv') srvInit();
  document.querySelectorAll('.tsec').forEach(e=>e.classList.toggle('on', e.id==='t-'+tsel));
  document.querySelectorAll('.seg').forEach(e=>e.classList.toggle('on', e.dataset.s===tsel));
  document.querySelectorAll('.page').forEach(e=>e.classList.toggle('on', e.id==='p-'+p));
  document.querySelectorAll('.nav[data-p]').forEach(e=>e.classList.toggle('on', e.dataset.p===p));
  $('#ttl').textContent = (p==='tun' ? L('Tunnels','تونل‌ها')+' · '+(tsel==='rev'?L('Reverse','معکوس'):L('Spoof','اسپوف')) : PAGES.filter(x=>x[0]===p)[0][2]);
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
/* ===== v6 frontend ===== */
async function apiX(path, body){ const r=await fetch(BASE+path,{method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)}); let j={}; try{ j=await r.json(); }catch(e){} return {s:r.status,j}; }
const rateTxt=b=>b==null?'—':fmtR(b).join(' ');
const ago=t=>{ if(!t) return '—'; const d=Math.max(0,Math.floor(Date.now()/1000-t)); if(d<60) return L('just now','هم‌اکنون'); if(d<3600) return Math.floor(d/60)+' '+L('min ago','دقیقه پیش'); if(d<86400) return Math.floor(d/3600)+' '+L('h ago','ساعت پیش'); return Math.floor(d/86400)+' '+L('d ago','روز پیش'); };
const ICA='<svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg>', ICT2='<svg viewBox="0 0 24 24"><path d="M3 19V11a9 9 0 0 1 18 0v8M7 19v-8a5 5 0 0 1 10 0v8"/></svg>', ICS2='<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>', ICC2='<svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/></svg>', ICX2='<svg viewBox="0 0 24 24"><path d="M4 8h14m0 0l-3-3m3 3l-3 3M20 16H6m0 0l3-3m-3 3l3 3"/></svg>', ICL2='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>';
function fmtR(b){ const x=(+b||0)*8; if(x>=1e9) return [(x/1e9).toFixed(2),'Gbps']; if(x>=1e6) return [(x/1e6).toFixed(x>=1e8?0:1),'Mbps']; if(x>=1e3) return [(x/1e3).toFixed(0),'Kbps']; return [Math.round(x),'bps']; }
function peerOf(s){ return s.peer_ip || (s.kind==='reverse' ? (s.server_ip||s.target_host) : s.peer) || 'remote'; }
function stCls(s){ return s==='active'?'active':s==='failed'?'failed':'off'; }
function stTxt(s){ return s==='active'?L('Flowing','جاری'):s==='failed'?L('Broken','قطع'):(s==='inactive'||s==='unknown')?L('Stopped','خاموش'):esc(s); }
function slotProto(s){ return s.kind==='reverse' ? 'tcp:'+(s.bridge||'') : (s.transport||'spoof')+':'+(s.port||''); }
function slotDetail(s){
  if(s.kind==='reverse') return 'reverse '+slotProto(s)+' · '+(s.role==='server' ? 'listen '+(s.ports||'-') : 'forward '+(s.target_host||'-'));
  return 'spoof '+slotProto(s)+' · '+(s.role==='server' ? 'UDP '+(s.listen_port||'-') : '→ '+(s.forward||'-'))+(s.spoof_ips?' · src '+s.spoof_ips:'');
}
const latCls=s=>s.lat==null?'':(s.loss>=20||s.lat>300)?'bad':(s.lat>150?'warn':'good');
function mxChips(s){
  return (s.rx_rate!=null?`<span class="mx">↓ ${rateTxt(s.rx_rate)}</span><span class="mx">↑ ${rateTxt(s.tx_rate)}</span>`:'')
   +(s.conns!=null&&s.acct?`<span class="mx">⇄ ${s.conns}</span>`:'')
   +(s.lat!=null?`<span class="mx ${latCls(s)}">⏱ ${s.lat.toFixed(0)} ms${s.loss>0?' · '+s.loss.toFixed(0)+'% '+L('loss','افت'):''}</span>`:'')
   +(s.up24!=null?`<span class="mx">▲ ${s.up24}%</span>`:'')+limChips(s);
}
/* ---- network nodes: this server, other panels, peers ---- */
function fleetNodes(st, slots){
  const fl=window._fleet||[], nodes=[{key:'local',name:st.hostname||L('this server','همین سرور'),ip:st.ip||'',kind:'local',ok:true}], tuns=[], seen=new Set();
  fl.forEach(f=>nodes.push({key:'srv:'+f.id,name:f.name,ip:(f.stats&&f.stats.ip)||'',kind:'remote',ok:f.ok,f}));
  const peer=ip=>{ let n=ip&&ip!=='remote'?nodes.find(x=>x.ip&&x.ip===ip):nodes.find(x=>x.key==='ip:?'); if(!n){ n={key:'ip:'+(ip||'?'),name:ip&&ip!=='remote'?ip:L('unknown','نامشخص'),ip:ip==='remote'?'':ip,kind:'peer',ok:null}; nodes.push(n); } return n; };
  slots.forEach(s=>{ const b=peer(peerOf(s)); tuns.push({a:nodes[0],b,s,own:L('this server','همین سرور')}); seen.add([nodes[0].key,b.key].sort().join('|')+':'+(s.port||s.bridge)); });
  fl.forEach(f=>{ const a=nodes.find(x=>x.key==='srv:'+f.id); (f.slots||[]).forEach(s=>{ const ip=peerOf(s); if(!ip||ip==='remote'||ip===nodes[0].ip) return; const b=peer(ip), k=[a.key,b.key].sort().join('|')+':'+(s.port||s.bridge); if(seen.has(k)) return; seen.add(k); tuns.push({a,b,s,own:f.name,remote:f.id}); }); });
  return {nodes,tuns};
}
let _dsig='';
function dashRender(st, slots){
  if(!$('#dstats')) return;
  const fl=window._fleet||[], act=slots.filter(s=>s.state==='active'), bad=slots.filter(s=>s.state==='failed').length, off=slots.length-act.length-bad;
  const rAll=slots.concat(...fl.map(f=>f.slots||[])), rAct=rAll.filter(s=>s.state==='active').length, rBad=rAll.filter(s=>s.state==='failed').length, rOff=rAll.length-rAct-rBad;
  const conns=rAll.reduce((a,s)=>a+(s.conns||0),0), lats=slots.filter(s=>s.lat!=null), avg=lats.length?lats.reduce((a,s)=>a+s.lat,0)/lats.length:null, worst=lats.length?Math.max(...lats.map(s=>s.lat)):null;
  const online=1+fl.filter(f=>f.ok).length, total=1+fl.length;
  const R=fmtR((st.rx_rate||0)+(st.tx_rate||0)), seg=(n,c)=>n?`<i style="flex:${n};background:${c}"></i>`:'';
  const mini=(k,p)=>`<div class="dm"><span>${k}</span><em><b style="width:${Math.max(0,Math.min(100,p||0))}%"></b></em><span>${(p||0).toFixed(0)}%</span></div>`;
  $('#dstats').innerHTML=`
   <div class="dc"><div class="dk">${ICA}${L('Throughput now','ترافیک همین حالا')}</div><div class="dv">${R[0]}<small>${R[1]}</small></div><canvas id="cth"></canvas><div class="ds"><bdi dir="ltr">↓ ${fmtB(st.rx_rate)}/s · ↑ ${fmtB(st.tx_rate)}/s</bdi></div></div>
   <div class="dc"><div class="dk">${ICT2}${L('Tunnels flowing','تونل‌های جاری')}</div><div class="dv">${rAct}<small>${L('of','از')} ${rAll.length}</small></div><div class="dseg">${seg(rAct,'#34d0c3')}${seg(rBad,'#f0707a')}${seg(rOff,'#6b7a93')}${rAll.length?'':'<i style="flex:1;background:#1d2e4a"></i>'}</div><div class="ds">${rBad?`<span class="bd">${rBad} ${L('broken','قطع')}</span>`:(rAll.length?L('All healthy','همه سالم'):L('No tunnel yet','هنوز تونلی نیست'))}</div></div>
   <div class="dc"><div class="dk">${ICX2}${L('Open connections','اتصال‌های باز')}</div><div class="dv">${conns}</div><div class="ds">${L('across','در')} ${rAct} ${L('flowing tunnels','تونل جاری')}</div></div>
   <div class="dc"><div class="dk">${ICL2}${L('Latency to peers','تأخیر تا سرورهای مقصد')}</div><div class="dv">${avg==null?'—':avg.toFixed(0)}<small>ms</small></div><div class="ds">${worst==null?L('no ping data yet','هنوز داده‌ای نیست'):L('worst','بدترین')+' '+worst.toFixed(0)+' ms'}</div></div>
   <div class="dc"><div class="dk">${ICS2}${L('Servers online','سرورهای آنلاین')}</div><div class="dv">${online}<small>${L('of','از')} ${total}</small></div><div class="dseg">${seg(online,'#34d0c3')}${seg(total-online,'#f0707a')}</div><div class="ds">${fl.filter(f=>!f.ok).map(f=>esc(f.name)).join(', ')||L('all reachable','همه در دسترس')}</div></div>
   <div class="dc"><div class="dk">${ICC2}${L('This server','این سرور')}</div>${mini('CPU',st.cpu)}${mini('RAM',st.mem_pct)}${mini('Disk',st.disk_pct)}<div class="ds">${L('Uptime','آپتایم')} ${fmtUp(st.uptime)}</div></div>`;
  spark('#cth', hist.rx.map((v,i)=>v+(hist.tx[i]||0)), '#34d0c3');
  const W=[], go2=s=>s.kind==='reverse'?'rev':'spoof', nm=(o)=>o?esc(o)+' · ':'';
  const addW=(cls,ico,txt,btn)=>W.push(`<div class="wr"><i class="${cls}">${ico}</i><span>${txt}</span>${btn||''}</div>`);
  fl.filter(f=>!f.ok).forEach(f=>addW('', '!', `${L('Server','سرور')} ${esc(f.name)} ${L('is offline','آفلاین است')}${f.err?' · '+esc(f.err).slice(0,60):''}`, `<button class="dlink" onclick="go('srv')">${L('Servers','سرورها')}</button>`));
  slots.concat(...fl.map(f=>(f.slots||[]).map(s=>Object.assign({_o:f.name},s)))).forEach(s=>{
    if(s.state==='failed') addW('', '!', `${nm(s._o)}${L('Tunnel','تونل')} #${s.slot} · ${esc(peerOf(s))} ${L('is broken','قطع است')}`, s._o?'':`<button class="dlink" onclick="openDetail(${s.slot})">${L('Open','باز کردن')}</button>`);
    else if(s.state!=='active') addW('y', '•', `${nm(s._o)}${L('Tunnel','تونل')} #${s.slot} · ${esc(peerOf(s))} ${L('is stopped','خاموش است')}`, s._o?'':`<button class="dlink" onclick="openDetail(${s.slot})">${L('Open','باز کردن')}</button>`);
    else if(s.loss>=20||s.lat>300) addW('y', '⏱', `${nm(s._o)}${L('Tunnel','تونل')} #${s.slot}: ${s.lat!=null?s.lat.toFixed(0)+' ms':''}${s.loss>0?' · '+s.loss.toFixed(0)+'% '+L('packet loss','افت بسته'):''}`, s._o?'':`<button class="dlink" onclick="openDetail(${s.slot})">${L('Open','باز کردن')}</button>`);
  });
  if((st.cpu||0)>85) addW('y','%',`${L('High CPU','پردازنده شلوغ است')} ${st.cpu.toFixed(0)}%`);
  if((st.mem_pct||0)>90) addW('y','%',`${L('High memory','حافظه پر است')} ${st.mem_pct.toFixed(0)}%`);
  if((st.disk_pct||0)>90) addW('y','%',`${L('Disk almost full','دیسک تقریباً پر است')} ${st.disk_pct.toFixed(0)}%`);
  if(!W.length) addW('g','✓',rAll.length?L('Everything is on track: all tunnels are flowing.','همه‌چیز روبه‌راه است: همه تونل‌ها جاری‌اند.'):L('Create your first tunnel to get started.','اولین تونل خود را بسازید.'), rAll.length?'':`<button class="dlink" onclick="go('rev')">${L('Create','ساخت')}</button>`);
  $('#dwarn').innerHTML=W.join('');
  const cw=($('#map')||{}).clientWidth||0, sig=lang+'|'+cw+'|'+(st.hostname||'')+'|'+JSON.stringify(rAll.map(s=>[s.slot,s.state,peerOf(s),s.port,s.bridge,s.rx_rate==null?0:Math.round(s.rx_rate/1e5)]))+JSON.stringify(fl.map(f=>[f.id,f.ok]));
  if(sig===_dsig) return; _dsig=sig;
  dashMap(st, slots);
  $('#dtun').innerHTML = rAll.length ? slotRows(slots) + fl.map(f=>(f.slots||[]).map(s=>slotRow(Object.assign({_o:f.name},s))).join('')).join('') : `<div class="dempty">${L('No tunnels yet. Create one from the Tunnels page.','هنوز تونلی نیست. از صفحه تونل‌ها یکی بسازید.')}<br><br><button class="dlink" onclick="go('rev')">${L('Create tunnel','ساخت تونل')}</button></div>`;
}
function slotRow(s){ return `<div class="tr" onclick="${s._o?"go('srv')":'openDetail('+s.slot+')'}"><i class="tb ${stCls(s.state)}"></i><div class="tm"><b>${s._o?esc(s._o)+' · ':''}#${s.slot} · ${esc(peerOf(s))}<em class="tg">${esc(s.side)}</em></b><span>${esc(slotDetail(s))}</span>${mxChips(s)?`<div class="mxs">${mxChips(s)}</div>`:''}</div><div class="tp ${stCls(s.state)}">${stTxt(s.state)}</div></div>`; }
function slotRows(slots){ return slots.map(slotRow).join(''); }
function dashMap(st, slots){
  const el=$('#map'); if(!el) return;
  const {nodes,tuns}=fleetNodes(st,slots), n=nodes.length-1, cw=Math.max(el.clientWidth||320,300), W=Math.max(cw,(n+1)*150), H0=96, X0=Math.min(86,W*.15), XR=W-70;
  nodes.forEach((nd,i)=>{ nd.x=i===0?X0:X0+i*((XR-X0)/Math.max(n,1)); });
  const yy=j=>H0+48+j*40, H=H0+48+Math.max(tuns.length,1)*40+16, cut=(t,m)=>{ t=String(t); return t.length>m?t.slice(0,m-1)+'…':t; };
  let g=`<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><defs><linearGradient id="dgd" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0a1c33"/><stop offset="1" stop-color="#050d18"/></linearGradient><linearGradient id="dsk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#050b17"/><stop offset="1" stop-color="#112340"/></linearGradient></defs>`;
  g+=`<rect width="${W}" height="${H0}" fill="url(#dsk)"/><rect y="${H0}" width="${W}" height="${H-H0}" fill="url(#dgd)"/>`;
  for(let k=0;k<46;k++) g+=`<circle cx="${((k*137.5)%W).toFixed(0)}" cy="${((k*61.8)%(H0-10)+4).toFixed(0)}" r="${k%5?0.8:1.3}" fill="#fff" opacity="${(0.25+(k%4)*0.18).toFixed(2)}"/>`;
  g+=`<line x1="0" y1="${H0}" x2="${W}" y2="${H0}" stroke="#e9c46a" stroke-width="1.6" opacity=".9"/>`;
  const depth=nodes.map(()=>H0+22); tuns.forEach((t,j)=>{ [t.a,t.b].forEach(nd=>{ const i=nodes.indexOf(nd); depth[i]=Math.max(depth[i],yy(j)); }); });
  nodes.forEach((nd,i)=>{ g+=`<line x1="${nd.x}" y1="${H0}" x2="${nd.x}" y2="${depth[i]}" stroke="#8a7340" stroke-width="2.5" stroke-linecap="round"/>`; });
  tuns.forEach((t,j)=>{
    const s=t.s, y=yy(j), x1=t.a.x, x2=t.b.x, dx=(x2-x1)*.4, col=s.state==='active'?'#34d0c3':s.state==='failed'?'#f0707a':'#6b7a93';
    const d=`M${x1} ${y} C${x1+dx} ${y+12} ${x2-dx} ${y+12} ${x2} ${y}`, r=s.state==='active'&&s.rx_rate!=null?' · '+rateTxt((s.rx_rate||0)+(s.tx_rate||0)):'', tx=(t.remote?cut(t.own,7)+' ':'')+'#'+s.slot+' · '+slotProto(s)+r, pw=tx.length*6.1+30, xm=(x1+x2)/2, ym=y+9;
    g+=`<g style="cursor:pointer" onclick="${t.remote?"go('srv')":'openDetail('+s.slot+')'}"><path d="${d}" fill="none" stroke="transparent" stroke-width="22"/><path d="${d}" fill="none" stroke="${col}" stroke-opacity=".14" stroke-width="12" stroke-linecap="round"/><path d="${d}" fill="none" stroke="${col}" stroke-width="${s.state==='active'?4:3}" stroke-linecap="round" ${s.state==='active'?'':'stroke-dasharray="5 6" opacity=".8"'}/>${s.state==='active'?`<path class="mdash" d="${d}" fill="none" stroke="#e8fffd" stroke-opacity=".8" stroke-width="1.6"/>`:''}<circle cx="${x1}" cy="${y}" r="4" fill="${col}"/><circle cx="${x2}" cy="${y}" r="4" fill="${col}"/><rect x="${(xm-pw/2).toFixed(1)}" y="${ym-10}" width="${pw.toFixed(1)}" height="20" rx="10" fill="#0a1a30" stroke="${col}" stroke-opacity=".5"/><circle cx="${(xm-pw/2+12).toFixed(1)}" cy="${ym}" r="3" fill="${col}"/><text class="dpl" x="${(xm-pw/2+20).toFixed(1)}" y="${ym+3.6}">${esc(tx)}</text></g>`;
  });
  if(!tuns.length) g+=`<text class="dn2" x="${W/2}" y="${H0+50}" text-anchor="middle">${L('No tunnel yet','هنوز تونلی نیست')}</text>`;
  nodes.forEach((nd,i)=>{
    const mine=tuns.filter(t=>t.a===nd||t.b===nd), col=nd.kind==='local'?'#34d0c3':nd.kind==='remote'?(nd.ok?'#34d0c3':'#f0707a'):(mine.some(t=>t.s.state==='active')?'#34d0c3':mine.some(t=>t.s.state==='failed')?'#f0707a':'#6b7a93');
    const sub=nd.kind==='local'?(nd.ip||''):nd.kind==='remote'?(nd.ok?'CPU '+((nd.f.stats||{}).cpu||0).toFixed(0)+'% · '+(nd.f.slots||[]).length+' '+L('tunnel','تونل'):L('offline','آفلاین')):((mine[0]&&mine[0].s.role==='server'?L('Foreign','خارج'):L('Iran','ایران'))+' · '+mine.length+' '+L('tunnel','تونل'));
    const anc=i===0?'start':'middle', x=nd.x;
    g+=`<path d="M${x-9} ${H0} a9 9 0 0 1 18 0z" fill="#e9c46a"/><circle cx="${anc==='start'?x-6:x-(String(nd.name).length*3.2+9)}" cy="${H0-34}" r="3" fill="${col}"/><text class="dn" x="${anc==='start'?x+2:x+4}" y="${H0-30}" text-anchor="${anc}">${esc(cut(nd.name,24))}</text><text class="dn2" x="${anc==='start'?x-6:x}" y="${H0-16}" text-anchor="${anc}">${esc(cut(sub,34))}</text>`;
  });
  el.innerHTML=g+'</svg>';
}
/* ---- shared UI bits ---- */
window._sp = true;
const ICRV='<svg viewBox="0 0 24 24"><path d="M4 8h14m0 0l-3-3m3 3l-3 3M20 16H6m0 0l3-3m-3 3l3 3"/></svg>', ICSF='<svg viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7z"/></svg>',
  ICNT='<svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>', ICDM='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>', ICIN='<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>';
const SETSECS=[['sec-sec',ICSH,'Security','امنیت'],['sec-2fa',ICSH,'Two-factor login','ورود دو مرحله‌ای'],['sec-up',ICIN,'About & update','درباره و به‌روزرسانی'],['sec-net',ICNT,'Network & speed','شبکه و سرعت'],['sec-dom',ICDM,'Domain & SSL','دامنه و SSL'],['sec-tg',ICTG,'Telegram','تلگرام'],['sec-alerts',ICNT,'Alerts','هشدارها'],['sec-access',ICSH,'Access','دسترسی'],['sec-adv',ICIN,'Advanced','پیشرفته'],['sec-time',ICUS,'Date & time','تاریخ و ساعت'],['sec-backup',ICBK,'Backup','پشتیبان'],['sec-app',ICAP,'Appearance','ظاهر']];
function flyItems(p){
  if(p==='tun') return [['rev',ICRV,L('Reverse tunnel','تونل معکوس'),tsel==='rev'],['spoof',ICSF,L('Spoof tunnel','تونل اسپوف'),tsel==='spoof']];
  const a=((document.querySelector('#setnav .nav.on')||{}).dataset||{}).anchor||'sec-sec';
  return SETSECS.map(x=>[x[0],x[1],L(x[2],x[3]),x[0]===a]);
}
function openFly(el,p){
  const f=$('#fly'); if(!f) return; f.dataset.p=p;
  f.innerHTML=`<div class="fh">${p==='tun'?L('Tunnel type','نوع تونل'):L('Settings sections','بخش‌های تنظیمات')}</div>`+flyItems(p).map(x=>`<button data-k="${x[0]}" class="${x[3]?'on':''}">${x[1]}<span>${x[2]}</span></button>`).join('');
  const r=el.getBoundingClientRect(), sr=$('#side').getBoundingClientRect(), rtl=getComputedStyle($('#shell')).direction==='rtl';
  f.classList.add('on'); const h=f.offsetHeight; f.style.top=Math.max(8,Math.min(r.top,innerHeight-h-8))+'px';
  if(rtl){ f.style.right=(innerWidth-sr.left+8)+'px'; f.style.left='auto'; } else { f.style.left=(sr.right+8)+'px'; f.style.right='auto'; }
}
function closeFly(){ const f=$('#fly'); if(f) f.classList.remove('on'); }
function navClick(el){
  const p=el.dataset.p;
  if(p==='tun'||p==='set'){ const f=$('#fly'), same=f.classList.contains('on')&&f.dataset.p===p; if(page!==p) go(p); if(same) closeFly(); else openFly(el,p); }
  else { closeFly(); go(p); }
}
document.addEventListener('click',e=>{
  const f=$('#fly'); if(!f||!e.target.closest) return;
  const b=e.target.closest('#fly button[data-k]');
  if(b){ const p=f.dataset.p,k=b.dataset.k; closeFly(); if(p==='tun') go(k); else { const el=document.getElementById(k); if(el) el.scrollIntoView({behavior:'smooth',block:'start'}); } return; }
  if(f.classList.contains('on') && !e.target.closest('#fly') && !e.target.closest('.nav[data-p="tun"]') && !e.target.closest('.nav[data-p="set"]')) closeFly();
});
document.addEventListener('keydown',e=>{ if(e.key==='Escape'){ closeFly(); dmClose(); } });
function ntLogo(s){ return '<svg viewBox="0 0 64 64" width="'+s+'" height="'+s+'"><defs><linearGradient id="ntsp" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fde68a"/><stop offset="1" stop-color="#d97706"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="16" fill="#0b1226" stroke="url(#ntsp)" stroke-width="2.5"/><path d="M12 52V32a20 20 0 0 1 40 0v20" fill="none" stroke="url(#ntsp)" stroke-width="4" stroke-linecap="round"/><path d="M20 52V33a12 12 0 0 1 24 0v19" fill="none" stroke="url(#ntsp)" stroke-width="3" stroke-linecap="round" opacity=".7"/><path d="M27 52V34a5 5 0 0 1 10 0v18z" fill="url(#ntsp)" opacity=".9"/><path d="M6 52h52" stroke="url(#ntsp)" stroke-width="3" stroke-linecap="round"/></svg>'; }
function splash(){
  if(document.getElementById('splash')) return;
  const d=document.createElement('div'); d.id='splash'; d.innerHTML='<div class="sl">'+ntLogo(96)+'</div><b>NiceTunnel</b><i></i>';
  document.body.appendChild(d); setTimeout(()=>d.classList.add('out'),1000); setTimeout(()=>d.remove(),1550);
}
function goLogs(n){ dmClose(); _lgsel=String(n); _lgsig=''; const s=$('#lgsel'); if(s) s.dataset.o=''; go('logs'); }
function slotBtns(n){ return `<button class="sm" onclick="openDetail(${n})">${L('Details','جزئیات')}</button><button class="sm ok" onclick="act(${n},'start')">${L('Connect','اتصال')}</button><button class="sm" onclick="act(${n},'restart')">${L('Restart','ری‌استارت')}</button><button class="sm" onclick="act(${n},'stop')">${L('Stop','توقف')}</button><button class="sm" onclick="goLogs(${n})">${L('Logs','لاگ')}</button><button class="sm danger" onclick="del(${n})">${L('Delete','حذف')}</button>`; }
function slotTable(slots, full){
  if(!slots.length) return `<div class="dempty">${L('No tunnel yet. Open Create to add one.','هنوز تونلی نیست. از بخش ساخت یکی بسازید.')}</div>`;
  return '<div class="tcards">'+slots.map(s=>`<div class="tcard"><div class="tch"><i class="tb ${stCls(s.state)}"></i><div class="tm"><b>#${s.slot} · ${esc(peerOf(s))}<em class="tg">${esc(s.side)}</em></b><span>${esc(slotDetail(s))}</span></div><div class="tp ${stCls(s.state)}">${stTxt(s.state)}</div></div>${mxChips(s)?`<div class="mxs">${mxChips(s)}</div>`:''}${full?`<div class="tact">${slotBtns(s.slot)}</div>`:''}</div>`).join('')+'</div>';
}
/* ---- charts ---- */
function drawLines(cv, series, fmt){
  if(!cv) return; const dpr=window.devicePixelRatio||1, w=cv.clientWidth||300, h=cv.clientHeight||90; cv.width=w*dpr; cv.height=h*dpr;
  const c=cv.getContext('2d'); c.scale(dpr,dpr); c.clearRect(0,0,w,h);
  const n=Math.max(0,...series.map(s=>s.data.length)); c.font='11px sans-serif';
  if(n<2){ c.fillStyle='#6f86a8'; c.fillText(L('Collecting data…','در حال جمع‌آوری داده…'),10,h/2); return; }
  const top=Math.max(1e-9,...series.flatMap(s=>s.data))*1.15, step=w/89;
  c.strokeStyle='rgba(255,255,255,.06)'; for(let i=1;i<4;i++){ c.beginPath(); c.moveTo(0,h*i/4); c.lineTo(w,h*i/4); c.stroke(); }
  series.forEach(s=>{ const d=s.data; c.beginPath(); d.forEach((v,i)=>{ const x=w-(d.length-1-i)*step, y=h-4-(v/top)*(h-12); i?c.lineTo(x,y):c.moveTo(x,y); }); c.strokeStyle=s.color; c.lineWidth=1.8; c.stroke();
    c.lineTo(w,h); c.lineTo(w-(d.length-1)*step,h); c.closePath(); const gr=c.createLinearGradient(0,0,0,h); gr.addColorStop(0,s.color+'44'); gr.addColorStop(1,s.color+'00'); c.fillStyle=gr; c.fill(); });
  c.fillStyle='#8fa2bf'; c.fillText(fmt(top/1.15),6,12);
}
/* ---- tunnel details ---- */
let _dm=null, _dmTimer=null;
function dmClose(){ clearInterval(_dmTimer); _dmTimer=null; _dm=null; const o=$('#dm'); if(o) o.remove(); }
function inp(id,label,val,extra){ return `<div class="ef"><label for="${id}">${label}</label><input id="${id}" dir="ltr" value="${esc(val==null?'':String(val))}" ${extra||''}></div>`; }
function editForm(s){
  const sp=s.kind==='spoof', srv=s.role==='server';
  const f= sp ? inp('ed_peer',L('Peer IP','آی‌پی طرف مقابل'),s.peer)+`<div class="ef"><label>${L('Packet type','نوع بسته')}</label><select id="ed_transport">${['udp','tcp','icmp'].map(t=>`<option ${t===s.transport?'selected':''}>${t}</option>`).join('')}</select></div>`+inp('ed_port',L('Tunnel port','پورت تونل'),s.port)+inp('ed_spoof_ips',L('Spoofed IPs','آی‌پی‌های جعلی'),s.spoof_ips)+(srv?inp('ed_listen_port',L('Listen port','پورت شنود'),s.listen_port):inp('ed_forward',L('Forward to (host:port)','فوروارد به (host:port)'),s.forward))
   : inp('ed_bridge',L('Bridge port','پورت پل'),s.bridge)+(srv?inp('ed_ports',L('Forwarded ports','پورت‌های انتقالی'),s.ports):inp('ed_server_ip',L('Server IP','آی‌پی سرور'),s.server_ip)+inp('ed_target_host',L('Target host','مقصد'),s.target_host));
  return f+inp('ed_token',L('Token','توکن'),'', `type="password" placeholder="${L('leave empty to keep','خالی = بدون تغییر')}" autocomplete="new-password"`);
}
async function openDetail(n){
  dmClose(); closeFly();
  const o=document.createElement('div'); o.id='dm'; o.className='dmo'; o.onclick=e=>{ if(e.target===o) dmClose(); };
  o.innerHTML=`<div class="dmb"><div class="dmh"><div><b id="dmt">#${n}</b><span id="dms"></span></div><button class="dmx" onclick="dmClose()" aria-label="Close">✕</button></div><div id="dmbody"><div class="dempty">…</div></div></div>`;
  document.body.appendChild(o); _dm={n,built:false};
  await dmLoad(); _dmTimer=setInterval(dmLoad,3000);
}
async function dmLoad(){
  if(!_dm) return; const r=await apiX('/api/slot/'+_dm.n+'/detail'); if(!_dm) return;
  if(r.s!==200){ $('#dmbody').innerHTML=`<div class="dempty">${esc(r.j.error||'error')}</div>`; return; }
  const d=r.j, s=d.slot, st=d.stats||{}, h=d.health||{}, n=_dm.n;
  $('#dmt').innerHTML=`#${n} · ${esc(peerOf(s))}<em class="tg">${esc(s.side)}</em>`; $('#dms').className='tp '+stCls(s.state); $('#dms').textContent=stTxt(s.state);
  const cell=(k,v,sub)=>`<div class="dcell"><span>${k}</span><b>${v}</b>${sub?`<small>${sub}</small>`:''}</div>`;
  const stats=`<div class="dgr">${cell(L('Speed','سرعت'),'↓ '+rateTxt(st.rx_rate),'↑ '+rateTxt(st.tx_rate))}${cell(L('Open connections','اتصال‌های باز'),st.acct?st.conns:'—',s.kind==='reverse'?'TCP':L('TCP only','فقط TCP'))}${cell(L('Today','امروز'),'↓ '+fmtB(st.day_rx||0),'↑ '+fmtB(st.day_tx||0))}${cell(L('Total','مجموع'),'↓ '+fmtB(st.rx_total||0),'↑ '+fmtB(st.tx_total||0))}${cell(L('Service uptime','آپتایم سرویس'),st.uptime==null?'—':fmtUp(st.uptime),(st.restarts||0)+' '+L('restarts','ری‌استارت'))}${cell(L('CPU / RAM','پردازنده / رم'),st.cpu==null?'—':st.cpu.toFixed(1)+'%',fmtB(st.mem||0))}</div>`+(st.acct?'':`<p class="dnote">${L('Traffic counters start after this tunnel restarts once.','شمارنده ترافیک بعد از یک بار ری‌استارت این تانل شروع می‌شود.')}</p>`);
  const lat=h.lat==null?'—':h.lat.toFixed(1)+' ms', hl=`<div class="dgr">${cell(L('Ping to peer','پینگ تا مقصد'),lat,h.peer?esc(h.peer):L('peer unknown yet','آدرس مقصد هنوز معلوم نیست'))}${cell(L('Packet loss','افت بسته'),h.loss==null?'—':h.loss.toFixed(0)+'%',h.t?ago(h.t):'')}${cell(L('Uptime 24h','آپتایم ۲۴ ساعت'),d.up24==null?'—':d.up24+'%',L('7 days','۷ روز')+': '+(d.up7==null?'—':d.up7+'%'))}${cell(L('Last reachable','آخرین دسترسی'),h.ok_t?ago(h.ok_t):'—','')}</div>`;
  const evTxt=e=>e.k==='state'||e.k==='seen'?(e.k==='seen'?L('First seen as ','برای اولین بار دیده شد: '):L('Became ','تغییر وضعیت به '))+stTxt(e.s):e.k==='edit'?L('Settings edited','تنظیمات ویرایش شد'):e.k==='loss'?L('Packet loss ','افت بسته ')+(e.v||0).toFixed(0)+'%':e.k==='loss_ok'?L('Connection to peer recovered','ارتباط با مقصد برگشت'):esc(e.k);
  const evs=(d.events||[]).map(e=>`<div class="ev"><i class="tb ${e.s?stCls(e.s):'off'}"></i><span>${evTxt(e)}</span><small>${new Date(e.t*1000).toLocaleString()}</small></div>`).join('')||`<div class="dempty">${L('No events yet.','هنوز رویدادی ثبت نشده.')}</div>`;
  if(!_dm.built){
    _dm.built=true;
    $('#dmbody').innerHTML=`<div id="dmstats"></div><div class="dmsec"><h4>${L('Traffic (last ~7 min)','ترافیک (۷ دقیقه اخیر)')}<span class="lgd"><i style="background:#34d0c3"></i>↓ <i style="background:#e9c46a"></i>↑</span></h4><canvas id="dch" class="dcv"></canvas></div>
     <div class="dmsec"><h4>${L('Health','سلامت')}<button class="sm" id="dmprobe" style="margin-inline-start:auto">${L('Test now','تست همین حالا')}</button></h4><div id="dmhl"></div><canvas id="dlat" class="dcv" style="height:70px"></canvas></div>
     <div class="dmsec adm"><h4>${L('Limits & auto-repair','محدودیت و ترمیم خودکار')}</h4><div id="dmlim"></div><div class="efg"><div class="ef"><label>${L('Quota (GB, 0 = none)','حجم مجاز (گیگابایت، ۰ = نامحدود)')}</label><input id="lm_q" type="number" min="0" step="any"></div><div class="ef"><label>${L('Counted','شمارش')}</label><select id="lm_p"><option value="month">${L('per month','ماهانه')}</option><option value="total">${L('in total','کل')}</option></select></div><div class="ef"><label>${L('Expires on','تاریخ انقضا')}</label><input id="lm_e" type="date"></div><div class="ef"><label>${L('Speed cap (Mbit/s, 0 = none)','سقف سرعت (مگابیت بر ثانیه، ۰ = بدون سقف)')}</label><input id="lm_m" type="number" min="0" step="any"></div></div><div class="nact"><button class="ok" id="lmsave">${L('Save limits','ذخیره محدودیت')}</button> <button id="lmreset">${L('Reset usage & unblock','صفر کردن مصرف و آزادسازی')}</button> <span id="lmmsg" class="dnote"></span></div><label class="swrow"><input type="checkbox" id="dmheal"> ${L('Auto-repair: restart if broken for 2.5 minutes (max 3 times an hour)','ترمیم خودکار: ری‌استارت اگر ۲٫۵ دقیقه خراب بماند (حداکثر ۳ بار در ساعت)')}</label></div>
     <div class="dmsec"><h4>${L('Last 30 days','۳۰ روز اخیر')}<span class="lgd"><i style="background:#34d0c3"></i>↓ <i style="background:#e9c46a"></i>↑</span></h4><canvas id="dday" class="dcv" style="height:90px"></canvas><div id="dmdays" class="dnote"></div></div>
     <div class="dmsec adm"><h4>${L('Customer link','لینک مشتری')}</h4><p class="dnote" style="margin-top:0">${L('A page without login that shows only usage, expiry and status of this tunnel.','صفحه‌ای بدون ورود که فقط مصرف، انقضا و وضعیت همین تانل را نشان می‌دهد.')}</p><div class="efg"><div class="ef"><label>${L('Name shown to the customer','نام نمایشی برای مشتری')}</label><input id="shlabel" maxlength="60"></div></div><div class="nact"><button class="ok" id="shon">${L('Create link','ساخت لینک')}</button> <button id="shregen" class="hide">${L('New link','لینک جدید')}</button> <button id="shoff" class="hide">${L('Disable','غیرفعال')}</button></div><div id="shbox" class="hide"><code id="shlink" style="direction:ltr;display:block;word-break:break-all;color:#f4d58a;margin:8px 0"></code><button class="sm" id="shcopy">${L('Copy link','کپی لینک')}</button></div></div>
     <div class="dmsec"><h4>${L('Events','رویدادها')}</h4><div id="dmev" class="evs"></div></div>
     <div class="dmsec adm"><details id="dmedit"><summary>${L('Edit tunnel','ویرایش تانل')}</summary><div class="efg">${editForm(s)}</div><p class="dnote">${L('Ports, token and spoofed IPs must match on the other server too.','پورت، توکن و آی‌پی‌های جعلی باید روی سرور مقابل هم یکی باشند.')}</p><div class="nact"><button class="ok" id="dmsave">${L('Save & restart','ذخیره و ری‌استارت')}</button> <span id="dmmsg" class="dnote"></span></div></details></div>
     <div class="tact">${slotBtns(n)}</div>`;
    wireDetailExtras(n,d);
    $('#dmprobe').onclick=async()=>{ const b=$('#dmprobe'); b.disabled=true; const r=await apiX('/api/slot/'+n+'/probe',{}); b.disabled=false; if(r.s!==200) alert(r.j.error||'error'); dmLoad(); };
    $('#dmsave').onclick=async()=>{ const body={}; ['peer','transport','port','spoof_ips','listen_port','forward','bridge','ports','server_ip','target_host','token'].forEach(k=>{ const e=$('#ed_'+k); if(e&&e.value.trim()!=='') body[k]=e.value.trim(); }); const b=$('#dmsave'); b.disabled=true; const r=await apiX('/api/slot/'+n+'/edit',body); b.disabled=false; $('#dmmsg').style.color=r.s===200?'#34d0c3':'#f0707a'; $('#dmmsg').textContent=r.s===200?(L('Saved','ذخیره شد')+(r.j.restarted?' · '+L('restarted','ری‌استارت شد'):'')+(r.j.token_changed?' · '+L('token changed','توکن عوض شد'):'')):(r.j.error||'error'); if(r.s===200) refresh(); };
  }
  $('#dmstats').innerHTML=stats; $('#dmhl').innerHTML=hl; $('#dmev').innerHTML=evs; $('#dmlim').innerHTML=limHtml(d.limits); drawBars($('#dday'),d.days||[]); $('#dmdays').innerHTML=L('Last 30 days','۳۰ روز اخیر')+': <bdi dir="ltr">↓ '+fmtB((d.days||[]).reduce((a,x)=>a+x.rx,0))+' · ↑ '+fmtB((d.days||[]).reduce((a,x)=>a+x.tx,0))+'</bdi>';
  drawLines($('#dch'),[{data:d.hist.rx,color:'#34d0c3'},{data:d.hist.tx,color:'#e9c46a'}],v=>rateTxt(v));
  drawLines($('#dlat'),[{data:d.hist.lat,color:'#8ab4ff'}],v=>v.toFixed(0)+' ms');
}
/* ---- servers page ---- */
const _srvOpen=new Set();
async function refreshFleet(){ const r=await apiX('/api/fleet'); window._fleet=(r.j&&r.j.servers)||[]; srvRender(); }
function mbar(l,p){ return `<div class="dm"><span>${l}</span><em><b style="width:${Math.max(0,Math.min(100,p||0))}%"></b></em><span>${(p||0).toFixed(0)}%</span></div>`; }
function srvCard(name,url,ok,st,slots,id,errTxt,t){
  const sl=slots||[], act=sl.filter(s=>s.state==='active').length, open=_srvOpen.has(id||'local');
  const rate=st?fmtR((st.rx_rate||0)+(st.tx_rate||0)).join(' '):'—';
  return `<div class="scard"><div class="sch"><span class="sdot ${ok?'on':'off'}"></span><div class="tm"><b>${esc(name)}${id?'':`<em class="tg">${L('This server','این سرور')}</em>`}</b><span>${esc(url||'')}${ok||!id?'':' · '+L('offline','آفلاین')+(errTxt?' · '+esc(errTxt).slice(0,60):'')+(t?' · '+L('last seen','آخرین دیدار')+' '+ago(t):'')}</span></div><div class="tp ${ok?'active':'failed'}">${ok?L('Online','آنلاین'):L('Offline','آفلاین')}</div></div>
   ${st?`<div class="sgr"><div>${mbar('CPU',st.cpu)}${mbar('RAM',st.mem_pct)}${mbar('Disk',st.disk_pct)}</div><div class="sinfo"><span>${L('Tunnels','تونل‌ها')}<b>${act} / ${sl.length}</b></span><span>${L('Throughput','ترافیک')}<b>${rate}</b></span><span>${L('Uptime','آپتایم')}<b>${fmtUp(st.uptime)}</b></span></div></div>`:''}
   <div class="tact"><button class="sm" onclick="srvToggle('${id||'local'}')">${open?L('Hide tunnels','بستن تونل‌ها'):L('Tunnels','تونل‌ها')} (${sl.length})</button>${id?`<a class="sm lnk" href="${esc(url)}" target="_blank" rel="noopener">${L('Open panel','باز کردن پنل')} ↗</a><button class="sm danger" onclick="srvDel('${id}')">${L('Remove','حذف')}</button>`:''}</div>
   ${open?`<div class="srows">${sl.length?sl.map(s=>`<div class="tr" style="cursor:default"><i class="tb ${stCls(s.state)}"></i><div class="tm"><b>#${s.slot} · ${esc(peerOf(s))}<em class="tg">${esc(s.side)}</em></b><span>${esc(slotDetail(s))}</span>${mxChips(s)?`<div class="mxs">${mxChips(s)}</div>`:''}</div><div class="tp ${stCls(s.state)}">${stTxt(s.state)}</div>${id?`<div class="tact" style="margin:0;padding:0;border:0"><button class="sm" onclick="srvAct('${id}',${s.slot},'start')">${L('Connect','اتصال')}</button><button class="sm" onclick="srvAct('${id}',${s.slot},'restart')">${L('Restart','ری‌استارت')}</button><button class="sm" onclick="srvAct('${id}',${s.slot},'stop')">${L('Stop','توقف')}</button><button class="sm" onclick="srvLogs('${id}',${s.slot})">${L('Logs','لاگ')}</button></div>`:`<button class="sm" onclick="openDetail(${s.slot})">${L('Details','جزئیات')}</button>`}</div>`).join(''):`<div class="dempty">${L('No tunnels.','تونلی نیست.')}</div>`}</div>`:''}</div>`;
}
function srvRender(){
  const el=$('#srvlist'); if(!el) return; const st=window._st||{}, fl=window._fleet||[];
  el.innerHTML=srvCard(st.hostname||L('This server','این سرور'), st.ip||'', true, st, window._slots||[], '', '', 0)+fl.map(f=>srvCard(f.name,f.url,f.ok,f.stats,f.slots,f.id,f.err,f.t)).join('')+(fl.length?'':`<div class="dempty">${L('No other servers yet. Add one to see it on the map and manage its tunnels from here.','هنوز سرور دیگری اضافه نشده. اضافه کنید تا روی نقشه ببینید و تانل‌هایش را از اینجا مدیریت کنید.')}</div>`);
}
function srvToggle(id){ _srvOpen.has(id)?_srvOpen.delete(id):_srvOpen.add(id); srvRender(); }
async function srvDel(id){ if(!confirm(L('Remove this server from the panel? Its tunnels keep running.','این سرور از پنل حذف شود؟ تانل‌هایش به کار خود ادامه می‌دهند.'))) return; await apiX('/api/servers/delete',{id}); _srvOpen.delete(id); await refreshFleet(); _dsig=''; }
async function srvAct(id,slot,action){ const r=await apiX('/api/servers/act',{id,slot,action}); if(r.s!==200) alert(r.j.error||'error'); setTimeout(refreshFleet,1500); }
async function srvLogs(id,slot){
  dmClose(); const o=document.createElement('div'); o.id='dm'; o.className='dmo'; o.onclick=e=>{ if(e.target===o) dmClose(); };
  o.innerHTML=`<div class="dmb"><div class="dmh"><div><b>${L('Logs','لاگ')} #${slot}</b></div><button class="dmx" onclick="dmClose()">✕</button></div><div class="lg" id="srvlg" style="max-height:60vh">…</div></div>`; document.body.appendChild(o);
  const r=await apiX('/api/servers/logs?id='+encodeURIComponent(id)+'&slot='+slot); $('#srvlg').innerHTML=r.s===200?(r.j.logs||'').split('\n').filter(Boolean).map(l=>`<div>${esc(l)}</div>`).join('')||'—':esc(r.j.error||'error');
}
async function srvSave(pin){
  const b={name:$('#srvname').value,url:$('#srvurl').value.trim(),key:$('#srvkey').value.trim()}; if(pin) b.pin=pin;
  const btn=$('#srvsave'); btn.disabled=true; const r=await apiX('/api/servers/add',b); btn.disabled=false;
  if(r.s===409&&r.j.need_pin){ if(confirm(L('This server uses a self-signed certificate.\nFingerprint (SHA-256):\n','این سرور گواهی خودامضا دارد.\nاثر انگشت (SHA-256):\n')+r.j.fingerprint+'\n\n'+L('Only trust it if this matches the other panel. Trust it?','فقط اگر با پنل مقابل یکی است اعتماد کنید. اعتماد می‌کنید؟'))) return srvSave(r.j.fingerprint); return; }
  if(r.s!==200){ $('#srvmsg').style.color='#f0707a'; $('#srvmsg').textContent=r.j.error||'error'; return; }
  ['srvname','srvurl','srvkey'].forEach(i=>$(('#'+i)).value=''); $('#srvform').classList.add('hide'); $('#srvmsg').textContent=''; _dsig=''; await refreshFleet();
}
async function keysRender(){
  const r=await apiX('/api/apikeys'); const el=$('#keylist'); if(!el) return;
  el.innerHTML=(r.j.keys||[]).map(k=>`<div class="wr"><span><b>${esc(k.name)}</b> ${k.perm==='full'?`<span class="mx warn">${L('can create tunnels','می‌تواند تانل بسازد')}</span>`:''} <small>${(k.ips&&k.ips.length)?'· '+esc(k.ips.join(', ')):''} · ${new Date(k.t*1000).toLocaleDateString()} · ${k.last?L('used','استفاده')+' '+ago(k.last):L('never used','استفاده نشده')}</small></span><button class="dlink" onclick="keyRevoke('${k.id}')">${L('Revoke','ابطال')}</button></div>`).join('')||`<div class="dempty">${L('No API keys.','کلیدی نیست.')}</div>`;
}
async function keyRevoke(id){ if(!confirm(L('Revoke this key? Panels using it lose access.','این کلید باطل شود؟ پنل‌هایی که از آن استفاده می‌کنند دسترسی را از دست می‌دهند.'))) return; await apiX('/api/apikeys/revoke',{id}); keysRender(); }
function srvInit(){
  $('#srvaddr').textContent=location.origin+BASE;
  $('#srvadd').onclick=()=>$('#srvform').classList.toggle('hide');
  $('#srvsave').onclick=()=>srvSave();
  $('#srvaddrcopy').onclick=()=>{ try{ navigator.clipboard.writeText(location.origin+BASE); }catch(e){} };
  $('#keymake').onclick=async()=>{ const r=await apiX('/api/apikeys/create',{name:$('#keyname').value,full:$('#keyfull').checked,ips:$('#keyips').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#keyname').value=''; $('#keynew').classList.remove('hide'); $('#keynewv').textContent=r.j.key; keysRender(); };
  $('#keycopy').onclick=()=>{ try{ navigator.clipboard.writeText($('#keynewv').textContent); }catch(e){} };
  refreshFleet(); keysRender();
}
/* ---- settings extras: 2FA, update, telegram ---- */
function tfaRender(s){ $('#tfastate').textContent=s.on?L('On','روشن')+' · '+s.left+' '+L('recovery codes left','کد بازیابی باقی مانده'):L('Off — only the password protects the panel','خاموش — فقط رمز از پنل محافظت می‌کند'); $('#tfaon').classList.toggle('hide',!!s.on); $('#tfaoff').classList.toggle('hide',!s.on); }
async function setExtras(){
  const r=await apiX('/api/2fa'); if(r.s===200){ window._tfa=r.j.on; tfaRender(r.j); }
  $('#tfaon').onclick=async()=>{ const r=await apiX('/api/2fa/setup',{}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#tfakey').textContent=r.j.secret.replace(/(.{4})/g,'$1 ').trim(); $('#tfauri').href=r.j.uri; $('#tfasetup').classList.remove('hide'); $('#tfacode').value=''; $('#tfacode').focus(); };
  $('#tfacopy').onclick=()=>{ try{ navigator.clipboard.writeText($('#tfakey').textContent.replace(/\s/g,'')); }catch(e){} };
  $('#tfaconfirm').onclick=async()=>{ const r=await apiX('/api/2fa/enable',{code:$('#tfacode').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#tfasetup').classList.add('hide'); const b=$('#tfacodes'); b.classList.remove('hide'); b.innerHTML=`<p class="dnote">${L('Save these recovery codes now. Each works once if you lose your phone. They will not be shown again.','این کدهای بازیابی را همین حالا ذخیره کنید. هر کدام یک بار کار می‌کند و دیگر نمایش داده نمی‌شوند.')}</p><div class="rcodes">${r.j.codes.map(c=>`<code>${c}</code>`).join('')}</div><button class="sm" id="rccopy">${L('Copy all','کپی همه')}</button>`; $('#rccopy').onclick=()=>{ try{ navigator.clipboard.writeText(r.j.codes.join('\n')); }catch(e){} }; const s=await apiX('/api/2fa'); tfaRender(s.j); };
  $('#tfaoff').onclick=()=>{ $('#tfadis').classList.toggle('hide'); };
  $('#tfadisgo').onclick=async()=>{ const r=await apiX('/api/2fa/disable',{password:$('#tfadpw').value,code:$('#tfadcode').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#tfadis').classList.add('hide'); $('#tfadpw').value=''; $('#tfadcode').value=''; const s=await apiX('/api/2fa'); tfaRender(s.j); };
  $('#updchk').onclick=async()=>{ const st=$('#updst'); st.textContent=L('Checking…','در حال بررسی…'); const r=await apiX('/api/update/check'); if(r.j.error){ st.textContent=L('Could not check: ','بررسی نشد: ')+r.j.error; return; } if(r.j.newer){ st.textContent=L('New version v','نسخه جدید v')+r.j.latest+L(' is available',' موجود است')+(r.j.verified?' · ✓ '+L('checksum verified','هش تأیید شد'):' · ⚠ '+L('no checksum published, so the update is blocked','هش منتشر نشده، پس به‌روزرسانی مسدود است')); $('#updgo').classList.toggle('hide',!r.j.verified); } else { st.textContent=L('You have the latest version (v','آخرین نسخه را دارید (v')+r.j.current+')'+(r.j.verified?' · ✓':''); $('#updgo').classList.add('hide'); } };
  $('#updgo').onclick=async()=>{ if(!confirm(L('Update the panel now? It restarts for a few seconds and your tunnels keep running.','پنل الان به‌روز شود؟ چند ثانیه راه‌اندازی مجدد می‌شود و تانل‌ها به کار خود ادامه می‌دهند.'))) return; const st=$('#updst'); st.textContent=L('Updating…','در حال به‌روزرسانی…'); const r=await apiX('/api/update/apply',{}); if(r.s!==200){ st.textContent=r.j.error||'error'; return; } st.textContent=L('Updated to v','به‌روز شد به v')+r.j.version+L(' — restarting…',' — در حال راه‌اندازی مجدد…'); setTimeout(()=>location.reload(),6000); };
}
let _lgsig='', _lgl='all', _lgsel='all', _lgbusy=false;
async function logsPage(){
  if(!$('#lgbox')||_lgbusy) return; if(_lgmode==='aud'){ _lgbusy=true; try{ await auditPage(); } finally{ _lgbusy=false; } return; } _lgbusy=true;
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
    const [st, sl, fl] = await Promise.all([api('/api/stats'), api('/api/slots'), api('/api/fleet').catch(()=>({servers:[]}))]); window._fleet=fl.servers||[]; window._st=st; pairFill();
    push(hist.cpu, st.cpu); push(hist.rx, st.rx_rate); push(hist.tx, st.tx_rate);
    const lv=$('#live'); if(lv){lv.classList.remove('off'); lv.querySelector('b').textContent=L('Online','آنلاین');}
    $('#host').textContent = st.hostname + ' · ' + st.ip;
    dashRender(st, sl.slots); window._slots=sl.slots; if(page==='logs') logsPage(); if(page==='srv') srvRender();
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
    document.body.classList.toggle('viewer',state.role==='viewer'); shell(); go(page); if(window._sp){ window._sp=false; splash(); } timer = setInterval(()=>{ refresh(); if(page==='tun' && tsel==='spoof' && cur==='mon') monitor(); }, 3000);
  } catch(e){ loginView(); msg(e.message,false); }
}
async function act(n, a){ try { const r = await api(`/api/slot/${n}/${a}`, {}); msg(`Tunnel ${n}: ${r.state}`, true); refresh(); } catch(e){ msg(e.message,false);} }
async function del(n){ if(!confirm('Delete tunnel '+n+'?')) return; try { await api(`/api/slot/${n}/delete`, {}); refresh(); } catch(e){ msg(e.message,false);} }
async function logs(n){ try { const r = await api(`/api/slot/${n}/logs`); logSlot = n; go('spoof'); sub('logs'); $('#logbox').textContent = r.logs || '(no logs)'; } catch(e){ msg(e.message,false);} }
/* ===== v7 frontend: pairs, limits, auto-repair, activity, encrypted backups ===== */
function pairFill(){
  const fl=(window._fleet||[]).filter(f=>f.ok&&f.perm==='full');
  const opts='<option value="">'+L('This server only','فقط این سرور')+'</option>'+fl.map(f=>`<option value="${f.id}">${L('This server + ','این سرور + ')}${esc(f.name)}</option>`).join('');
  ['rpair','spair'].forEach(id=>{ const e=$('#'+id); if(e&&e.dataset.o!==opts){ const v=e.value; e.innerHTML=opts; e.dataset.o=opts; e.value=[...e.options].some(o=>o.value===v)?v:''; } });
  pairLayout();
}
function pairLayout(){
  const hide=(sel,on)=>{ const e=$(sel); if(e) e.classList.toggle('hide',on); };
  if($('#rpair')){ const on=!!$('#rpair').value, srv=$('#rrole').value==='server';
    hide('#rports',on?false:!srv); hide('#rth',on?false:srv); hide('#rsip',on?true:srv); }
  if($('#spair')){ const on=!!$('#spair').value, srv=$('#role').value==='server', pr=$('#peer')&&$('#peer').parentElement;
    hide('#lp',on?false:!srv); hide('#fw',on?false:srv); if(pr) pr.classList.toggle('hide',on); }
}
document.addEventListener('change',e=>{ if(['rpair','spair','rrole','role'].includes(e.target.id)) setTimeout(pairLayout,0); });
async function create(){
  const body={role:$('#role').value, peer:$('#peer').value.trim(), transport:$('#transport').value, port:$('#port').value, spoof_ips:$('#spoof_ips').value, listen_port:$('#listen_port').value, forward:$('#forward').value, token:$('#token').value.trim()}, pair=$('#spair').value;
  try{
    if(pair){ const r=await api('/api/pair/create',Object.assign({kind:'spoof',server_id:pair},body)); $('#newtoken').innerHTML=`<div class="msg good">${L('Created on both servers','روی هر دو سرور ساخته شد')}: #${r.local_slot} ⇄ ${esc(r.server)} #${r.remote_slot}</div>`; }
    else { const r=await api('/api/spoof',body); $('#newtoken').innerHTML=`<div class="msg good">Tunnel ${r.slot} created. Token (copy it to the other server):<br><code>${esc(r.token)}</code></div>`; }
    refresh(); _dsig=''; } catch(e){ msg(e.message,false); } }
async function createRev(){
  const body={role:$('#rrole').value, bridge:$('#rbridge').value, ports:$('#rport').value, server_ip:$('#rserver').value.trim(), target_host:$('#rtarget').value.trim(), token:$('#rtoken').value.trim()}, pair=$('#rpair').value;
  try{
    if(pair){ const r=await api('/api/pair/create',Object.assign({kind:'reverse',server_id:pair},body)); $('#rnew').innerHTML=`<div class="msg good">${L('Created on both servers','روی هر دو سرور ساخته شد')}: #${r.local_slot} ⇄ ${esc(r.server)} #${r.remote_slot}</div>`; }
    else { const r=await api('/api/reverse',body); $('#rnew').innerHTML=`<div class="msg good">Tunnel ${r.slot} created. Token (copy it to the other server):<br><code>${esc(r.token)}</code></div>`; }
    refresh(); _dsig=''; } catch(e){ msg(e.message,false); } }
/* limits & history in the details modal */
function limChips(s){
  const l=s.lim; if(!l) return '';
  let o='';
  if(l.blocked) o+=`<span class="mx bad">⛔ ${l.blocked==='quota'?L('quota reached','حجم تمام شد'):L('expired','منقضی شد')}</span>`;
  if(l.quota){ const p=l.used/l.quota; o+=`<span class="mx ${p>=1?'bad':p>.8?'warn':''}">▤ ${fmtB(l.used)} / ${fmtB(l.quota)}</span>`; }
  if(l.days_left!=null&&!l.blocked) o+=`<span class="mx ${l.days_left<=3?'warn':''}">⏳ ${l.days_left} ${L('days','روز')}</span>`;
  return o;
}
function drawBars(cv, days){
  if(!cv) return; const dpr=window.devicePixelRatio||1, w=cv.clientWidth||300, h=cv.clientHeight||90; cv.width=w*dpr; cv.height=h*dpr;
  const c=cv.getContext('2d'); c.scale(dpr,dpr); c.clearRect(0,0,w,h);
  const tot=days.map(d=>d.rx+d.tx), top=Math.max(1,...tot)*1.15, bw=w/days.length;
  c.strokeStyle='rgba(255,255,255,.06)'; for(let i=1;i<4;i++){ c.beginPath(); c.moveTo(0,h*i/4); c.lineTo(w,h*i/4); c.stroke(); }
  days.forEach((d,i)=>{ const x=i*bw+bw*.18, ww=bw*.64, hr=d.rx/top*(h-14), ht=d.tx/top*(h-14); c.fillStyle='#34d0c3'; c.fillRect(x,h-2-hr,ww,hr); c.fillStyle='#e9c46a'; c.fillRect(x,h-2-hr-ht,ww,ht); });
  c.fillStyle='#8fa2bf'; c.font='11px sans-serif'; c.fillText(fmtB(top/1.15),6,12);
}
function limHtml(l){
  if(!l) return `<p class="dnote" style="margin-top:0">${L('No limit set.','محدودیتی تنظیم نشده.')}</p>`;
  const p=l.quota?Math.min(100,l.used/l.quota*100):0;
  return (l.quota?`<div class="dm"><span>${L('Used','مصرف')}</span><em><b style="width:${p}%;${p>=100?'background:#f0707a':''}"></b></em><span style="width:auto;direction:ltr">${fmtB(l.used)} / ${fmtB(l.quota)}</span></div>`:'')
   +`<div class="mxs">${limChips({lim:l})||`<span class="mx">${L('active','فعال')}</span>`}</div>`;
}
function wireDetailExtras(n,d){
  $('#lm_q').value=d.limits&&d.limits.quota?(d.limits.quota/1073741824).toFixed(2).replace(/\.?0+$/,''):'';
  $('#lm_p').value=(d.limits&&d.limits.period)||'month'; $('#lm_e').value=(d.limits&&d.limits.expires)||''; $('#lm_m').value=(d.limits&&d.limits.mbit)||''; $('#lm_m').disabled=!d.nft; $('#lm_m').title=d.nft?'':'nftables is not installed'; $('#dmheal').checked=!!d.heal; shareRender(d.share||{on:false}); wireShare(n);
  const send=async(reset)=>{ const r=await apiX('/api/slot/'+n+'/limits',{quota_gb:$('#lm_q').value||0,period:$('#lm_p').value,expires:$('#lm_e').value,mbit:$('#lm_m').value||0,reset:!!reset}); $('#lmmsg').style.color=r.s===200?'#34d0c3':'#f0707a'; $('#lmmsg').textContent=r.s===200?L('Saved','ذخیره شد'):(r.j.error||'error'); if(r.s===200){ refresh(); dmLoad(); } };
  $('#lmsave').onclick=()=>send(false); $('#lmreset').onclick=()=>{ if(confirm(L('Reset the usage counter and unblock this tunnel?','شمارنده مصرف صفر و تانل آزاد شود؟'))) send(true); };
  $('#dmheal').onchange=async()=>{ const r=await apiX('/api/slot/'+n+'/heal',{on:$('#dmheal').checked}); if(r.s!==200){ alert(r.j.error||'error'); $('#dmheal').checked=!$('#dmheal').checked; } };
}
/* panel activity */
let _lgmode='svc', _lgasig='';
const AUD={login:['Signed in','ورود به پنل'],login_failed:['Failed sign-in','ورود ناموفق'],reverse:['Created reverse tunnel','ساخت تانل معکوس'],spoof:['Created spoof tunnel','ساخت تانل اسپوف'],'pair/create':['Created a tunnel on two servers','ساخت تانل روی دو سرور'],'servers/add':['Added a server','افزودن سرور'],'servers/delete':['Removed a server','حذف سرور'],'servers/act':['Acted on a remote tunnel','عملیات روی تانل سرور دیگر'],'apikeys/create':['Created an API key','ساخت کلید API'],'apikeys/revoke':['Revoked an API key','ابطال کلید API'],'2fa/enable':['Enabled two-factor login','فعال‌سازی ورود دومرحله‌ای'],'2fa/disable':['Disabled two-factor login','غیرفعال‌سازی ورود دومرحله‌ای'],'update/apply':['Updated the panel','به‌روزرسانی پنل'],'backup/create':['Created a backup','ساخت بکاپ'],'backup/restore':['Restored a backup','بازیابی بکاپ'],'backup/pass':['Changed the backup passphrase','تغییر رمز بکاپ'],'backup/delete':['Deleted a backup','حذف بکاپ']};
function audTxt(e){
  let m=AUD[e.a]; if(m) return L(m[0],m[1])+(e.d?' · '+esc(e.d):'');
  const r=e.a.match(/^slot\/(\d+)\/(start|stop|restart|delete|edit|limits|heal)$/);
  if(r){ const v={start:['Started','شروع'],stop:['Stopped','توقف'],restart:['Restarted','ری‌استارت'],delete:['Deleted','حذف'],edit:['Edited','ویرایش'],limits:['Changed limits of','تغییر محدودیت'],heal:['Changed auto-repair of','تغییر ترمیم خودکار']}[r[2]]; return L(v[0]+' tunnel '+r[1],v[1]+' تانل '+r[1])+(e.d?' · '+esc(e.d):''); }
  return esc(e.a)+(e.d?' · '+esc(e.d):'');
}
async function auditPage(){
  const r=await apiX('/api/audit'), q=($('#lgq').value||'').toLowerCase(), box=$('#lgbox'); if(!box) return;
  const rows=(r.j.list||[]).filter(e=>!q||(e.who+' '+e.ip+' '+e.a+' '+e.d).toLowerCase().includes(q));
  const html=rows.map(e=>`<div class="ar"><span class="t">${new Date(e.t*1000).toLocaleString()}</span><b>${esc(e.who)}</b><span class="t">${esc(e.ip)}</span><span class="${/failed/.test(e.a)?'e':''}">${audTxt(e)}</span></div>`).join('')||`<div class="t">${L('No activity yet.','فعالیتی ثبت نشده.')}</div>`;
  if(html!==_lgasig){ _lgasig=html; box.innerHTML=html; }
}
document.addEventListener('click',e=>{ const b=e.target.closest&&e.target.closest('#lgmode button'); if(!b) return; _lgmode=b.dataset.m; document.querySelectorAll('#lgmode button').forEach(x=>x.classList.toggle('on',x===b)); ['#lgsel','#lgl'].forEach(s=>{ const el=$(s); if(el) el.classList.toggle('hide',_lgmode==='aud'); }); _lgsig=''; _lgasig=''; logsPage(); });
/* encrypted backups */
async function bkPassInit(){
  const st=$('#bkpst'); if(!st) return;
  $('#bkpsave').onclick=async()=>{ const r=await apiX('/api/backup/pass',{pass:$('#bkpass').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#bkpass').value=''; alert(L('Saved. New backups are encrypted. Remember this passphrase: without it a backup cannot be restored.','ذخیره شد. بکاپ‌های جدید رمزنگاری می‌شوند. این رمز را به خاطر بسپارید؛ بدون آن بکاپ قابل بازیابی نیست.')); loadBkPass(); };
  $('#bkpclear').onclick=async()=>{ if(!confirm(L('Stop encrypting new backups? Old encrypted backups still need the passphrase.','رمزنگاری بکاپ‌های جدید متوقف شود؟ بکاپ‌های رمزنگاری‌شده قبلی همچنان رمز می‌خواهند.'))) return; await apiX('/api/backup/pass',{clear:true}); loadBkPass(); };
  loadBkPass();
}
async function loadBkPass(){ const r=await apiX('/api/backups'); window._bkenc=!!(r.j&&r.j.enc); const st=$('#bkpst'); if(st) st.textContent=window._bkenc?L('On: new backups (including Telegram copies) are encrypted.','روشن: بکاپ‌های جدید (و نسخه تلگرام) رمزنگاری می‌شوند.'):L('Off: backups are plain files. They contain your tokens and settings.','خاموش: بکاپ‌ها فایل ساده‌اند و توکن‌ها و تنظیمات را دارند.'); $('#bkpclear').classList.toggle('hide',!window._bkenc); }
function askBkPass(){ const p=prompt(L('This backup is encrypted. Passphrase (leave empty to use this panel\'s saved one):','این بکاپ رمزنگاری شده است. رمز را وارد کنید (خالی = رمز ذخیره‌شده همین پنل):')); return p===null?null:p; }
/* ===== v8 frontend: alerts, access, advanced, customer link ===== */
const ALEV=[['tunnel','Tunnel up/down/created/deleted','وصل/قطع/ساخت/حذف تانل'],['login','Logins','ورودها'],['backup','Backups','بکاپ‌ها'],['resource','High CPU / RAM / disk','پر شدن CPU / رم / دیسک'],['health','Latency, packet loss, server offline','تأخیر، افت بسته، آفلاین شدن سرور'],['ssl','SSL certificate expiring','نزدیک انقضای گواهی SSL']];
async function alSave(){
  const body={events:[...document.querySelectorAll('.alev')].filter(c=>c.checked).map(c=>c.value),th:+($('#alth').value||90),
    webhook:{on:$('#whon').checked,url:$('#whurl').value.trim(),fmt:$('#whfmt').value},
    email:{on:$('#emon').checked,host:$('#emhost').value.trim(),port:$('#emport').value||587,sec:$('#emsec').value,user:$('#emuser').value.trim(),pass:$('#empass').value,from:$('#emfrom').value.trim(),to:$('#emto').value.trim()}};
  const r=await apiX('/api/alerts',body); const m=$('#almsg'); m.style.color=r.s===200?'#34d0c3':'#f0707a'; m.textContent=r.s===200?L('Saved','ذخیره شد'):(r.j.error||'error');
  if(r.s===200){ $('#empass').value=''; $('#empass').placeholder=r.j.email.has_pass?'••••••••':''; }
  return r.s===200;
}
async function alTest(ch){ if(ch!=='tg'&&!(await alSave())) return; const r=await apiX('/api/alerts/test',{channel:ch}); alert((r.j.ok?'✓ ':'✗ ')+(r.j.msg||(r.j.error||''))); }
async function vwRender(){ const r=await apiX('/api/viewers'); const el=$('#vwlist'); if(!el) return; el.innerHTML=(r.j.list||[]).map(v=>`<div class="vwr"><span><b>${esc(v.name)}</b> <small style="color:#6f86a8">· ${new Date(v.t*1000).toLocaleDateString()}</small></span><button class="dlink" onclick="vwDel('${esc(v.name)}')">${L('Remove','حذف')}</button></div>`).join('')||`<div class="dempty">${L('No viewer accounts.','حساب بینندهای نیست.')}</div>`; }
async function vwDel(n){ if(!confirm(L('Remove this viewer? They are signed out now.','این بیننده حذف شود؟ همین حالا خارج می‌شود.'))) return; await apiX('/api/viewers/delete',{name:n}); vwRender(); }
async function v8Init(){
  if(!$('#alsave')) return;
  $('#alevs').innerHTML=ALEV.map(e=>`<label><input type="checkbox" class="alev" value="${e[0]}"> ${L(e[1],e[2])}</label>`).join('');
  const a=(await apiX('/api/alerts')).j;
  document.querySelectorAll('.alev').forEach(c=>c.checked=(a.events||[]).includes(c.value)); $('#alth').value=a.th||90;
  const w=a.webhook||{}; $('#whon').checked=w.on!==false; $('#whurl').value=w.url||''; $('#whfmt').value=w.fmt||'generic';
  const m=a.email||{}; $('#emon').checked=m.on!==false; $('#emhost').value=m.host||''; $('#emport').value=m.port||587; $('#emsec').value=m.sec||'starttls'; $('#emuser').value=m.user||''; $('#emfrom').value=m.from||''; $('#emto').value=m.to||''; $('#empass').placeholder=m.has_pass?'••••••••':L('password','رمز');
  $('#alsave').onclick=alSave; $('#whtest').onclick=()=>alTest('webhook'); $('#emtest').onclick=()=>alTest('email');
  const ip=(await apiX('/api/allowips')).j; $('#allowips').value=(ip.list||[]).join(', '); $('#myip').textContent=ip.you||'';
  $('#allowsave').onclick=async()=>{ const r=await apiX('/api/allowips',{list:$('#allowips').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#allowips').value=(r.j.list||[]).join(', '); alert(r.j.list.length?L('Saved. Only these addresses can open the panel now.','ذخیره شد. از این به بعد فقط این آدرس‌ها پنل را باز می‌کنند.'):L('Saved. Everyone can open the panel.','ذخیره شد. همه می‌توانند پنل را باز کنند.')); };
  $('#vwadd').onclick=async()=>{ const r=await apiX('/api/viewers/add',{name:$('#vwname').value.trim(),password:$('#vwpass').value}); if(r.s!==200){ alert(r.j.error||'error'); return; } $('#vwname').value=''; $('#vwpass').value=''; vwRender(); };
  vwRender();
  const ad=(await apiX('/api/advanced')).j; $('#advmax').value=ad.max_slots; $('#metricsurl').textContent=location.origin+BASE+'/metrics';
  $('#nftst').textContent=ad.nft?L('nftables is installed: speed caps are available in each tunnel\'s details (outgoing traffic only, experimental).','nftables نصب است: سقف سرعت در جزئیات هر تانل در دسترس است (فقط ترافیک خروجی، آزمایشی).'):L('nftables is not installed, so speed caps are unavailable (apt install nftables).','nftables نصب نیست، پس سقف سرعت در دسترس نیست (apt install nftables).');
  $('#advsave').onclick=async()=>{ const r=await apiX('/api/advanced',{max_slots:$('#advmax').value}); alert(r.s===200?L('Saved','ذخیره شد'):(r.j.error||'error')); };
}
function shareRender(sh){
  const on=!!(sh&&sh.on); $('#shbox').classList.toggle('hide',!on); $('#shoff').classList.toggle('hide',!on); $('#shregen').classList.toggle('hide',!on);
  $('#shlink').textContent=on?location.origin+'/s/'+sh.token:''; if(on&&sh.label!==undefined) $('#shlabel').value=sh.label;
  $('#shon').textContent=on?L('Save name','ذخیره نام'):L('Create link','ساخت لینک');
}
function wireShare(n){
  const go2=async(body)=>{ const r=await apiX('/api/slot/'+n+'/share',body); if(r.s!==200){ alert(r.j.error||'error'); return; } shareRender(r.j.share); };
  $('#shon').onclick=()=>go2({on:true,label:$('#shlabel').value});
  $('#shregen').onclick=()=>{ if(confirm(L('The old link stops working. Continue?','لینک قبلی از کار می‌افتد. ادامه می‌دهید؟'))) go2({on:true,regen:true}); };
  $('#shoff').onclick=()=>{ if(confirm(L('Disable the customer link?','لینک مشتری غیرفعال شود؟'))) go2({on:false}); };
  $('#shcopy').onclick=()=>{ try{ navigator.clipboard.writeText($('#shlink').textContent); }catch(e){} };
}
async function tfaExtras(){
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
    $('#tgproxy').value=t.proxy||''; }catch(e){}
  $('#tgsave').onclick=async()=>{ try{ await api('/api/tg/save',{token:$('#tgtok').value,chat:$('#tgchat').value,api:$('#tgapi').value,on:true,proxy:$('#tgproxy').value}); $('#tgtok').value=''; alert(L('Saved','ذخیره شد')); }catch(e){alert(e.message);} };
  $('#tgtest').onclick=async()=>{ try{ await api('/api/tg/test',{}); alert(L('Sent. Check Telegram.','ارسال شد. تلگرام را ببینید.')); }catch(e){alert(e.message);} };
  $('#tgdel').onclick=async()=>{ if(confirm(L('Remove Telegram settings?','تنظیمات تلگرام حذف شود؟'))){ await api('/api/tg/clear',{}); $('#tgchat').value='';$('#tgapi').value='';$('#tgcur').textContent=''; } };
  // backups
  const loadBk=async()=>{ try{ const r=await api('/api/backups'); $('#abon').checked=!!r.auto.on; $('#abh').value=r.auto.hours||24; $('#abfull').checked=!!r.auto.full;
    $('#bklist').innerHTML=r.list.map(b=>`<div class="srow"><div class="st"><b dir="ltr">${b.enc?'🔒 ':''}${esc(b.name)}</b><p>${fdate(b.time)} · ${fmtB(b.size)}</p></div><div><a class="sbtn" href="${BASE}/api/backup/get?name=${encodeURIComponent(b.name)}" download>${L('Download','دانلود')}</a> <button class="br" data-n="${esc(b.name)}" data-e="${b.enc?1:0}">${L('Restore','بازیابی')}</button> <button class="bd" data-n="${esc(b.name)}">${L('Delete','حذف')}</button></div></div>`).join('');
    document.querySelectorAll('#bklist .br').forEach(b=>b.onclick=()=>{ const pw=b.dataset.e==='1'?askBkPass():''; if(pw===null) return; restore(pw?{name:b.dataset.n,pass:pw}:{name:b.dataset.n}); });
    document.querySelectorAll('#bklist .bd').forEach(b=>b.onclick=async()=>{ if(confirm(L('Delete this backup?','این بکاپ حذف شود؟'))){await api('/api/backup/delete',{name:b.dataset.n});loadBk();} }); }catch(e){} };
  const restore=async(body)=>{ body.panel=$('#bkpanel').checked; try{ let r; try{ r=await api('/api/backup/restore',body); }catch(e){ if(e.message==='exists' && confirm(L('Some tunnels already exist and will be overwritten. Continue?','برخی تونل‌ها از قبل وجود دارند و بازنویسی می‌شوند. ادامه؟'))){ body.overwrite=true; r=await api('/api/backup/restore',body); } else if(e.message!=='exists') throw e; else return; }
    alert(L(r.restored+' tunnel(s) restored. Now set this server\'s new IP on the other side of each tunnel.',r.restored+' تونل بازیابی شد. حالا آی‌پی جدید این سرور را در سرور مقابل هر تونل وارد کنید.')); }catch(e){alert(e.message);} };
  $('#bknow').onclick=async()=>{ try{ const r=await api('/api/backup/create',{full:$('#bkfull').checked,telegram:$('#bktg').checked}); alert(L('Done: ','انجام شد: ')+r.slots+L(' tunnels',' تونل')+(r.sent?' · Telegram ✓':'')); loadBk(); }catch(e){alert(e.message);} };
  bkPassInit();
  v8Init();
  $('#absave').onclick=async()=>{ try{ await api('/api/backup/auto',{on:$('#abon').checked,hours:+$('#abh').value||24,full:$('#abfull').checked}); alert(L('Saved','ذخیره شد')); }catch(e){alert(e.message);} };
  $('#bkrest').onclick=()=>{ const f=$('#bkfile').files[0]; if(!f) return alert(L('Choose a file','فایل را انتخاب کنید')); const rd=new FileReader(); rd.onload=()=>{ const t=String(rd.result); if(t.startsWith('NTBK1:')){ const pw=askBkPass(); if(pw===null) return; restore(pw?{data:t.trim(),pass:pw}:{data:t.trim()}); return; } let d; try{d=JSON.parse(t);}catch(e){return alert('Invalid JSON');} restore({data:d}); }; rd.readAsText(f); };
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
APP_VERSION = "1.8.0"


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


def make_backup(full=False):
    """Backup = every tunnel slot file (+ tokens) and, if full, the panel settings."""
    slots = {}
    for n in range(1, max_slots() + 1):
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
        if not (k.isdigit() and 1 <= int(k) <= max_slots()) or not isinstance(v, str) or len(v) > 8192:
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
        pw = bk_pass()
        fh.write(bk_encrypt(json.dumps(data), pw) if pw else json.dumps(data))
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
                out.append({"name": f, "size": st.st_size, "time": int(st.st_mtime), "enc": read_backup_text(f)[:6] == BK_MAGIC})
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
                            {"document": (name, read_backup_text(name).encode())})
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
    if raw == base + "/metrics":
        return "/metrics"
    return None


# --------------------------------------------------------------------------
# v6: per-tunnel stats, health, edit, update, 2FA, API keys, multi-server
# --------------------------------------------------------------------------
conf_lock = threading.RLock()
EVENTS_FILE = os.path.join(CONF_DIR, "events.json")
USAGE_FILE = os.path.join(CONF_DIR, "usage.json")
ACCT_DIR = "/etc/systemd/system/nicetunnel@.service.d"
HIST_LEN = 90
slot_stats = {}    # slot -> live numbers from the sampler
slot_hist = {}     # slot -> {"rx": [], "tx": [], "lat": []}
slot_health = {}   # slot -> {"lat", "loss", "peer", "t", "ok_t"}
events_log = []    # [{"t", "slot", "k", "s"?, "v"?}]
usage = {}         # str(slot) -> persistent traffic counters
fleet = {}         # server id -> last poll of a remote panel
_prev = {}
_last_state = {}
_alert_state = {}
_key_last = {}
_state = {"dirty": False}
_cpu_prev = [None]


def _num(v):
    """systemd prints '[not set]' or UINT64_MAX when accounting is off."""
    try:
        x = int(v)
    except (TypeError, ValueError):
        return None
    return x if 0 <= x < 2 ** 63 else None


def _delta(cur, last):
    if cur is None or last is None:
        return 0
    return cur - last if cur >= last else cur


def _atomic_write(path, text):
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def load_state():
    global events_log
    try:
        with open(EVENTS_FILE) as fh:
            ev = json.load(fh)
        if isinstance(ev, list):
            events_log = [e for e in ev if isinstance(e, dict)][-300:]
    except Exception:
        events_log = []
    try:
        with open(USAGE_FILE) as fh:
            u = json.load(fh)
        if isinstance(u, dict):
            usage.update(u)
    except Exception:
        pass
    for e in events_log:
        if e.get("s"):
            _last_state[e["slot"]] = e["s"]


def save_state():
    try:
        _atomic_write(EVENTS_FILE, json.dumps(events_log[-300:]))
        _atomic_write(USAGE_FILE, json.dumps(usage))
    except OSError:
        pass
    _state["dirty"] = False


def record_event(n, kind, state=None, value=None):
    e = {"t": int(time.time()), "slot": n, "k": kind}
    if state is not None:
        e["s"] = state
    if value is not None:
        e["v"] = value
    events_log.append(e)
    del events_log[:-300]
    _state["dirty"] = True


def uptime_pct(n, window=86400):
    """Share of the last `window` seconds the tunnel was active, from recorded state changes."""
    now = time.time()
    evs = sorted((e for e in events_log if e.get("slot") == n and e.get("s")), key=lambda e: e["t"])
    if not evs:
        return None
    start = max(now - window, evs[0]["t"])
    if now - start < 60:
        return None
    cur = None
    for e in evs:
        if e["t"] <= start:
            cur = e["s"]
        else:
            break
    if cur is None:
        cur = evs[0]["s"]
    act, t = 0.0, start
    for e in evs:
        if e["t"] <= start:
            continue
        if cur == "active":
            act += e["t"] - t
        t, cur = e["t"], e["s"]
    if cur == "active":
        act += now - t
    return round(100.0 * act / (now - start), 1)


# -- alerts ------------------------------------------------------------------
def alert_raise(key, text, event, cooldown=1800):
    s = _alert_state.setdefault(key, {"on": False, "t": 0})
    now = time.time()
    if not s["on"] or now - s["t"] >= cooldown:
        tg_send(text, event)
        s["t"] = now
    s["on"] = True


def alert_clear(key, text, event):
    s = _alert_state.get(key)
    if s and s["on"]:
        s["on"] = False
        tg_send(text, event)


# -- per-tunnel stats --------------------------------------------------------
def ensure_accounting(slots=None):
    """Per-service byte/CPU/memory accounting is what makes per-tunnel numbers possible."""
    want = "[Service]\nIPAccounting=yes\nCPUAccounting=yes\nMemoryAccounting=yes\n"
    try:
        os.makedirs(ACCT_DIR, exist_ok=True)
        p = os.path.join(ACCT_DIR, "accounting.conf")
        cur = ""
        if os.path.exists(p):
            with open(p) as fh:
                cur = fh.read()
        if cur != want:
            with open(p, "w") as fh:
                fh.write(want)
            run(["systemctl", "daemon-reload"])
    except OSError:
        pass
    for sl in (slots if slots is not None else list_slots()):
        if sl["state"] == "active":
            run(["systemctl", "set-property", "--runtime", "nicetunnel@%d" % sl["slot"],
                 "IPAccounting=yes", "CPUAccounting=yes", "MemoryAccounting=yes"])


def tcp_conn_counts():
    out = {}
    _, o = run(["ss", "-H", "-t", "-n", "-p", "state", "established"], timeout=8)
    for line in o.splitlines():
        for pid in re.findall(r"pid=(\d+)", line):
            out[pid] = out.get(pid, 0) + 1
    return out


def cgroup_pids(cg):
    if not cg or not cg.startswith("/") or ".." in cg:
        return []
    try:
        with open("/sys/fs/cgroup" + cg + "/cgroup.procs") as fh:
            return [x.strip() for x in fh if x.strip().isdigit()]
    except OSError:
        return []


def sample_slots():
    slots = list_slots()
    conns = tcp_conn_counts()
    now = time.time()
    today, mon = time.strftime("%Y-%m-%d"), time.strftime("%Y-%m")
    conf = load_panel_conf()
    seen = set()
    ncpu = os.cpu_count() or 1
    for sl in slots:
        n = sl["slot"]
        seen.add(n)
        _, o = run(["systemctl", "show", "nicetunnel@%d" % n, "-p",
                    "IPIngressBytes,IPEgressBytes,CPUUsageNSec,MemoryCurrent,NRestarts,"
                    "ActiveEnterTimestampMonotonic,ControlGroup"])
        p = dict(l.split("=", 1) for l in o.splitlines() if "=" in l)
        i_b, o_b = _num(p.get("IPIngressBytes")), _num(p.get("IPEgressBytes"))
        cpu_ns, mem = _num(p.get("CPUUsageNSec")), _num(p.get("MemoryCurrent"))
        state = sl["state"]
        u = usage.setdefault(str(n), {})
        if u.get("day") != today:
            u.update(day=today, drx=0, dtx=0)
        d_in, d_out = _delta(i_b, u.get("li")), _delta(o_b, u.get("lo"))
        if i_b is not None:
            u["li"] = i_b
        if o_b is not None:
            u["lo"] = o_b
        u["rx"], u["tx"] = u.get("rx", 0) + d_in, u.get("tx", 0) + d_out
        u["drx"], u["dtx"] = u.get("drx", 0) + d_in, u.get("dtx", 0) + d_out
        if u.get("mon") != mon:
            u.update(mon=mon, mrx=0, mtx=0)
        u["mrx"], u["mtx"] = u.get("mrx", 0) + d_in, u.get("mtx", 0) + d_out
        dd = u.setdefault("days", {}).setdefault(today, [0, 0])
        dd[0] += d_in
        dd[1] += d_out
        if len(u["days"]) > 95:
            for k in sorted(u["days"])[:-90]:
                u["days"].pop(k, None)
        pv = _prev.get(n)
        rx = tx = cpu = None
        if pv and now > pv["t"] + 0.5:
            dt = now - pv["t"]
            if i_b is not None:
                rx, tx = d_in / dt, d_out / dt
            if cpu_ns is not None and pv.get("cpu") is not None and cpu_ns >= pv["cpu"]:
                cpu = min(999.0, (cpu_ns - pv["cpu"]) / 1e9 / dt * 100.0)
        _prev[n] = {"t": now, "cpu": cpu_ns}
        up_s = None
        amt = _num(p.get("ActiveEnterTimestampMonotonic"))
        if state == "active" and amt:
            up_s = max(0, int(time.monotonic() - amt / 1e6))
        slot_stats[n] = {
            "state": state, "acct": i_b is not None, "rx_rate": rx, "tx_rate": tx,
            "rx_total": u["rx"], "tx_total": u["tx"], "day_rx": u["drx"], "day_tx": u["dtx"],
            "conns": sum(conns.get(x, 0) for x in cgroup_pids(p.get("ControlGroup", ""))),
            "cpu": cpu, "mem": mem or 0, "uptime": up_s, "cg": p.get("ControlGroup", ""),
            "restarts": int(p["NRestarts"]) if p.get("NRestarts", "").isdigit() else 0,
        }
        if rx is not None:
            h = slot_hist.setdefault(n, {"rx": [], "tx": [], "lat": []})
            h["rx"].append(round(rx, 1))
            h["tx"].append(round(tx, 1))
            del h["rx"][:-HIST_LEN], h["tx"][:-HIST_LEN]
        if _last_state.get(n) != state:
            record_event(n, "seen" if n not in _last_state else "state", state=state)
            _last_state[n] = state
        limits_tick(n, conf)
        heal_tick(n, state, slot_health.get(n, {}), conf)
    cleanup_orphans(seen)
    for n in list(slot_stats):
        if n not in seen:
            for d in (slot_stats, slot_hist, slot_health, _prev):
                d.pop(n, None)
            usage.pop(str(n), None)
            _last_state.pop(n, None)


def reverse_server_peer(bridge):
    """On the Iran side of a reverse tunnel the peer is whoever holds the bridge connection."""
    if not str(bridge).isdigit():
        return ""
    _, o = run(["ss", "-H", "-t", "-n", "state", "established", "sport", "=", ":%s" % bridge], timeout=6)
    for line in o.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[-1].rsplit(":", 1)[0].strip("[]")
            if valid_ipv4(ip):
                return ip
    return ""


def slot_peer(sl):
    ip = sl.get("peer") if sl["kind"] == "spoof" else sl.get("server_ip")
    if ip and valid_ipv4(ip):
        return ip
    if sl["kind"] == "reverse" and sl.get("role") == "server":
        return reverse_server_peer(sl.get("bridge"))
    return ""


def probe_host(ip, count=3):
    if not valid_ip(ip):
        return None
    cmd = ["ping", "-n", "-c", str(count), "-i", "0.3", "-W", "1", ip]
    if ":" in ip:
        cmd.insert(1, "-6")
    _, out = run(cmd, timeout=count * 2 + 5)
    m = re.search(r"([\d.]+)% packet loss", out)
    if not m:
        return None
    r = re.search(r"= [\d.]+/([\d.]+)/([\d.]+)/", out)
    return {"lat": float(r.group(1)) if r else None, "max": float(r.group(2)) if r else None,
            "loss": float(m.group(1)), "t": int(time.time())}


def apply_probe(n, ip, r):
    h = slot_health.get(n, {})
    if r:
        h = dict(h, lat=r["lat"], loss=r["loss"], max=r["max"], t=r["t"], peer=ip)
        if r["loss"] < 100:
            h["ok_t"] = r["t"]
        hist = slot_hist.setdefault(n, {"rx": [], "tx": [], "lat": []})
        if r["lat"] is not None:
            hist["lat"].append(round(r["lat"], 1))
            del hist["lat"][:-HIST_LEN]
    else:
        h = dict(h, peer=ip, t=int(time.time()), lat=None, loss=None)
    slot_health[n] = h
    return h


def health_round():
    slots = list_slots()
    targets = {}
    for sl in slots:
        ip = slot_peer(sl)
        if ip:
            targets[sl["slot"]] = ip
    results = {}
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futs = {n: ex.submit(probe_host, ip) for n, ip in targets.items()}
            for n, f in futs.items():
                try:
                    results[n] = f.result(timeout=30)
                except Exception:
                    results[n] = None
    for n in list(slot_health):
        if n not in targets:
            slot_health.pop(n, None)
    for n, ip in targets.items():
        h = apply_probe(n, ip, results.get(n))
        key = "loss:%d" % n
        if h.get("loss") is not None and h["loss"] >= 50:
            h["bad"] = h.get("bad", 0) + 1
            if h["bad"] == 2:
                record_event(n, "loss", value=h["loss"])
            if h["bad"] >= 2:
                alert_raise(key, "📉 تانل %d (%s): افت بسته %d٪ به %s" % (n, host_label(), h["loss"], ip), "health")
        elif h.get("loss") is not None:
            if h.get("bad", 0) >= 2:
                record_event(n, "loss_ok")
            h["bad"] = 0
            alert_clear(key, "✅ تانل %d (%s): ارتباط با %s برگشت" % (n, host_label(), ip), "health")
        key2 = "lat:%d" % n
        if h.get("lat") is not None and h["lat"] > 350:
            h["slow"] = h.get("slow", 0) + 1
            if h["slow"] >= 3:
                alert_raise(key2, "🐢 تانل %d (%s): تأخیر بالا %d ms به %s" % (n, host_label(), h["lat"], ip), "health")
        elif h.get("lat") is not None:
            h["slow"] = 0
            alert_clear(key2, "✅ تانل %d (%s): تأخیر عادی شد" % (n, host_label()), "health")
        slot_health[n] = h


def health_loop():
    while True:
        try:
            health_round()
        except Exception:
            pass
        time.sleep(30)


# -- server resources & certificate alerts -----------------------------------
def cpu_percent():
    try:
        with open("/proc/stat") as fh:
            v = [int(x) for x in fh.readline().split()[1:]]
    except Exception:
        return None
    idle, total = v[3] + (v[4] if len(v) > 4 else 0), sum(v)
    p, _cpu_prev[0] = _cpu_prev[0], (idle, total)
    if not p or total == p[1]:
        return None
    return 100.0 * (1 - (idle - p[0]) / (total - p[1]))


def mem_percent():
    try:
        m = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                m[k] = int(v.split()[0])
        return 100.0 * (1 - m["MemAvailable"] / m["MemTotal"])
    except Exception:
        return None


def disk_percent():
    try:
        u = shutil.disk_usage("/")
        return 100.0 * u.used / u.total
    except Exception:
        return None


_cpu_samples = []


def resource_alerts():
    th = alert_th(load_panel_conf())
    c = cpu_percent()
    if c is not None:
        _res["cpu"] = c
    if c is not None:
        _cpu_samples.append(c)
        del _cpu_samples[:-6]
        avg = sum(_cpu_samples) / len(_cpu_samples)
        if len(_cpu_samples) >= 6 and avg >= th:
            alert_raise("cpu", "🔥 مصرف پردازنده سرور %s بالاست: %d٪" % (host_label(), avg), "resource")
        elif avg < th - 5:
            alert_clear("cpu", "✅ مصرف پردازنده سرور %s عادی شد" % host_label(), "resource")
    for key, val, label in (("mem", mem_percent(), "حافظه (RAM)"), ("disk", disk_percent(), "دیسک")):
        if val is None:
            continue
        _res[key] = val
        if val >= th:
            alert_raise(key, "⚠️ %s سرور %s پر شده: %d٪" % (label, host_label(), val), "resource")
        elif val < th - 5:
            alert_clear(key, "✅ %s سرور %s به حالت عادی برگشت" % (label, host_label()), "resource")


def ssl_days_left():
    import calendar
    try:
        with open(UNIT_PATH) as fh:
            txt = fh.read()
    except OSError:
        return None
    m = re.search(r"--cert (\S+)", txt)
    if not m:
        return None
    _, out = run(["openssl", "x509", "-enddate", "-noout", "-in", m.group(1)])
    mm = re.search(r"notAfter=(.+)", out)
    if not mm:
        return None
    try:
        ts = calendar.timegm(time.strptime(re.sub(r"\s+", " ", mm.group(1).replace("GMT", "")).strip(), "%b %d %H:%M:%S %Y"))
    except ValueError:
        return None
    return (ts - time.time()) / 86400.0


def ssl_alert():
    d = ssl_days_left()
    if d is None:
        return
    if d < 14:
        alert_raise("ssl", "🔐 گواهی SSL پنل %s تا %d روز دیگر منقضی می‌شود" % (host_label(), max(0, d)), "ssl", cooldown=86400)
    elif d > 20:
        alert_clear("ssl", "✅ گواهی SSL پنل %s تمدید شد" % host_label(), "ssl")


def sampler_loop():
    load_state()
    audit_load()
    try:
        ensure_accounting()
    except Exception:
        pass
    tick = 0
    while True:
        try:
            sample_slots()
            resource_alerts()
            if tick == 3:
                err = caps_apply()
                if err:
                    record_event(0, "cap_error", value=err)
            if tick % 720 == 0:
                ssl_alert()
            if tick % 12 == 0 or _state["dirty"]:
                save_state()
        except Exception:
            pass
        tick += 1
        time.sleep(5)


def slots_with_stats():
    out = list_slots()
    conf = load_panel_conf()
    for sl in out:
        n = sl["slot"]
        st, h = slot_stats.get(n, {}), slot_health.get(n, {})
        sl.update(rx_rate=st.get("rx_rate"), tx_rate=st.get("tx_rate"), rx_total=st.get("rx_total"),
                  tx_total=st.get("tx_total"), conns=st.get("conns"), acct=st.get("acct", False),
                  lat=h.get("lat"), loss=h.get("loss"), peer_ip=h.get("peer", "") or slot_peer_cached(sl),
                  up24=uptime_pct(n), lim=limit_state(n, conf), heal=heal_on(n, conf))
    return out


def slot_peer_cached(sl):
    ip = sl.get("peer") if sl["kind"] == "spoof" else sl.get("server_ip")
    return ip if ip and valid_ipv4(ip) else ""


def slot_detail(n):
    sl = next((x for x in slots_with_stats() if x["slot"] == n), None)
    if not sl:
        return None
    return {"slot": sl, "stats": slot_stats.get(n, {}), "health": slot_health.get(n, {}),
            "hist": slot_hist.get(n, {"rx": [], "tx": [], "lat": []}),
            "events": [e for e in events_log if e.get("slot") == n][-30:][::-1],
            "up24": uptime_pct(n), "up7": uptime_pct(n, 7 * 86400),
            "limits": limit_state(n), "heal": heal_on(n), "days": last_days(n),
            "share": share_view(n), "nft": nft_available()}


# -- edit a tunnel -------------------------------------------------------------
def slot_edit(n, d):
    """Changes a tunnel's settings in place. Role cannot change. Returns (result, error)."""
    try:
        env = read_env(slot_file(n))
    except OSError:
        return None, "no such tunnel"
    kind = env.get("TYPE") or "tcp"
    role = env.get("ROLE", "")
    if kind == "spoof":
        base = {"role": role, "transport": env.get("TRANSPORT", "udp"), "peer": env.get("PEER_IP", ""),
                "spoof_ips": env.get("SPOOF_IPS", ""), "port": env.get("TPORT", "4500"),
                "listen_port": env.get("LISTEN_PORT", "0"), "forward": env.get("FORWARD", ""),
                "token": env.get("NICETUNNEL_TOKEN", "")}
        check, writer = validate_spoof, write_spoof_slot
    else:
        base = {"role": role, "bridge": env.get("BRIDGE", "7000"), "ports": env.get("PORTS", ""),
                "server_ip": env.get("SERVER_IP", ""), "target_host": env.get("TARGET_HOST", ""),
                "token": env.get("NICETUNNEL_TOKEN", "")}
        check, writer = validate_reverse, write_reverse_slot
    for k, v in d.items():
        if k in base and k != "role" and v is not None and str(v).strip() != "":
            base[k] = v
    clean, err = check(base)
    if err:
        return None, err
    _, st = run(["systemctl", "is-active", "nicetunnel@%d" % n])
    was_active = st.strip() == "active"
    writer(n, clean)
    run(["systemctl", "daemon-reload"])
    restarted = False
    if was_active or d.get("restart"):
        code, out = run(["systemctl", "restart", "nicetunnel@%d" % n])
        restarted = code == 0
        if code != 0:
            return None, "saved but could not restart: " + out.strip()[-200:]
    record_event(n, "edit")
    tg_send("✏️ تانل %d ویرایش شد (%s)" % (n, host_label()), "tunnel")
    return {"ok": True, "restarted": restarted, "token_changed": clean["token"] != env.get("NICETUNNEL_TOKEN", "")}, None


# -- update (verified against a SHA-256 published beside the file) -------------------
def fetch_url(url, limit=4000000):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "NiceTunnelPanel/" + APP_VERSION, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read(limit)


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def update_fetch():
    """Returns (data, version, verified, note). `verified` means it matches NAME.sha256 from the same place."""
    import urllib.error
    data = fetch_url(RAW_URL)
    m = re.search(rb'^APP_VERSION = "([0-9][0-9.]*)"', data, re.M)
    ver = m.group(1).decode() if m else None
    verified, note = False, ""
    try:
        txt = fetch_url(os.environ.get("NICETUNNEL_CHECKSUM_URL") or RAW_URL + ".sha256", 4096).decode("ascii", "ignore")
        mm = re.match(r"\s*([0-9a-fA-F]{64})\b", txt)
        if not mm:
            raise ValueError("the checksum file is malformed")
        if not hmac.compare_digest(mm.group(1).lower(), hashlib.sha256(data).hexdigest()):
            raise ValueError("checksum mismatch: the download does not match its published SHA-256, try again later")
        verified = True
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        note = "no checksum published"
    except urllib.error.URLError as exc:
        if not isinstance(exc.reason, FileNotFoundError):
            raise
        note = "no checksum published"
    return data, ver, verified, note


def update_check():
    try:
        _, ver, verified, note = update_fetch()
    except Exception as exc:
        return {"current": APP_VERSION, "error": str(exc)[:160]}
    if not ver:
        return {"current": APP_VERSION, "error": "remote file has no version"}
    return {"current": APP_VERSION, "latest": ver, "newer": version_tuple(ver) > version_tuple(APP_VERSION),
            "verified": verified, "note": note}


def update_apply(restart_delay=1.5):
    data, ver, verified, _ = update_fetch()
    if not verified and os.environ.get("NICETUNNEL_ALLOW_UNVERIFIED") != "1":
        raise ValueError("update blocked: no SHA-256 checksum is published next to the file (%s.sha256). "
                         "Publish one (see the README), or set NICETUNNEL_ALLOW_UNVERIFIED=1 to accept the risk." % os.path.basename(RAW_URL))
    if not ver or len(data) < 50000 or b"def main" not in data or b"class Handler" not in data:
        raise ValueError("downloaded file looks wrong")
    compile(data, "nicetunnel_panel.py", "exec")   # never replace a working panel with a broken file
    target = os.path.join(APP_DIR, "nicetunnel_panel.py")
    try:
        shutil.copy2(target, target + ".bak")
    except OSError:
        pass
    with open(target + ".new", "wb") as fh:
        fh.write(data)
    os.chmod(target + ".new", 0o755)
    os.replace(target + ".new", target)
    if restart_delay <= 0:
        run(["systemctl", "restart", "nicetunnel-panel"])
    else:
        threading.Timer(restart_delay, lambda: run(["systemctl", "restart", "nicetunnel-panel"])).start()
    return ver


# -- two-factor login (TOTP, RFC 6238) ---------------------------------------------
def totp_at(secret, counter, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%0*d" % (digits, (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits))


def totp_match(secret, code, now=None, window=1):
    """Counter of the matching 30 s step, or None."""
    code = re.sub(r"\s", "", str(code))
    if not re.fullmatch(r"\d{6}", code):
        return None
    c0 = int((now if now is not None else time.time()) // 30)
    found = None
    for d in range(-window, window + 1):
        if hmac.compare_digest(totp_at(secret, c0 + d), code):
            found = c0 + d
    return found


def tfa_enabled(conf=None):
    t = (conf if conf is not None else load_panel_conf()).get("tfa") or {}
    return bool(t.get("on") and t.get("secret"))


def norm_rec(c):
    return re.sub(r"[^0-9a-f]", "", str(c).lower())


def tfa_verify(code):
    """TOTP code (each 30 s step only once) or a single-use recovery code."""
    with conf_lock:
        conf = load_panel_conf()
        t = conf.get("tfa") or {}
        if not t.get("secret"):
            return False
        ctr = totp_match(t["secret"], code)
        if ctr is not None:
            if ctr > int(t.get("last", 0)):
                t["last"] = ctr
                conf["tfa"] = t
                save_panel_conf(conf)
                return True
            return False
        rc = norm_rec(code)
        if len(rc) == 12:
            h = hash_tok(rc)
            for x in list(t.get("rec", [])):
                if hmac.compare_digest(x, h):
                    t["rec"].remove(x)
                    conf["tfa"] = t
                    save_panel_conf(conf)
                    return True
        return False


def tfa_setup():
    from urllib.parse import quote
    secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    with conf_lock:
        conf = load_panel_conf()
        conf["tfa_pending"] = {"s": secret, "t": int(time.time())}
        save_panel_conf(conf)
    label = quote("NiceTunnel:%s@%s" % (conf.get("username", "admin"), host_label()))
    return secret, "otpauth://totp/%s?secret=%s&issuer=NiceTunnel&algorithm=SHA1&digits=6&period=30" % (label, secret)


def tfa_enable(code):
    with conf_lock:
        conf = load_panel_conf()
        p = conf.get("tfa_pending") or {}
        if not p or time.time() - p.get("t", 0) > 900:
            return None, "the setup key expired, start again"
        ctr = totp_match(p["s"], code)
        if ctr is None:
            return None, "wrong code, check the time on your phone"
        raw = [secrets.token_hex(6) for _ in range(8)]
        conf["tfa"] = {"on": True, "secret": p["s"], "last": ctr, "rec": [hash_tok(r) for r in raw]}
        conf.pop("tfa_pending", None)
        save_panel_conf(conf)
    return ["-".join(r[i:i + 4] for i in (0, 4, 8)) for r in raw], None


def tfa_disable():
    with conf_lock:
        conf = load_panel_conf()
        conf.pop("tfa", None)
        conf.pop("tfa_pending", None)
        save_panel_conf(conf)


# -- API keys (let another panel manage this server) --------------------------------
KEY_GET = re.compile(r"/(api/(ping|stats|slots|slot/\d+/(logs|detail))|metrics)")
KEY_POST = re.compile(r"/api/slot/\d+/(start|stop|restart|probe)")
KEY_FULL_POST = re.compile(r"/api/(reverse|spoof|slot/\d+/(edit|delete))")


def apikey_create(name, full=False, ips=""):
    ip_list = parse_ip_list(ips)
    with conf_lock:
        conf = load_panel_conf()
        keys = conf.get("apikeys", [])
        if len(keys) >= 10:
            raise ValueError("too many API keys (max 10)")
        key = "nt_" + secrets.token_urlsafe(32)
        kid = secrets.token_hex(4)
        keys.append({"id": kid, "name": (str(name).strip() or "key")[:40], "h": hash_tok(key), "t": int(time.time()),
                     "perm": "full" if full else "manage", "ips": ip_list})
        conf["apikeys"] = keys
        save_panel_conf(conf)
    return kid, key


def apikey_check(key):
    """Returns the key's permission level ("manage" or "full"), or "" if the key is not valid."""
    if not key or len(key) > 200:
        return ""
    h, perm = hash_tok(key), ""
    for k in load_panel_conf().get("apikeys", []):
        if hmac.compare_digest(k["h"], h):
            perm = k.get("perm", "manage")
            _key_last[k["id"]] = int(time.time())
    return perm


def apikey_list():
    return [{"id": k["id"], "name": k["name"], "t": k["t"], "last": _key_last.get(k["id"], 0), "perm": k.get("perm", "manage"),
             "ips": k.get("ips", [])}
            for k in load_panel_conf().get("apikeys", [])]


def apikey_revoke(kid):
    with conf_lock:
        conf = load_panel_conf()
        conf["apikeys"] = [k for k in conf.get("apikeys", []) if k["id"] != kid]
        save_panel_conf(conf)


# -- other servers ---------------------------------------------------------------------
class RemoteError(Exception):
    def __init__(self, msg, fp=None, untrusted=False):
        super().__init__(msg)
        self.fp, self.untrusted = fp, untrusted


def cert_fp(der):
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


def parse_srv_url(u):
    p = urlparse(str(u).strip())
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.query or p.fragment:
        return None
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return None
    base = p.path.rstrip("/")
    if not re.fullmatch(r"(/[A-Za-z0-9._~-]{1,64}){0,3}", base):
        return None
    return p.scheme, p.hostname, port, base


def fetch_fp(host, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return cert_fp(ss.getpeercert(binary_form=True))
    except Exception:
        return ""


def remote_call(srv, method, path, body=None, timeout=8):
    """Talks to another NiceTunnel panel with its API key. Pinned certificates are compared by fingerprint."""
    parsed = parse_srv_url(srv.get("url", ""))
    if not parsed:
        raise RemoteError("bad server address")
    sch, host, port, base = parsed
    pin = srv.get("pin") or ""
    conn = None
    try:
        if sch == "https":
            ctx = ssl.create_default_context()
            if pin:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.connect()
        if sch == "https" and pin:
            fp = cert_fp(conn.sock.getpeercert(binary_form=True))
            if not hmac.compare_digest(fp, pin):
                raise RemoteError("the server's certificate changed", fp)
        data = json.dumps(body).encode() if body is not None else None
        hdr = {"X-API-Key": srv.get("key", ""), "Accept": "application/json"}
        if data is not None:
            hdr["Content-Type"] = "application/json"
        conn.request(method, base + path, data, hdr)
        r = conn.getresponse()
        raw = r.read(2000000)
        try:
            obj = json.loads(raw)
        except ValueError:
            raise RemoteError("not a NiceTunnel panel (HTTP %d)" % r.status)
        if r.status >= 400:
            raise RemoteError(str(obj.get("error", "HTTP %d" % r.status)) if isinstance(obj, dict) else "HTTP %d" % r.status)
        return obj
    except RemoteError:
        raise
    except ssl.SSLCertVerificationError:
        raise RemoteError("certificate not trusted", untrusted=True)
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise RemoteError(str(exc)[:150] or "connection failed")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def host_for_url(h):
    return "[%s]" % h if ":" in h else h


def server_add(name, url, key, pin=""):
    parsed = parse_srv_url(url)
    if not parsed:
        raise ValueError("panel address is not valid, example: https://1.2.3.4:45152/k-abc123")
    if not re.fullmatch(r"nt_[A-Za-z0-9_-]{20,90}", str(key or "")):
        raise ValueError("the API key looks wrong")
    nm = re.sub(r"[\x00-\x1f<>]", "", str(name or "")).strip()[:40] or parsed[1]
    srv = {"id": secrets.token_hex(4), "name": nm, "key": key, "pin": str(pin or "")[:100],
           "url": "%s://%s:%d%s" % (parsed[0], host_for_url(parsed[1]), parsed[2], parsed[3])}
    try:
        info = remote_call(srv, "GET", "/api/ping")
    except RemoteError as exc:
        if exc.untrusted:
            exc.fp = fetch_fp(parsed[1], parsed[2])
        raise
    if not isinstance(info, dict) or not info.get("ok"):
        raise ValueError("that address is not a NiceTunnel panel")
    srv["perm"] = info.get("perm", "manage")
    with conf_lock:
        conf = load_panel_conf()
        lst = conf.get("servers", [])
        if len(lst) >= 20:
            raise ValueError("too many servers (max 20)")
        if any(s["url"] == srv["url"] for s in lst):
            raise ValueError("this server is already added")
        lst.append(srv)
        conf["servers"] = lst
        save_panel_conf(conf)
    return srv, info


def fleet_round():
    servers = load_panel_conf().get("servers", [])
    ids = {s["id"] for s in servers}
    for k in list(fleet):
        if k not in ids:
            fleet.pop(k, None)

    def one(s):
        old = fleet.get(s["id"], {})
        try:
            pg = remote_call(s, "GET", "/api/ping")
            st = remote_call(s, "GET", "/api/stats")
            sl = remote_call(s, "GET", "/api/slots")
            fleet[s["id"]] = {"ok": True, "t": int(time.time()), "stats": st, "slots": sl.get("slots", []),
                              "err": "", "fails": 0, "perm": pg.get("perm", "manage")}
            alert_clear("srv:" + s["id"], "✅ سرور %s دوباره آنلاین شد" % s["name"], "health")
        except RemoteError as exc:
            nf = old.get("fails", 0) + 1
            fleet[s["id"]] = {"ok": False, "t": old.get("t", 0), "stats": old.get("stats"),
                              "slots": old.get("slots", []), "err": str(exc), "fails": nf}
            if nf >= 3:
                alert_raise("srv:" + s["id"], "🔴 سرور %s آفلاین شد: %s" % (s["name"], str(exc)[:80]), "health")

    if servers:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(one, servers))


def fleet_loop():
    while True:
        try:
            fleet_round()
        except Exception:
            pass
        time.sleep(10)


def fleet_view():
    out = []
    for s in load_panel_conf().get("servers", []):
        f = fleet.get(s["id"], {})
        out.append({"id": s["id"], "name": s["name"], "url": s["url"], "ok": bool(f.get("ok")), "t": f.get("t", 0),
                    "err": f.get("err", ""), "stats": f.get("stats"), "slots": f.get("slots", []),
                    "pinned": bool(s.get("pin")), "checked": bool(f), "perm": f.get("perm") or s.get("perm", "manage")})
    return out


def find_server(sid):
    return next((s for s in load_panel_conf().get("servers", []) if s["id"] == sid), None)



# --------------------------------------------------------------------------
# v7: one-click pairs, auto-repair, limits, audit log, encrypted backups
# --------------------------------------------------------------------------
AUDIT_FILE = os.path.join(CONF_DIR, "audit.json")
audit_log = []
_heal = {}
_audit_lock = threading.Lock()


# -- create a tunnel on this server and on another one --------------------------
def create_local(kind, clean):
    n = first_free_slot()
    if n is None:
        return None, "no free slot (max %d)" % max_slots()
    (write_spoof_slot if kind == "spoof" else write_reverse_slot)(n, clean)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "nicetunnel@%d" % n])
    code, out = run(["systemctl", "restart", "nicetunnel@%d" % n])
    if code != 0:
        return n, "saved but could not start: " + out.strip()[-300:]
    return n, None


def pair_create(d):
    """Builds both ends of a tunnel with the same token and ports. Rolls back the far end if this end fails."""
    srv = find_server(str(d.get("server_id", "")))
    if not srv:
        raise ValueError("unknown server")
    f = fleet.get(srv["id"], {})
    if not f.get("ok"):
        raise ValueError("that server is offline right now")
    if (f.get("perm") or srv.get("perm") or "manage") != "full":
        raise ValueError("the API key for that server cannot create tunnels. Make a key with that option on the other panel and add the server again.")
    remote_ip = str((f.get("stats") or {}).get("ip") or "")
    local_ip = public_ip_guess()
    if not valid_ipv4(remote_ip) or not valid_ipv4(local_ip):
        raise ValueError("could not work out the public IP of both servers")
    kind, role = d.get("kind"), d.get("role")
    if kind not in ("spoof", "reverse") or role not in ("server", "client"):
        raise ValueError("bad request")
    other = "client" if role == "server" else "server"
    if kind == "spoof":
        base = {"transport": d.get("transport", "udp"), "spoof_ips": d.get("spoof_ips", ""), "port": d.get("port", 4500),
                "listen_port": d.get("listen_port", 0), "forward": d.get("forward") or "127.0.0.1:51820",
                "token": str(d.get("token", "")).strip()}
        loc, rem = dict(base, role=role, peer=remote_ip), dict(base, role=other, peer=local_ip)
        check, route = validate_spoof, "/api/spoof"
    else:
        srv_ip = local_ip if role == "server" else remote_ip
        base = {"bridge": d.get("bridge", 7000), "token": str(d.get("token", "")).strip()}
        side = {"server": {"role": "server", "ports": d.get("ports", "")},
                "client": {"role": "client", "server_ip": srv_ip, "target_host": d.get("target_host") or "127.0.0.1"}}
        loc, rem = dict(base, **side[role]), dict(base, **side[other])
        check, route = validate_reverse, "/api/reverse"
    c_loc, err = check(loc)
    if err:
        raise ValueError(err)
    rem["token"] = c_loc["token"]
    c_rem, err = check(rem)
    if err:
        raise ValueError(err)
    r = remote_call(srv, "POST", route, c_rem, timeout=25)
    rslot = r.get("slot")
    n, err = create_local(kind, c_loc)
    if err:
        if isinstance(rslot, int):
            try:
                remote_call(srv, "POST", "/api/slot/%d/delete" % rslot, {}, timeout=15)
            except RemoteError:
                pass
        raise ValueError(err + " (the other server's copy was removed)")
    return {"ok": True, "local_slot": n, "remote_slot": rslot, "token": c_loc["token"], "server": srv["name"]}


# -- auto-repair -------------------------------------------------------------------
def heal_on(n, conf=None):
    return bool(((conf if conf is not None else load_panel_conf()).get("heal") or {}).get(str(n)))


def heal_set(n, on):
    with conf_lock:
        conf = load_panel_conf()
        h = conf.get("heal") or {}
        h[str(n)] = bool(on)
        conf["heal"] = h
        save_panel_conf(conf)


def heal_tick(n, state, h, conf):
    """Restarts a tunnel that stays broken for 2.5 minutes (failed, or no ping reply). At most 3 times an hour."""
    if not heal_on(n, conf) or limit_blocked(n, conf):
        _heal.pop(n, None)
        return
    s = _heal.setdefault(n, {"bad": 0, "t": []})
    broken = state == "failed" or (state == "active" and h.get("loss") == 100)
    s["bad"] = s["bad"] + 1 if broken else 0
    if s["bad"] < 30:
        return
    s["bad"] = 0
    now = time.time()
    s["t"] = [t for t in s["t"] if now - t < 3600]
    if len(s["t"]) >= 3:
        alert_raise("heal:%d" % n, "🛠 تانل %d (%s): ری‌استارت خودکار نتیجه نداد، بررسی دستی لازم است" % (n, host_label()), "tunnel", cooldown=3600)
        return
    s["t"].append(now)
    run(["systemctl", "restart", "nicetunnel@%d" % n])
    record_event(n, "heal")
    tg_send("🛠 تانل %d (%s) به‌صورت خودکار ری‌استارت شد" % (n, host_label()), "tunnel")


# -- traffic and time limits ---------------------------------------------------------
def limit_state(n, conf=None):
    lim = ((conf if conf is not None else load_panel_conf()).get("limits") or {}).get(str(n))
    if not lim:
        return None
    u = usage.get(str(n), {})
    quota = int(float(lim.get("quota_gb") or 0) * 1024 ** 3)
    period = lim.get("period", "month")
    used = max(0, u.get("rx", 0) + u.get("tx", 0) - u.get("qbase", 0)) if period == "total" else u.get("mrx", 0) + u.get("mtx", 0)
    exp, days_left = lim.get("expires") or "", None
    if exp:
        try:
            import datetime
            days_left = (datetime.date.fromisoformat(exp) - datetime.date.today()).days
        except ValueError:
            days_left = None
    return {"quota": quota, "used": used, "period": period, "expires": exp, "days_left": days_left, "blocked": lim.get("blocked", ""), "mbit": lim.get("mbit", 0)}


def limit_blocked(n, conf=None):
    s = limit_state(n, conf)
    return s["blocked"] if s else ""


def limit_write(n, **changes):
    with conf_lock:
        conf = load_panel_conf()
        lim = conf.get("limits") or {}
        cur = lim.get(str(n)) or {}
        cur.update(changes)
        if not cur.get("quota_gb") and not cur.get("expires") and not cur.get("mbit"):
            lim.pop(str(n), None)
        else:
            lim[str(n)] = cur
        conf["limits"] = lim
        save_panel_conf(conf)


def limits_tick(n, conf):
    s = limit_state(n, conf)
    if not s:
        return
    reason = ""
    if s["quota"] and s["used"] >= s["quota"]:
        reason = "quota"
    if s["days_left"] is not None and s["days_left"] < 0:
        reason = "expired"
    cur, unit = s["blocked"], "nicetunnel@%d" % n
    if reason and cur != reason:
        limit_write(n, blocked=reason)
        run(["systemctl", "stop", unit])
        record_event(n, "blocked", value=reason)
        tg_send("⛔ تانل %d (%s) متوقف شد: %s" % (n, host_label(), "حجم مجاز تمام شد" if reason == "quota" else "مهلت تمام شد"), "tunnel")
    elif not reason and cur:
        limit_write(n, blocked="")
        run(["systemctl", "start", unit])
        record_event(n, "unblocked")
        tg_send("✅ تانل %d (%s) دوباره فعال شد" % (n, host_label()), "tunnel")


def limit_apply(n, d):
    import datetime
    try:
        quota = float(d.get("quota_gb") or 0)
    except (TypeError, ValueError):
        raise ValueError("quota must be a number of GB")
    if not (0 <= quota <= 1000000):
        raise ValueError("quota must be between 0 and 1,000,000 GB")
    period = d.get("period", "month")
    if period not in ("month", "total"):
        raise ValueError("period must be month or total")
    exp = str(d.get("expires") or "").strip()
    if exp:
        try:
            datetime.date.fromisoformat(exp)
        except ValueError:
            raise ValueError("expiry must look like 2026-12-31")
    u = usage.setdefault(str(n), {})
    if d.get("reset"):
        u["mrx"] = u["mtx"] = 0
        u["qbase"] = u.get("rx", 0) + u.get("tx", 0)
        _state["dirty"] = True
    if "mbit" in d:
        try:
            mbit = float(d.get("mbit") or 0)
        except (TypeError, ValueError):
            raise ValueError("the speed cap must be a number of Mbit/s")
        if not (0 <= mbit <= 100000):
            raise ValueError("the speed cap must be between 0 and 100000 Mbit/s")
        prev = float(((load_panel_conf().get("limits") or {}).get(str(n)) or {}).get("mbit", 0) or 0)
        if mbit != prev:
            limit_write(n, mbit=mbit)
            err = caps_apply()
            if err:
                limit_write(n, mbit=prev)
                caps_apply()
                raise ValueError(err)
    limit_write(n, quota_gb=quota, period=period, expires=exp, **({"blocked": ""} if d.get("reset") else {}))
    limits_tick(n, load_panel_conf())
    return limit_state(n)


def last_days(n, count=30):
    import datetime
    days = (usage.get(str(n)) or {}).get("days", {})
    out, today = [], datetime.date.today()
    for i in range(count - 1, -1, -1):
        k = (today - datetime.timedelta(days=i)).isoformat()
        rx, tx = days.get(k, [0, 0])
        out.append({"d": k, "rx": rx, "tx": tx})
    return out


# -- audit log ------------------------------------------------------------------------
def audit_load():
    global audit_log
    try:
        with open(AUDIT_FILE) as fh:
            a = json.load(fh)
        audit_log = [e for e in a if isinstance(e, dict)][-500:] if isinstance(a, list) else []
    except Exception:
        audit_log = []


def audit_add(who, ip, action, detail=""):
    with _audit_lock:
        audit_log.append({"t": int(time.time()), "who": str(who)[:40], "ip": str(ip)[:45], "a": str(action)[:60], "d": str(detail)[:120]})
        del audit_log[:-500]
        try:
            _atomic_write(AUDIT_FILE, json.dumps(audit_log))
        except OSError:
            pass


AUDIT_SKIP = re.compile(r"/api/(slot/\d+/probe|logout|tester/.*|spoof-test.*)")


def audit_http(h, code, obj):
    """Called for every JSON reply. Logs changes (POST) and failed logins, never request values."""
    if h.command != "POST":
        return
    path = getattr(h, "_path", "") or ""
    body = getattr(h, "_body", None) or {}
    ip = h.client_address[0]
    if path == "/api/login":
        user = str(body.get("username", "") or ("link" if body.get("link") else ""))
        if code == 200 and not (isinstance(obj, dict) and obj.get("need_otp")):
            audit_add(user or "admin", ip, "login")
        elif code in (401, 429):
            audit_add(user or "?", ip, "login_failed")
        return
    if code >= 400 or AUDIT_SKIP.fullmatch(path) or not path.startswith("/api/"):
        return
    who = "api-key" if getattr(h, "_apikey", False) else (sess_owner.get(h.session_id()) or "?")
    detail = ""
    if isinstance(body, dict) and re.search(r"/(edit|limits|heal)$", path):
        detail = ", ".join(sorted(k for k in body if k != "token"))[:100]
    elif isinstance(obj, dict) and obj.get("slot"):
        detail = "slot %s" % obj["slot"]
    elif isinstance(obj, dict) and obj.get("local_slot"):
        detail = "slot %s + %s#%s" % (obj["local_slot"], obj.get("server", "remote"), obj.get("remote_slot"))
    audit_add(who, ip, path[5:], detail)


# -- encrypted backups (scrypt + HMAC-SHA256 stream, encrypt-then-MAC) ---------------------
BK_MAGIC = "NTBK1:"


def _bk_keys(passphrase, salt):
    k = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=64)
    return k[:32], k[32:]


def _bk_stream(key, nonce, length):
    out, i = bytearray(), 0
    while len(out) < length:
        out += hmac.new(key, nonce + struct.pack(">Q", i), hashlib.sha256).digest()
        i += 1
    return bytes(out[:length])


def bk_encrypt(text, passphrase):
    salt, nonce = os.urandom(16), os.urandom(16)
    ek, mk = _bk_keys(passphrase, salt)
    raw = text.encode("utf-8") if isinstance(text, str) else text
    ct = bytes(a ^ b for a, b in zip(raw, _bk_stream(ek, nonce, len(raw))))
    tag = hmac.new(mk, b"NTBK1" + salt + nonce + ct, hashlib.sha256).digest()
    return BK_MAGIC + base64.b64encode(salt + nonce + ct + tag).decode("ascii")


def bk_decrypt(text, passphrase):
    if not str(text).startswith(BK_MAGIC):
        raise ValueError("not an encrypted backup")
    try:
        blob = base64.b64decode(str(text)[len(BK_MAGIC):].strip(), validate=True)
    except Exception:
        raise ValueError("the backup file is damaged")
    if len(blob) < 64 + 1:
        raise ValueError("the backup file is damaged")
    salt, nonce, ct, tag = blob[:16], blob[16:32], blob[32:-32], blob[-32:]
    ek, mk = _bk_keys(passphrase, salt)
    if not hmac.compare_digest(hmac.new(mk, b"NTBK1" + salt + nonce + ct, hashlib.sha256).digest(), tag):
        raise ValueError("wrong passphrase (or the file was changed)")
    return bytes(a ^ b for a, b in zip(ct, _bk_stream(ek, nonce, len(ct)))).decode("utf-8")


def bk_pass():
    return str(load_panel_conf().get("bk_pass") or "")


def bk_load_text(text, passphrase=""):
    """Plain or encrypted backup text -> dict."""
    if str(text).startswith(BK_MAGIC):
        pw = passphrase or bk_pass()
        if not pw:
            raise ValueError("this backup is encrypted, a passphrase is required")
        text = bk_decrypt(text, pw)
    return json.loads(text)


def read_backup_text(name):
    with open(os.path.join(BACKUP_DIR, name), "r") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# v8: proxy for Telegram, webhook + email alerts, IP allowlists, customer links,
#     viewer accounts, Prometheus metrics, speed caps, IPv6 access, tunnel limit
# --------------------------------------------------------------------------
share_fails = {}
key_fails = {}
_res = {"cpu": None, "mem": None, "disk": None}
_max_slots = {"v": None}
DEFAULT_EVENTS = ["tunnel", "login", "backup", "resource", "ssl", "health"]
NFT_TABLE = "nicetunnel_cap"
SHARE_RE = re.compile(r"/s/([A-Za-z0-9_-]{16,64})(\.json)?")
VIEWER_GET = re.compile(r"/api/(state|stats|slots|fleet|ping|slot/\d+/(logs|detail))")


def valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# -- outgoing HTTP with optional proxy (HTTP CONNECT or SOCKS5) -------------------------
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("the proxy closed the connection")
        buf += chunk
    return buf


def socks5_connect(proxy_url, host, port, timeout):
    pp = urlparse(proxy_url)
    s = socket.create_connection((pp.hostname, pp.port or 1080), timeout=timeout)
    try:
        s.settimeout(timeout)
        want_auth = pp.username is not None
        s.sendall(b"\x05\x02\x00\x02" if want_auth else b"\x05\x01\x00")
        r = _recv_exact(s, 2)
        if r[0] != 5 or r[1] == 0xFF:
            raise OSError("the SOCKS5 proxy refused the login method")
        if r[1] == 2:
            from urllib.parse import unquote
            u, p = unquote(pp.username or "").encode(), unquote(pp.password or "").encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _recv_exact(s, 2)[1] != 0:
                raise OSError("the SOCKS5 proxy rejected the username or password")
        try:
            ip = ipaddress.ip_address(host)
            addr = (b"\x01" + ip.packed) if ip.version == 4 else (b"\x04" + ip.packed)
        except ValueError:
            h = host.encode("idna")
            addr = b"\x03" + bytes([len(h)]) + h     # the proxy resolves the name (socks5h behaviour)
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
        resp = _recv_exact(s, 4)
        if resp[1] != 0:
            raise OSError("the SOCKS5 proxy could not connect (code %d)" % resp[1])
        if resp[3] == 1:
            _recv_exact(s, 6)
        elif resp[3] == 4:
            _recv_exact(s, 18)
        elif resp[3] == 3:
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        return s
    except Exception:
        s.close()
        raise


class _Socks5HTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, proxy, timeout):
        super().__init__(host, port, timeout=timeout)
        self._proxy = proxy

    def connect(self):
        self.sock = socks5_connect(self._proxy, self.host, self.port, self.timeout)


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, proxy, timeout):
        super().__init__(host, port, timeout=timeout)
        self._proxy = proxy

    def connect(self):
        raw = socks5_connect(self._proxy, self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def valid_proxy(p):
    u = urlparse(str(p))
    if u.scheme not in ("http", "socks5", "socks5h") or not u.hostname or u.path not in ("", "/") or u.query:
        return False
    try:
        u.port
    except ValueError:
        return False
    return len(str(p)) <= 200


def mask_proxy(p):
    u = urlparse(str(p or ""))
    if not u.hostname:
        return ""
    auth = (u.username + ":***@") if u.username else ""
    return "%s://%s%s%s" % (u.scheme, auth, host_for_url(u.hostname), (":%d" % u.port) if u.port else "")


def http_request(method, url, data=None, headers=None, timeout=15, proxy=""):
    """One HTTP request, directly or through an HTTP (CONNECT) or SOCKS5 proxy. Returns (status, body)."""
    from urllib.parse import unquote
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("bad address")
    https = u.scheme == "https"
    host, port = u.hostname, u.port or (443 if https else 80)
    target = (u.path or "/") + (("?" + u.query) if u.query else "")
    hdrs = dict(headers or {})
    conn = None
    try:
        if proxy:
            pp = urlparse(proxy)
            if pp.scheme in ("socks5", "socks5h"):
                conn = (_Socks5HTTPSConnection if https else _Socks5HTTPConnection)(host, port, proxy, timeout)
            elif pp.scheme == "http":
                pauth = None
                if pp.username:
                    tok = base64.b64encode(("%s:%s" % (unquote(pp.username), unquote(pp.password or ""))).encode()).decode()
                    pauth = {"Proxy-Authorization": "Basic " + tok}
                if https:
                    conn = http.client.HTTPSConnection(pp.hostname, pp.port or 8080, timeout=timeout)
                    conn.set_tunnel(host, port, headers=pauth)
                else:
                    conn = http.client.HTTPConnection(pp.hostname, pp.port or 8080, timeout=timeout)
                    target = url
                    hdrs.update(pauth or {})
            else:
                raise ValueError("unsupported proxy type")
        else:
            conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=timeout)
        conn.request(method, target, body=data, headers=hdrs)
        r = conn.getresponse()
        return r.status, r.read(1000000)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def tg_call(method, fields=None, files=None):
    """Calls the Telegram Bot API (through the saved proxy, if any). Returns (ok, text). Never raises."""
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
            body, ctype = b"".join(parts), "multipart/form-data; boundary=" + bd
        else:
            body, ctype = json.dumps(fields or {}).encode(), "application/json"
        status, raw = http_request("POST", url, body, {"Content-Type": ctype}, 15, tg.get("proxy", ""))
        text = raw.decode("utf-8", "replace")[:300]
        if status >= 400:
            return False, ("HTTP %d: %s" % (status, text)).replace(token, "***")[:200]
        return True, text
    except Exception as exc:
        return False, str(exc).replace(token, "***")[:200]


# -- alert channels: Telegram, webhook, email ------------------------------------------------
def alert_conf(conf):
    return (conf or {}).get("alerts") or {}


def alert_events(conf):
    a = alert_conf(conf)
    if "events" in a:
        return a["events"]
    return (conf.get("tg") or {}).get("events", DEFAULT_EVENTS)


def alert_th(conf):
    try:
        return min(99, max(50, int(alert_conf(conf).get("th") or (conf.get("tg") or {}).get("th") or 90)))
    except (TypeError, ValueError):
        return 90


def webhook_send(wh, text, event):
    fmt = wh.get("fmt", "generic")
    if fmt == "discord":
        payload = {"content": text[:1900]}
    elif fmt == "slack":
        payload = {"text": text[:3000]}
    else:
        payload = {"text": text, "event": event or "alert", "host": host_label(), "time": int(time.time()), "version": APP_VERSION}
    try:
        status, raw = http_request("POST", wh["url"], json.dumps(payload).encode(), {"Content-Type": "application/json"}, 12)
    except Exception as exc:
        return False, str(exc)[:160]
    return (200 <= status < 300), ("HTTP %d" % status)


def email_send(em, text, event):
    msg = EmailMessage()
    clean = lambda v: re.sub(r"[\r\n\x00-\x1f]", " ", str(v))[:120]
    msg["Subject"] = "NiceTunnel %s: %s" % (clean(host_label()), clean(event or "alert"))
    msg["From"], msg["To"] = clean(em["from"]), clean(em["to"])
    msg.set_content(text)
    try:
        if em.get("sec") == "ssl":
            s = smtplib.SMTP_SSL(em["host"], int(em["port"]), timeout=15, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(em["host"], int(em["port"]), timeout=15)
        with s:
            s.ehlo()
            if em.get("sec") == "starttls":
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if em.get("user"):
                s.login(em["user"], em.get("pass", ""))
            s.send_message(msg)
    except Exception as exc:
        return False, str(exc).replace(em.get("pass", "\0"), "***")[:160]
    return True, "sent"


def tg_send(text, event=None):
    """Sends an alert to every channel that is switched on (name kept for the existing callers)."""
    conf = load_panel_conf()
    if event and event not in alert_events(conf):
        return
    tg, a = conf.get("tg", {}), alert_conf(conf)
    if tg.get("token") and tg.get("chat") and tg.get("on", True):
        threading.Thread(target=tg_call, args=("sendMessage", {"chat_id": tg["chat"], "text": text}), daemon=True).start()
    wh = a.get("webhook") or {}
    if wh.get("url") and wh.get("on", True):
        threading.Thread(target=webhook_send, args=(wh, text, event), daemon=True).start()
    em = a.get("email") or {}
    if em.get("host") and em.get("to") and em.get("on", True):
        threading.Thread(target=email_send, args=(em, text, event), daemon=True).start()


def alerts_view(conf=None):
    conf = conf if conf is not None else load_panel_conf()
    a, tg = alert_conf(conf), conf.get("tg", {})
    wh, em = a.get("webhook") or {}, a.get("email") or {}
    return {"events": alert_events(conf), "th": alert_th(conf),
            "webhook": {"on": wh.get("on", True), "url": wh.get("url", ""), "fmt": wh.get("fmt", "generic")},
            "email": {"on": em.get("on", True), "host": em.get("host", ""), "port": em.get("port", 587), "sec": em.get("sec", "starttls"),
                      "user": em.get("user", ""), "from": em.get("from", ""), "to": em.get("to", ""), "has_pass": bool(em.get("pass"))},
            "proxy": mask_proxy(tg.get("proxy", ""))}


def alerts_save(d):
    with conf_lock:
        conf = load_panel_conf()
        a = conf.get("alerts") or {}
        if "events" in d:
            a["events"] = [e for e in (d["events"] or []) if e in DEFAULT_EVENTS]
        if "th" in d:
            try:
                a["th"] = min(99, max(50, int(d["th"])))
            except (TypeError, ValueError):
                a["th"] = 90
        if "webhook" in d:
            w = d["webhook"] or {}
            url = str(w.get("url", "")).strip()
            if url and not re.fullmatch(r"https?://[^\s]{4,480}", url):
                raise ValueError("the webhook address must start with http:// or https://")
            fmt = w.get("fmt", "generic")
            if fmt not in ("generic", "discord", "slack"):
                raise ValueError("unknown webhook format")
            a["webhook"] = {"on": bool(w.get("on", True)), "url": url, "fmt": fmt}
        if "email" in d:
            e = d["email"] or {}
            old = a.get("email") or {}
            host, to, frm = str(e.get("host", "")).strip(), str(e.get("to", "")).strip(), str(e.get("from", "")).strip()
            if host:
                if not re.fullmatch(r"[A-Za-z0-9.-]{1,200}", host):
                    raise ValueError("the mail server name looks wrong")
                try:
                    port = int(e.get("port") or 587)
                except (TypeError, ValueError):
                    raise ValueError("the mail port must be a number")
                if not 1 <= port <= 65535:
                    raise ValueError("the mail port must be between 1 and 65535")
                sec = e.get("sec", "starttls")
                if sec not in ("starttls", "ssl", "none"):
                    raise ValueError("unknown mail security mode")
                mail = r"[^@\s<>,;]{1,64}@[A-Za-z0-9.-]{1,200}"
                if not re.fullmatch(mail, to) or not re.fullmatch(mail, frm or to):
                    raise ValueError("the email addresses look wrong")
                pw = str(e.get("pass", ""))
                a["email"] = {"on": bool(e.get("on", True)), "host": host, "port": port, "sec": sec, "user": str(e.get("user", "")).strip()[:120],
                              "from": frm or to, "to": to, "pass": pw if pw else ("" if e.get("clear_pass") else old.get("pass", ""))}
            else:
                a["email"] = {}
        conf["alerts"] = a
        if "proxy" in d:
            p = str(d["proxy"] or "").strip()
            tg = conf.get("tg", {})
            if not p:
                tg.pop("proxy", None)
            elif p != mask_proxy(tg.get("proxy", "")):     # unchanged masked value keeps the saved one
                if not valid_proxy(p):
                    raise ValueError("the proxy must look like socks5://host:1080 or http://host:8080")
                tg["proxy"] = p
            conf["tg"] = tg
        save_panel_conf(conf)
    return alerts_view()


def alert_test(channel):
    conf = load_panel_conf()
    text = "✅ NiceTunnel test message from %s" % host_label()
    if channel == "tg":
        tg = conf.get("tg", {})
        if not tg.get("chat"):
            return False, "set the chat ID first"
        return tg_call("sendMessage", {"chat_id": tg["chat"], "text": text})
    if channel == "webhook":
        wh = alert_conf(conf).get("webhook") or {}
        return webhook_send(wh, text, "test") if wh.get("url") else (False, "set the webhook address first")
    if channel == "email":
        em = alert_conf(conf).get("email") or {}
        return email_send(em, text, "test") if em.get("host") else (False, "set the mail server first")
    return False, "unknown channel"


# -- who may reach the panel -------------------------------------------------------------------
def norm_ip(s):
    try:
        ip = ipaddress.ip_address(str(s).split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def parse_ip_list(v):
    items = [x.strip() for x in (re.split(r"[,\s]+", v) if isinstance(v, str) else (v or [])) if str(x).strip()]
    if len(items) > 50:
        raise ValueError("too many entries (max 50)")
    out = []
    for x in items:
        try:
            out.append(str(ipaddress.ip_network(x, strict=False)))
        except ValueError:
            raise ValueError("not a valid IP address or network: %s" % str(x)[:40])
    return out


def ip_allowed(ip, nets):
    a = norm_ip(ip)
    if a is None:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def apikey_match(key):
    if not key or len(key) > 200:
        return None
    h, found = hash_tok(key), None
    for k in load_panel_conf().get("apikeys", []):
        if hmac.compare_digest(k["h"], h):
            found = k
            _key_last[k["id"]] = int(time.time())
    return found


def key_ip_ok(k, ip):
    ips = k.get("ips") or []
    return (not ips) or ip_allowed(ip, ips)


# -- viewer accounts (read only) ---------------------------------------------------------------
def viewer_add(name, pw):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", str(name)):
        raise ValueError("the name must be 3 to 32 letters, digits, dots, dashes or underscores")
    if not (8 <= len(str(pw)) <= 200):
        raise ValueError("the password must be 8 to 200 characters")
    with conf_lock:
        conf = load_panel_conf()
        lst = conf.get("viewers", [])
        if name == conf.get("username", "admin") or any(v["name"] == name for v in lst):
            raise ValueError("that name is already taken")
        if len(lst) >= 10:
            raise ValueError("too many viewer accounts (max 10)")
        lst.append({"name": name, "hash": hash_password(str(pw)), "t": int(time.time())})
        conf["viewers"] = lst
        save_panel_conf(conf)


def viewer_delete(name):
    with conf_lock:
        conf = load_panel_conf()
        conf["viewers"] = [v for v in conf.get("viewers", []) if v["name"] != name]
        save_panel_conf(conf)
    with lock:
        for sid, own in list(sess_owner.items()):
            if own == "viewer:" + name:
                sessions.pop(sid, None)
                sess_owner.pop(sid, None)
                sess_info.pop(sid, None)


# -- customer links (public, read only) --------------------------------------------------------------
def share_set(n, on=True, label=None, regen=False):
    with conf_lock:
        conf = load_panel_conf()
        sh = conf.get("shares") or {}
        cur = sh.get(str(n))
        if not on:
            sh.pop(str(n), None)
        else:
            if not cur or regen:
                cur = {"tok": secrets.token_urlsafe(18), "t": int(time.time()), "label": (cur or {}).get("label", "")}
            if label is not None:
                cur["label"] = re.sub(r"[\x00-\x1f<>]", "", re.sub(r"<[^>]*>", "", str(label))).strip()[:60]
            sh[str(n)] = cur
        conf["shares"] = sh
        save_panel_conf(conf)
    return share_view(n)


def share_view(n, conf=None):
    e = ((conf if conf is not None else load_panel_conf()).get("shares") or {}).get(str(n))
    return {"on": True, "token": e["tok"], "label": e.get("label", "")} if e else {"on": False}


def share_find(tok):
    found = None
    for k, v in (load_panel_conf().get("shares") or {}).items():
        if hmac.compare_digest(str(v.get("tok", "")), tok):
            found = (int(k), v)
    return found


def share_data(n, ent):
    st, lim, u = slot_stats.get(n, {}), limit_state(n) or {}, usage.get(str(n), {})
    state = lim.get("blocked") or ("active" if st.get("state") == "active" else "failed" if st.get("state") == "failed" else "off")
    return {"label": ent.get("label", ""), "state": state, "quota": lim.get("quota", 0), "used": lim.get("used", 0),
            "period": lim.get("period", "month"), "days_left": lim.get("days_left"), "expires": lim.get("expires", ""),
            "today": [u.get("drx", 0), u.get("dtx", 0)], "month": [u.get("mrx", 0), u.get("mtx", 0)],
            "days": last_days(n), "t": int(time.time())}


SHARE_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>NiceTunnel</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,#040a16,#08172b 60%,#071426);color:#e6ecf6;font:15px/1.6 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;display:flex;justify-content:center;padding:24px 14px}
.c{width:100%;max-width:460px}.logo{text-align:center;margin:6px 0 18px;font-weight:700;letter-spacing:.4px;font-size:18px;background:linear-gradient(90deg,#fff3c9,#e9c46a);-webkit-background-clip:text;background-clip:text;color:transparent}
.card{background:linear-gradient(160deg,rgba(14,30,54,.94),rgba(8,18,34,.94));border:1px solid rgba(233,196,106,.16);border-radius:18px;padding:18px;box-shadow:0 20px 60px rgba(0,0,0,.45)}
h1{margin:0 0 8px;font-size:20px;color:#fff;word-break:break-word}.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12px;border:1px solid #2a3b57;color:#8fa2bf}.pill.ok{color:#34d0c3;border-color:rgba(52,208,195,.4);background:rgba(52,208,195,.08)}.pill.bad{color:#f0707a;border-color:rgba(240,112,122,.4);background:rgba(240,112,122,.08)}
.row{display:flex;justify-content:space-between;gap:10px;margin:16px 0 6px;font-size:13px;color:#8fa2bf}.row b{color:#fff;direction:ltr;unicode-bidi:isolate}
.bar{height:8px;border-radius:6px;background:#0e2038;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,#34d0c3,#e9c46a);border-radius:6px}.bar.full i{background:#f0707a}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}.cell{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:10px 12px}.cell span{display:block;font-size:11.5px;color:#8fa2bf}.cell b{display:block;margin-top:2px;font-size:14px;direction:ltr;text-align:start;unicode-bidi:isolate}
h2{font-size:13px;margin:18px 0 0;color:#fff}canvas{width:100%;height:90px;display:block;margin-top:8px;border:1px solid rgba(255,255,255,.05);border-radius:12px;background:#050d18}.note{margin-top:12px;font-size:12px;color:#6f86a8;text-align:center}
</style></head><body><div class="c"><div class="logo">NiceTunnel</div><div class="card" id="card"><div class="note">&hellip;</div></div><div class="note" id="upd"></div></div>
<script>
(function(){
var fa=(navigator.language||'').toLowerCase().indexOf('fa')===0;
var T=fa?{active:'فعال',off:'متوقف',failed:'قطع',quota:'حجم تمام شد',expired:'منقضی شده',used:'مصرف',left:'باقی‌مانده',days:'روز',exp:'انقضا',today:'امروز',month:'این ماه',last30:'۳۰ روز اخیر',nolim:'بدون سقف حجم',updated:'به‌روزرسانی',nf:'این لینک معتبر نیست.',total:'کل'}
:{active:'Active',off:'Stopped',failed:'Not connected',quota:'Data limit reached',expired:'Expired',used:'Used',left:'Left',days:'days',exp:'Expires',today:'Today',month:'This month',last30:'Last 30 days',nolim:'No data limit',updated:'Updated',nf:'This link is not valid.',total:'Total'};
if(fa){document.documentElement.lang='fa';document.documentElement.dir='rtl';}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function fmt(b){var u=['B','KB','MB','GB','TB'],i=0;b=+b||0;while(b>=1024&&i<4){b/=1024;i++;}return (b>=100||i===0?b.toFixed(0):b.toFixed(1))+' '+u[i];}
var tok=location.pathname.split('/').pop().replace(/\.json$/,'');
function draw(days){var cv=document.getElementById('cv');if(!cv)return;var dpr=window.devicePixelRatio||1,w=cv.clientWidth||300,h=cv.clientHeight||90;cv.width=w*dpr;cv.height=h*dpr;var c=cv.getContext('2d');c.scale(dpr,dpr);
 var top=Math.max.apply(null,days.map(function(d){return d.rx+d.tx;}).concat([1]))*1.15,bw=w/days.length;
 days.forEach(function(d,i){var x=i*bw+bw*.18,ww=bw*.64,a=d.rx/top*(h-14),b=d.tx/top*(h-14);c.fillStyle='#34d0c3';c.fillRect(x,h-2-a,ww,a);c.fillStyle='#e9c46a';c.fillRect(x,h-2-a-b,ww,b);});}
function render(d){
 var ok=d.state==='active',cls=ok?'ok':(d.state==='off'?'':'bad'),h='<h1>'+esc(d.label||'NiceTunnel')+'</h1><span class="pill '+cls+'">'+esc(T[d.state]||d.state)+'</span>';
 if(d.quota){var p=Math.min(100,d.used/d.quota*100);h+='<div class="row"><span>'+T.used+'</span><b>'+fmt(d.used)+' / '+fmt(d.quota)+'</b></div><div class="bar'+(p>=100?' full':'')+'"><i style="width:'+p+'%"></i></div><div class="row"><span>'+T.left+'</span><b>'+fmt(Math.max(0,d.quota-d.used))+'</b></div>';}
 else h+='<div class="row"><span>'+T.nolim+'</span><b></b></div>';
 h+='<div class="grid">';
 if(d.days_left!==null&&d.days_left!==undefined)h+='<div class="cell"><span>'+T.exp+'</span><b>'+(d.days_left<0?T.expired:d.days_left+' '+T.days)+'</b></div>';
 h+='<div class="cell"><span>'+T.today+'</span><b>'+fmt(d.today[0]+d.today[1])+'</b></div><div class="cell"><span>'+T.month+'</span><b>'+fmt(d.month[0]+d.month[1])+'</b></div></div>';
 h+='<h2>'+T.last30+'</h2><canvas id="cv"></canvas>';
 document.getElementById('card').innerHTML=h;draw(d.days);
 document.getElementById('upd').textContent=T.updated+': '+new Date(d.t*1000).toLocaleTimeString();}
function load(){fetch('/s/'+tok+'.json',{cache:'no-store'}).then(function(r){if(!r.ok)throw 0;return r.json();}).then(render).catch(function(){document.getElementById('card').innerHTML='<div class="note">'+T.nf+'</div>';});}
load();setInterval(load,30000);
})();
</script></body></html>"""


# -- Prometheus metrics ----------------------------------------------------------------------------
def _mesc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _net_totals():
    rx = tx = 0
    try:
        with open("/proc/net/dev") as fh:
            for line in fh.readlines()[2:]:
                name, _, rest = line.partition(":")
                if name.strip() == "lo":
                    continue
                f = rest.split()
                rx, tx = rx + int(f[0]), tx + int(f[8])
    except (OSError, ValueError, IndexError):
        return None, None
    return rx, tx


def metrics_text():
    out = []

    def put(name, typ, help_, rows):
        rows = [(l, v) for l, v in rows if v is not None]
        if not rows:
            return
        out.append("# HELP %s %s" % (name, help_))
        out.append("# TYPE %s %s" % (name, typ))
        for labels, v in rows:
            lab = ",".join('%s="%s"' % (k, _mesc(x)) for k, x in labels.items())
            out.append("%s%s %s" % (name, "{%s}" % lab if lab else "", repr(float(v)) if not isinstance(v, int) else v))

    put("nicetunnel_info", "gauge", "Panel version and host name", [({"version": APP_VERSION, "host": host_label()}, 1)])
    put("nicetunnel_cpu_percent", "gauge", "CPU use of this server", [({}, _res["cpu"])])
    put("nicetunnel_memory_percent", "gauge", "Memory use of this server", [({}, _res["mem"])])
    put("nicetunnel_disk_percent", "gauge", "Disk use of this server", [({}, _res["disk"])])
    rx, tx = _net_totals()
    put("nicetunnel_network_receive_bytes_total", "counter", "Bytes received on all interfaces", [({}, rx)])
    put("nicetunnel_network_transmit_bytes_total", "counter", "Bytes sent on all interfaces", [({}, tx)])
    slots = slots_with_stats()
    base = lambda s: {"slot": s["slot"], "kind": s["kind"], "peer": s.get("peer_ip", "")}
    put("nicetunnel_tunnel_up", "gauge", "1 when the tunnel service is active", [(base(s), 1 if s["state"] == "active" else 0) for s in slots])
    put("nicetunnel_tunnel_receive_bytes_total", "counter", "Bytes received by the tunnel", [(base(s), s.get("rx_total")) for s in slots])
    put("nicetunnel_tunnel_transmit_bytes_total", "counter", "Bytes sent by the tunnel", [(base(s), s.get("tx_total")) for s in slots])
    put("nicetunnel_tunnel_receive_bytes_per_second", "gauge", "Current receive rate", [(base(s), s.get("rx_rate")) for s in slots])
    put("nicetunnel_tunnel_transmit_bytes_per_second", "gauge", "Current send rate", [(base(s), s.get("tx_rate")) for s in slots])
    put("nicetunnel_tunnel_connections", "gauge", "Open TCP connections", [(base(s), s.get("conns")) for s in slots])
    put("nicetunnel_tunnel_latency_ms", "gauge", "Ping to the peer", [(base(s), s.get("lat")) for s in slots])
    put("nicetunnel_tunnel_packet_loss_percent", "gauge", "Packet loss to the peer", [(base(s), s.get("loss")) for s in slots])
    put("nicetunnel_tunnel_uptime_percent_24h", "gauge", "Share of the last 24 hours the tunnel was active", [(base(s), s.get("up24")) for s in slots])
    lims = [(s, s.get("lim")) for s in slots if s.get("lim")]
    put("nicetunnel_tunnel_quota_bytes", "gauge", "Traffic quota", [(base(s), l["quota"]) for s, l in lims if l["quota"]])
    put("nicetunnel_tunnel_quota_used_bytes", "gauge", "Traffic counted against the quota", [(base(s), l["used"]) for s, l in lims if l["quota"]])
    put("nicetunnel_tunnel_expires_days", "gauge", "Days until the tunnel expires", [(base(s), l["days_left"]) for s, l in lims if l["days_left"] is not None])
    put("nicetunnel_tunnel_blocked", "gauge", "1 when a quota or expiry limit stopped the tunnel", [(base(s), 1 if l["blocked"] else 0) for s, l in lims])
    put("nicetunnel_server_up", "gauge", "1 when another managed panel answers", [({"name": f["name"]}, 1 if f["ok"] else 0) for f in fleet_view()])
    return "\n".join(out) + "\n"


# -- speed caps (outgoing traffic, nftables) -----------------------------------------------------------------
def nft_available():
    return shutil.which("nft") is not None


def cap_rules(caps):
    """caps: {slot: (cgroup_path, mbit)} -> nftables text for one dedicated table."""
    lines = ["table inet %s {" % NFT_TABLE, "  chain out {", "    type filter hook output priority filter; policy accept;"]
    for n, (cg, mbit) in sorted(caps.items()):
        parts = [p for p in cg.strip("/").split("/") if p]
        lines.append('    socket cgroupv2 level %d "%s" limit rate over %d kbytes/second drop' % (len(parts), "/".join(parts), max(1, int(mbit * 125))))
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def caps_apply():
    """Rebuilds the dedicated nftables table from the saved limits. Returns an error text or None."""
    conf = load_panel_conf()
    caps = {}
    for k, v in (conf.get("limits") or {}).items():
        if v.get("mbit") and k.isdigit() and os.path.exists(slot_file(int(k))):
            n = int(k)
            cg = (slot_stats.get(n) or {}).get("cg") or "/system.slice/system-nicetunnel.slice/nicetunnel@%d.service" % n
            caps[n] = (cg, float(v["mbit"]))
    if not caps:
        if nft_available():
            run(["nft", "delete", "table", "inet", NFT_TABLE])
        return None
    if not nft_available():
        return "nftables is not installed on this server (apt install nftables)"
    text = "table inet %s\ndelete table inet %s\n%s" % (NFT_TABLE, NFT_TABLE, cap_rules(caps))
    path = os.path.join(CONF_DIR, "cap.nft")
    try:
        _atomic_write(path, text)
    except OSError as exc:
        return "could not write the rules: %s" % exc
    code, out = run(["nft", "-c", "-f", path])
    if code != 0:
        return "nftables rejected the rule: %s" % out.strip()[-200:]
    code, out = run(["nft", "-f", path])
    if code != 0:
        return "nftables could not apply the rule: %s" % out.strip()[-200:]
    return None


_absent = {}


def cleanup_orphans(seen):
    """Forgets limits, auto-repair flags and customer links of tunnels that stayed gone for 15 seconds."""
    changed = []
    for n in list(_absent):
        if n in seen:
            _absent.pop(n)
    with conf_lock:
        conf = load_panel_conf()
        for key in ("limits", "heal", "shares"):
            d = conf.get(key) or {}
            gone = []
            for k in d:
                if k.isdigit() and int(k) not in seen:
                    _absent[int(k)] = _absent.get(int(k), 0) + 1
                    if _absent[int(k)] >= 3:
                        gone.append(k)
            for k in gone:
                d.pop(k)
            if gone:
                conf[key] = d
                changed.append(key)
        if changed:
            save_panel_conf(conf)
    if "limits" in changed:
        caps_apply()


# -- how many tunnels this server may hold ------------------------------------------------------------------
def max_slots():
    if _max_slots["v"] is None:
        try:
            v = int(load_panel_conf().get("max_slots", MAX_SLOT))
        except (TypeError, ValueError):
            v = MAX_SLOT
        _max_slots["v"] = min(100, max(1, v))
    return _max_slots["v"]


def set_max_slots(v):
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError("the number of tunnels must be a whole number")
    if not 1 <= v <= 100:
        raise ValueError("the number of tunnels must be between 1 and 100")
    highest = max([int(m.group(1)) for f in os.listdir(CONF_DIR) for m in [re.fullmatch(r"slot(\d+)\.env", f)] if m] or [0]) \
        if os.path.isdir(CONF_DIR) else 0
    if v < highest:
        raise ValueError("tunnel number %d already exists, delete it first or choose at least %d" % (highest, highest))
    with conf_lock:
        conf = load_panel_conf()
        conf["max_slots"] = v
        save_panel_conf(conf)
    _max_slots["v"] = v


# -- IPv6 for the panel itself -----------------------------------------------------------------------------------
class V6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)   # accept IPv4 too on ::
        except (OSError, AttributeError):
            pass
        super().server_bind()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NiceTunnelPanel"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200, headers=None):
        try:
            audit_http(self, code, obj)
        except Exception:
            pass
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

    def request_key(self):
        k = self.headers.get("X-API-Key")
        if k:
            return k
        a = self.headers.get("Authorization") or ""
        return a[7:].strip() if a.startswith("Bearer nt_") else ""

    def ip_gate(self):
        """Optional allowlist for browser access. Requests with an API key are checked against the key's own list."""
        lst = load_panel_conf().get("allow_ips")
        if not lst or self.request_key():
            return True
        if ip_allowed(self.client_address[0], lst):
            return True
        self.send_json({"error": "your IP address is not allowed"}, 403)
        return False

    def viewer_gate(self, path, method):
        """Viewer accounts may only read. Returns True when it already answered."""
        sid = self.session_id()
        if not sid or getattr(self, "_apikey", False):
            return False
        if not str(sess_owner.get(sid, "")).startswith("viewer:"):
            return False
        ok = (path == "/" or VIEWER_GET.fullmatch(path)) if method == "GET" else path in ("/api/login", "/api/logout")
        if ok:
            return False
        self.send_json({"error": "this is a view-only account"}, 403)
        return True

    def share_serve(self, tok, is_json):
        ip = self.client_address[0]
        with lock:
            cnt, first = share_fails.get(ip, [0, time.time()])
            if time.time() - first > 900:
                cnt, first = 0, time.time()
            if cnt >= 30:
                return self.send_json({"error": "too many attempts"}, 429)
        hit = share_find(tok)
        if not hit:
            with lock:
                share_fails[ip] = [cnt + 1, first]
            return self.send_json({"error": "not found"}, 404)
        if is_json:
            return self.send_json(share_data(*hit))
        data = SHARE_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def key_gate(self, path, method):
        ip = self.client_address[0]
        with lock:
            cnt, first = key_fails.get(ip, [0, time.time()])
            if time.time() - first > 900:
                cnt, first = 0, time.time()
            if cnt >= 20:
                self.send_json({"error": "too many attempts"}, 429)
                return False
        kent = apikey_match(self.request_key())
        if kent and not key_ip_ok(kent, ip):
            with lock:
                key_fails[ip] = [cnt + 1, first]
            self.send_json({"error": "this API key is not allowed from %s" % ip}, 403)
            return False
        perm = (kent.get("perm", "manage") if kent else "")
        if not perm:
            with lock:
                key_fails[ip] = [cnt + 1, first]
            time.sleep(0.5)
            self.send_json({"error": "invalid API key"}, 401)
            return False
        self._perm = perm
        if not ((KEY_GET if method == "GET" else KEY_POST).fullmatch(path)
                or (perm == "full" and method == "POST" and KEY_FULL_POST.fullmatch(path))):
            self.send_json({"error": "not allowed with an API key"}, 403)
            return False
        self._apikey = True
        return True

    def session_ok(self):
        if getattr(self, "_apikey", False):
            return True
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
        raw = urlparse(self.path).path
        m = SHARE_RE.fullmatch(raw)
        if m:
            return self.share_serve(m.group(1), bool(m.group(2)))
        path = route_path(raw)
        if path is None:
            return self.send_json({"error": "not found"}, 404)
        self._apikey = False
        if not self.ip_gate():
            return
        if self.request_key():
            if not self.key_gate(path, "GET"):
                return
        if self.viewer_gate(path, "GET"):
            return
        if path == "/api/audit":
            if not self.require_admin():
                return
            return self.send_json({"list": audit_log[-300:][::-1]})
        if path == "/metrics":
            if not self.require_login():
                return
            data = metrics_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/alerts":
            if not self.require_admin():
                return
            return self.send_json(alerts_view())
        if path == "/api/allowips":
            if not self.require_admin():
                return
            return self.send_json({"list": load_panel_conf().get("allow_ips", []), "you": self.client_address[0]})
        if path == "/api/viewers":
            if not self.require_admin():
                return
            return self.send_json({"list": [{"name": v["name"], "t": v.get("t", 0)} for v in load_panel_conf().get("viewers", [])]})
        if path == "/api/advanced":
            if not self.require_admin():
                return
            return self.send_json({"max_slots": max_slots(), "nft": nft_available(), "version": APP_VERSION})
        if path == "/api/ping":
            if not self.require_login():
                return
            return self.send_json({"ok": True, "name": host_label(), "version": APP_VERSION, "perm": getattr(self, "_perm", "admin")})
        if path == "/api/fleet":
            if not self.require_login():
                return
            return self.send_json({"servers": fleet_view()})
        m = re.fullmatch(r"/api/slot/(\d+)/detail", path)
        if m:
            if not self.require_login():
                return
            n = int(m.group(1))
            d = slot_detail(n) if valid_slot(n) else None
            if not d:
                return self.send_json({"error": "no such tunnel"}, 404)
            return self.send_json(d)
        if path == "/api/2fa":
            if not self.require_admin():
                return
            t = load_panel_conf().get("tfa") or {}
            return self.send_json({"on": tfa_enabled(), "left": len(t.get("rec", []))})
        if path == "/api/apikeys":
            if not self.require_admin():
                return
            return self.send_json({"keys": apikey_list()})
        if path == "/api/update/check":
            if not self.require_admin():
                return
            return self.send_json(update_check())
        if path == "/api/servers/logs":
            if not self.require_admin():
                return
            q = parse_qs(urlparse(self.path).query)
            srv = find_server((q.get("id") or [""])[0])
            sn = (q.get("slot") or [""])[0]
            if not srv or not sn.isdigit():
                return self.send_json({"error": "unknown server or tunnel"}, 404)
            try:
                return self.send_json(remote_call(srv, "GET", "/api/slot/%s/logs" % sn))
            except RemoteError as exc:
                return self.send_json({"error": str(exc)}, 502)
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
            own = str(sess_owner.get(self.session_id(), ""))
            role = "admin" if own == "admin" else ("viewer" if own.startswith("viewer:") else "user")
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
                                   "events": tg.get("events", ["tunnel", "login", "backup", "resource", "ssl", "health"]), "th": tg.get("th", 90), "proxy": mask_proxy(tg.get("proxy", ""))})
        if path == "/api/tune":
            if not self.require_login():
                return
            return self.send_json(tune_state())
        if path == "/api/domain":
            if not self.require_login():
                return
            return self.send_json(domain_state())
        if path == "/api/backups":
            if not self.require_login():
                return
            conf = load_panel_conf()
            return self.send_json({"list": list_backups(), "auto": conf.get("autobackup", {"on": False, "hours": 24, "full": False}),
                                   "last": conf.get("ab_last", 0), "enc": bool(conf.get("bk_pass"))})
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
            return self.send_json({"slots": slots_with_stats()})
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
        self._apikey = False
        self._path = path
        if not self.ip_gate():
            return
        if self.request_key():
            if not self.key_gate(path, "POST"):
                return
        if self.viewer_gate(path, "POST"):
            return
        if not self.same_origin_ok():
            return self.send_json({"error": "cross-site request refused"}, 403)
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "bad request body"}, 400)

        self._body = body
        if path == "/api/alerts":
            if not self.require_admin():
                return
            try:
                return self.send_json(alerts_save(body))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
        if path == "/api/alerts/test":
            if not self.require_admin():
                return
            ok, msg = alert_test(str(body.get("channel", "")))
            return self.send_json({"ok": bool(ok), "msg": str(msg)[:200]})
        if path == "/api/allowips":
            if not self.require_admin():
                return
            try:
                lst = parse_ip_list(body.get("list", ""))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            me = self.client_address[0]
            if lst and not ip_allowed(me, lst):
                return self.send_json({"error": "this would lock you out: your own address %s is not in the list" % me}, 400)
            with conf_lock:
                conf = load_panel_conf()
                if lst:
                    conf["allow_ips"] = lst
                else:
                    conf.pop("allow_ips", None)
                save_panel_conf(conf)
            return self.send_json({"ok": True, "list": lst, "you": me})
        if path == "/api/viewers/add":
            if not self.require_admin():
                return
            try:
                viewer_add(str(body.get("name", "")), str(body.get("password", "")))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            return self.send_json({"ok": True})
        if path == "/api/viewers/delete":
            if not self.require_admin():
                return
            viewer_delete(str(body.get("name", "")))
            return self.send_json({"ok": True})
        if path == "/api/advanced":
            if not self.require_admin():
                return
            try:
                set_max_slots(body.get("max_slots"))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            return self.send_json({"ok": True, "max_slots": max_slots()})
        m = re.fullmatch(r"/api/slot/(\d+)/share", path)
        if m:
            if not self.require_admin():
                return
            n = int(m.group(1))
            if not valid_slot(n):
                return self.send_json({"error": "no such tunnel"}, 404)
            return self.send_json({"ok": True, "share": share_set(n, bool(body.get("on", True)), body.get("label"), bool(body.get("regen")))})
        m = re.fullmatch(r"/api/slot/(\d+)/(limits|heal)", path)
        if m:
            if not self.require_admin():
                return
            n = int(m.group(1))
            if not valid_slot(n) or not os.path.exists(slot_file(n)):
                return self.send_json({"error": "no such tunnel"}, 404)
            if m.group(2) == "heal":
                heal_set(n, bool(body.get("on")))
                return self.send_json({"ok": True, "heal": heal_on(n)})
            try:
                st = limit_apply(n, body)
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            return self.send_json({"ok": True, "limits": st})
        if path == "/api/pair/create":
            if not self.require_admin():
                return
            try:
                return self.send_json(pair_create(body))
            except RemoteError as exc:
                return self.send_json({"error": str(exc)}, 502)
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
        if path == "/api/backup/pass":
            if not self.require_admin():
                return
            conf = load_panel_conf()
            if body.get("clear"):
                conf.pop("bk_pass", None)
            else:
                pw = str(body.get("pass", ""))
                if not (8 <= len(pw) <= 200):
                    return self.send_json({"error": "the passphrase must be 8 to 200 characters"}, 400)
                conf["bk_pass"] = pw
            save_panel_conf(conf)
            return self.send_json({"ok": True, "enc": bool(conf.get("bk_pass"))})
        m = re.fullmatch(r"/api/slot/(\d+)/(edit|probe)", path)
        if m:
            if not self.require_login():
                return
            n = int(m.group(1))
            if not valid_slot(n) or not os.path.exists(slot_file(n)):
                return self.send_json({"error": "no such tunnel"}, 404)
            if m.group(2) == "probe":
                sl = next((x for x in list_slots() if x["slot"] == n), None)
                ip = slot_peer(sl) if sl else ""
                if not ip:
                    return self.send_json({"error": "the peer address is not known yet"}, 400)
                r = probe_host(ip)
                return self.send_json({"ok": bool(r), "health": apply_probe(n, ip, r)})
            res, err = slot_edit(n, body)
            if err:
                return self.send_json({"error": err}, 400)
            return self.send_json(res)
        if path == "/api/2fa/setup":
            if not self.require_admin():
                return
            s, uri = tfa_setup()
            return self.send_json({"secret": s, "uri": uri})
        if path == "/api/2fa/enable":
            if not self.require_admin():
                return
            codes, err = tfa_enable(body.get("code", ""))
            if err:
                return self.send_json({"error": err}, 400)
            return self.send_json({"ok": True, "codes": codes})
        if path == "/api/2fa/disable":
            if not self.require_admin():
                return
            conf = load_panel_conf()
            if not (conf.get("password") and check_password(str(body.get("password", "")), conf["password"])) \
                    or not tfa_verify(body.get("code", "")):
                return self.send_json({"error": "wrong password or code"}, 400)
            tfa_disable()
            return self.send_json({"ok": True})
        if path == "/api/apikeys/create":
            if not self.require_admin():
                return
            try:
                kid, key = apikey_create(body.get("name", ""), bool(body.get("full")), body.get("ips", ""))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            return self.send_json({"ok": True, "id": kid, "key": key})
        if path == "/api/apikeys/revoke":
            if not self.require_admin():
                return
            apikey_revoke(str(body.get("id", "")))
            return self.send_json({"ok": True})
        if path == "/api/servers/add":
            if not self.require_admin():
                return
            try:
                srv, info = server_add(body.get("name", ""), body.get("url", ""), str(body.get("key", "")).strip(), body.get("pin", ""))
            except RemoteError as exc:
                if exc.untrusted:
                    return self.send_json({"error": "untrusted certificate", "need_pin": True, "fingerprint": exc.fp or ""}, 409)
                return self.send_json({"error": str(exc)}, 400)
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
            threading.Thread(target=fleet_round, daemon=True).start()
            return self.send_json({"ok": True, "id": srv["id"], "version": info.get("version", "")})
        if path == "/api/servers/delete":
            if not self.require_admin():
                return
            sid = str(body.get("id", ""))
            with conf_lock:
                conf = load_panel_conf()
                conf["servers"] = [s for s in conf.get("servers", []) if s["id"] != sid]
                save_panel_conf(conf)
            fleet.pop(sid, None)
            return self.send_json({"ok": True})
        if path == "/api/servers/act":
            if not self.require_admin():
                return
            srv = find_server(str(body.get("id", "")))
            act, sn = str(body.get("action", "")), str(body.get("slot", ""))
            if not srv or act not in ("start", "stop", "restart") or not sn.isdigit():
                return self.send_json({"error": "bad request"}, 400)
            try:
                return self.send_json(remote_call(srv, "POST", "/api/slot/%s/%s" % (sn, act), {}))
            except RemoteError as exc:
                return self.send_json({"error": str(exc)}, 502)
        if path == "/api/update/apply":
            if not self.require_admin():
                return
            try:
                return self.send_json({"ok": True, "version": update_apply()})
            except Exception as exc:
                return self.send_json({"error": str(exc)[:200]}, 400)
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
            if not owner and not body.get("link"):
                vname = str(body.get("username", ""))
                for v in conf.get("viewers", []):
                    if hmac.compare_digest(v["name"], vname):
                        if check_password(pw, v["hash"]):
                            owner, how = "viewer:" + v["name"], "viewer"
                        break
            bad_otp = False
            if owner and how == "password" and tfa_enabled(conf):
                otp = str(body.get("otp", "")).strip()
                if not otp:
                    return self.send_json({"need_otp": True})
                if not tfa_verify(otp):
                    owner, bad_otp = None, True
            if not owner:
                with lock:
                    fails[ip] = [cnt + 1, first]
                time.sleep(1)
                tg_send("⚠️ تلاش ناموفق ورود به پنل %s\nIP: %s" % (host_label(), ip), "login")
                return self.send_json({"error": "wrong verification code" if bad_otp else ("wrong username or password" if how == "password" and not body.get("link") else "link is invalid, expired or already used")}, 401)
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

        if path == "/api/domain/apply":
            if os.geteuid() != 0:
                return self.send_json({"error": "panel must run as root"}, 403)
            url, err = domain_apply(body.get("domain"), body.get("email"))
            if err:
                return self.send_json({"error": err}, 400)
            return self.send_json({"ok": True, "url": url})

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
            if "events" in body:
                tg["events"] = [e for e in body.get("events", []) if e in DEFAULT_EVENTS]
            if "th" in body:
                try:
                    tg["th"] = min(99, max(50, int(body.get("th", 90))))
                except (TypeError, ValueError):
                    tg["th"] = 90
            if "proxy" in body:
                px = str(body.get("proxy") or "").strip()
                if not px:
                    tg.pop("proxy", None)
                elif px != mask_proxy(tg.get("proxy", "")):
                    if not valid_proxy(px):
                        return self.send_json({"error": "the proxy must look like socks5://host:1080 or http://host:8080"}, 400)
                    tg["proxy"] = px
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
                                  {"document": (name, read_backup_text(name).encode())})
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
            try:
                if d is None:
                    name = str(body.get("name", ""))
                    if not re.fullmatch(r"darkcore-[0-9-]+-(full|tunnels)\.json", name):
                        return self.send_json({"error": "bad name"}, 400)
                    try:
                        d = bk_load_text(read_backup_text(name), str(body.get("pass", "")))
                    except OSError:
                        return self.send_json({"error": "backup not found"}, 404)
                elif isinstance(d, str):
                    d = bk_load_text(d, str(body.get("pass", "")))
            except ValueError as exc:
                return self.send_json({"error": str(exc)}, 400)
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
                return self.send_json({"error": "no free slot (max %d)" % max_slots()}, 400)
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
                return self.send_json({"error": "no free slot (max %d)" % max_slots()}, 400)
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
            if action in ("start", "restart") and limit_blocked(n):
                return self.send_json({"error": "blocked by the %s limit: open the tunnel details and raise or reset it" % limit_blocked(n)}, 403)
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


DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def domain_state():
    c = load_panel_conf()
    host = c.get("host", "")
    return {"host": host, "scheme": c.get("scheme", "https"), "ip": public_ip_detect(),
            "is_domain": bool(DOMAIN_RE.match(host)), "port": c.get("port"), "base": c.get("base", ""),
            "root": os.geteuid() == 0}


def domain_apply(domain, email):
    """Issues a Let's Encrypt cert for the domain and switches the panel service to it."""
    domain = (domain or "").strip().lower()
    email = (email or "").strip()
    if not DOMAIN_RE.match(domain):
        return None, "invalid domain name"
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return None, "invalid email"
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET)}
    except OSError:
        return None, "domain does not resolve yet; add an A record pointing to this server"
    ip = public_ip_detect()
    if ip and ip not in ips:
        return None, "domain points to %s, but this server is %s" % (", ".join(sorted(ips)), ip)
    if not shutil.which("certbot"):
        run(["sh", "-c", "apt-get update -qq && apt-get install -y -qq certbot"], timeout=300)
        if not shutil.which("certbot"):
            return None, "could not install certbot"
    cmd = ["certbot", "certonly", "--standalone", "-d", domain, "--non-interactive", "--agree-tos"]
    cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
    rc, out = run(cmd, timeout=180)
    if rc != 0:
        return None, "certbot failed (port 80 must be free and open): " + out[-400:]
    cert = "/etc/letsencrypt/live/%s/fullchain.pem" % domain
    key = "/etc/letsencrypt/live/%s/privkey.pem" % domain
    hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
    os.makedirs(hook_dir, exist_ok=True)
    with open(hook_dir + "/nicetunnel-panel.sh", "w") as f:
        f.write("#!/bin/sh\nsystemctl restart nicetunnel-panel\n")
    os.chmod(hook_dir + "/nicetunnel-panel.sh", 0o755)
    conf = load_panel_conf()
    conf["host"], conf["scheme"] = domain, "https"
    save_panel_conf(conf)
    port = int(conf.get("port", 0))
    if not (1 <= port <= 65535):
        return None, "panel port is not configured"
    target = os.path.join(APP_DIR, "nicetunnel_panel.py")
    unit = (
        "[Unit]\nDescription=NiceTunnel Spoof Panel\nAfter=network-online.target\n"
        "Wants=network-online.target\n\n[Service]\n"
        "ExecStart=%s %s serve --bind 0.0.0.0 --port %d --cert %s --key %s\nRestart=always\nRestartSec=3\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    ) % (sys.executable, target, port, cert, key)
    with open(UNIT_PATH, "w") as f:
        f.write(unit)
    run(["systemctl", "daemon-reload"])
    threading.Timer(1.5, lambda: run(["systemctl", "restart", "nicetunnel-panel"])).start()
    return "https://%s:%d%s/" % (domain, port, conf.get("base", "")), None


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


RAW_URL = os.environ.get("NICETUNNEL_UPDATE_URL") or "https://raw.githubusercontent.com/arshamsmok/nicetunnel/main/nicetunnel_panel.py"


def cmd_update(_args):
    """Download the newest panel from GitHub (checked against its SHA-256) and restart the service."""
    if os.geteuid() != 0:
        sys.exit("error: run as root")
    try:
        ver = update_apply(restart_delay=0)
    except Exception as exc:
        sys.exit("error: %s" % exc)
    print("Panel updated to v%s and restarted." % ver)


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
    srv = (V6Server if ":" in args.bind else http.server.ThreadingHTTPServer)((args.bind, args.port), Handler)
    if args.cert and args.key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=background_loop, daemon=True).start()
    for fn in (sampler_loop, health_loop, fleet_loop):
        threading.Thread(target=fn, daemon=True).start()
    print("NiceTunnel panel on %s:%d" % (args.bind, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_disable_allowlist(args):
    conf = load_panel_conf()
    conf.pop("allow_ips", None)
    save_panel_conf(conf)
    print("The IP allowlist is off: the panel now accepts any IP address.")


def cmd_disable_2fa(args):
    tfa_disable()
    print("Two-factor login is now off.")


def main():
    p = argparse.ArgumentParser(description="NiceTunnel web panel for spoof tunnels")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password", help="set or change the panel password").set_defaults(func=cmd_set_password)
    sub.add_parser("install", help="install and start the panel service").set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="remove the panel service").set_defaults(func=cmd_uninstall)
    sub.add_parser("disable-allowlist", help="turn off the panel IP allowlist (locked out)").set_defaults(func=cmd_disable_allowlist)
    sub.add_parser("disable-2fa", help="turn off two-factor login (lost phone)").set_defaults(func=cmd_disable_2fa)
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
