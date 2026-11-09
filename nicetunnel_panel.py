#!/usr/bin/env python3
"""NiceTunnel web panel - create, connect and manage SPOOF tunnels from a browser.

Runs on ONE server (the one you manage from). It manages only the spoof tunnel
slots of that server, using the same slot files and systemd units as the
"nicetunnel" menu, so a tunnel made here also shows up in the menu and vice versa.
To control the other server too, run the panel there as well.

Usage (as root):
  python3 nicetunnel_panel.py set-password          # first time
  python3 nicetunnel_panel.py serve [--bind 127.0.0.1] [--port 8787]

Keep it on 127.0.0.1 and open it through an SSH tunnel:
  ssh -L 8787:127.0.0.1:8787 root@SERVER_IP   then open http://127.0.0.1:8787

Scope: this panel only manages SPOOF tunnels (Type 2) and the spoof tester of
THIS server. Reverse TCP tunnels stay in the "nicetunnel" menu.

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
fails = {}      # client ip -> [count, first_failure_time]
lock = threading.Lock()


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


def list_spoof_slots():
    out = []
    for n in range(1, MAX_SLOT + 1):
        if not os.path.exists(slot_file(n)):
            continue
        try:
            env = read_env(slot_file(n))
        except OSError:
            continue
        if env.get("TYPE") != "spoof":
            continue
        _, st = run(["systemctl", "is-active", "nicetunnel@%d" % n])
        out.append({
            "slot": n,
            "role": env.get("ROLE", ""),
            "side": "Iran (entry)" if env.get("ROLE") == "server" else "Foreign (exit)",
            "transport": env.get("TRANSPORT", ""),
            "port": env.get("TPORT", ""),
            "peer": env.get("PEER_IP", ""),
            "spoof_ips": env.get("SPOOF_IPS", ""),
            "listen_port": env.get("LISTEN_PORT", ""),
            "forward": env.get("FORWARD", ""),
            "state": st.strip() or "unknown",
        })
    return out


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
    if len(token) < 16:
        return None, "token must be at least 16 characters"
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
PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NiceTunnel Panel</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#ddd;margin:20px auto;padding:0 20px;max-width:980px}
h1{font-size:20px} h2{font-size:16px;margin-top:28px;border-bottom:1px solid #333;padding-bottom:6px}
input,select,button{background:#1c1c1c;color:#eee;border:1px solid #444;border-radius:6px;padding:7px;margin:3px 0}
button{cursor:pointer} button.danger{border-color:#803} button.ok{border-color:#276}
table{width:100%;border-collapse:collapse;font-size:14px} td,th{border-bottom:1px solid #2a2a2a;padding:6px;text-align:left}
.active{color:#6d6} .inactive,.failed{color:#e66} .box{background:#181818;padding:12px;border-radius:8px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end} .row>div{display:flex;flex-direction:column;min-width:200px}
pre{background:#000;padding:10px;overflow:auto;max-height:300px;font-size:12px}
.msg{padding:8px;border-radius:6px;margin:8px 0} .good{background:#163}.bad{background:#411}
label{font-size:13px;color:#aaa}
</style>
<body>
<div id="app"></div>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state = {logged: false, needSetup: false};
function msg(t, ok){ const m=$('#msg'); if(m){ m.className='msg '+(ok?'good':'bad'); m.textContent=t; } else alert(t); }
async function api(path, body){
  const r = await fetch(path, {method: body===undefined?'GET':'POST', headers:{'Content-Type':'application/json'},
    body: body===undefined?undefined:JSON.stringify(body), credentials:'same-origin'});
  let j = {}; try { j = await r.json(); } catch(e){}
  if(!r.ok) throw new Error(j.error || ('HTTP '+r.status));
  return j;
}
function loginView(){
  $('#app').innerHTML = `<h1>NiceTunnel Panel</h1><div class="box"><div id="msg"></div>
  <div class="row"><div><label>Username</label>
  <input id="un" value="admin" autocomplete="username"></div>
  <div><label>${state.needSetup?'Create admin password (min 8 chars)':'Password'}</label>
  <input id="pw" type="password"></div>
  <button class="ok" id="go">${state.needSetup?'Save password':'Login'}</button></div></div>`;
  $('#go').onclick = async () => { try {
      await api(state.needSetup ? '/api/setup' : '/api/login', {username:$('#un').value,password:$('#pw').value});
      await load(); } catch(e){ msg(e.message,false); } };
  $('#pw').onkeydown = e => { if(e.key==='Enter') $('#go').click(); };
}
function dashView(d){
  const rows = d.slots.map(s => `<tr><td>${s.slot}</td><td>${esc(s.side)}</td><td>${esc(s.transport)}:${esc(s.port)}</td>
    <td>${esc(s.peer)}</td><td>${esc(s.spoof_ips)}</td>
    <td>${s.role==='server'?'listen UDP '+esc(s.listen_port):'forward '+esc(s.forward)}</td>
    <td class="${esc(s.state)}">${esc(s.state)}</td>
    <td><button class="ok" onclick="act(${s.slot},'start')">Connect</button>
    <button onclick="act(${s.slot},'restart')">Restart</button>
    <button onclick="act(${s.slot},'stop')">Stop</button>
    <button onclick="logs(${s.slot})">Logs</button>
    <button class="danger" onclick="del(${s.slot})">Delete</button></td></tr>`).join('');
  $('#app').innerHTML = `
  <div class="row" style="justify-content:space-between"><h1>NiceTunnel Spoof Panel</h1>
    <button onclick="logout()">Logout</button></div>
  <div id="msg"></div>
  <h2>Spoof tunnels on this server</h2>
  ${d.slots.length? `<table><tr><th>Slot</th><th>Side</th><th>Type:port</th><th>Other server</th><th>Source IPs</th><th>Ports</th><th>State</th><th></th></tr>${rows}</table>`
    : '<p>No spoof tunnel yet. Create one below.</p>'}
  <h2>Create spoof tunnel</h2>
  <div class="box"><div class="row">
    <div><label>This server is</label><select id="role">
      <option value="server">Iran (entry: apps send UDP here)</option>
      <option value="client">Foreign (exit: forwards to a UDP service)</option></select></div>
    <div><label>Other server real IP</label><input id="peer" placeholder="203.0.113.5"></div>
    <div><label>Packet type</label><select id="transport"><option>udp</option><option>tcp</option><option>icmp</option></select></div>
    <div><label>Tunnel port (both sides)</label><input id="port" value="4500"></div>
    <div><label>Fake source IPs (from Spoof tester)</label><input id="spoof_ips" placeholder="10.0.0.0/28 or 1.2.3.4,5.5.5.1-5.5.5.9"></div>
    <div id="lp"><label>Listen UDP port (apps send here)</label><input id="listen_port" value="51820"></div>
    <div id="fw" style="display:none"><label>Forward to HOST:PORT</label><input id="forward" value="127.0.0.1:51820"></div>
    <div><label>Token (empty = generate)</label><input id="token" placeholder="min 16 chars"></div>
  </div><p><button class="ok" id="create">Create and connect</button></p>
  <div id="newtoken"></div></div>
  <h2>Spoof tester</h2>
  <p>Run <b>Receive</b> on the receiving server first, then <b>Send</b> on the sending server, with the same packet type and port. The result lists the fake source IPs that arrived. Copy them into "Fake source IPs" above.</p>
  <div class="box"><div class="row">
    <div><label>Mode</label><select id="tmode"><option value="recv">Receive (run first)</option><option value="send">Send (run second)</option></select></div>
    <div><label>Packet type</label><select id="ttr"><option>udp</option><option>tcp</option><option>icmp</option></select></div>
    <div><label>Port</label><input id="tport" value="4500"></div>
    <div class="trecv"><label>Listen seconds (5-300)</label><input id="tsec" value="60"></div>
    <div class="tsend" style="display:none"><label>Other server real IP</label><input id="tpeer" placeholder="203.0.113.5"></div>
    <div class="tsend" style="display:none"><label>Fake source IPs to test</label><input id="tspoof" placeholder="10.0.0.0/28"></div>
    <div class="tsend" style="display:none"><label>Packets per address (1-10)</label><input id="tcount" value="5"></div>
  </div><p><button class="ok" id="tstart">Start test</button> <button onclick="tstatus()">Refresh result</button></p>
  <pre id="tbox">No test run yet.</pre></div>
  <h2>Logs</h2><pre id="logbox">Click Logs on a tunnel.</pre>
  <p><button onclick="load()">Refresh</button></p>`;
  $('#role').onchange = () => { const s=$('#role').value==='server'; $('#lp').style.display=s?'':'none'; $('#fw').style.display=s?'none':''; };
  $('#create').onclick = create;
  $('#tmode').onchange = tmodeView;
  $('#tstart').onclick = tstart;
  tmodeView();
  tstatus();
}
function tmodeView(){ const s=$('#tmode').value==='send'; document.querySelectorAll('.tsend').forEach(e=>e.style.display=s?'':'none');
  document.querySelectorAll('.trecv').forEach(e=>e.style.display=s?'none':''); }
async function tstart(){
  const m=$('#tmode').value;
  const body={transport:$('#ttr').value, port:$('#tport').value, seconds:$('#tsec').value,
    peer:$('#tpeer').value.trim(), spoof_ips:$('#tspoof').value, count:$('#tcount').value};
  try { await api('/api/test/'+m, body); msg('Test started', true); tstatus(); } catch(e){ msg(e.message,false); } }
let tTimer = null;
async function tstatus(){
  clearTimeout(tTimer);
  try { const r = await api('/api/test/status');
    const state = r.running ? 'running...' : (r.code === null ? 'idle' : 'finished (exit '+r.code+')');
    $('#tbox').textContent = (r.title ? '['+r.title+'] ' : '') + state + '\\n' + (r.log || '');
    if (r.running) tTimer = setTimeout(tstatus, 2000);
  } catch(e){ msg(e.message,false); } }
async function load(){
  try { state = await api('/api/state');
    if(!state.logged){ loginView(); return; }
    dashView(await api('/api/slots'));
  } catch(e){ loginView(); msg(e.message,false); }
}
async function act(n, a){ try { const r = await api(`/api/slot/${n}/${a}`, {}); msg(`Tunnel ${n}: ${r.state}`, true); await load(); } catch(e){ msg(e.message,false);} }
async function del(n){ if(!confirm('Delete tunnel '+n+'?')) return; try { await api(`/api/slot/${n}/delete`, {}); await load(); } catch(e){ msg(e.message,false);} }
async function logs(n){ try { const r = await api(`/api/slot/${n}/logs`); $('#logbox').textContent = r.logs || '(no logs)'; } catch(e){ msg(e.message,false);} }
async function create(){
  const body = {role:$('#role').value, peer:$('#peer').value.trim(), transport:$('#transport').value,
    port:$('#port').value, spoof_ips:$('#spoof_ips').value, listen_port:$('#listen_port').value,
    forward:$('#forward').value, token:$('#token').value.trim()};
  try { const r = await api('/api/spoof', body);
    $('#newtoken').innerHTML = `<div class="msg good">Tunnel ${r.slot} created. Token (copy it to the other server):<br><code>${esc(r.token)}</code></div>`;
    await load(); } catch(e){ msg(e.message,false); } }
async function logout(){ await api('/api/logout', {}); state.logged=false; load(); }
load();
</script></body></html>
"""


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
SESSION_RE = re.compile(r"nt_session=([0-9a-f]{64})")


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
            if exp and exp > time.time():
                return True
            sessions.pop(sid, None)
        return False

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
            return self.send_json({"logged": self.session_ok(), "needSetup": "password" not in conf})
        if path == "/api/slots":
            if not self.require_login():
                return
            return self.send_json({"slots": list_spoof_slots()})
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
            if not conf.get("password") or not hmac.compare_digest(
                    str(body.get("username", "")), conf.get("username", "admin")) or not check_password(str(body.get("password", "")), conf["password"]):
                with lock:
                    fails[ip] = [cnt + 1, first]
                time.sleep(1)
                return self.send_json({"error": "wrong password"}, 401)
            sid = secrets.token_hex(32)
            with lock:
                fails.pop(ip, None)
                sessions[sid] = time.time() + SESSION_TTL
            return self.send_json({"ok": True}, headers=[(
                "Set-Cookie", "nt_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                % (sid, SESSION_TTL))])

        if path == "/api/logout":
            sid = self.session_id()
            if sid:
                with lock:
                    sessions.pop(sid, None)
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
        "ExecStart=%s %s serve --bind 0.0.0.0 --port %d\nRestart=on-failure\nRestartSec=3\n\n"
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
    s = sub.add_parser("serve", help="run the web panel")
    s.add_argument("--bind", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    s.add_argument("--port", type=int, default=8787)
    s.set_defaults(func=cmd_serve)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
