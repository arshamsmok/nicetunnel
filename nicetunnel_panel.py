#!/usr/bin/env python3
"""NiceTunnel web panel: a small password-protected HTTPS dashboard that shows
live status of the tunnels created by nicetunnel.sh, and can start/stop/restart
them and show their logs.

Author: Arsham Smoke
License: MIT (see LICENSE)

Not started on its own: the menu ("nicetunnel" -> Web panel) sets a password
and turns it on as the "nicetunnel-panel" systemd service.

Standard library only. Python 3.8+. Needs root (reads /etc/nicetunnel and
runs systemctl/journalctl). Uses a self-signed TLS certificate generated with
the system's "openssl" the first time it runs; falls back to plain HTTP (with
a warning) if openssl is not available.
"""
import argparse
import hashlib
import hmac
import http.server
import json
import os
import platform
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

try:
    import resource
except ImportError:
    resource = None

VERSION = "1.3.0"
COOKIE_NAME = "nt_session"
SESSION_TTL = 8 * 3600
STALE_AFTER = 12          # seconds; a stats file older than this is "stale" (process probably down)
PBKDF2_ROUNDS = 200_000

CONF_DIR = "/etc/nicetunnel"
PANEL_STARTED = time.time()

sessions = {}              # token -> expiry (monotonic-ish: time.time())
sessions_lock = threading.Lock()
fails = {}                 # client ip -> (fail_count, locked_until)
fails_lock = threading.Lock()


# --------------------------------------------------------------------------
# data: slot config files + live stats files written by the engine
# --------------------------------------------------------------------------
def panel_auth():
    data = {}
    try:
        with open(os.path.join(CONF_DIR, "panel.env")) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                data[k] = v
    except OSError:
        pass
    return data


def check_password(pw):
    auth = panel_auth()
    salt, want = auth.get("PANEL_SALT"), auth.get("PANEL_HASH")
    if not salt or not want:
        return False
    try:
        got = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS).hex()
    except ValueError:
        return False
    return hmac.compare_digest(got, want)


def parse_env_file(path):
    data = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                data[k] = v
    except OSError:
        return None
    return data


def list_slots():
    try:
        names = sorted(n for n in os.listdir(CONF_DIR) if n.startswith("slot") and n.endswith(".env"))
    except OSError:
        return []
    out = []
    for n in names:
        slot = n[4:-4]
        if slot.isdigit():
            out.append(slot)
    return out


def read_live(slot):
    try:
        with open(os.path.join(CONF_DIR, "stats", "slot%s.json" % slot)) as fh:
            d = json.load(fh)
    except Exception:
        return None
    if time.time() - d.get("ts", 0) > STALE_AFTER:
        d["stale"] = True
    return d


def systemctl(*args):
    try:
        r = subprocess.run(["systemctl"] + list(args), capture_output=True, text=True, timeout=10)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def unit_state(slot):
    ok, out = systemctl("is-active", "nicetunnel@%s" % slot)
    first = out.splitlines()[0] if out else ""
    return first or ("active" if ok else "unknown")


def run_journal(slot, lines):
    try:
        r = subprocess.run(["journalctl", "-u", "nicetunnel@%s" % slot, "-n", str(lines), "--no-pager"],
                            capture_output=True, text=True, timeout=10)
        return True, (r.stdout or r.stderr)
    except Exception as exc:
        return False, str(exc)


def panel_memory_kb():
    if not resource:
        return None
    try:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux
    except Exception:
        return None


MAX_SLOT = 10
ENGINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nicetunnel.py")


def gen_token():
    return secrets.token_urlsafe(24)


def next_free_slot():
    for i in range(1, MAX_SLOT + 1):
        if not os.path.exists(os.path.join(CONF_DIR, "slot%d.env" % i)):
            return i
    return None


def valid_port(v):
    try:
        return 1 <= int(v) <= 65535
    except (TypeError, ValueError):
        return False


def valid_ports_list(v):
    if not v:
        return False
    for item in v.split(","):
        item = item.strip()
        if not item:
            return False
        a, _, b = item.partition(":")
        if not valid_port(a) or (b and not valid_port(b)):
            return False
    return True


def write_slot_file(slot, text):
    os.makedirs(CONF_DIR, exist_ok=True)
    try:
        os.chmod(CONF_DIR, 0o700)
    except OSError:
        pass
    path = os.path.join(CONF_DIR, "slot%s.env" % slot)
    tmp = path + ".new"
    old_umask = os.umask(0o077)
    try:
        with open(tmp, "w") as fh:
            fh.write(text)
    finally:
        os.umask(old_umask)
    os.replace(tmp, path)


def create_tcp_slot(slot, role, f):
    if role == "server":
        if not valid_port(f.get("bridge")) or not valid_ports_list(f.get("ports", "")):
            return False, "پورت یا لیست پورت‌های عمومی نامعتبر است"
        args = "server --bridge %s --ports %s" % (f["bridge"], f["ports"])
        server_ip, target_host = "", ""
    else:
        if not valid_port(f.get("bridge")) or not f.get("server_ip"):
            return False, "آی‌پی سرور ایران یا پورت نامعتبر است"
        target_host = f.get("target_host") or "127.0.0.1"
        server_ip = f["server_ip"]
        args = "client --server %s --bridge %s --target-host %s" % (server_ip, f["bridge"], target_host)
    token = f.get("token") or (gen_token() if role == "server" else "")
    if not token or len(token) < 16:
        return False, "توکن باید حداقل ۱۶ کاراکتر باشد"
    args += " --slot %s --stats-dir %s" % (slot, os.path.join(CONF_DIR, "stats"))
    text = (
        "TYPE=tcp\nROLE=%s\nBRIDGE=%s\nPORTS=%s\nSERVER_IP=%s\nTARGET_HOST=%s\n"
        "NICETUNNEL_TOKEN=%s\nRT_ARGS=\"%s\"\n"
    ) % (role, f.get("bridge", ""), f.get("ports", ""), server_ip, target_host, token, args)
    write_slot_file(slot, text)
    return True, token


def create_spoof_slot(slot, role, f):
    transport = f.get("transport") or "udp"
    if transport not in ("udp", "tcp", "icmp"):
        return False, "نوع بسته نامعتبر است"
    tport = f.get("tport") or "4500"
    if not valid_port(tport) or not f.get("peer") or not f.get("spoofs"):
        return False, "پورت تانل، سرور مقابل یا لیست آی‌پی‌ها نامعتبر است"
    args = "--peer %s --spoof-ip %s --transport %s --port %s" % (f["peer"], f["spoofs"], transport, tport)
    if role == "server":
        listen_port = f.get("listen_port") or "51820"
        if not valid_port(listen_port):
            return False, "پورت UDP برنامه‌ها نامعتبر است"
        args = "spoof-entry %s --listen-port %s" % (args, listen_port)
        forward = ""
    else:
        forward = f.get("forward") or "127.0.0.1:51820"
        if ":" not in forward or not valid_port(forward.rsplit(":", 1)[-1]):
            return False, "آدرس HOST:PORT نامعتبر است"
        args = "spoof-exit %s --forward %s" % (args, forward)
        listen_port = ""
    token = f.get("token") or (gen_token() if role == "server" else "")
    if not token or len(token) < 16:
        return False, "توکن باید حداقل ۱۶ کاراکتر باشد"
    args += " --slot %s --stats-dir %s" % (slot, os.path.join(CONF_DIR, "stats"))
    text = (
        "TYPE=spoof\nROLE=%s\nTRANSPORT=%s\nTPORT=%s\nPEER_IP=%s\nSPOOF_IPS=%s\nLISTEN_PORT=%s\nFORWARD=%s\n"
        "NICETUNNEL_TOKEN=%s\nRT_ARGS=\"%s\"\n"
    ) % (role, transport, tport, f.get("peer", ""), f.get("spoofs", ""), listen_port, forward, token, args)
    write_slot_file(slot, text)
    return True, token


def collect_status():
    slots = []
    for slot in list_slots():
        env = parse_env_file(os.path.join(CONF_DIR, "slot%s.env" % slot)) or {}
        token = env.get("NICETUNNEL_TOKEN", "")
        info = {
            "slot": slot,
            "type": env.get("TYPE", "tcp"),
            "role": env.get("ROLE", ""),
            "state": unit_state(slot),
            "token_preview": (token[:8] + "...") if token else "",
        }
        if info["type"] == "spoof":
            info.update(transport=env.get("TRANSPORT", ""), port=env.get("TPORT", ""),
                        peer=env.get("PEER_IP", ""), listen_port=env.get("LISTEN_PORT", ""),
                        forward=env.get("FORWARD", ""))
        else:
            info.update(bridge=env.get("BRIDGE", ""), ports=env.get("PORTS", ""),
                        server_ip=env.get("SERVER_IP", ""), target_host=env.get("TARGET_HOST", ""))
        live = read_live(slot)
        if live:
            info["live"] = live
        slots.append(info)
    slots.sort(key=lambda s: int(s["slot"]))
    system = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "arch": platform.machine(),
        "cpus": os.cpu_count() or 1,
        "python": platform.python_version(),
        "uptime": time.time() - PANEL_STARTED,
        "memory_kb": panel_memory_kb(),
    }
    return {"version": VERSION, "slots": slots, "system": system}


# --------------------------------------------------------------------------
# auth: sessions + a slow-down on repeated bad passwords
# --------------------------------------------------------------------------
def new_session():
    token = secrets.token_hex(32)
    with sessions_lock:
        sessions[token] = time.time() + SESSION_TTL
    return token


def valid_session(token):
    if not token:
        return False
    with sessions_lock:
        exp = sessions.get(token)
        if exp is None:
            return False
        if exp < time.time():
            sessions.pop(token, None)
            return False
        return True


def drop_session(token):
    if token:
        with sessions_lock:
            sessions.pop(token, None)


def is_locked(ip):
    with fails_lock:
        _, until = fails.get(ip, (0, 0))
        return until > time.time()


def record_fail(ip):
    with fails_lock:
        cnt, _ = fails.get(ip, (0, 0))
        cnt += 1
        fails[ip] = (cnt, time.time() + min(300, 2 ** min(cnt, 8)))


def record_ok(ip):
    with fails_lock:
        fails.pop(ip, None)


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------
LOGIN_PAGE = """<!doctype html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NiceTunnel</title>
<style>
 body{font-family:system-ui,Tahoma,sans-serif;background:#0b0d12;color:#e6e6e6;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 form{background:#151823;padding:30px;border-radius:14px;min-width:300px;
      box-shadow:0 10px 30px rgba(0,0,0,.4);border:1px solid #242938}
 .brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
 .logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#3b82f6);
       display:flex;align-items:center;justify-content:center;font-weight:bold;color:#fff;font-size:15px;flex:none}
 h1{font-size:16px;margin:0}
 .sub{color:#8b93a7;font-size:12px;margin-top:2px}
 input{width:100%;box-sizing:border-box;padding:11px;border-radius:9px;border:1px solid #2a3041;
       background:#0b0d12;color:#fff;margin-bottom:14px;font-size:15px}
 button{width:100%;padding:11px;border:0;border-radius:9px;background:linear-gradient(135deg,#6366f1,#3b82f6);
        color:#fff;font-weight:bold;cursor:pointer;font-size:15px}
 .err{color:#f87171;margin-bottom:12px;font-size:13px;background:rgba(239,68,68,.1);
      padding:8px 10px;border-radius:8px}
</style></head><body>
<form method="post" action="/login">
<div class="brand"><div class="logo">NT</div><div><h1>NiceTunnel</h1><div class="sub">ورود به پنل مدیریت</div></div></div>
__ERR__
<input type="password" name="password" placeholder="رمز عبور" autofocus>
<button type="submit">ورود</button>
</form></body></html>"""

PAGE = """<!doctype html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NiceTunnel</title>
<style>
 :root{--bg:#0b0d12;--card:#151823;--card2:#11141d;--line:#242938;--fg:#e6e6e6;--mut:#8b93a7;
       --ok:#22c55e;--bad:#ef4444;--warn:#f59e0b;--acc:#3b82f6;--acc2:#6366f1}
 *{box-sizing:border-box}
 body{font-family:system-ui,Tahoma,sans-serif;background:var(--bg);color:var(--fg);margin:0;
      display:flex;flex-direction:column;min-height:100vh}
 .topbar{display:flex;align-items:center;justify-content:space-between;padding:10px 20px;
         background:var(--card2);border-bottom:1px solid var(--line);flex:none}
 .topbar .tb-left{display:flex;align-items:center;gap:10px}
 .topbar b{font-size:14.5px}
 .tbver{color:var(--mut);font-size:11px;margin-right:9px;direction:ltr;display:inline-block}
 .tbbtn{color:var(--fg);text-decoration:none;font-size:12.5px;border:1px solid rgba(255,255,255,.14);
        padding:7px 14px;border-radius:8px;background:rgba(255,255,255,.06);backdrop-filter:blur(8px);
        -webkit-backdrop-filter:blur(8px);transition:background .15s,border-color .15s}
 .tbbtn:hover{border-color:var(--acc);background:rgba(255,255,255,.13)}
 .footbar{text-align:center;color:var(--mut);font-size:11.5px;padding:14px;border-top:1px solid var(--line);flex:none}
 .shell{display:flex;flex:1;min-height:0}
 .sidebar{width:210px;flex:none;background:var(--card2);border-left:1px solid var(--line);
          display:flex;flex-direction:column;padding:16px 12px;gap:4px}
 .logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--acc2),var(--acc));
       display:flex;align-items:center;justify-content:center;font-weight:bold;color:#fff;font-size:14px;flex:none}
 .navlink{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:9px;color:var(--mut);
          text-decoration:none;font-size:13.5px;cursor:pointer;user-select:none}
 .navlink:hover{background:#1b1f2c;color:var(--fg)}
 .navlink.active{background:rgba(59,130,246,.15);color:#fff}
 .navlink .ic{width:18px;text-align:center;flex:none}
 .side-bottom{margin-top:auto;display:flex;flex-direction:column;gap:4px}
 .content{flex:1;padding:22px;min-width:0}
 .topline{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:8px}
 .topline h2{font-size:17px;margin:0;font-weight:600}
 .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
 .stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:15px}
 .stat .lbl{color:var(--mut);font-size:12px;margin-bottom:8px}
 .stat .val{font-size:24px;font-weight:700}
 .stat .val.ok{color:var(--ok)} .stat .val.bad{color:var(--bad)}
 .panel{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:18px}
 .panel .ph{padding:14px 16px;border-bottom:1px solid var(--line);font-size:14px;font-weight:600}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{text-align:right;color:var(--mut);font-weight:normal;font-size:12px;padding:10px 16px;
    border-bottom:1px solid var(--line)}
 td{padding:12px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
 tr:last-child td{border-bottom:none}
 td.sub{color:var(--mut);font-size:12px;margin-top:2px}
 .badge{font-size:11.5px;padding:3px 10px;border-radius:999px;white-space:nowrap;display:inline-block}
 .b-active{background:rgba(34,197,94,.15);color:var(--ok)}
 .b-down{background:rgba(239,68,68,.15);color:var(--bad)}
 .b-unknown{background:rgba(245,158,11,.15);color:var(--warn)}
 .mono{direction:ltr;text-align:right;display:inline-block;font-variant-numeric:tabular-nums}
 .acts{display:flex;gap:6px;flex-wrap:wrap}
 .acts button{padding:7px 11px;border:1px solid rgba(255,255,255,.14);border-radius:7px;
              background:rgba(255,255,255,.06);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
              color:var(--fg);cursor:pointer;font-size:12px;transition:background .15s,border-color .15s}
 .acts button:hover{background:rgba(255,255,255,.13);border-color:var(--acc)}
 .acts button.danger:hover{border-color:var(--bad);color:#fca5a5}
 .empty{color:var(--mut);text-align:center;padding:40px}
 .gbtn{background:rgba(255,255,255,.06);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
      border:1px solid rgba(255,255,255,.16);color:var(--fg);border-radius:9px;cursor:pointer;
      padding:9px 18px;font-size:13px;transition:background .15s,border-color .15s}
 .gbtn:hover{background:rgba(255,255,255,.14);border-color:rgba(255,255,255,.32)}
 .gbtn.primary{background:linear-gradient(135deg,rgba(99,102,241,.4),rgba(59,130,246,.4));
              border-color:rgba(99,102,241,.55)}
 .gbtn.primary:hover{background:linear-gradient(135deg,rgba(99,102,241,.6),rgba(59,130,246,.6))}
 .formcard{padding:16px}
 .frow{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:10px}
 .field label{display:block;font-size:11.5px;color:var(--mut);margin-bottom:5px}
 .field input,.field select{width:100%;box-sizing:border-box;padding:9px 10px;border-radius:8px;
      border:1px solid var(--line);background:#0e1119;color:var(--fg);font-size:13px;
      direction:ltr;text-align:right}
 .field input:focus,.field select:focus{outline:none;border-color:var(--acc)}
 .hint{color:var(--mut);font-size:11.5px;margin:9px 0 2px;line-height:1.8;white-space:pre-wrap}
 .hint.ok{color:var(--ok)} .hint.bad{color:var(--bad)}
 .divider{height:1px;background:var(--line);margin:16px 0}
 pre.logs{background:#0b0d12;border-top:1px solid var(--line);padding:12px 16px;max-height:260px;
          overflow:auto;font-size:12px;white-space:pre-wrap;direction:ltr;text-align:left;display:none;margin:0}
 .sysgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:0}
 .sysgrid div{padding:14px 16px;border-top:1px solid var(--line)}
 .sysgrid div:nth-child(-n+5){border-top:none}
 .sysgrid .lbl{color:var(--mut);font-size:11.5px;margin-bottom:4px}
 .sysgrid .val{font-size:14px;direction:ltr;text-align:right}
 .view{display:none} .view.active{display:block}
 .toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1b1f2c;
        border:1px solid var(--line);padding:9px 18px;border-radius:9px;font-size:13px;display:none;z-index:9}
 @media (max-width:760px){
   .shell{flex-direction:column}
   .sidebar{width:100%;flex-direction:row;align-items:center;overflow-x:auto;border-left:none;
            border-bottom:1px solid var(--line)}
   .side-bottom{margin-top:0;flex-direction:row}
   .topbar{padding:10px 14px}
   table{font-size:12px} th,td{padding:9px 8px}
 }
</style></head><body>
<div class="topbar">
  <div class="tb-left"><div class="logo">NT</div><div><b>NiceTunnel</b><span class="tbver">v__VERSION__</span></div></div>
  <a class="tbbtn" href="https://github.com/arshamsmok/nicetunnel" target="_blank" rel="noopener">GitHub</a>
</div>
<div class="shell">
  <aside class="sidebar">
    <a class="navlink active" data-view="dash" onclick="showView('dash')"><span class="ic">&#9635;</span>داشبورد</a>
    <a class="navlink" data-view="reverse" onclick="showView('reverse')"><span class="ic">&#8646;</span>تانل ریورس</a>
    <a class="navlink" data-view="spoof" onclick="showView('spoof')"><span class="ic">&#128272;</span>تانل اسپوف</a>
    <a class="navlink" data-view="settings" onclick="showView('settings')"><span class="ic">&#9881;</span>تنظیمات</a>
    <div class="side-bottom">
      <a class="navlink" href="/logout"><span class="ic">&#10140;</span>خروج</a>
    </div>
  </aside>
  <main class="content">
    <div class="topline"><h2 id="pagetitle">داشبورد</h2></div>

    <div id="dash" class="view active">
      <div class="stats">
        <div class="stat"><div class="lbl">کل تانل‌ها</div><div class="val" id="st-total">-</div></div>
        <div class="stat"><div class="lbl">روشن</div><div class="val ok" id="st-up">-</div></div>
        <div class="stat"><div class="lbl">خاموش</div><div class="val bad" id="st-down">-</div></div>
        <div class="stat"><div class="lbl">ترافیک کل</div><div class="val mono" id="st-traffic">-</div></div>
      </div>
      <div class="panel">
        <div class="ph">تانل‌ها</div>
        <div id="tablewrap"><div class="empty">در حال بارگذاری...</div></div>
      </div>
    </div>

    <div id="reverse" class="view">
      <div class="panel">
        <div class="ph">ساخت تانل ریورس (TCP)</div>
        <div class="formcard">
          <div class="frow">
            <div class="field"><label>سمت</label>
              <select id="r-role" onchange="toggleRole('r')">
                <option value="server">سرور ایران</option><option value="client">سرور خارج</option>
              </select></div>
            <div class="field"><label>پورت Bridge</label><input id="r-bridge" value="7000"></div>
          </div>
          <div class="frow" id="r-server-row">
            <div class="field"><label>پورت‌های عمومی (مثلاً 443 یا 443,8443:8080)</label>
              <input id="r-ports" placeholder="443"></div>
          </div>
          <div class="frow" id="r-client-row" style="display:none">
            <div class="field"><label>آی‌پی سرور ایران</label><input id="r-serverip" placeholder="203.0.113.5"></div>
            <div class="field"><label>Forward به (روی این سرور)</label><input id="r-target" value="127.0.0.1"></div>
            <div class="field"><label>توکن (از سرور ایران کپی کن)</label><input id="r-token"></div>
          </div>
          <button class="gbtn primary" onclick="createTunnel('tcp')">ساخت تانل</button>
          <div class="hint" id="r-result"></div>
        </div>
      </div>
      <div class="panel"><div class="ph">تانل‌های TCP</div>
        <div id="tablewrap-rev"><div class="empty">تانل TCP ساخته نشده.</div></div></div>
    </div>

    <div id="spoof" class="view">
      <div class="panel">
        <div class="ph">ساخت تانل اسپوف</div>
        <div class="formcard">
          <div class="frow">
            <div class="field"><label>سمت</label>
              <select id="s-role" onchange="toggleRole('s')">
                <option value="server">سرور ایران (entry)</option><option value="client">سرور خارج (exit)</option>
              </select></div>
            <div class="field"><label>آی‌پی واقعی سرور مقابل</label><input id="s-peer" placeholder="203.0.113.9"></div>
            <div class="field"><label>نوع بسته</label>
              <select id="s-transport"><option value="udp">udp</option><option value="tcp">tcp</option><option value="icmp">icmp</option></select></div>
            <div class="field"><label>پورت تانل</label><input id="s-tport" value="4500"></div>
          </div>
          <div class="frow">
            <div class="field" style="grid-column:1/-1"><label>آی‌پی‌های مبدأ (از تستر پایین پیدا کن)</label>
              <input id="s-spoofs" placeholder="10.0.0.0/28 یا 5.5.5.1-5.5.5.9"></div>
          </div>
          <div class="frow" id="s-server-row">
            <div class="field"><label>پورت UDP برنامه‌ها</label><input id="s-listen" value="51820"></div>
          </div>
          <div class="frow" id="s-client-row" style="display:none">
            <div class="field"><label>Forward (HOST:PORT سرویس UDP)</label><input id="s-forward" value="127.0.0.1:51820"></div>
            <div class="field"><label>توکن (از سرور ایران کپی کن)</label><input id="s-token"></div>
          </div>
          <button class="gbtn primary" onclick="createTunnel('spoof')">ساخت تانل</button>
          <div class="hint" id="s-result"></div>
        </div>
      </div>

      <div class="panel">
        <div class="ph">تستر اسپوف</div>
        <div class="formcard">
          <button class="gbtn" onclick="testCheck()">بررسی این سرور</button>
          <div class="hint" id="t-check-result"></div>
          <div class="divider"></div>
          <div class="frow">
            <div class="field"><label>نوع بسته</label>
              <select id="t-transport"><option value="udp">udp</option><option value="tcp">tcp</option><option value="icmp">icmp</option></select></div>
            <div class="field"><label>پورت</label><input id="t-port" value="4500"></div>
            <div class="field"><label>ثانیه انتظار (Receive)</label><input id="t-seconds" value="20"></div>
          </div>
          <button class="gbtn" onclick="testRecv()">&#9312; گوش کن (Receive) &mdash; روی این سرور</button>
          <div class="frow" style="margin-top:12px">
            <div class="field"><label>آی‌پی واقعی سرور گیرنده</label><input id="t-peer" placeholder="203.0.113.9"></div>
            <div class="field" style="grid-column:1/-1"><label>آی‌پی‌های تست</label><input id="t-spoofs" placeholder="10.0.0.0/28"></div>
          </div>
          <button class="gbtn" onclick="testSend()">&#9313; بفرست (Send) &mdash; روی سرور دیگر</button>
          <pre class="logs" id="t-out" style="display:block;margin-top:12px;max-height:220px"></pre>
        </div>
      </div>
      <div class="panel"><div class="ph">تانل‌های اسپوف</div>
        <div id="tablewrap-spoof"><div class="empty">تانل اسپوف ساخته نشده.</div></div></div>
    </div>

    <div id="settings" class="view">
      <div class="panel">
        <div class="ph">اطلاعات سیستم</div>
        <div class="sysgrid" id="sysinfo"></div>
      </div>
      <div class="panel">
        <div class="ph">درباره‌ی پنل</div>
        <div style="padding:14px 16px;color:var(--mut);font-size:13px;line-height:1.9">
          ساخت تانل جدید، تغییر رمز پنل و تغییر پورت فقط از منوی ترمینال سرور انجام می‌شود:
          <span class="mono" style="color:var(--fg)">nicetunnel</span> &larr; Web panel.<br>
          NiceTunnel &copy; Arsham Smoke &middot; MIT License
        </div>
      </div>
    </div>
  </main>
</div>
<div class="footbar">NiceTunnel v__VERSION__ &middot; پنل مدیریت تانل &middot; ساخته‌ی Arsham Smoke</div>
<div class="toast" id="toast"></div>
<script>
function fmtBytes(n){
  n = n || 0;
  var u = ["B","KB","MB","GB"], i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtUptime(sec){
  sec = Math.floor(sec || 0);
  var d = Math.floor(sec / 86400); sec -= d * 86400;
  var h = Math.floor(sec / 3600); sec -= h * 3600;
  var m = Math.floor(sec / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m";
}
function toast(msg){
  var t = document.getElementById("toast");
  t.textContent = msg; t.style.display = "block";
  setTimeout(function(){ t.style.display = "none"; }, 2500);
}
var VIEW_TITLE = {dash: "داشبورد", reverse: "تانل ریورس", spoof: "تانل اسپوف", settings: "تنظیمات"};
function toggleRole(p){
  var role = document.getElementById(p + "-role").value;
  var srow = document.getElementById(p + "-server-row");
  var crow = document.getElementById(p + "-client-row");
  if (srow) srow.style.display = role === "server" ? "" : "none";
  if (crow) crow.style.display = role === "server" ? "none" : "";
}
function showView(v){
  document.querySelectorAll(".view").forEach(function(el){ el.classList.toggle("active", el.id === v); });
  document.querySelectorAll(".navlink[data-view]").forEach(function(el){
    el.classList.toggle("active", el.getAttribute("data-view") === v);
  });
  document.getElementById("pagetitle").textContent = VIEW_TITLE[v] || v;
}
function badgeClass(s){
  if (s === "active") return "b-active";
  if (s === "failed" || s === "inactive") return "b-down";
  return "b-unknown";
}
var STATE_LABEL = {active:"روشن", inactive:"خاموش", failed:"خطا", activating:"در حال اتصال", deactivating:"در حال توقف"};
function stLabel(s){ return STATE_LABEL[s] || s || "نامشخص"; }
function roleLabel(r){ return r === "server" ? "ایران" : "خارج"; }
function typeLabel(t){ return t === "spoof" ? "اسپوف" : "TCP"; }

function detailLine(s){
  if (s.type === "spoof") {
    return (s.transport || "-").toUpperCase() + " &middot; پورت " + (s.port || "-") +
           " &middot; مقابل " + (s.peer || "-");
  }
  return "Bridge " + (s.bridge || "-") + " &middot; " +
         (s.role === "server" ? (s.ports || "-") : (s.server_ip || "-"));
}

function row(s){
  var live = s.live || {};
  var stale = live.stale ? " (قدیمی)" : "";
  return '<tr>' +
    '<td><span class="badge ' + badgeClass(s.state) + '">' + stLabel(s.state) + stale + '</span></td>' +
    '<td>تانل ' + s.slot + '<div class="sub">' + typeLabel(s.type) + ' &middot; ' + roleLabel(s.role) + '</div></td>' +
    '<td><span class="mono">' + detailLine(s) + '</span></td>' +
    '<td><span class="mono">' + fmtBytes(live.bytes_tx) + ' &#8593; / ' + fmtBytes(live.bytes_rx) + ' &#8595;</span></td>' +
    '<td><div class="acts">' +
      '<button onclick="act(\\'' + s.slot + '\\',\\'start\\')">روشن</button>' +
      '<button onclick="act(\\'' + s.slot + '\\',\\'restart\\')">ری‌استارت</button>' +
      '<button class="danger" onclick="act(\\'' + s.slot + '\\',\\'stop\\')">خاموش</button>' +
      '<button onclick="toggleLogs(\\'' + s.slot + '\\')">لاگ</button>' +
    '</div></td>' +
  '</tr>' +
  '<tr><td colspan="5" style="padding:0"><pre class="logs" id="logs-' + s.slot + '"></pre></td></tr>';
}

function act(slot, action){
  fetch("/api/action", {method:"POST", headers:{"X-NT-Panel":"1","Content-Type":"application/json"},
                        body: JSON.stringify({slot: slot, action: action})})
    .then(function(r){ return r.json(); })
    .then(function(d){ toast(d.ok ? "انجام شد" : ("خطا: " + (d.detail || d.error || ""))); refresh(); })
    .catch(function(){ toast("خطا در ارتباط"); });
}

function toggleLogs(slot){
  var el = document.getElementById("logs-" + slot);
  if (el.style.display === "block") { el.style.display = "none"; return; }
  document.querySelectorAll("pre.logs").forEach(function(p){ p.style.display = "none"; });
  el.style.display = "block";
  el.textContent = "...";
  fetch("/api/logs?slot=" + encodeURIComponent(slot) + "&lines=150")
    .then(function(r){ return r.json(); })
    .then(function(d){ el.textContent = d.text || d.error || "(خالی)"; });
}

function createTunnel(type){
  var body = {type: type};
  if (type === "tcp") {
    body.role = document.getElementById("r-role").value;
    body.bridge = document.getElementById("r-bridge").value;
    body.ports = document.getElementById("r-ports").value;
    body.server_ip = document.getElementById("r-serverip").value;
    body.target_host = document.getElementById("r-target").value;
    body.token = document.getElementById("r-token").value;
  } else {
    body.role = document.getElementById("s-role").value;
    body.peer = document.getElementById("s-peer").value;
    body.transport = document.getElementById("s-transport").value;
    body.tport = document.getElementById("s-tport").value;
    body.spoofs = document.getElementById("s-spoofs").value;
    body.listen_port = document.getElementById("s-listen").value;
    body.forward = document.getElementById("s-forward").value;
    body.token = document.getElementById("s-token").value;
  }
  var res = document.getElementById(type === "tcp" ? "r-result" : "s-result");
  res.className = "hint"; res.textContent = "در حال ساخت...";
  fetch("/api/create", {method:"POST", headers:{"X-NT-Panel":"1","Content-Type":"application/json"},
                        body: JSON.stringify(body)})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.ok) {
        res.className = "hint ok";
        res.textContent = "ساخته شد: تانل " + d.slot + (d.token ? " \u2014 توکن: " + d.token : "") +
                           (d.started ? "" : " (روشن نشد، از لاگ تانل بررسی کن)");
        toast("تانل ساخته شد");
        refresh();
      } else {
        res.className = "hint bad";
        res.textContent = "خطا: " + (d.detail || d.error || "نامشخص");
      }
    })
    .catch(function(){ res.className = "hint bad"; res.textContent = "خطا در ارتباط"; });
}

function testCheck(){
  var el = document.getElementById("t-check-result");
  el.className = "hint"; el.textContent = "در حال بررسی...";
  fetch("/api/spoof-test", {method:"POST", headers:{"X-NT-Panel":"1","Content-Type":"application/json"},
                            body: JSON.stringify({mode:"check"})})
    .then(function(r){ return r.json(); })
    .then(function(d){ el.className = "hint " + (d.ok ? "ok" : "bad"); el.textContent = d.text; })
    .catch(function(){ el.className = "hint bad"; el.textContent = "خطا در ارتباط"; });
}

function spoofTest(mode, extra){
  var out = document.getElementById("t-out");
  out.style.display = "block";
  out.textContent = "در حال اجرا... (ممکن است چند ثانیه طول بکشد)";
  var body = {mode: mode, transport: document.getElementById("t-transport").value,
              port: document.getElementById("t-port").value};
  for (var k in extra) body[k] = extra[k];
  fetch("/api/spoof-test", {method:"POST", headers:{"X-NT-Panel":"1","Content-Type":"application/json"},
                            body: JSON.stringify(body)})
    .then(function(r){ return r.json(); })
    .then(function(d){ out.textContent = d.text || d.error || "(خالی)"; })
    .catch(function(){ out.textContent = "خطا در ارتباط"; });
}
function testRecv(){ spoofTest("recv", {seconds: document.getElementById("t-seconds").value}); }
function testSend(){
  spoofTest("send", {peer: document.getElementById("t-peer").value,
                      spoofs: document.getElementById("t-spoofs").value});
}

function renderSys(sys){
  if (!sys) return;
  document.getElementById("sysinfo").innerHTML =
    '<div><div class="lbl">نام میزبان</div><div class="val">' + sys.hostname + '</div></div>' +
    '<div><div class="lbl">سیستم عامل</div><div class="val">' + sys.os + ' / ' + sys.arch + '</div></div>' +
    '<div><div class="lbl">هسته‌های CPU</div><div class="val">' + sys.cpus + '</div></div>' +
    '<div><div class="lbl">نسخه پایتون</div><div class="val">' + sys.python + '</div></div>' +
    '<div><div class="lbl">مدت فعالیت پنل</div><div class="val">' + fmtUptime(sys.uptime) + '</div></div>' +
    '<div><div class="lbl">حافظه‌ی مصرفی پنل</div><div class="val">' +
      (sys.memory_kb ? fmtBytes(sys.memory_kb * 1024) : "-") + '</div></div>';
}

function renderTable(wrap, list, emptyMsg){
  if (!wrap) return;
  if (!list.length) {
    wrap.innerHTML = '<div class="empty">' + emptyMsg + '</div>';
  } else {
    wrap.innerHTML = '<table><thead><tr>' +
      '<th>وضعیت</th><th>تانل</th><th>جزئیات</th><th>ترافیک</th><th>عملیات</th>' +
      '</tr></thead><tbody>' + list.map(row).join("") + '</tbody></table>';
  }
}
function refresh(){
  fetch("/api/status").then(function(r){
    if (r.status === 401) { location.href = "/"; throw new Error("auth"); }
    return r.json();
  }).then(function(d){
    var up = 0, down = 0, tx = 0, rx = 0;
    d.slots.forEach(function(s){
      if (s.state === "active") up++; else down++;
      if (s.live) { tx += s.live.bytes_tx || 0; rx += s.live.bytes_rx || 0; }
    });
    document.getElementById("st-total").textContent = d.slots.length;
    document.getElementById("st-up").textContent = up;
    document.getElementById("st-down").textContent = down;
    document.getElementById("st-traffic").textContent = fmtBytes(tx + rx);
    renderTable(document.getElementById("tablewrap"), d.slots,
                "هنوز تانلی ساخته نشده.");
    renderTable(document.getElementById("tablewrap-rev"),
                d.slots.filter(function(s){ return s.type !== "spoof"; }), "تانل TCP ساخته نشده.");
    renderTable(document.getElementById("tablewrap-spoof"),
                d.slots.filter(function(s){ return s.type === "spoof"; }), "تانل اسپوف ساخته نشده.");
    renderSys(d.system);
  }).catch(function(){ /* keep the last view on a transient error */ });
}
refresh();
setInterval(refresh, 3000);
</script>
</body></html>""".replace("__VERSION__", VERSION)


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NiceTunnelPanel/" + VERSION

    def log_message(self, fmt, *a):
        pass  # the systemd journal would otherwise fill up with access logs

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(COOKIE_NAME + "="):
                return part[len(COOKIE_NAME) + 1:]
        return None

    def _authed(self):
        return valid_session(self._cookie())

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", extra_headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj), code, "application/json")

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path == "/":
            return self._send(PAGE if self._authed() else LOGIN_PAGE.replace("__ERR__", ""))

        if path == "/logout":
            drop_session(self._cookie())
            return self._send("", 302, extra_headers=[
                ("Location", "/"), ("Set-Cookie", COOKIE_NAME + "=; Path=/; Max-Age=0")])

        if not self._authed():
            return self._json({"error": "auth"}, 401)

        if path == "/api/status":
            return self._json(collect_status())

        if path == "/api/logs":
            qs = urllib.parse.parse_qs(parsed.query)
            slot = (qs.get("slot") or [""])[0]
            if not slot.isdigit():
                return self._json({"error": "bad slot"}, 400)
            try:
                lines = min(int((qs.get("lines") or ["150"])[0]), 500)
            except ValueError:
                lines = 150
            ok, out = run_journal(slot, lines)
            return self._json({"ok": ok, "text": out})

        self._send("not found", 404)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(min(length, 1 << 16)) if length else b""
        ip = self.client_address[0]

        if path == "/login":
            if is_locked(ip):
                return self._send(LOGIN_PAGE.replace(
                    "__ERR__", '<div class="err">تلاش زیاد. کمی صبر کن.</div>'), 429)
            form = urllib.parse.parse_qs(raw.decode(errors="replace"))
            pw = (form.get("password") or [""])[0]
            if check_password(pw):
                record_ok(ip)
                token = new_session()
                return self._send("", 302, extra_headers=[
                    ("Location", "/"),
                    ("Set-Cookie", "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=%d"
                     % (COOKIE_NAME, token, SESSION_TTL))])
            record_fail(ip)
            time.sleep(1)
            return self._send(LOGIN_PAGE.replace(
                "__ERR__", '<div class="err">رمز اشتباه است.</div>'), 401)

        if not self._authed():
            return self._json({"error": "auth"}, 401)

        if path == "/api/action":
            if self.headers.get("X-NT-Panel") != "1":
                return self._json({"error": "bad request"}, 403)
            try:
                body = json.loads(raw.decode() or "{}")
            except Exception:
                return self._json({"error": "bad json"}, 400)
            slot = str(body.get("slot", ""))
            action = body.get("action", "")
            if not slot.isdigit() or action not in ("start", "stop", "restart"):
                return self._json({"error": "bad request"}, 400)
            ok, out = systemctl(action, "nicetunnel@%s" % slot)
            return self._json({"ok": ok, "detail": out})

        if path == "/api/create":
            if self.headers.get("X-NT-Panel") != "1":
                return self._json({"error": "bad request"}, 403)
            try:
                body = json.loads(raw.decode() or "{}")
            except Exception:
                return self._json({"error": "bad json"}, 400)
            ttype, role = body.get("type"), body.get("role")
            if ttype not in ("tcp", "spoof") or role not in ("server", "client"):
                return self._json({"error": "bad request"}, 400)
            slot = next_free_slot()
            if slot is None:
                return self._json({"ok": False, "detail": "همه‌ی %d اسلات پر است" % MAX_SLOT})
            fn = create_tcp_slot if ttype == "tcp" else create_spoof_slot
            ok, detail = fn(slot, role, body)
            if not ok:
                return self._json({"ok": False, "detail": detail})
            systemctl("enable", "nicetunnel@%s" % slot)
            started, _ = systemctl("restart", "nicetunnel@%s" % slot)
            return self._json({"ok": True, "slot": slot, "token": detail, "started": started})

        if path == "/api/spoof-test":
            if self.headers.get("X-NT-Panel") != "1":
                return self._json({"error": "bad request"}, 403)
            try:
                body = json.loads(raw.decode() or "{}")
            except Exception:
                return self._json({"error": "bad json"}, 400)
            mode = body.get("mode")
            transport = body.get("transport") or "udp"
            port = str(body.get("port") or "4500")
            if mode == "check":
                try:
                    r = subprocess.run([sys.executable, ENGINE_PATH, "spoof-check", "--raw"],
                                        capture_output=True, text=True, timeout=10)
                    out = (r.stdout + r.stderr).strip()
                    return self._json({"ok": out == "ok", "text": out or "نامشخص"})
                except Exception as exc:
                    return self._json({"ok": False, "text": str(exc)})
            if mode == "recv":
                try:
                    seconds = max(5, min(int(body.get("seconds") or 20), 90))
                except (TypeError, ValueError):
                    seconds = 20
                cmd = [sys.executable, ENGINE_PATH, "spoof-test", "recv",
                       "--transport", transport, "--port", port, "--seconds", str(seconds)]
                budget = seconds + 15
            elif mode == "send":
                peer, spoofs = body.get("peer") or "", body.get("spoofs") or ""
                if not peer or not spoofs:
                    return self._json({"ok": False, "text": "آی‌پی سرور یا لیست آی‌پی‌ها خالی است"})
                cmd = [sys.executable, ENGINE_PATH, "spoof-test", "send", "--peer", peer,
                       "--transport", transport, "--port", port, "--spoof-ip", spoofs]
                budget = 30
            else:
                return self._json({"error": "bad request"}, 400)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=budget)
                return self._json({"ok": True, "text": (r.stdout + r.stderr).strip()})
            except subprocess.TimeoutExpired:
                return self._json({"ok": False, "text": "زمان تست تمام شد"})
            except Exception as exc:
                return self._json({"ok": False, "text": str(exc)})

        self._send("not found", 404)


# --------------------------------------------------------------------------
# TLS + entry point
# --------------------------------------------------------------------------
def ensure_cert(dirpath):
    cert, key = os.path.join(dirpath, "cert.pem"), os.path.join(dirpath, "key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    try:
        os.makedirs(dirpath, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825",
                        "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=nicetunnel"],
                       check=True, capture_output=True)
        os.chmod(key, 0o600)
        return cert, key
    except Exception as exc:
        print("warning: could not create a TLS certificate (%s); serving plain HTTP instead." % exc,
              file=sys.stderr)
        return None, None


def main():
    global CONF_DIR
    p = argparse.ArgumentParser(description="NiceTunnel web panel")
    p.add_argument("--conf-dir", default=CONF_DIR)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--no-tls", action="store_true", help="serve plain HTTP (not recommended)")
    p.add_argument("--version", action="version", version="NiceTunnel panel " + VERSION)
    args = p.parse_args()
    CONF_DIR = args.conf_dir

    if not panel_auth().get("PANEL_HASH"):
        sys.exit("error: no panel password is set yet. Set one from the menu (nicetunnel -> Web panel) first.")

    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), Handler)
    scheme = "http"
    if not args.no_tls:
        cert, key = ensure_cert(os.path.join(CONF_DIR, "panel"))
        if cert and key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
    print("NiceTunnel panel listening on %s://%s:%d" % (scheme, args.bind, args.port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
