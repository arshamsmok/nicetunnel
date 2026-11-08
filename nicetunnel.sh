#!/usr/bin/env bash
# NiceTunnel manager: interactive menu for creating and managing tunnels.
# Author: Arsham Smoke - MIT License (see LICENSE)
# Installed as /usr/local/bin/nicetunnel by install.sh. Open it with:  nicetunnel

CONF_DIR="${NICETUNNEL_CONF_DIR:-/etc/nicetunnel}"
APP_DIR="${NICETUNNEL_APP_DIR:-/opt/nicetunnel}"
BIN_PATH="${NICETUNNEL_BIN:-/usr/local/bin/nicetunnel}"
UNIT_FILE="${NICETUNNEL_UNIT_DIR:-/etc/systemd/system}/nicetunnel@.service"
SYSCTL_FILE="${NICETUNNEL_SYSCTL_DIR:-/etc/sysctl.d}/99-nicetunnel.conf"
TTY="${NICETUNNEL_TTY:-/dev/tty}"
MAX_SLOT=10

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$G" "$*" "$N"; }
warn() { printf '%s%s%s\n' "$Y" "$*" "$N"; }
err()  { printf '%s%s%s\n' "$R" "$*" "$N" >&2; }

# ask "prompt" [default]  -> answer in $REPLY (input always comes from fd 3)
ask() {
  if [ -n "${2:-}" ]; then printf '%s [%s]: ' "$1" "$2"; else printf '%s: ' "$1"; fi
  IFS= read -r REPLY <&3 || { echo; exit 1; }
  REPLY="${REPLY//$'\r'/}"
  REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
  REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
  REPLY="${REPLY:-${2:-}}"
}

yesno() { ask "$1" "${2:-n}"; [[ "$REPLY" =~ ^[Yy] ]]; }
pause() { printf '\nPress Enter to continue...'; read -r _ <&3 || true; echo; }

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]]; }
valid_token() { [[ "$1" =~ ^[A-Za-z0-9._-]{16,}$ ]]; }

# 443,8443:8080  (public[:target])
valid_ports() {
  local item a b
  local -a items
  [ -n "$1" ] || return 1
  IFS=',' read -ra items <<<"$1"
  for item in "${items[@]}"; do
    a="${item%%:*}"; b="${item#*:}"
    is_port "$a" && is_port "$b" || return 1
  done
}

port_in_use() { ss -H -lnt "sport = :$1" 2>/dev/null | grep -q .; }
gen_token() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }

# --------------------------------------------------------------------------
# slots (each slot = one independent tunnel = one systemd instance)
# --------------------------------------------------------------------------
slot_file()   { echo "$CONF_DIR/slot$1.env"; }
slot_exists() { [ -f "$(slot_file "$1")" ]; }
slot_state()  { local s; s="$(systemctl is-active "nicetunnel@$1" 2>/dev/null)"; echo "${s:-unknown}"; }

list_slots() {
  local n
  for n in $(seq 1 "$MAX_SLOT"); do slot_exists "$n" && echo "$n"; done
}

first_free_slot() {
  local n
  for n in $(seq 1 "$MAX_SLOT"); do
    slot_exists "$n" || { echo "$n"; return; }
  done
  echo 1
}

load_slot() {
  ROLE=""; BRIDGE=""; PORTS=""; SERVER_IP=""; TARGET_HOST=""; NICETUNNEL_TOKEN=""
  # shellcheck disable=SC1090
  . "$(slot_file "$1")"
}

write_slot() { # slot role bridge ports server_ip target_host token
  local args
  if [ "$2" = server ]; then
    args="server --bridge $3 --ports $4"
  else
    args="client --server $5 --bridge $3 --target-host $6"
  fi
  (
    umask 077
    cat >"$(slot_file "$1")" <<EOF
ROLE=$2
BRIDGE=$3
PORTS=$4
SERVER_IP=$5
TARGET_HOST=$6
NICETUNNEL_TOKEN=$7
RT_ARGS="$args"
EOF
  )
}

print_slots() {
  local n what found=0
  printf '%s%-5s %-9s %-7s %-26s %s%s\n' "$B" Slot Role Bridge "Ports / Server" State "$N"
  for n in $(list_slots); do
    found=1
    load_slot "$n"
    if [ "$ROLE" = server ]; then what="$PORTS"; else what="$SERVER_IP"; fi
    printf '%-5s %-9s %-7s %-26s %s\n' "$n" "$ROLE" "$BRIDGE" "$what" "$(slot_state "$n")"
  done
  [ "$found" = 1 ] || say "(no tunnels yet - choose 1 to create one)"
}

show_settings() {
  load_slot "$1"
  say
  say "Slot:         $1"
  say "Role:         $ROLE"
  say "Bridge port:  $BRIDGE"
  if [ "$ROLE" = server ]; then
    say "Public ports: $PORTS"
  else
    say "Iran server:  $SERVER_IP"
    say "Forwards to:  $TARGET_HOST"
  fi
  say "Token:        $NICETUNNEL_TOKEN"
  say "State:        $(slot_state "$1")"
  if [ "$ROLE" = server ]; then
    say
    say "On the foreign server open 'nicetunnel' -> Create tunnel -> Foreign server,"
    say "then enter this server's IP, bridge port $BRIDGE and the token above."
  fi
}

# --------------------------------------------------------------------------
# firewall (only touches ufw when it is installed AND already active)
# --------------------------------------------------------------------------
maybe_open_ufw() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q '^Status: active' || return 0
  local p
  say
  warn "ufw is active. These TCP ports must be open: $*"
  if yesno "Open them now?" y; then
    for p in "$@"; do
      ufw allow "$p/tcp" >/dev/null 2>&1 && ok "ufw: allowed $p/tcp"
    done
  fi
}

# --------------------------------------------------------------------------
# menu actions
# --------------------------------------------------------------------------
create_tunnel() {
  local role slot bridge ports="" server_ip="" target="127.0.0.1" token item p
  local -a items open_ports

  say
  say "Which side is this machine?"
  say "  1) Iran server     (users connect here)"
  say "  2) Foreign server  (the tunnel is dialed from here to Iran)"
  ask "Choose"
  case "$REPLY" in
    1) role=server ;;
    2) role=client ;;
    *) err "Invalid choice."; return ;;
  esac

  ask "Slot number (1-$MAX_SLOT)" "$(first_free_slot)"
  slot="$REPLY"
  if ! [[ "$slot" =~ ^[0-9]+$ ]] || [ "$slot" -lt 1 ] || [ "$slot" -gt "$MAX_SLOT" ]; then
    err "Slot must be a number from 1 to $MAX_SLOT."; return
  fi
  if slot_exists "$slot"; then
    yesno "Slot $slot already exists. Replace it?" n || return
    systemctl stop "nicetunnel@$slot" >/dev/null 2>&1
  fi

  ask "Bridge port (must be the same on both servers)" 7000
  bridge="$REPLY"
  is_port "$bridge" || { err "Invalid port."; return; }

  if [ "$role" = server ]; then
    ask "Public ports users connect to (e.g. 443 or 443,8443:8080)"
    ports="$REPLY"
    valid_ports "$ports" || { err "Invalid ports. Use numbers like 443 or 8443:8080, separated by commas."; return; }
    ask "Token (press Enter to generate one)"
    token="$REPLY"
    [ -n "$token" ] || token="$(gen_token)"

    open_ports=("$bridge")
    IFS=',' read -ra items <<<"$ports"
    for item in "${items[@]}"; do open_ports+=("${item%%:*}"); done
    for p in "${open_ports[@]}"; do
      if port_in_use "$p"; then
        warn "Port $p is already in use by another program."
        yesno "Continue anyway?" n || return
      fi
    done
  else
    ask "IP address or hostname of the Iran server"
    server_ip="$REPLY"
    valid_host "$server_ip" || { err "Invalid address."; return; }
    ask "Token (copy it from the Iran server)"
    token="$REPLY"
    ask "Send forwarded connections to (on this machine)" 127.0.0.1
    target="$REPLY"
    valid_host "$target" || { err "Invalid address."; return; }
  fi

  valid_token "$token" || { err "Token must be at least 16 characters (letters, digits, . _ -)."; return; }

  write_slot "$slot" "$role" "$bridge" "$ports" "$server_ip" "$target" "$token"
  systemctl enable "nicetunnel@$slot" >/dev/null 2>&1
  systemctl restart "nicetunnel@$slot"
  sleep 1

  say
  ok "Tunnel $slot created ($role) - state: $(slot_state "$slot")"
  show_settings "$slot"
  if [ "$role" = server ]; then
    maybe_open_ufw "${open_ports[@]}"
    say
    warn "Also open these ports in your hosting provider's firewall panel, if it has one."
  fi
}

manage_tunnel() {
  local n
  say; print_slots; say
  ask "Slot number (0 = back)"
  [ "$REPLY" = 0 ] && return
  n="$REPLY"
  if ! [[ "$n" =~ ^[0-9]+$ ]] || ! slot_exists "$n"; then err "No such slot."; return; fi

  while true; do
    say
    say "${B}Slot $n${N} - $(slot_state "$n")"
    say "  1) Start      2) Stop      3) Restart"
    say "  4) Status     5) Logs      6) Show settings / token"
    say "  7) Delete this tunnel      0) Back"
    ask "Choose"
    case "$REPLY" in
      1) systemctl start "nicetunnel@$n"; sleep 1; ok "State: $(slot_state "$n")" ;;
      2) systemctl stop "nicetunnel@$n"; ok "State: $(slot_state "$n")" ;;
      3) systemctl restart "nicetunnel@$n"; sleep 1; ok "State: $(slot_state "$n")" ;;
      4) systemctl status "nicetunnel@$n" --no-pager -l 2>&1 | head -n 15 ;;
      5) journalctl -u "nicetunnel@$n" -n 50 --no-pager 2>&1 ;;
      6) show_settings "$n" ;;
      7)
        ask "Type yes to delete slot $n"
        if [ "$REPLY" = yes ]; then
          systemctl disable --now "nicetunnel@$n" >/dev/null 2>&1
          rm -f "$(slot_file "$n")"
          ok "Slot $n deleted."
          return
        fi
        ;;
      0) return ;;
      *) err "Invalid choice." ;;
    esac
  done
}

optimize_server() {
  say
  modprobe tcp_bbr >/dev/null 2>&1
  if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    err "BBR is not available on this kernel (some VPS types do not allow it)."
    return
  fi
  mkdir -p "$(dirname "$SYSCTL_FILE")"
  cat >"$SYSCTL_FILE" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=4096
EOF
  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  ok "Applied. Congestion control is now: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  say "Run this on both servers."
}

update_all() {
  local tmp n
  if [ ! -f "$CONF_DIR/source.conf" ]; then
    err "No GitHub source is recorded on this server, so there is nothing to update from."
    return
  fi
  # shellcheck disable=SC1090
  . "$CONF_DIR/source.conf"
  tmp="$(mktemp -d)"
  if ! curl -fsSL --retry 3 --connect-timeout 15 "$REPO_RAW/install.sh" -o "$tmp/install.sh"; then
    err "Could not download $REPO_RAW/install.sh"
    rm -rf "$tmp"; return
  fi
  if bash "$tmp/install.sh" --no-menu; then
    for n in $(list_slots); do systemctl restart "nicetunnel@$n"; done
    rm -rf "$tmp"
    ok "Updated and restarted all tunnels. Run 'nicetunnel' again to open the new menu."
    exit 0
  fi
  rm -rf "$tmp"
  err "Update failed; the previous version is still installed."
}

uninstall_all() {
  local n
  say
  warn "This stops and deletes ALL tunnels on this server and removes nicetunnel."
  ask "Type yes to continue"
  [ "$REPLY" = yes ] || { say "Cancelled."; return; }
  for n in $(list_slots); do systemctl disable --now "nicetunnel@$n" >/dev/null 2>&1; done
  rm -f "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1
  rm -rf "$CONF_DIR" "$APP_DIR"
  rm -f "$BIN_PATH"
  ok "nicetunnel removed. (BBR settings, if you enabled them, were left in place.)"
  exit 0
}

main_menu() {
  local n
  while true; do
    [ -t 1 ] && clear
    printf '%s=== NiceTunnel Manager ===%s\n' "$B" "$N"
    printf 'by Arsham Smoke\n\n'
    print_slots
    say
    say "  1) Create tunnel"
    say "  2) Manage tunnels"
    say "  3) Optimize server (BBR)"
    say "  4) Update from GitHub"
    say "  5) Uninstall"
    say "  0) Exit"
    ask "Choose"
    case "$REPLY" in
      1) create_tunnel; pause ;;
      2) manage_tunnel ;;
      3) optimize_server; pause ;;
      4) update_all; pause ;;
      5) uninstall_all; pause ;;
      0) exit 0 ;;
      *) err "Invalid choice."; sleep 1 ;;
    esac
  done
}

# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root:  sudo nicetunnel"
  exit 1
fi

case "${1:-menu}" in
  restart-all)
    for n in $(list_slots); do systemctl restart "nicetunnel@$n"; done
    exit 0 ;;
  menu) ;;
  *) echo "usage: nicetunnel [menu|restart-all]"; exit 1 ;;
esac

exec 3<"$TTY" || { err "No terminal available."; exit 1; }
main_menu
