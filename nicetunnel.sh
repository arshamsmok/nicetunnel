#!/usr/bin/env bash
# NiceTunnel manager: interactive menu for creating and managing tunnels.
# Author: Arsham Smoke - MIT License (see LICENSE)
# Installed as /usr/local/bin/nicetunnel by install.sh. Open it with:  nicetunnel
#
# Display options (environment variables):
#   NICETUNNEL_THEME=ocean|sunset|matrix|mono   color theme (also changeable from the menu)
#   NICETUNNEL_ASCII=1                          plain characters if boxes/arrows look broken
#   NICETUNNEL_SIMPLE=1                         numbered prompts instead of arrow-key lists
#   NO_COLOR=1                                  no colors at all

VERSION="1.1.0"
CONF_DIR="${NICETUNNEL_CONF_DIR:-/etc/nicetunnel}"
APP_DIR="${NICETUNNEL_APP_DIR:-/opt/nicetunnel}"
BIN_PATH="${NICETUNNEL_BIN:-/usr/local/bin/nicetunnel}"
UNIT_FILE="${NICETUNNEL_UNIT_DIR:-/etc/systemd/system}/nicetunnel@.service"
SYSCTL_FILE="${NICETUNNEL_SYSCTL_DIR:-/etc/sysctl.d}/99-nicetunnel.conf"
TTY="${NICETUNNEL_TTY:-/dev/tty}"
MAX_SLOT=10

# --------------------------------------------------------------------------
# look & feel: colors, glyphs, themes
# --------------------------------------------------------------------------
COLOR=0; C256=0; ASCII=0
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then COLOR=1; fi
case "${TERM:-}:${COLORTERM:-}" in *256color*|*truecolor*|*24bit*) C256=1 ;; esac
if [ "${NICETUNNEL_ASCII:-0}" = 1 ] || [ "${TERM:-}" = linux ]; then ASCII=1; fi

if [ "$ASCII" = 1 ]; then
  BLK='#'; CHK='+'; DOT='-'; PTR='>'; HR='-'; UPDN='up/down'
else
  BLK='█'; CHK='✓'; DOT='·'; PTR='❯'; HR='─'; UPDN='↑/↓'
fi

THEME="${NICETUNNEL_THEME:-$(cat "$CONF_DIR/theme" 2>/dev/null)}"
case "$THEME" in ocean|sunset|matrix|mono) ;; *) THEME=ocean ;; esac

set_colors() {
  NC=""; BD=""; REV=""; A=""; GR=""; DM=""; RD=""; YL=""; PAL=()
  [ "$COLOR" = 1 ] || return 0
  NC=$'\033[0m'; BD=$'\033[1m'; REV=$'\033[7m'
  if [ "$C256" = 1 ]; then
    GR=$'\033[38;5;42m'; DM=$'\033[38;5;245m'; RD=$'\033[38;5;203m'; YL=$'\033[38;5;221m'
    local acc
    case "$THEME" in
      sunset) PAL=(226 220 214 208 202 197 198 163); acc=208 ;;
      matrix) PAL=(22 28 34 40 46 82 118 154);       acc=46  ;;
      mono)   PAL=(240 243 246 249 252 255);         acc=255 ;;
      *)      PAL=(49 44 39 33 27 63 99 135);        acc=45  ;;
    esac
    A=$'\033[38;5;'"${acc}m"
  else
    GR=$'\033[32m'; DM=$'\033[2m'; RD=$'\033[31m'; YL=$'\033[33m'; A=$'\033[36m'
  fi
}
set_colors

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s%s%s\n' "$GR" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YL" "$*" "$NC"; }
err()  { printf '%s%s%s\n' "$RD" "$*" "$NC" >&2; }
kv()   { printf '  %s%-14s%s %s\n' "$DM" "$1" "$NC" "$2"; }

term_cols() {
  local c
  c="$(tput cols 2>/dev/null)"
  if [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -gt 0 ]; then echo "$c"; else echo 80; fi
}

hr() {
  local w i s=""
  w=$(( $(term_cols) - 4 ))
  [ "$w" -gt 58 ] && w=58
  [ "$w" -lt 10 ] && w=10
  for ((i = 0; i < w; i++)); do s+="$HR"; done
  printf '  %s%s%s\n' "$DM" "$s" "$NC"
}

# 5-row block font (# = filled cell). The glyph is swapped in when printing,
# so this also works when the server locale is not UTF-8.
declare -A GL=(
  [N0]='#   #' [N1]='##  #' [N2]='# # #' [N3]='#  ##' [N4]='#   #'
  [I0]='#####' [I1]='  #  ' [I2]='  #  ' [I3]='  #  ' [I4]='#####'
  [C0]=' ####' [C1]='#    ' [C2]='#    ' [C3]='#    ' [C4]=' ####'
  [E0]='#####' [E1]='#    ' [E2]='#### ' [E3]='#    ' [E4]='#####'
  [T0]='#####' [T1]='  #  ' [T2]='  #  ' [T3]='  #  ' [T4]='  #  '
  [U0]='#   #' [U1]='#   #' [U2]='#   #' [U3]='#   #' [U4]=' ### '
  [L0]='#    ' [L1]='#    ' [L2]='#    ' [L3]='#    ' [L4]='#####'
)

banner() {
  local word=NICETUNNEL r i c n idx pn line out ch
  if [ "$(term_cols)" -lt 66 ]; then
    printf '  %s%sNiceTunnel%s\n' "$A" "$BD" "$NC"
    return
  fi
  pn=${#PAL[@]}
  for r in 0 1 2 3 4; do
    line=""
    for ((i = 0; i < ${#word}; i++)); do line+="${GL[${word:i:1}$r]} "; done
    n=${#line}; out=""
    for ((c = 0; c < n; c++)); do
      ch="${line:c:1}"
      if [ "$ch" = "#" ]; then
        if [ "$pn" -gt 0 ]; then
          idx=$(( c * (pn - 1) / (n - 2) ))   # n-2: the last column is a blank gap
          [ "$idx" -ge "$pn" ] && idx=$((pn - 1))
          out+=$'\033[38;5;'"${PAL[idx]}m${BLK}"
        else
          out+="${A}${BLK}"
        fi
      else
        out+=" "
      fi
    done
    printf '  %s%s\n' "$out" "$NC"
  done
}

header() {
  [ "$COLOR" = 1 ] && printf '\033[H\033[2J'
  echo
  banner
  printf '  %s%s v%s %s  %sFast reverse tunnels for two servers%s\n' "$REV" "$A" "$VERSION" "$NC" "$DM" "$NC"
  printf '  %smade by Arsham Smoke%s\n' "$DM" "$NC"
  hr
  echo
}

# --------------------------------------------------------------------------
# input helpers (all input comes from fd 3, the real terminal)
# --------------------------------------------------------------------------

# ask "prompt" [default] -> $REPLY ; returns 1 when the user typed "<" (go back)
ask() {
  printf '%s?%s %s%s%s' "$A" "$NC" "$BD" "$1" "$NC"
  [ -n "${2:-}" ] && printf ' %s(%s)%s' "$DM" "$2" "$NC"
  printf ' %s%s%s ' "$A" "$PTR" "$NC"
  IFS= read -r REPLY <&3 || { echo; exit 1; }
  REPLY="${REPLY//$'\r'/}"
  REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
  REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
  [ "$REPLY" = "<" ] && return 1
  REPLY="${REPLY:-${2:-}}"
  return 0
}

yesno() { ask "$1 [y/n]" "${2:-n}"; [[ "$REPLY" =~ ^[Yy] ]]; }
pause() { printf '\n  %sPress Enter to continue...%s' "$DM" "$NC"; read -r _ <&3 || true; echo; }

_sel_draw() { # uses n lw maxd sel labels descs from select_menu
  local j d
  for ((j = 0; j < n; j++)); do
    d="${descs[j]:0:maxd}"
    if [ "$j" -eq "$sel" ]; then
      printf '\033[2K  %s%s%s %s%-*s%s  %s%s%s\n' "$A" "$PTR" "$NC" "$A$BD" "$lw" "${labels[j]}" "$NC" "$A" "$d" "$NC"
    else
      printf '\033[2K    %-*s  %s%s%s\n' "$lw" "${labels[j]}" "$DM" "$d" "$NC"
    fi
  done
  printf '\033[2K  %s%s move %s Enter select %s Esc back%s\n' "$DM" "$UPDN" "$DOT" "$DOT" "$NC"
}

# select_menu "Question" "key|label|description" ...
#   arrow keys + Enter, or press the key's number. Esc goes back.
#   sets SEL (key) and SEL_LABEL; returns 1 when the user goes back.
select_menu() {
  local q="$1"; shift
  local -a keys=() labels=() descs=()
  local item rest n=0 lw=0 i sel=0 maxd k k2 act=""
  for item in "$@"; do
    keys[n]="${item%%|*}"
    rest="${item#*|}"
    labels[n]="${rest%%|*}"
    if [[ "$rest" == *"|"* ]]; then descs[n]="${rest#*|}"; else descs[n]=""; fi
    [ "${#labels[n]}" -gt "$lw" ] && lw=${#labels[n]}
    n=$((n + 1))
  done

  if [ -t 3 ] && [ -t 1 ] && [ "$COLOR" = 1 ] && [ "${NICETUNNEL_SIMPLE:-0}" != 1 ]; then
    maxd=$(( $(term_cols) - lw - 10 )); [ "$maxd" -lt 8 ] && maxd=8
    printf '%s?%s %s%s%s\n' "$A" "$NC" "$BD" "$q" "$NC"
    printf '\033[?25l'
    _sel_draw
    while [ -z "$act" ]; do
      IFS= read -rsn1 -u 3 k || { printf '\033[?25h\n'; exit 1; }
      case "$k" in
        $'\x1b')
          k2=""; read -rsn2 -t 0.1 -u 3 k2 || true
          case "$k2" in
            '[A'|'OA') sel=$(( (sel + n - 1) % n )) ;;
            '[B'|'OB') sel=$(( (sel + 1) % n )) ;;
            '') act=back ;;
          esac ;;
        '') act=accept ;;
        '<'|q|Q) act=back ;;
        [0-9])
          for ((i = 0; i < n; i++)); do
            [ "${keys[i]}" = "$k" ] && { sel=$i; act=accept; }
          done ;;
      esac
      if [ -z "$act" ]; then printf '\033[%dA' $((n + 1)); _sel_draw; fi
    done
    printf '\033[?25h'
    [ "$act" = back ] && return 1
    SEL="${keys[sel]}"; SEL_LABEL="${labels[sel]}"
    return 0
  fi

  # plain numbered list (no terminal, or NICETUNNEL_SIMPLE=1)
  printf '%s?%s %s%s%s\n' "$A" "$NC" "$BD" "$q" "$NC"
  for ((i = 0; i < n; i++)); do
    printf '    %s) %-*s  %s%s%s\n' "${keys[i]}" "$lw" "${labels[i]}" "$DM" "${descs[i]}" "$NC"
  done
  while true; do
    ask "Choose" || return 1
    for ((i = 0; i < n; i++)); do
      if [ "${keys[i]}" = "$REPLY" ]; then SEL="${keys[i]}"; SEL_LABEL="${labels[i]}"; return 0; fi
    done
    err "Invalid choice."
  done
}

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
  mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR" || return 1
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

role_name() { if [ "$1" = server ]; then echo "Iran"; else echo "Foreign"; fi; }

print_slots() {
  local n what found=0 st col
  printf '  %s%-5s %-9s %-7s %-24s %s%s\n' "$BD" Slot Side Bridge "Ports / Server" State "$NC"
  for n in $(list_slots); do
    found=1
    load_slot "$n"
    if [ "$ROLE" = server ]; then what="$PORTS"; else what="$SERVER_IP"; fi
    st="$(slot_state "$n")"
    if [ "$st" = active ]; then col="$GR"; else col="$RD"; fi
    printf '  %-5s %-9s %-7s %-24s %s%s%s\n' "$n" "$(role_name "$ROLE")" "$BRIDGE" "$what" "$col" "$st" "$NC"
  done
  [ "$found" = 1 ] || printf '  %s(no tunnels yet - choose "Create tunnel" to add one)%s\n' "$DM" "$NC"
}

show_settings() {
  load_slot "$1"
  echo
  kv "Slot" "$1"
  kv "Side" "$(role_name "$ROLE") server"
  kv "Bridge port" "$BRIDGE"
  if [ "$ROLE" = server ]; then
    kv "Public ports" "$PORTS"
  else
    kv "Iran server" "$SERVER_IP"
    kv "Forwards to" "$TARGET_HOST"
  fi
  kv "Token" "$NICETUNNEL_TOKEN"
  kv "State" "$(slot_state "$1")"
  if [ "$ROLE" = server ]; then
    echo
    printf '  %sOn the foreign server open "nicetunnel" > Create tunnel > Foreign server,%s\n' "$DM" "$NC"
    printf '  %sthen enter this server'"'"'s IP, bridge port %s and the token above.%s\n' "$DM" "$BRIDGE" "$NC"
  fi
}

# --------------------------------------------------------------------------
# firewall (only touches ufw when it is installed AND already active)
# --------------------------------------------------------------------------
maybe_open_ufw() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | grep -q '^Status: active' || return 0
  local p
  echo
  warn "  ufw is active. These TCP ports must be open: $*"
  if yesno "Open them now?" y; then
    for p in "$@"; do
      ufw allow "$p/tcp" >/dev/null 2>&1 && ok "  ufw: allowed $p/tcp"
    done
  fi
}

# --------------------------------------------------------------------------
# new-tunnel wizard (answers stay on screen as check-marked lines)
# --------------------------------------------------------------------------
HIST=()
HSEP=$'\x1f'
hist_add() { HIST+=("$1$HSEP$2"); }
hist_pop() { [ "${#HIST[@]}" -gt 0 ] && HIST=("${HIST[@]:0:${#HIST[@]}-1}"); }
hist_show() {
  local h
  for h in "${HIST[@]}"; do
    printf '%s%s%s %s%s%s %s%s%s %s%s%s\n' "$GR" "$CHK" "$NC" "$BD" "${h%%"$HSEP"*}" "$NC" \
      "$DM" "$DOT" "$NC" "$A" "${h#*"$HSEP"}" "$NC"
  done
}

wiz_screen() { # step total
  header
  if [ "${#HIST[@]}" -gt 0 ]; then hist_show; echo; fi
  printf '%s%sNew tunnel%s %s%s step %s of %s   (Esc or < = previous page)%s\n\n' \
    "$A" "$BD" "$NC" "$DM" "$DOT" "$1" "$2" "$NC"
}

create_tunnel() {
  local role="" slot="" bridge="" ports="" server_ip="" target="" token="" gen
  local step=1 total=6 kind msg="" item p
  local -a items open_ports

  gen="$(gen_token)"
  HIST=()

  collect_open_ports() {
    open_ports=("$bridge")
    IFS=',' read -ra items <<<"$ports"
    for item in "${items[@]}"; do open_ports+=("${item%%:*}"); done
  }

  while true; do
    if [ "$role" = client ]; then total=7; else total=6; fi
    case "$step" in
      1) kind=role ;;
      2) kind=slot ;;
      3) kind=bridge ;;
      4) if [ "$role" = server ]; then kind=ports; else kind=serverip; fi ;;
      5) kind=token ;;
      6) if [ "$role" = server ]; then kind=confirm; else kind=target; fi ;;
      *) kind=confirm ;;
    esac

    wiz_screen "$step" "$total"
    if [ -n "$msg" ]; then err "  $msg"; echo; msg=""; fi

    case "$kind" in
      role)
        select_menu "Which server is this?" \
          "1|Iran server|users connect to this one" \
          "2|Foreign server|this one dials the tunnel to Iran" || return 1
        if [ "$SEL" = 1 ]; then role=server; else role=client; fi
        hist_add "Which server is this?" "$SEL_LABEL"; step=2 ;;

      slot)
        ask "Slot number (1-$MAX_SLOT)" "${slot:-$(first_free_slot)}" || { hist_pop; step=1; continue; }
        if ! [[ "$REPLY" =~ ^[0-9]+$ ]] || [ "$REPLY" -lt 1 ] || [ "$REPLY" -gt "$MAX_SLOT" ]; then
          msg="Slot must be a number from 1 to $MAX_SLOT."; continue
        fi
        slot="$REPLY"; hist_add "Slot number" "$slot"; step=3 ;;

      bridge)
        ask "Bridge port (same on both servers)" "${bridge:-7000}" || { hist_pop; step=2; continue; }
        is_port "$REPLY" || { msg="That is not a valid port number (1-65535)."; continue; }
        bridge="$REPLY"; hist_add "Bridge port" "$bridge"; step=4 ;;

      ports)
        ask "Public ports users connect to (e.g. 443 or 443,8443:8080)" "$ports" || { hist_pop; step=3; continue; }
        valid_ports "$REPLY" || { msg="Invalid ports. Use numbers like 443 or 8443:8080, separated by commas."; continue; }
        ports="$REPLY"; hist_add "Public ports" "$ports"; step=5 ;;

      serverip)
        ask "IP address or hostname of the Iran server" "$server_ip" || { hist_pop; step=3; continue; }
        valid_host "$REPLY" || { msg="That is not a valid address."; continue; }
        server_ip="$REPLY"; hist_add "Iran server" "$server_ip"; step=5 ;;

      token)
        if [ "$role" = server ]; then
          ask "Token (Enter keeps the suggested one)" "${token:-$gen}" || { hist_pop; step=4; continue; }
        else
          ask "Token (copy it from the Iran server)" "$token" || { hist_pop; step=4; continue; }
        fi
        valid_token "$REPLY" || { msg="Token must be at least 16 characters (letters, digits, . _ -)."; continue; }
        token="$REPLY"; hist_add "Token" "${token:0:8}..."; step=6 ;;

      target)
        ask "Send forwarded connections to (on this machine)" "${target:-127.0.0.1}" || { hist_pop; step=5; continue; }
        valid_host "$REPLY" || { msg="That is not a valid address."; continue; }
        target="$REPLY"; hist_add "Forward to" "$target"; step=7 ;;

      confirm)
        [ -n "$target" ] || target=127.0.0.1
        printf '  %sReview%s\n' "$BD" "$NC"
        kv "Side" "$(role_name "$role") server"
        kv "Slot" "$slot"
        kv "Bridge port" "$bridge"
        if [ "$role" = server ]; then
          kv "Public ports" "$ports"
        else
          kv "Iran server" "$server_ip:$bridge"
          kv "Forwards to" "$target"
        fi
        kv "Token" "${token:-$gen}"
        echo
        if slot_exists "$slot"; then
          warn "  Slot $slot already exists and will be replaced."
          echo
        elif [ "$role" = server ]; then
          collect_open_ports
          for p in "${open_ports[@]}"; do
            if port_in_use "$p"; then warn "  Port $p is already in use by another program."; fi
          done
        fi
        if select_menu "Everything correct?" \
             "1|Create tunnel|save it and start it now" \
             "2|Go back|change an answer" && [ "$SEL" = 1 ]; then
          break
        fi
        hist_pop; step=$((step - 1)) ;;
    esac
  done

  slot_exists "$slot" && systemctl stop "nicetunnel@$slot" >/dev/null 2>&1
  if ! write_slot "$slot" "$role" "$bridge" "$ports" "$server_ip" "$target" "$token"; then
    header
    err "  Could not save the tunnel settings in $CONF_DIR."
    pause
    return 1
  fi
  systemctl enable "nicetunnel@$slot" >/dev/null 2>&1
  systemctl restart "nicetunnel@$slot"
  sleep 1

  header
  ok "$CHK Tunnel $slot created ($(role_name "$role") server) - state: $(slot_state "$slot")"
  show_settings "$slot"
  if [ "$role" = server ]; then
    collect_open_ports
    maybe_open_ufw "${open_ports[@]}"
    echo
    warn "  Also open these ports in your hosting provider's firewall panel, if it has one."
  fi
}

# --------------------------------------------------------------------------
# other menu actions
# --------------------------------------------------------------------------
slot_menu() {
  local n="$1"
  while true; do
    slot_exists "$n" || return
    header
    print_slots
    echo
    select_menu "Tunnel $n - $(slot_state "$n")" \
      "1|Start|" \
      "2|Stop|" \
      "3|Restart|" \
      "4|Status|systemd status" \
      "5|Logs|last 50 lines" \
      "6|Settings|ports and token" \
      "7|Delete|remove this tunnel" \
      "0|Back|" || return
    echo
    case "$SEL" in
      1) systemctl start "nicetunnel@$n"; sleep 1; ok "  State: $(slot_state "$n")"; pause ;;
      2) systemctl stop "nicetunnel@$n"; ok "  State: $(slot_state "$n")"; pause ;;
      3) systemctl restart "nicetunnel@$n"; sleep 1; ok "  State: $(slot_state "$n")"; pause ;;
      4) systemctl status "nicetunnel@$n" --no-pager -l 2>&1 | head -n 15; pause ;;
      5) journalctl -u "nicetunnel@$n" -n 50 --no-pager 2>&1; pause ;;
      6) show_settings "$n"; pause ;;
      7)
        ask "Type yes to delete tunnel $n"
        if [ "$REPLY" = yes ]; then
          systemctl disable --now "nicetunnel@$n" >/dev/null 2>&1
          rm -f "$(slot_file "$n")"
          ok "  Tunnel $n deleted."
          return
        fi ;;
      0) return ;;
    esac
  done
}

manage_tunnel() {
  local n
  local -a opts
  while true; do
    header
    opts=()
    for n in $(list_slots); do
      load_slot "$n"
      opts+=("$n|Tunnel $n|$(role_name "$ROLE") - bridge $BRIDGE - $(slot_state "$n")")
    done
    if [ "${#opts[@]}" -eq 0 ]; then
      warn "  No tunnels yet. Choose \"Create tunnel\" first."
      pause
      return
    fi
    opts+=("0|Back|")
    select_menu "Which tunnel?" "${opts[@]}" || return
    [ "$SEL" = 0 ] && return
    slot_menu "$SEL"
  done
}

optimize_server() {
  header
  modprobe tcp_bbr >/dev/null 2>&1
  if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    err "  BBR is not available on this kernel (some VPS types do not allow it)."
    return
  fi
  mkdir -p "$(dirname "$SYSCTL_FILE")"
  cat >"$SYSCTL_FILE" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=4096
EOF
  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  ok "  $CHK Applied. Congestion control is now: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  say "  Run this on both servers."
}

theme_menu() {
  header
  select_menu "Pick a color theme" \
    "1|ocean|cyan to violet" \
    "2|sunset|yellow to pink" \
    "3|matrix|green" \
    "4|mono|white and gray" || return 0
  case "$SEL" in
    1) THEME=ocean ;;
    2) THEME=sunset ;;
    3) THEME=matrix ;;
    4) THEME=mono ;;
  esac
  mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
  printf '%s\n' "$THEME" >"$CONF_DIR/theme"
  set_colors
}

update_all() {
  local tmp n
  header
  if [ ! -f "$CONF_DIR/source.conf" ]; then
    err "  No GitHub source is recorded on this server, so there is nothing to update from."
    return
  fi
  # shellcheck disable=SC1090
  . "$CONF_DIR/source.conf"
  tmp="$(mktemp -d)"
  if ! curl -fsSL --retry 3 --connect-timeout 15 "$REPO_RAW/install.sh" -o "$tmp/install.sh"; then
    err "  Could not download $REPO_RAW/install.sh"
    rm -rf "$tmp"; return
  fi
  if bash "$tmp/install.sh" --no-menu; then
    for n in $(list_slots); do systemctl restart "nicetunnel@$n"; done
    rm -rf "$tmp"
    ok "  $CHK Updated and restarted all tunnels. Run 'nicetunnel' again to open the new menu."
    exit 0
  fi
  rm -rf "$tmp"
  err "  Update failed; the previous version is still installed."
}

uninstall_all() {
  local n
  header
  warn "  This stops and deletes ALL tunnels on this server and removes NiceTunnel."
  echo
  ask "Type yes to continue"
  [ "$REPLY" = yes ] || { say "  Cancelled."; return; }
  for n in $(list_slots); do systemctl disable --now "nicetunnel@$n" >/dev/null 2>&1; done
  rm -f "$UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1
  rm -rf "$CONF_DIR" "$APP_DIR"
  rm -f "$BIN_PATH"
  ok "  $CHK NiceTunnel removed. (BBR settings, if you enabled them, were left in place.)"
  exit 0
}

main_menu() {
  while true; do
    header
    print_slots
    echo
    select_menu "What do you want to do?" \
      "1|Create tunnel|set up the Iran side or the foreign side" \
      "2|Manage tunnels|start, stop, logs, delete" \
      "3|Optimize server|turn on BBR congestion control" \
      "4|Theme|change the colors of this menu" \
      "5|Update|get the newest version from GitHub" \
      "6|Uninstall|remove NiceTunnel and all tunnels" \
      "0|Exit|" || continue
    case "$SEL" in
      1) create_tunnel && pause ;;
      2) manage_tunnel ;;
      3) optimize_server; pause ;;
      4) theme_menu ;;
      5) update_all; pause ;;
      6) uninstall_all; pause ;;
      0) [ "$COLOR" = 1 ] && printf '\033[H\033[2J'; exit 0 ;;
    esac
  done
}

# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
case "${1:-menu}" in
  version|--version|-v) echo "NiceTunnel $VERSION"; exit 0 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root:  sudo nicetunnel"
  exit 1
fi

case "${1:-menu}" in
  restart-all)
    for n in $(list_slots); do systemctl restart "nicetunnel@$n"; done
    exit 0 ;;
  menu) ;;
  *) echo "usage: nicetunnel [menu|restart-all|version]"; exit 1 ;;
esac

exec 3<"$TTY" || { err "No terminal available."; exit 1; }
if [ "$COLOR" = 1 ]; then
  trap 'printf "\033[?25h"' EXIT
  trap 'printf "\033[?25h\n"; stty sane <&3 2>/dev/null; exit 130' INT
fi
main_menu
