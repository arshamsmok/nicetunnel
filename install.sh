#!/usr/bin/env bash
# NiceTunnel installer (by Arsham Smoke, MIT License) - run it on BOTH servers (as root):
#
#   bash <(curl -Ls https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/nicetunnel/main/install.sh)
#
# It installs the tunnel engine and the "nicetunnel" menu command, then opens the menu.
# If the files nicetunnel.py and nicetunnel.sh sit next to this script, they are used instead of
# downloading (handy when a server cannot reach GitHub):  bash install.sh
set -euo pipefail

GITHUB_USER="arshamsmok"   # <-- EDIT: your GitHub username
GITHUB_REPO="nicetunnel"             # <-- EDIT only if your repository has another name
REPO_RAW="${NICETUNNEL_RAW:-https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/main}"

APP_DIR="${NICETUNNEL_APP_DIR:-/opt/nicetunnel}"
CONF_DIR="${NICETUNNEL_CONF_DIR:-/etc/nicetunnel}"
BIN_PATH="${NICETUNNEL_BIN:-/usr/local/bin/nicetunnel}"
UNIT_DIR="${NICETUNNEL_UNIT_DIR:-/etc/systemd/system}"

NO_MENU=0
[ "${1:-}" = "--no-menu" ] && NO_MENU=1

die()  { echo "Error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || die "run as root (use 'sudo -i' first, then run the command again)."

# --- dependencies -----------------------------------------------------------
if ! need python3; then
  need apt-get || die "python3 is missing and apt-get is not available."
  apt-get update -y && apt-get install -y python3 || die "could not install python3."
fi

# --- get the files ----------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
LOCAL=0
if [ -n "$HERE" ] && [ -f "$HERE/nicetunnel.py" ] && [ -f "$HERE/nicetunnel.sh" ] && [ -f "$HERE/nicetunnel_panel.py" ]; then
  LOCAL=1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ "$LOCAL" = 1 ]; then
  echo "Installing from local files in $HERE"
  cp "$HERE/nicetunnel.py" "$HERE/nicetunnel.sh" "$HERE/nicetunnel_panel.py" "$WORK/"
else
  case "$REPO_RAW" in
    *YOUR_GITHUB_USERNAME*) die "open install.sh and set GITHUB_USER to your GitHub username first." ;;
  esac
  if ! need curl; then
    need apt-get && apt-get install -y curl || die "curl is required."
  fi
  echo "Downloading from $REPO_RAW ..."
  for f in nicetunnel.py nicetunnel.sh nicetunnel_panel.py; do
    curl -fsSL --retry 3 --connect-timeout 15 "$REPO_RAW/$f" -o "$WORK/$f" \
      || die "could not download $f. If this server cannot reach GitHub, copy the files here with scp and run: bash install.sh"
  done
fi

python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$WORK/nicetunnel.py" \
  || die "nicetunnel.py is not valid Python (incomplete download?)."
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$WORK/nicetunnel_panel.py" \
  || die "nicetunnel_panel.py is not valid Python (incomplete download?)."
bash -n "$WORK/nicetunnel.sh" || die "nicetunnel.sh is not a valid script (incomplete download?)."

# --- install ----------------------------------------------------------------
install -d -m 755 "$APP_DIR" "$UNIT_DIR" "$(dirname "$BIN_PATH")"
install -d -m 700 "$CONF_DIR"

install -m 755 "$WORK/nicetunnel.py" "$APP_DIR/nicetunnel.py.new" && mv -f "$APP_DIR/nicetunnel.py.new" "$APP_DIR/nicetunnel.py"
install -m 755 "$WORK/nicetunnel_panel.py" "$APP_DIR/nicetunnel_panel.py.new" && mv -f "$APP_DIR/nicetunnel_panel.py.new" "$APP_DIR/nicetunnel_panel.py"
install -m 755 "$WORK/nicetunnel.sh" "$BIN_PATH.new" && mv -f "$BIN_PATH.new" "$BIN_PATH"

PYBIN="$(command -v python3)"
cat >"$UNIT_DIR/nicetunnel@.service" <<EOF
[Unit]
Description=nicetunnel slot %i
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$CONF_DIR/slot%i.env
ExecStart=$PYBIN $APP_DIR/nicetunnel.py \$RT_ARGS
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

if need systemctl; then
  systemctl daemon-reload
else
  echo "Warning: systemctl not found; services will not start automatically." >&2
fi

# remember where updates come from (used by the menu's "Update from GitHub")
case "$REPO_RAW" in
  *YOUR_GITHUB_USERNAME*) ;;
  *) printf 'REPO_RAW="%s"\n' "$REPO_RAW" >"$CONF_DIR/source.conf" ;;
esac

echo
echo "nicetunnel installed. Open the menu any time with:  nicetunnel"
echo

rm -rf "$WORK"
if [ "$NO_MENU" = 1 ]; then
  exit 0
fi
exec "$BIN_PATH"
