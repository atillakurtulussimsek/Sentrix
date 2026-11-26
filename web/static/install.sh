#!/bin/sh
# Sentrix agent installer.
#   curl -fsSL https://SENTRIX/install.sh | sudo sh -s -- --token sxe_… --ca-fingerprint …
# Options:
#   --server URL            agent gateway URL (default: the server this script came from)
#   --token TOKEN           one-time enrolment token (Settings → Enrolment)
#   --ca-fingerprint SHA256 fingerprint of the server CA (shown next to the token)
#   --hostname NAME         report this hostname instead of the system's
#   --download-url URL      where to fetch sentrix-agent-linux-<arch> (default: this server)
#   --no-patching           install read-only (allow_patching: false)
set -eu

BASE_URL="__SENTRIX_BASE_URL__"
SERVER="__SENTRIX_GATEWAY_URL__"
TOKEN=""
FP=""
NAME=""
DOWNLOAD=""
ALLOW_PATCHING=true
RELEASES="https://github.com/atillakurtulussimsek/Sentrix/releases/latest/download"

case "$BASE_URL" in __*) BASE_URL="" ;; esac
case "$SERVER" in __*) SERVER="" ;; esac

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --ca-fingerprint) FP="$2"; shift 2 ;;
    --hostname) NAME="$2"; shift 2 ;;
    --download-url) DOWNLOAD="$2"; shift 2 ;;
    --no-patching) ALLOW_PATCHING=false; shift ;;
    -h|--help) sed -n '2,13p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "sentrix-install: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
[ -n "$SERVER" ] || die "--server is required"
[ -n "$TOKEN" ] || die "--token is required"
[ -n "$FP" ] || die "--ca-fingerprint is required"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [ -z "$DOWNLOAD" ]; then
  if [ -n "$BASE_URL" ]; then DOWNLOAD="$BASE_URL/download"; else DOWNLOAD="$RELEASES"; fi
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
  else die "curl or wget required"; fi
}

echo "==> downloading sentrix-agent ($ARCH)"
TMP=$(mktemp)
fetch "$DOWNLOAD/sentrix-agent-linux-$ARCH" "$TMP" || die "download failed from $DOWNLOAD"
chmod 0755 "$TMP"
"$TMP" version >/dev/null 2>&1 || die "downloaded file is not a valid sentrix-agent binary"
mv "$TMP" /usr/local/bin/sentrix-agent

mkdir -p /etc/sentrix /var/lib/sentrix-agent
chmod 0700 /var/lib/sentrix-agent
if [ ! -f /etc/sentrix/agent.yaml ]; then
  cat > /etc/sentrix/agent.yaml <<YAML
# Sentrix agent configuration — see docs/configuration.md
state_dir: /var/lib/sentrix-agent
server_url: $SERVER
interval: 10s
send_interval: 30s
allow_patching: $ALLOW_PATCHING
YAML
  chmod 0600 /etc/sentrix/agent.yaml
fi

echo "==> enrolling with $SERVER"
set -- --config /etc/sentrix/agent.yaml enroll --server "$SERVER" --token "$TOKEN" --ca-fingerprint "$FP"
[ -n "$NAME" ] && set -- "$@" --hostname "$NAME"
if [ -f /var/lib/sentrix-agent/identity.json ]; then set -- "$@" --force; fi
/usr/local/bin/sentrix-agent "$@"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  cat > /etc/systemd/system/sentrix-agent.service <<'UNIT'
[Unit]
Description=Sentrix agent
Documentation=https://github.com/atillakurtulussimsek/Sentrix
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sentrix-agent --config /etc/sentrix/agent.yaml run
Restart=always
RestartSec=5
# The agent must run as root to read package databases and apply updates.
User=root
Nice=10
IOSchedulingClass=idle
MemoryMax=200M
LimitNOFILE=4096
NoNewPrivileges=false
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now sentrix-agent
  systemctl restart sentrix-agent
  echo "==> sentrix-agent is running (systemctl status sentrix-agent)"
else
  echo "==> systemd not found; start the agent with:"
  echo "    /usr/local/bin/sentrix-agent --config /etc/sentrix/agent.yaml run"
fi
