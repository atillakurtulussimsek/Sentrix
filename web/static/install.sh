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
#   --no-self-update        never install agent updates offered by the server (allow_self_update: false)
#   --allow-package-management  let admins install/remove packages from the UI (allow_package_management: true)
#   --lang tr|en            installer and agent CLI language (default: tr)
set -eu

BASE_URL="__SENTRIX_BASE_URL__"
SERVER="__SENTRIX_GATEWAY_URL__"
TOKEN=""
FP=""
NAME=""
DOWNLOAD=""
ALLOW_PATCHING=true
ALLOW_SELF_UPDATE=true
ALLOW_PACKAGE_MANAGEMENT=false
LNG=tr
BADOPT=""
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
    --no-self-update) ALLOW_SELF_UPDATE=false; shift ;;
    --allow-package-management) ALLOW_PACKAGE_MANAGEMENT=true; shift ;;
    --lang) LNG="$2"; shift 2 ;;
    --lang=*) LNG="${1#--lang=}"; shift ;;
    -h|--help) sed -n '2,14p' "$0" 2>/dev/null || true; exit 0 ;;
    *) [ -n "$BADOPT" ] || BADOPT="$1"; shift ;;
  esac
done

# Messages (tr default, en optional).
case "$LNG" in en*|EN*) LNG=en ;; *) LNG=tr ;; esac
if [ "$LNG" = en ]; then
  M_BADOPT="unknown option: %s"
  M_ROOT="run as root (sudo)"
  M_REQ="%s is required"
  M_ARCH="unsupported architecture %s"
  M_FETCH="curl or wget required"
  M_DOWNLOADING="==> downloading sentrix-agent (%s)"
  M_DLFAIL="download failed from %s"
  M_BADBIN="downloaded file is not a valid sentrix-agent binary"
  M_ENROLL="==> enrolling with %s"
  M_RUNNING="==> sentrix-agent is running (systemctl status sentrix-agent)"
  M_NOSYSTEMD="==> systemd not found; start the agent with:"
else
  M_BADOPT="bilinmeyen seçenek: %s"
  M_ROOT="root olarak çalıştırın (sudo)"
  M_REQ="%s gerekli"
  M_ARCH="desteklenmeyen mimari: %s"
  M_FETCH="curl veya wget gerekli"
  M_DOWNLOADING="==> sentrix-agent indiriliyor (%s)"
  M_DLFAIL="indirme başarısız: %s"
  M_BADBIN="indirilen dosya geçerli bir sentrix-agent ikili dosyası değil"
  M_ENROLL="==> %s ile kayıt yapılıyor"
  M_RUNNING="==> sentrix-agent çalışıyor (systemctl status sentrix-agent)"
  M_NOSYSTEMD="==> systemd bulunamadı; ajanı şu komutla başlatın:"
fi
msg() { fmt="$1"; shift; printf "$fmt\n" "$@"; }
die() { fmt="$1"; shift; printf "sentrix-install: $fmt\n" "$@" >&2; exit 1; }
if [ -n "$BADOPT" ]; then printf "$M_BADOPT\n" "$BADOPT" >&2; exit 2; fi
[ "$(id -u)" -eq 0 ] || die "$M_ROOT"
[ -n "$SERVER" ] || die "$M_REQ" "--server"
[ -n "$TOKEN" ] || die "$M_REQ" "--token"
[ -n "$FP" ] || die "$M_REQ" "--ca-fingerprint"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "$M_ARCH" "$(uname -m)" ;;
esac
if [ -z "$DOWNLOAD" ]; then
  if [ -n "$BASE_URL" ]; then DOWNLOAD="$BASE_URL/download"; else DOWNLOAD="$RELEASES"; fi
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
  else die "$M_FETCH"; fi
}

msg "$M_DOWNLOADING" "$ARCH"
TMP=$(mktemp)
fetch "$DOWNLOAD/sentrix-agent-linux-$ARCH" "$TMP" || die "$M_DLFAIL" "$DOWNLOAD"
chmod 0755 "$TMP"
"$TMP" version >/dev/null 2>&1 || die "$M_BADBIN"
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
allow_self_update: $ALLOW_SELF_UPDATE
allow_package_management: $ALLOW_PACKAGE_MANAGEMENT
YAML
  chmod 0600 /etc/sentrix/agent.yaml
fi

msg "$M_ENROLL" "$SERVER"
set -- --config /etc/sentrix/agent.yaml enroll --server "$SERVER" --token "$TOKEN" --ca-fingerprint "$FP"
[ -n "$NAME" ] && set -- "$@" --hostname "$NAME"
if [ -f /var/lib/sentrix-agent/identity.json ]; then set -- "$@" --force; fi
SENTRIX_LANGUAGE="$LNG" /usr/local/bin/sentrix-agent "$@"

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
  msg "$M_RUNNING"
else
  msg "$M_NOSYSTEMD"
  echo "    /usr/local/bin/sentrix-agent --config /etc/sentrix/agent.yaml run"
fi
