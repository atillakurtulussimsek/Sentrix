#!/usr/bin/env bash
# M7 acceptance: filling a real test filesystem past a threshold triggers exactly one
# webhook alert (no repeat within cooldown) and a resolve message after cleanup.
# Linux + root (loop mount). Run: sudo -E test/acceptance/alert-disk.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN=${BIN:-bin}
WORK=$(mktemp -d)
MNT=/mnt/sxdisk-$$
cleanup() { kill $(jobs -p) 2>/dev/null || true; sleep 1; umount "$MNT" 2>/dev/null || true; rm -rf "$MNT"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- hooks"; cat "$WORK/hooks.log" 2>/dev/null; tail -30 "$WORK/server.log"; exit 1; }

dd if=/dev/zero of="$WORK/disk.img" bs=1M count=64 status=none
mkfs.ext4 -q -m 0 "$WORK/disk.img"
mkdir -p "$MNT" && mount -o loop "$WORK/disk.img" "$MNT"

# webhook receiver: appends each JSON body as one line
cat > "$WORK/recv.py" <<'PY'
import http.server, sys
log = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        with open(log, 'a') as f: f.write(body.replace('\n', ' ') + '\n')
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', 18099), H).serve_forever()
PY
python3 "$WORK/recv.py" "$WORK/hooks.log" &
touch "$WORK/hooks.log"

cat > "$WORK/server.yaml" <<YAML
data_dir: $WORK/server
listen: 127.0.0.1:48080
gateway_listen: 127.0.0.1:48443
gateway_url: https://127.0.0.1:48443
heartbeat_interval: 5s
feeds: {enabled: false}
YAML
SRV() { "$BIN/sentrix-server" --config "$WORK/server.yaml" "$@"; }
SRV serve > "$WORK/server.log" 2>&1 &
sleep 2
SRV channel create --name ci-hook --kind webhook --url http://127.0.0.1:18099/hook >/dev/null
SRV rule create --name "CI disk" --metric disk.used_pct --labels "mount=$MNT" --op '>' --value 90 --for 20s --cooldown 1h --channel ci-hook >/dev/null
OUT=$(SRV token create); TOK=$(echo "$OUT" | awk '/^token:/{print $2}'); FP=$(echo "$OUT" | awk '/^ca fingerprint:/{print $3}')
cat > "$WORK/agent.yaml" <<YAML
state_dir: $WORK/agent
interval: 5s
send_interval: 5s
YAML
"$BIN/sentrix-agent" --config "$WORK/agent.yaml" enroll --server https://127.0.0.1:48443 --token "$TOK" --ca-fingerprint "$FP"
"$BIN/sentrix-agent" --config "$WORK/agent.yaml" run > "$WORK/agent.log" 2>&1 &
sleep 15
firing() { grep -c '"event":"firing"' "$WORK/hooks.log" || true; }
resolved() { grep -c '"event":"resolved"' "$WORK/hooks.log" || true; }
[ "$(firing)" -eq 0 ] || fail "alert before filling the disk"

echo "== filling $MNT to ~95%"
avail=$(df --output=avail -B1 "$MNT" | tail -1); size=$(df --output=size -B1 "$MNT" | tail -1)
fallocate -l $(( size * 95 / 100 - (size - avail) )) "$MNT/fill"
df -h "$MNT" | tail -1
for _ in $(seq 1 120); do [ "$(firing)" -ge 1 ] && break; sleep 1; done
[ "$(firing)" -eq 1 ] || fail "expected one firing notification, got $(firing)"
echo "firing notification received; watching 60s for repeats"
sleep 60
[ "$(firing)" -eq 1 ] || fail "alert repeated within cooldown ($(firing) notifications)"

echo "== cleaning up"
rm -f "$MNT/fill"
for _ in $(seq 1 120); do [ "$(resolved)" -ge 1 ] && break; sleep 1; done
[ "$(resolved)" -eq 1 ] || fail "no resolve notification"
cat "$WORK/hooks.log" | cut -c1-200
echo PASS
