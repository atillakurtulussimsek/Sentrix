#!/usr/bin/env bash
# Linux acceptance test: real server + real agent on the same host.
# Verifies M1 (enrol, online, offline) and M2 (all collectors, rollups, RSS).
# Used by CI (ubuntu-latest); run manually with: sudo -E test/acceptance/linux-local.sh
set -euo pipefail
export SENTRIX_LANGUAGE=en   # this script parses CLI output (token create, patch plan)
cd "$(dirname "$0")/../.."
BIN=${BIN:-bin}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; sleep 1' EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -50 "$WORK/server.log"; echo "--- agent log"; tail -50 "$WORK/agent.log"; exit 1; }

cat > "$WORK/server.yaml" <<YAML
data_dir: $WORK/server
listen: 127.0.0.1:18080
gateway_listen: 127.0.0.1:18443
gateway_url: https://127.0.0.1:18443
offline_after: 20s
heartbeat_interval: 5s
feeds: {enabled: false}
YAML
cat > "$WORK/agent.yaml" <<YAML
state_dir: $WORK/agent
interval: 10s
send_interval: 15s
allow_patching: false
watch_services: [ssh.service]
YAML

"$BIN/sentrix-server" --config "$WORK/server.yaml" serve > "$WORK/server.log" 2>&1 &
sleep 2
OUT=$("$BIN/sentrix-server" --config "$WORK/server.yaml" token create --note ci)
TOKEN=$(echo "$OUT" | awk '/^token:/{print $2}')
FP=$(echo "$OUT" | awk '/^ca fingerprint:/{print $3}')
"$BIN/sentrix-agent" --config "$WORK/agent.yaml" enroll --server https://127.0.0.1:18443 --token "$TOKEN" --ca-fingerprint "$FP"
if "$BIN/sentrix-agent" --config "$WORK/agent.yaml" --state-dir "$WORK/agent2" enroll --server https://127.0.0.1:18443 --token "$TOKEN" --ca-fingerprint "$FP" 2>/dev/null; then
  fail "token reuse accepted"
fi
"$BIN/sentrix-agent" --config "$WORK/agent.yaml" run > "$WORK/agent.log" 2>&1 &
AGENT=$!
sleep 4
curl -fsS http://127.0.0.1:18080/healthz >/dev/null || fail "healthz"
echo "== M1: agent online"
"$BIN/sentrix-server" --config "$WORK/server.yaml" hosts | tee /dev/stderr | grep -q online || fail "agent not online"

echo "== M2: collecting for 130s"
sleep 130
RSS_KB=$(awk '/VmRSS/{print $2}' /proc/$AGENT/status)
CPU_TICKS=$(awk '{print $14+$15}' /proc/$AGENT/stat)
echo "agent RSS: ${RSS_KB} kB, cpu ticks: ${CPU_TICKS}"
[ "$RSS_KB" -lt 30720 ] || fail "agent RSS ${RSS_KB}kB >= 30MB"
STATS=$("$BIN/sentrix-server" --config "$WORK/server.yaml" stats)
echo "$STATS"
for p in cpu load mem swap disk diskio net system agent; do
  echo "$STATS" | grep -q "\"$p\":" || fail "no series for collector $p"
done
echo "$STATS" | grep -q '"minute_rows":0' && fail "no 1m rollups"

echo "== M1: kill agent → offline"
kill $AGENT; wait $AGENT 2>/dev/null || true
sleep 30
"$BIN/sentrix-server" --config "$WORK/server.yaml" hosts | tee /dev/stderr | grep -q offline || fail "agent not offline"
grep -q "state=offline" "$WORK/server.log" || fail "no offline transition logged"
echo "PASS"
