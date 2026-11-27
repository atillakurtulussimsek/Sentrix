#!/usr/bin/env bash
# M10 acceptance: a fresh machine following only the README quick start —
# docker compose up + the agent one-liner — has its host visible and scanned within 5 minutes.
set -euo pipefail
cd "$(dirname "$0")/../.."
export SENTRIX_IMAGE=${SENTRIX_IMAGE:-sentrix:ci} SENTRIX_HOST=127.0.0.1
START=$(date +%s)
fail() { echo "FAIL: $*"; docker compose logs --tail 80; exit 1; }
cleanup() { docker compose down -v >/dev/null 2>&1 || true; sudo systemctl disable --now sentrix-agent >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== README step 1: docker compose up -d"
docker compose up -d
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8080/healthz || fail "server not healthy"

echo "== README step 2 (headless variant): create an enrolment token"
OUT=$(docker compose exec -T -e SENTRIX_LANGUAGE=en sentrix sentrix-server token create --note quickstart)
echo "$OUT"
TOKEN=$(echo "$OUT" | awk '/^token:/{print $2}'); FP=$(echo "$OUT" | awk '/^ca fingerprint:/{print $3}')

echo "== README step 3: agent one-liner"
curl -fsSL http://127.0.0.1:8080/install.sh | sudo sh -s -- --token "$TOKEN" --ca-fingerprint "$FP"
systemctl is-active --quiet sentrix-agent || fail "agent service not active"

echo "== waiting for the host to be visible and scanned"
visible="" scanned=""
while [ $(( $(date +%s) - START )) -lt 300 ]; do
  H=$(docker compose exec -T sentrix sentrix-server hosts || true)
  echo "$H" | grep -q online && visible=yes
  if [ -n "$visible" ] && [ "$(docker compose exec -T sentrix sentrix-server findings | wc -l)" -gt 0 ]; then scanned=yes; break; fi
  sleep 5
done
ELAPSED=$(( $(date +%s) - START ))
echo "$H"
[ -n "$visible" ] || fail "host not visible after ${ELAPSED}s"
[ -n "$scanned" ] || fail "host not scanned (no findings) after ${ELAPSED}s"
echo "host visible and scanned after ${ELAPSED}s: $(docker compose exec -T sentrix sentrix-server findings | wc -l) findings"
echo PASS
