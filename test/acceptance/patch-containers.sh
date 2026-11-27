#!/usr/bin/env bash
# M6 acceptance (live feeds, real package managers): a security-only plan for two old
# containers (Debian + Rocky) → dry run lists packages → apply with --approve → hosts
# re-inventory with fewer CVEs → audit log complete. Uses only the sentrix CLI.
set -euo pipefail
export SENTRIX_LANGUAGE=en   # this script parses CLI output (token create, patch plan)
cd "$(dirname "$0")/../.."
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BIN="$PWD/bin/linux_$ARCH"
WORK=$(mktemp -d)
P=sx-patch-$$
cleanup() { docker rm -f $P-deb $P-rocky >/dev/null 2>&1 || true; kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; tail -60 "$WORK/server.log"; exit 1; }
SRV() { "$BIN/sentrix-server" --config "$WORK/server.yaml" "$@"; }

cat > "$WORK/server.yaml" <<YAML
data_dir: $WORK/server
listen: 127.0.0.1:38080
gateway_listen: 127.0.0.1:38443
gateway_url: https://127.0.0.1:38443
offline_after: 60s
heartbeat_interval: 5s
feeds: {enabled: true, interval: 6h}
YAML
SRV serve > "$WORK/server.log" 2>&1 &
sleep 2
SENTRIX_PASSWORD=ci-password-123 SRV user create --username ci --role operator
TOKEN=$(SRV api-token create --user ci --scope operate --name ci)

enrol() { # enrol <container> <image> <hostname>
  docker run -d --name "$1" --network host -v "$BIN:/sx:ro" "$2" sleep infinity >/dev/null
  local out tok fp
  out=$(SRV token create); tok=$(echo "$out" | awk '/^token:/{print $2}'); fp=$(echo "$out" | awk '/^ca fingerprint:/{print $3}')
  docker exec "$1" /sx/sentrix-agent --state-dir /var/lib/sx enroll --server https://127.0.0.1:38443 --token "$tok" --ca-fingerprint "$fp" --hostname "$3"
  docker exec -d "$1" sh -c 'exec /sx/sentrix-agent --state-dir /var/lib/sx run >/var/log/sx.log 2>&1'
}
enrol $P-deb debian:bookworm-20240110 deb-old
enrol $P-rocky rockylinux:9.3 rocky-old

count() { SRV findings --host "$1" | wc -l; }
for h in deb-old rocky-old; do
  for _ in $(seq 1 600); do [ "$(count $h)" -gt 0 ] && break; sleep 1; done
  [ "$(count $h)" -gt 0 ] || fail "no findings for $h"
done
sleep 5
B_DEB=$(count deb-old); B_ROCKY=$(count rocky-old)
echo "CVEs before: deb-old=$B_DEB rocky-old=$B_ROCKY"

export SENTRIX_URL=http://127.0.0.1:38080 SENTRIX_TOKEN=$TOKEN
"$BIN/sentrix" cve list --severity high | tail -3
echo "== plan (security only, dry run)"
"$BIN/sentrix" patch plan --hosts deb-old,rocky-old --scope security --canary 1 --parallel 2 | tee "$WORK/plan.txt"
PLAN=$(awk '/^Plan /{print $2; exit}' "$WORK/plan.txt")
grep -q "status: ready" "$WORK/plan.txt" || fail "plan not ready after dry run"
for h in deb-old rocky-old; do
  n=$(awk -v h=$h '$1==h{f=1;next} /^$/{f=0} f && /→/' "$WORK/plan.txt" | wc -l)
  echo "dry run $h: $n package changes"; [ "$n" -gt 0 ] || fail "dry run listed no packages for $h"
done
# dry run must not change anything
[ "$(count deb-old)" -eq "$B_DEB" ] || fail "dry run changed deb-old"

echo "== apply"
"$BIN/sentrix" patch apply "$PLAN" --approve | tee "$WORK/apply.txt" || fail "apply failed"
A_DEB=$(count deb-old); A_ROCKY=$(count rocky-old)
echo "CVEs after: deb-old=$A_DEB rocky-old=$A_ROCKY"
[ "$A_DEB" -lt "$B_DEB" ] || fail "deb-old CVEs did not decrease"
[ "$A_ROCKY" -lt "$B_ROCKY" ] || fail "rocky-old CVEs did not decrease"

echo "== audit log"
SRV audit --target "$PLAN" --limit 200 | tee "$WORK/audit.txt"
for a in plan.create plan.dry_run_complete plan.approve plan.start plan.done; do
  grep -q "	$a	" "$WORK/audit.txt" || fail "audit missing $a"
done
SRV audit --limit 500 > "$WORK/all-audit.txt"
[ "$(grep -c 'plan.host.done' "$WORK/all-audit.txt")" -ge 2 ] || fail "audit missing per-host results"
grep -q "command.result.patch_security_only" "$WORK/all-audit.txt" || fail "audit missing command results"
echo PASS
