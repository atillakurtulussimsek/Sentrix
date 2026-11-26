#!/usr/bin/env bash
# M5 acceptance with live feeds: a deliberately old Debian container must report exactly
# the glibc CVEs that the Debian Security Tracker lists as fixed in a newer version
# (oracle: dpkg --compare-versions inside the container) plus open ones; after upgrading
# openssl those CVEs must disappear. Needs Docker, jq, network.
set -euo pipefail
cd "$(dirname "$0")/../.."
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BIN="$PWD/bin/linux_$ARCH"
IMG=${IMG:-debian:bookworm-20240110}
PKG=${PKG:-glibc}          # source package (Debian tracker key)
BINS=${BINS:-libc6 libc-bin} # its binaries installed in the image
FIRSTBIN=${BINS%% *}
WORK=$(mktemp -d)
C=sx-vuln-$$
cleanup() { docker rm -f $C >/dev/null 2>&1 || true; kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; tail -40 "$WORK/server.log"; exit 1; }

cat > "$WORK/server.yaml" <<YAML
data_dir: $WORK/server
listen: 127.0.0.1:28080
gateway_listen: 127.0.0.1:28443
gateway_url: https://127.0.0.1:28443
offline_after: 30s
heartbeat_interval: 5s
feeds: {enabled: true, interval: 6h}
YAML
"$BIN/sentrix-server" --config "$WORK/server.yaml" serve > "$WORK/server.log" 2>&1 &
sleep 2
OUT=$("$BIN/sentrix-server" --config "$WORK/server.yaml" token create)
TOKEN=$(echo "$OUT" | awk '/^token:/{print $2}'); FP=$(echo "$OUT" | awk '/^ca fingerprint:/{print $3}')

docker run -d --name $C --network host -v "$BIN:/sx:ro" "$IMG" sleep infinity >/dev/null
docker exec $C /sx/sentrix-agent --state-dir /var/lib/sx enroll --server https://127.0.0.1:28443 --token "$TOKEN" --ca-fingerprint "$FP" --hostname deb-old
start_agent() { docker exec -d $C sh -c 'echo $$ > /run/sx.pid; exec /sx/sentrix-agent --state-dir /var/lib/sx run >/var/log/sx.log 2>&1'; }
start_agent

wait_for() { # wait_for <seconds> <description> <command...>
  local t=$1 d=$2; shift 2
  for _ in $(seq 1 "$t"); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 1; done
  fail "timeout waiting for $d"
}
has_findings() { "$BIN/sentrix-server" --config "$WORK/server.yaml" findings --host deb-old | grep -q .; }
echo "== waiting for inventory + Debian tracker sync (large download)"
wait_for 600 "findings" has_findings
TRACKER="$WORK/server/feeds/debian-tracker.json"
[ -s "$TRACKER" ] || fail "tracker not downloaded"

expected() { # prints "CVE fixed" lines for $PKG given the container's installed source version
  local inst
  inst=$(docker exec $C dpkg-query -W -f='${source:Version}\n' $FIRSTBIN | head -1)
  jq -r --arg p "$PKG" '.[$p] | to_entries[] | select(.key|startswith("CVE-")) | .key as $k | .value.releases.bookworm // empty
     | select((.status=="resolved" and .fixed_version!="0" and .fixed_version!=null) or .status=="open" or .status=="undetermined")
     | "\($k) \(if .status=="resolved" then .fixed_version else "-" end)"' "$TRACKER" |
  while read -r cve fixed; do
    if [ "$fixed" = "-" ]; then echo "$cve -"; elif docker exec $C dpkg --compare-versions "$inst" lt "$fixed"; then echo "$cve $fixed"; fi
  done | sort
}
actual() { "$BIN/sentrix-server" --config "$WORK/server.yaml" findings --host deb-old | awk -F'\t' -v p=$PKG '$3==p {print $2" "$5}' | sort; }

expected > "$WORK/exp1"; actual > "$WORK/act1"
echo "installed $FIRSTBIN: $(docker exec $C dpkg-query -W -f='${Version}' $FIRSTBIN) — expected $(wc -l < "$WORK/exp1") $PKG CVEs, Sentrix reports $(wc -l < "$WORK/act1")"
diff -u "$WORK/exp1" "$WORK/act1" || fail "$PKG findings differ from tracker+dpkg oracle"
FIXABLE=$(awk '$2!="-"' "$WORK/exp1" | head -1)
[ -n "$FIXABLE" ] || fail "image has no fixable $PKG CVE — pick an older image"
echo "example: $FIXABLE"

echo "== upgrading $PKG in the container"
docker exec $C sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade $BINS" >/dev/null
docker exec $C sh -c 'kill $(cat /run/sx.pid)'; sleep 1; start_agent
gone() { ! actual | grep -q "^${FIXABLE%% *} "; }
wait_for 180 "${FIXABLE%% *} to disappear" gone
expected > "$WORK/exp2"; actual > "$WORK/act2"
diff -u "$WORK/exp2" "$WORK/act2" || fail "post-upgrade findings differ"
echo "after upgrade: $(wc -l < "$WORK/act2") $PKG CVEs remain (all unfixed or newer)"
echo PASS
