#!/usr/bin/env bash
# M4 acceptance: inside real distro containers (deliberately old images), the agent's
# inventory must match native tools: installed package names and security update names.
# Needs Docker and jq. Usage: test/acceptance/inventory-containers.sh [image...]
set -euo pipefail
cd "$(dirname "$0")/../.."
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BIN="$PWD/bin/linux_$ARCH"
[ -x "$BIN/sentrix-agent" ] || { echo "build first: make build-linux"; exit 1; }
IMAGES=${*:-"debian:bookworm-20240110 ubuntu:noble-20240423 rockylinux:9.3 alpine:3.19.0"}
rc=0
for img in $IMAGES; do
  out=$(mktemp -d)
  echo "=== $img"
  docker run --rm -v "$BIN:/sx:ro" -v "$out:/out" "$img" sh -c '
    set -e
    if command -v apt-get >/dev/null; then
      apt-get update -qq >/dev/null
      dpkg-query -W -f="\${db:Status-Abbrev} \${Package}\n" | awk "\$1 ~ /^.i/ {print \$2}" | sort -u > /out/native-pkgs
      apt list --upgradable 2>/dev/null | grep -- "-security" | cut -d/ -f1 | sort -u > /out/native-sec
    elif command -v dnf >/dev/null; then
      rpm -qa --qf "%{NAME}\n" | grep -v "^gpg-pubkey$" | sort -u > /out/native-pkgs
      dnf -q updateinfo list --updates --security 2>/dev/null | awk "{print \$3}" | sed -E "s/\.[^.]+$//; s/-[^-]+-[^-]+$//" | sort -u > /out/native-sec
    elif command -v apk >/dev/null; then
      apk update -q >/dev/null
      apk info 2>/dev/null | sort -u > /out/native-pkgs
      : > /out/native-sec   # apk has no security metadata (server derives it from CVE matches)
    fi
    /sx/sentrix-agent inventory --refresh > /out/inv.json
  '
  jq -r '.packages[].name' "$out/inv.json" | sort -u > "$out/agent-pkgs"
  jq -r '.updates[] | select(.security) | .name' "$out/inv.json" | sort -u > "$out/agent-sec"
  np=$(wc -l < "$out/native-pkgs"); ap=$(wc -l < "$out/agent-pkgs")
  ns=$(wc -l < "$out/native-sec"); as=$(wc -l < "$out/agent-sec")
  nu=$(jq '.updates | length' "$out/inv.json")
  echo "packages: native=$np agent=$ap   security updates: native=$ns agent=$as   all updates: $nu   os: $(jq -r '.os.pretty_name' "$out/inv.json")"
  jq -r '.errors // [] | .[]' "$out/inv.json"
  if ! diff -u "$out/native-pkgs" "$out/agent-pkgs" > "$out/pkgs.diff"; then echo "FAIL: package lists differ"; head -40 "$out/pkgs.diff"; rc=1; fi
  if ! diff -u "$out/native-sec" "$out/agent-sec" > "$out/sec.diff"; then echo "FAIL: security updates differ"; head -40 "$out/sec.diff"; rc=1; fi
  [ "$np" -gt 0 ] || { echo "FAIL: no packages"; rc=1; }
  case "$img" in alpine*) ;; *) [ "$ns" -gt 0 ] || echo "WARN: image has no pending security updates (test less meaningful)";; esac
done
[ $rc -eq 0 ] && echo PASS
exit $rc
