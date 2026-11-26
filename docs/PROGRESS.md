# Progress
Current milestone: M6 — Actions & patch orchestration
Last updated: 2026-11-27

## Milestones
- [x] M0 Repository bootstrap
- [x] M1 Core architecture & protocol
- [x] M2 Metrics collection & storage — verified in CI on ubuntu-latest: all collectors present after 130 s, 1-min rollups, agent RSS 14 MB, ~0.08 % CPU
- [x] M3 Web UI foundation — role/CSRF/MFA/rate-limit tests; live charts verified in browser via SSE (test/tools/fakefleet)
- [x] M4 Inventory — CI `inventory-containers`: package names and security updates identical to native tools on debian:bookworm-20240110 (88/13), ubuntu:noble-20240423 (90/41), rockylinux:9.3 (141/62), alpine:3.19.0 (15/–)
- [x] M5 Vulnerability engine — CI `vuln-container` (live feeds): debian:bookworm-20240110 glibc 47/47 CVEs identical to tracker+dpkg oracle; CVE-2023-6246 (fixed 2.36-9+deb12u4) disappears after upgrade; golden feed tests + lifecycle test
- [ ] M6 Actions & patch orchestration
- [ ] M7 Alerts & notifications
- [ ] M8 Proxmox snapshot hook & generic webhook hook
- [ ] M9 Hardening & polish
- [ ] M10 Packaging & docs → v0.1.0

## Blocked
- No Linux VM on the dev Mac: Linux acceptance runs in GitHub Actions (`acceptance` job, `test/acceptance/linux-local.sh`).
- Docker is not installed on the build host: `make e2e` (multi-distro containers) cannot be executed here.

## Next up
- M6: verify patch-containers CI job; then M7 alerts & notifications.
