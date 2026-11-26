# Progress
Current milestone: M5 — Vulnerability engine
Last updated: 2026-11-27

## Milestones
- [x] M0 Repository bootstrap
- [x] M1 Core architecture & protocol
- [x] M2 Metrics collection & storage — verified in CI on ubuntu-latest: all collectors present after 130 s, 1-min rollups, agent RSS 14 MB, ~0.08 % CPU
- [x] M3 Web UI foundation — role/CSRF/MFA/rate-limit tests; live charts verified in browser via SSE (test/tools/fakefleet)
- [x] M4 Inventory — CI `inventory-containers`: package names and security updates identical to native tools on debian:bookworm-20240110 (88/13), ubuntu:noble-20240423 (90/41), rockylinux:9.3 (141/62), alpine:3.19.0 (15/–)
- [ ] M5 Vulnerability engine
- [ ] M6 Actions & patch orchestration
- [ ] M7 Alerts & notifications
- [ ] M8 Proxmox snapshot hook & generic webhook hook
- [ ] M9 Hardening & polish
- [ ] M10 Packaging & docs → v0.1.0

## Blocked
- No Linux VM on the dev Mac: Linux acceptance runs in GitHub Actions (`acceptance` job, `test/acceptance/linux-local.sh`).
- Docker is not installed on the build host: `make e2e` (multi-distro containers) cannot be executed here.

## Next up
- M5: feed sync (Debian tracker, OSV Ubuntu/Alpine/Rocky/Alma, KEV, EPSS, NVD), matcher, risk score, vuln views, exceptions.
