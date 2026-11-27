# Progress

## Final summary (v0.1.0)

**What was built.** Sentrix v0.1.0: a single Go server binary/container (web UI, REST API, mTLS agent gateway,
SQLite store) and a static agent for linux/amd64+arm64.
- Monitoring with live charts and rollups; inventory (dpkg/rpm/apk, updates with security flag, ports, images).
- Vulnerability engine: Debian Security Tracker, OSV (Ubuntu, Alpine, Rocky, AlmaLinux), KEV, EPSS, NVD;
  dpkg/RPM/apk comparators; explained risk score; fleet/CVE/host/package views; exceptions with expiry.
- Patch orchestration: typed executor (no remote shell), dry run → approval → canary rollout, reboot handling,
  verification, policies with maintenance windows, Proxmox VE and webhook snapshot hooks, full audit log, CLI.
- Alerts (threshold/state/vulnerability/patch) to email, Telegram, Discord, Slack, ntfy, webhook; digest.
- Security: argon2id, TOTP 2FA, roles, scoped API tokens, CSRF, strict CSP, rate limits, secrets at rest,
  SECURITY.md and an ASVS L1 self-review.
- Packaging: Dockerfile (distroless), docker-compose, install.sh one-liner served by the server, systemd units,
  GoReleaser + nfpm (.deb/.rpm), release workflow (draft releases, tag-triggered — not run).

**How to run.** `SENTRIX_HOST=… docker compose up -d` → open :8080 → setup wizard → Settings → Enrolment →
run the shown `curl …/install.sh | sudo sh` on each host. Dev: `make run-server` + `go run ./test/tools/fakefleet`
(test login admin / devpassword123 in `deploy/dev`). Details: README.md, docs/install.md.

**Verification.** Unit/integration tests (`make test`, race in CI) and CI acceptance jobs on real Linux and distro
containers for every milestone (see milestone notes below). `v0.1.0` is tagged **locally only**; no GitHub
release or image was published (needs owner approval — push the tag to trigger `.github/workflows/release.yml`,
which creates a *draft* release and pushes `ghcr.io/…/sentrix`).

**Known limitations.** SQLite only; no vulnerability data for RHEL/Fedora/SUSE; Ubuntu feed is large (~750k
rows, few hundred MB); UI is plain HTTP unless behind a proxy or `tls_cert` set; password minimum 10 chars;
Turkish UI partial; dnf security-only dry runs rely on `dnf --assumeno` output parsing; agent runs as root.

**Recommended next steps.** PostgreSQL backend; RHEL OVAL/CSAF ingestion; container image scanning; complete
Turkish translation; per-user notification preferences; signed agent self-update; Windows/macOS agents;
Kubernetes view; publish v0.1.0 after owner review (push tag, check the draft release).

---
Current milestone: done (v0.1.0)
Last updated: 2026-11-27

## Milestones
- [x] M0 Repository bootstrap
- [x] M1 Core architecture & protocol
- [x] M2 Metrics collection & storage — verified in CI on ubuntu-latest: all collectors present after 130 s, 1-min rollups, agent RSS 14 MB, ~0.08 % CPU
- [x] M3 Web UI foundation — role/CSRF/MFA/rate-limit tests; live charts verified in browser via SSE (test/tools/fakefleet)
- [x] M4 Inventory — CI `inventory-containers`: package names and security updates identical to native tools on debian:bookworm-20240110 (88/13), ubuntu:noble-20240423 (90/41), rockylinux:9.3 (141/62), alpine:3.19.0 (15/–)
- [x] M5 Vulnerability engine — CI `vuln-container` (live feeds): debian:bookworm-20240110 glibc 47/47 CVEs identical to tracker+dpkg oracle; CVE-2023-6246 (fixed 2.36-9+deb12u4) disappears after upgrade; golden feed tests + lifecycle test
- [x] M6 Actions & patch orchestration — CI `patch-containers` via `sentrix` CLI: security-only plan on debian:bookworm-20240110 + rockylinux:9.3, dry run 13/68 package changes, applied, CVEs 199→148 and 615→2, audit trail complete; executor test proves unknown/raw actions are rejected before any program runs; policy outside window creates nothing (unit test)
- [x] M7 Alerts & notifications — CI `alert-disk`: loop-mounted ext4 filled to 95 % → exactly one webhook `firing`, no repeat during 60 s (cooldown 1 h), `resolved` after cleanup; `TestDiskThresholdAlertLifecycle`
- [x] M8 Proxmox snapshot hook & generic webhook hook — httptest-mocked PVE: snapshot created and audited before the patch command; snapshot failure → host failed, no patch command, plan failed (`TestProxmoxSnapshot*`)
- [x] M9 Hardening & polish — ASVS L1 self-review in docs/security-review.md (5 findings fixed); TOTP 2FA with QR, password change revokes sessions, scoped API tokens UI, rate limits, body limits, SECURITY.md; tests `TestAPITokenScopes`, `TestPasswordChangeRevokesSessions`, `TestLoginRateLimitAndMFA`
- [x] M10 Packaging & docs → v0.1.0 — CI `quickstart`: docker compose + install.sh one-liner → host visible and scanned after 100 s (2177 findings); CI `package`: GoReleaser snapshot builds deb/rpm; screenshots in docs/screenshots; v0.1.0 tagged locally

## Blocked
- No Linux VM on the dev Mac: Linux acceptance runs in GitHub Actions (`acceptance` job, `test/acceptance/linux-local.sh`).
- Docker is not installed on the build host: `make e2e` (multi-distro containers) cannot be executed here.

## Post-0.1.0
- Turkish localization (default) with per-user language, localized notifications/CLIs/installer and Turkish docs — done, `make build test lint` green, verified in the browser (TR/EN switch, no untranslated UI text on all pages).

## Next up
- Owner: publish the v0.1.0 draft release on GitHub.
- Roadmap items listed in the final summary above.
