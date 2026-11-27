# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Package management (admin only): install packages from the configured repositories and remove or purge installed ones from host → *Patches & actions*. Every operation is previewed with a dry run and applied after review (removals need an extra acknowledgement); kernels, boot, init, SSH, the package manager and the agent are protected, also as dependencies. Agents opt in with `allow_package_management: true` / `install.sh --allow-package-management` (off by default).
- "Remove…" links in the host inventory and "Update…" links on pending updates (prefilled patch plan).

## [0.2.0] - 2026-11-27

Turkish-first release with signed agent self-update.

### Added
- Signed agent self-update: the server fetches release-key signed agent builds (GitHub release by default), shows outdated agents, and in "automatic" mode asks them to update; agents verify the Ed25519 signature, digest and version before replacing themselves and re-executing (no host reboot). Mode per server in *Settings → Enrolment*; per-host opt-out `allow_self_update: false` / `install.sh --no-self-update`.
- Full Turkish translation; Turkish is now the default language (`language: tr` / `SENTRIX_LANGUAGE`, `en` also supported).
- Per-user UI language: picker in the sidebar, on the sign-in/setup pages and in Account settings (stored per account; "server default" option).
- Notifications, digests, default rule/plan names and stored patch messages use the server default language.
- CLIs (`sentrix`, `sentrix-server`, `sentrix-agent`) are localized: `--lang tr|en` > `SENTRIX_LANGUAGE` > config `language` > `tr`.
- Agent installer `install.sh --lang tr|en`; enrolment one-liners pass the server language.
- Translatable risk-score explanations; Turkish documentation (`README.md`, `docs/tr/`, `SECURITY.tr.md`, `CONTRIBUTING.tr.md`); English README moved to `README.en.md`.

### Fixed
- Kernel CVEs are matched against the running kernel only: fallback kernels that are installed but not booted no longer keep findings open after a reboot, and a newly installed but not yet booted kernel no longer hides a vulnerable running kernel (RPM). Findings whose fix waits for a reboot are marked "reboot required".

### Changed
- docker-compose host ports are configurable (`SENTRIX_UI_PORT`, `SENTRIX_GATEWAY_PORT`) for hosts where 8080/8443 are taken.
- Message catalogs split per language and area (`web/i18n/<lang>/*.json`); a parity test enforces identical keys and format verbs.

## [0.1.0] - 2026-11-27

First public release: monitoring, inventory, vulnerability detection, patch orchestration and alerting
for small Linux fleets in a single self-hosted server plus a small static agent.

### Highlights
- Outbound-only agents with mutual TLS and a closed set of typed actions — no remote shell.
- Distro-aware CVE matching (Debian tracker, OSV for Ubuntu/Alpine/Rocky/AlmaLinux, KEV, EPSS, NVD) with an explained risk score.
- Patch plans with mandatory dry run, approval, canary rollout, reboots, verification, Proxmox snapshots, maintenance-window policies.
- Alerts to email, Telegram, Discord, Slack, ntfy and webhooks; daily digest.
- Docker image, docker-compose quick start, install.sh one-liner, .deb/.rpm packages, `sentrix` CLI.

### Verified
- CI acceptance on real Linux and distro containers: enrolment/presence, collectors + rollups (agent RSS ~14 MB),
  inventory identical to native tools (Debian/Ubuntu/Rocky/Alpine), live-feed CVE detection and disappearance after
  upgrade, security-only patch plan on Debian + Rocky via CLI, disk-threshold alert lifecycle via webhook, README
  quick start (host visible and scanned in ~100 s).

### Known limitations
- SQLite only (PostgreSQL planned); RHEL/Fedora/SUSE have no vulnerability source yet.
- The UI listener is plain HTTP by default — run it behind an HTTPS reverse proxy.
- Turkish UI translation is partial.

### Added
- Agent protocol with a closed, strictly validated action set (no remote shell).
- Internal CA, one-time enrolment tokens with CA fingerprint pinning, mTLS agent gateway, certificate revocation and renewal.
- SQLite store with embedded migrations, audit log, host presence (online/offline) tracking.
- `sentrix-server token create`, `sentrix-agent enroll|run`.
- Agent collectors: CPU (total/per-core/iowait/steal), load, memory/swap, disk usage + inodes, disk I/O, network, processes, systemd failed/watched units, Docker containers, pending reboot, TLS certificate expiry.
- Bounded on-disk agent buffer with replay; server ingestion with raw → 1 min → 1 h rollups and retention.
- dpkg, RPM (EVR) and apk version comparators with table tests.
- Linux acceptance test in CI.
- Web UI (server-rendered, HTMX, Tailwind, uPlot): first-run wizard with disclaimer, login with argon2id, optional TOTP, CSRF protection, roles (admin/operator/viewer), dashboard, hosts list with search/filters, host detail with live SSE charts, users and enrolment-token settings, audit log page, dark/light theme.
- Security headers (strict CSP), login rate limiting, secrets encryption key, i18n message catalog (en, partial tr).
- `test/tools/fakefleet` demo fleet simulator.
- Inventory: OS/kernel/arch/virtualization, dpkg/rpm/apk packages (with source packages), apt/dnf/apk available updates with security classification, listening ports with owning process, container images; `sentrix-agent inventory --json`; host Inventory and Updates tabs.
- Vulnerability engine: Debian Security Tracker, OSV (Ubuntu, Alpine, Rocky, AlmaLinux — Alma advisories also applied to Rocky), CISA KEV, FIRST EPSS, NVD CVSS enrichment; local distro-aware matching (source packages, backports); explained 0–100 risk score; fleet/CVE/host/package views; accept-risk/ignore with expiry; feed status page and stale-data banner; `sentrix-server findings|sync-feeds`.
- Patch management: typed action executor (no remote shell), command long-poll with idempotent delivery, patch plans with mandatory dry run and approval, canary + max parallel rollout that stops on failure, reboot handling and post-patch verification, per-group policies with timezone-aware maintenance windows, host actions (refresh inventory, restart service, reboot), host settings (group, tags, watched services, TLS endpoints), REST API and `sentrix` CLI (`patch plan|apply|status|list|cancel`, `cve list`, `hosts`), `sentrix-server user|audit|api-token`.
- Alerts & notifications: threshold/state/vulnerability/patch rules with `for` durations, dedup, cooldown and flap suppression, resolve notifications; channels: SMTP email, Telegram, Discord, Slack, ntfy, generic webhook (HMAC-signed) with test-send and delivery log; scheduled daily/weekly digest; default rule set; secrets encrypted at rest.
- Pre-patch snapshot hooks: Proxmox VE (API token, QEMU and LXC, task polling, TLS fingerprint pinning) and generic HMAC-signed webhook; a failed required snapshot aborts that host before any package changes; hooks settings page with connection test; per-host Proxmox node/VM ID mapping.
- Hardening: TOTP 2FA enrolment with QR code, password change (revokes other sessions), scoped API token management UI, per-IP limits for bearer tokens and enrolment, 2 MiB request limit, Secure cookies derived from `base_url`, SECURITY.md and OWASP ASVS L1 self-review.
- Repository bootstrap: Go module, layout, Makefile, CI, lint config, licence, docs skeleton.

[Unreleased]: https://github.com/atillakurtulussimsek/Sentrix/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/atillakurtulussimsek/Sentrix/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/atillakurtulussimsek/Sentrix/releases/tag/v0.1.0
