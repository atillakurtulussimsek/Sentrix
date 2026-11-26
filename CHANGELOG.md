# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Repository bootstrap: Go module, layout, Makefile, CI, lint config, licence, docs skeleton.
