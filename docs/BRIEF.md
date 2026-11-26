# Project brief (condensed copy of the owner's original brief)

Sentrix (by Varkhe Digital) — self-hosted server health, CVE and patch management. Apache-2.0.

## Operating mode (§0)
- Autonomous. Ask only on stop conditions: touching real infrastructure, needing paid credentials/accounts,
  irreversible actions outside the repo (publishing releases, remote deletes, repo settings), or an
  architecture-changing contradiction in the brief.
- Never stop at a plan. Milestones in order; DoD per milestone: `make build` + `go vet` clean, tests pass,
  `golangci-lint run` clean, acceptance criteria verified by running, PROGRESS/CHANGELOG updated, committed.
- Conventional commits; never force-push. Debug failures (3 genuinely different attempts), else record in
  PROGRESS "Blocked", work around, move on.
- Files: `docs/PROGRESS.md`, `docs/DECISIONS.md`, `CHANGELOG.md`, `CLAUDE.md`.

## Vision (§1)
Monitor health/resources; inventory packages/kernel/OS/services/ports/containers; detect CVEs prioritised by
real risk; tell what to patch & notify; apply patches on command or by policy in maintenance windows. 5–200 servers.

## Principles (§2)
- Safe by default: auto-patch OFF, every patch logged, dry-run always available.
- No arbitrary remote shell: fixed typed actions (`refresh_inventory`, `scan`, `patch_packages{list}`,
  `patch_security_only`, `reboot`, `restart_service{name}`). Must be tested.
- Outbound-only agents. Agent static binary, <30 MB RSS, <1% CPU idle.
- Offline-ish: keep working on last synced feeds and say so.
- Honest data: never show "fixed" unless installed version verified ≥ distro fixed version.

## Stack (§3)
Go; chi + server-rendered HTML + HTMX (+Alpine where needed); Tailwind compiled, embedded assets; uPlot + SSE.
SQLite (modernc, WAL) default, Postgres optional via same interface; embedded migrations.
Metrics rollups: raw 10s/24h → 1m/7d → 1h/90d, configurable, behind an interface.
Agent↔server: HTTPS + mTLS (cert issued at enrolment via one-time token), JSON over HTTP/2, long-poll commands.
Agent: CGO_ENABLED=0, linux/amd64+arm64, systemd. Packaging: Docker image, static binaries, install.sh,
nfpm deb/rpm, GoReleaser. Makefile, golangci-lint, GitHub Actions (lint, test, build, race).

## Features (§5)
5.1 Collectors: CPU (total, per-core, steal, iowait), load, mem/swap, disk usage + inodes, disk I/O, net
throughput/errors, uptime, process count, top processes; systemd failed units + watched services; Docker
(containers, state, restarts, CPU/RAM, images); pending reboot; TLS expiry (nice-to-have). 10 s interval,
batched, bounded on-disk buffer.
5.2 Inventory: OS/distro/version/kernel/arch/virt; packages (dpkg/rpm/apk); available + security updates;
listening ports + processes; container images.
5.3 Vuln engine: OSV, Debian tracker, Ubuntu, RH-family OVAL/CSAF, NVD, CISA KEV, EPSS. Local matching.
Distro-aware version comparison (dpkg, rpm EVR, apk) with thorough table tests. Respect backports. Risk score
from CVSS, EPSS, KEV, fix availability, network exposure — show components. Views per server/CVE/package/fleet.
Accept-risk/ignore with reason + expiry.
5.4 Patch: plans (servers/tags → scope security/specific/all → dry-run → approve → execute). Policies per group
(`notify_only` default, `auto_security`, `auto_all`), maintenance windows (cron, TZ), max parallel, canary.
Pre-patch snapshot hooks (Proxmox VE API, generic webhook); abort host if required snapshot fails. Post-patch
re-inventory, reboot handling by policy, health-check. Full audit log. CLI: `sentrix patch plan`,
`sentrix patch apply --approve`, `sentrix cve list --severity high`.
5.5 Alerts: threshold, state (offline, service failed, reboot pending > N days), vulnerability (new KEV/critical),
patch result. Channels: SMTP, Telegram, Discord, Slack, ntfy, webhook; test-send. Daily/weekly digest. Dedup,
cooldown, resolve notifications.
5.6 UI: dashboard, hosts list (search/tags/groups/status/risk/pending), host detail (live charts, inventory,
vulns, updates, patch history, actions), vulnerabilities, patch plans, alerts, settings. Dark/light, responsive,
English with i18n catalog (Turkish next).
5.7 Auth: argon2id, secure sessions, CSRF, optional TOTP; roles admin/operator/viewer; scoped API tokens; per-agent
revocable mTLS certs; idempotent command IDs; secrets encrypted at rest; security headers; login rate limit;
admin audit log; SECURITY.md.

## Targets (§6)
Must: Debian 11/12/13, Ubuntu 22.04/24.04, Rocky/Alma 8/9. Should: Alpine, Fedora. Later: Windows, macOS,
image scanning, Kubernetes.

## Testing (§7)
Collector fixtures, comparator tables, matchers, risk, policies, windows. Docker multi-distro integration
(`test/`, `make e2e`). Golden feed-parser tests with committed fixtures. Race detector in CI.

## Docs & legal (§8)
README (quick start, features, roadmap, disclaimer), docs/ (install, config, architecture, agent security model,
policies, notifications, Proxmox, FAQ), LICENSE Apache-2.0 "Varkhe Digital", NOTICE, CONTRIBUTING,
CODE_OF_CONDUCT, issue/PR templates.

Disclaimer (README + first-run + before enabling auto-patch):
> Sentrix is provided "AS IS", without warranty of any kind. Patching can break systems. Always test patches in a
> non-production environment and keep verified backups/snapshots. You are solely responsible for actions
> performed on your servers.

## Milestones (§9)
- M0 Bootstrap — `make build test lint` succeed; CI green.
- M1 Protocol, store+migrations, health endpoint, enrolment (token → cert via internal CA), heartbeat —
  agent appears online; killed agent → offline after timeout.
- M2 Collectors, batching, disk buffer, ingestion, rollups/retention — metrics for every collector after 2 min;
  1-min rollups; idle RSS < 30 MB.
- M3 Auth (login, sessions, CSRF, roles), layout, dashboard, hosts, host detail with live SSE charts —
  viewer cannot reach admin pages (tested).
- M4 Inventory apt/dnf/apk, updates, ports, UI tabs — matches native tool output.
- M5 Feeds, matcher, comparators, risk, views, ignore/accept — known-vulnerable package reports expected CVE
  with correct fixed version; disappears after upgrade.
- M6 Typed executor (test rejects unknown/raw actions), plans, dry-run, approval, policies, windows, canary,
  reboot, verify, audit, CLI — E2E security-only plan on two hosts; auto policy outside window does nothing.
- M7 Rules, channels, digest, dedup/cooldown, test-send — disk threshold → one alert in cooldown → resolve.
- M8 Proxmox snapshot (mock httptest) + webhook hook — snapshot before patch; abort host on failure.
- M9 2FA, API tokens, secret encryption, rate limit, headers, SECURITY.md, i18n, empty states, error pages,
  first-run wizard, theme — `docs/security-review.md` vs OWASP ASVS L1.
- M10 Dockerfile, compose, install.sh, systemd, nfpm, GoReleaser, docs, screenshots — tag v0.1.0 locally
  (do not publish).

## Quality (§10)
Idiomatic Go, slog, graceful shutdown, no panics in long-running paths, no secrets in logs, config file + env,
documented exports in vuln/patch, justify each dependency in DECISIONS.md.
