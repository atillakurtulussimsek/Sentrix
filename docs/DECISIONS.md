# Architecture decision log

Short ADR entries: date, decision, alternatives, reason.

## 2026-11-27 — Module path
- **Decision:** `github.com/atillakurtulussimsek/Sentrix` (matches the git remote exactly).
- **Alternatives:** vanity path, lowercase path.
- **Reason:** `go install` from the repo works without redirects.

## 2026-11-27 — Docker unavailable on the dev machine
- **Decision:** Multi-distro e2e suite is written (`test/e2e`) but cannot be executed locally;
  acceptance checks that need distro containers are covered by fixture-based tests of the native
  tool outputs plus local end-to-end runs of server+agent on the host.
- **Reason:** No Docker binary on the build host; CI or the owner can run `make e2e`.

## 2026-11-27 — Dependencies (core)
- `github.com/go-chi/chi/v5` — router mandated by the brief; tiny, stdlib-compatible.
- `modernc.org/sqlite` — pure-Go SQLite, keeps `CGO_ENABLED=0` single binary.
- `gopkg.in/yaml.v3` — config files; de-facto standard YAML library.
- `golang.org/x/crypto` — argon2id (and later bcrypt-free password hashing).
- `github.com/google/uuid` — host/command/plan IDs.

## 2026-11-27 — Own migration runner instead of goose
- **Decision:** ~60-line embedded migration runner (`internal/store/migrate.go`), numbered `.sql` files.
- **Alternatives:** pressly/goose, golang-migrate.
- **Reason:** we only need forward migrations; avoids a dependency with many transitive drivers.

## 2026-11-27 — Storage abstraction
- **Decision:** a single `store.DB` type with portable SQL (`?` placeholders, `ON CONFLICT`, no SQLite-only
  functions in queries beyond migrations). PostgreSQL is *not* implemented in v0.1.0; adding it means a
  placeholder rebinder + a dialect-specific migration set.
- **Reason:** delivering every milestone mattered more than a second backend nobody can test yet.
  Single-connection SQLite (WAL) easily handles 200 hosts × ~150 series / 10 s.

## 2026-11-27 — Agent gateway & trust bootstrap
- **Decision:** two listeners. UI/API on `:8080` (plain HTTP behind a reverse proxy, or own TLS), agent
  gateway on `:8443` with TLS terminated by Sentrix itself (`VerifyClientCertIfGiven`, internal ECDSA P-256 CA).
  Agents pin the CA by SHA-256 fingerprint given out-of-band with the token (kubeadm-style).
  Agents verify the server by chain + `ServerAuth` EKU (no hostname check, works via NAT/IP); agent certs carry
  only `ClientAuth`, so an agent can never impersonate the gateway. Revocation = per-host current serial check.
- **Alternatives:** single listener with mTLS behind a TLS-terminating proxy (breaks mTLS on Dokploy/Traefik
  unless TCP passthrough); public CA + bearer tokens.
- **Reason:** mTLS end-to-end even behind proxies that terminate HTTP TLS; zero external PKI.

## 2026-11-27 — Command delivery
- **Decision:** HTTP long-poll (`GET /agent/v1/commands`, up to 30 s) instead of WebSocket.
- **Reason:** works through every proxy, no extra dependency, latency is irrelevant for patching.

## 2026-11-27 — Linux verification in CI
- **Decision:** acceptance scripts (`test/acceptance/*.sh`) run in GitHub Actions on `ubuntu-latest`
  (real Linux, Docker available) because the development machine is macOS without a VM.
- **Reason:** brief §0.0.7 "verify, don't assume"; CI is the only Linux available.

## 2026-11-27 — Metrics schema
- **Decision:** `series(host, name, labels)` + `metrics_raw/1m/1h` (WITHOUT ROWID, PK series+ts).
  Rollups are watermark-driven with a 10-bucket overlap so late (buffer-replayed) data is re-aggregated.
- **Reason:** compact, idempotent, easily replaced by a TSDB behind `store.MetricStore`.

## 2026-11-27 — UI build pipeline
- **Decision:** Tailwind v4 CLI via a build-only `package.json`; compiled `web/static/app.css` is committed so
  `go build` needs no Node. htmx 2 and uPlot 1.6 are vendored into `web/static/vendor` (licences in NOTICE).
- **Reason:** single static binary, reproducible builds on machines without Node.

## 2026-11-27 — Sessions and CSRF
- **Decision:** server-side sessions (random 256-bit ID, only SHA-256 stored), 12 h idle / 7 d absolute,
  synchroniser CSRF token per session; double-submit cookie before login; Origin check as defence in depth.
  API calls with `Authorization: Bearer` tokens are CSRF-exempt (not ambient credentials). Strict CSP
  (`script-src 'self'`, no inline handlers).
- **Reason:** OWASP ASVS L1 V3/V4 basics with no extra dependencies.

## 2026-11-27 — Vulnerability data sources
- **Decision:** Debian → Debian Security Tracker JSON (includes open/unfixed issues and urgency). Ubuntu,
  Alpine, Rocky, AlmaLinux → OSV.dev ecosystem exports (`<eco>/all.zip`). Red Hat OVAL/CSAF is *not* parsed.
  Rocky's OSV export is incomplete (e.g. RLSA-2024:4312 / CVE-2024-6387 missing), so Rocky hosts are also
  matched against AlmaLinux advisories (same RHEL sources and NEVRs; `.alma.N` rebuild suffix stripped).
  NVD is queried per CVE (rate-limited) only for CVEs present in findings without a CVSS score.
- **Alternatives:** RHEL OVAL v2 (large XML, RHEL-only NEVRs), NVD bulk sync (slow without key).
- **Reason:** keyless, uniform JSON, distro-fixed versions (backport aware) for every v0.1 target.
- **Cost:** the Ubuntu export is large (~750k affected rows for 24.04 because of kernel flavours); matching
  loads only advisories for installed packages.

## 2026-11-27 — Matching semantics
- dpkg/apk: match by *source* package and source version (binNMU-safe); rpm: binary name, highest installed
  version for install-only packages (kernels). A finding disappears only when the installed version compares
  ≥ the distro fixed version with the distro's own comparator. Exceptions never delete findings; they are
  excluded from counts/risk and visible on demand.

## 2026-11-27 — Patch orchestration
- **Decision:** database-driven state machine advanced by a single orchestrator loop (idempotent, survives
  restarts). Every plan dry-runs first; approval is a separate step (policies auto-approve only after a clean
  dry run, inside their window). Any host failure stops the rollout. Security-only on apk is resolved server-side
  into `patch_packages` (apk has no security metadata). The agent executes only allow-listed programs with
  validated argv; `allow_patching: false` makes an agent read-only (dry runs still allowed).
- **Dependency:** `github.com/robfig/cron/v3` for maintenance-window cron parsing (CRON_TZ support).

## 2026-11-27 — Hardening choices (M9)
- `rsc.io/qr` (tiny, no transitive deps) renders the TOTP enrolment QR code as an inline PNG (`img-src data:`).
- Cookies are `Secure` whenever `base_url` is https; plain-HTTP installs keep working but log a warning.
- Per-IP limiter shared for login, bearer-token and enrolment failures; per-user limiter for password/TOTP.
- Password minimum is 10 characters (accepted deviation from ASVS 2.1.1, see docs/security-review.md).
