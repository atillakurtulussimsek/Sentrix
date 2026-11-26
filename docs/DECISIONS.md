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
