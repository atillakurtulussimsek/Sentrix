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
