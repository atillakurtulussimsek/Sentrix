# Sentrix — agent instructions

Self-hosted server health, CVE and patch management (Varkhe Digital, Apache-2.0).
Full product brief lives in `docs/BRIEF.md`.

## Session start
1. Read `docs/PROGRESS.md`, `docs/DECISIONS.md`, `git log --oneline -30`.
2. Continue from "Next up" in PROGRESS.md.

## Autonomy contract
- Work milestones M0→M10 in order without asking; only stop for the conditions in BRIEF §0.2
  (real infrastructure, paid credentials, irreversible actions outside the repo, contradictory brief).
- Record every non-trivial choice in `docs/DECISIONS.md`. Keep `docs/PROGRESS.md` current.
- Commit after each meaningful unit (Conventional Commits). Never force-push or rewrite history.
- A milestone is done only when: `make build test lint` pass, acceptance criteria verified by running it,
  PROGRESS + CHANGELOG updated, committed.

## Commands
- `make build` — builds all binaries into `bin/` and runs `go vet`.
- `make test` / `make race` — unit tests (race detector in CI).
- `make lint` — golangci-lint v2.
- `make run-server` / `make run-agent` — local dev using `deploy/dev/*.yaml`.
- `make e2e` — Docker-based multi-distro integration tests (needs Docker).
- `make css` — regenerate Tailwind stylesheet (needs Node.js); output is committed.

## Conventions
- Go, single module `github.com/atillakurtulussimsek/Sentrix`. `log/slog`, context everywhere, wrapped errors.
- camelCase identifiers; PascalCase types; UPPER_SNAKE_CASE only for env names.
- No arbitrary shell in the agent: actions are a fixed typed enum (`internal/protocol/actions.go`).
- Unit tests never hit live feeds; use `test/fixtures`.
- User-facing text goes through the catalog (`web/i18n/{tr,en}/*.json`, Turkish is the default); add every key to both languages (parity test).
- Every exported identifier in `internal/vuln` and `internal/patch` has a doc comment.
