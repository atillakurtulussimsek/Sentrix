[Türkçe](CONTRIBUTING.tr.md) · **English**

# Contributing to Sentrix

Thanks for your interest! Bug reports, docs fixes and pull requests are welcome.

## Development

```bash
make build test lint     # Go 1.26+, golangci-lint v2
make race                # race detector (CI runs it)
make run-server          # dev server: http://localhost:18080 (deploy/dev/server.yaml)
go run ./test/tools/fakefleet   # six simulated hosts for UI work
make css                 # rebuild Tailwind after template changes (Node.js)
```

Linux-only behaviour (collectors, package managers) is covered by fixture tests and by the acceptance scripts in
`test/acceptance/` that run in CI on real Linux and in distro containers.

## Guidelines

- Keep the agent's action set closed: new capabilities need a new typed action, strict parameter validation,
  and tests proving that malformed input is rejected before anything runs.
- Never compare package versions with string or semver logic — use `internal/vuln/version`.
- Unit tests must not hit live feeds; add small fixtures under `test/fixtures/`.
- Exported identifiers in `internal/vuln` and `internal/patch` need doc comments.
- Use Conventional Commits (`feat(agent): …`, `fix(server): …`). Record notable design decisions in
  `docs/DECISIONS.md`.
- UI strings live in the `web/i18n/tr` and `web/i18n/en` catalogs; add every new string to both languages.
- Security issues: see [SECURITY.md](SECURITY.md) — please report privately.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
