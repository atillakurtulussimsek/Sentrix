[Türkçe](tr/architecture.md) · **English**

# Architecture

```
┌──────────────────── Sentrix server (one binary / container) ────────────────────┐
│ Web UI (HTMX, Tailwind, uPlot) · REST API · Agent gateway (mTLS, :8443)           │
│ Vuln engine (feed sync + local matcher) · Patch orchestrator · Policy scheduler   │
│ Alert engine + notifier · Audit log · SQLite (WAL)                                │
└────────────────────────────────▲────────────────────────────────────────────────┘
                                 │ outbound HTTPS + client certificate from every host
            ┌────────────────────┴────────────┐
            │ sentrix-agent (static binary)   │  collectors (/proc, statfs, systemd, Docker API)
            │ inventory (dpkg/rpm/apk, ports) │  on-disk buffer · long-poll commands
            │ typed action executor           │  (apt-get / dnf / apk / systemctl, argv only)
            └─────────────────────────────────┘
```

## Packages

| Package | Responsibility |
|---|---|
| `internal/protocol` | wire types; the closed `Action` set and its strict validation |
| `internal/pki` | internal CA, CSR signing, server-chain verification |
| `internal/agent` (+ `collect`, `inventory`, `executor`) | agent runtime, collectors, inventory parsers, executor |
| `internal/store` | SQLite persistence, embedded migrations, metric tiers (`MetricStore` interface) |
| `internal/vuln` (+ `version`) | feed parsers, distro version comparators, matcher, risk score |
| `internal/patch` | maintenance windows, canary scheduling, policy decisions, snapshot hooks |
| `internal/notify` | channel senders, rule configuration, alert state transitions |
| `internal/auth` | argon2id, TOTP, AES-GCM secret box, rate limiter |
| `internal/server` | HTTP handlers, orchestration loops, jobs |
| `web` | templates, static assets, i18n catalogs (embedded) |

## Data flow

1. **Enrolment** — the agent fetches the CA, checks its SHA-256 against the fingerprint given with the token,
   sends a CSR + one-time token, receives a client certificate (CN = host ID). The token is consumed atomically.
2. **Telemetry** — every 10 s the agent samples metrics into memory; every 30 s it writes a gzip batch to its disk
   buffer and drains the buffer to the server (oldest first, deleted only on success). State (processes, units,
   containers, reboot) every 30 s; inventory at start, every 6 h, and after patches.
3. **Storage** — raw samples (24 h) are rolled up every minute into 1-min (7 d) and 1-h (90 d) tiers by a
   watermark job that re-aggregates a small overlap so late (buffered) data is included.
4. **Vulnerabilities** — feeds for the distributions present in the fleet are downloaded (ETag-aware) and
   normalised into `vuln_affected(ecosystem, package, vuln, fixed)`. After every inventory and feed sync, each
   host's packages are matched with the distro's comparator; findings are stored with an explained risk score.
5. **Patching** — a plan is a row per host in a state machine (`pending → dry_run → dry_ok → snapshot →
   patching → rebooting → verifying → done/failed`) advanced by one orchestrator loop. Commands are queued in
   the database and delivered through the agent's long-poll; results are idempotent (command IDs).
6. **Alerts** — rules are evaluated every 15 s (thresholds, state) or on events (new findings, plan results);
   alert instances move `pending → firing → resolved` with `for`, cooldown and flap suppression.

## Design decisions

See [DECISIONS.md](DECISIONS.md) for the ADR log (transport, storage, feeds, matching semantics, UI build).
