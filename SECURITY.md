# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately through
GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab).
Include the affected version, a description, and reproduction steps. We aim to acknowledge
reports within 3 working days and to publish a fix or mitigation within 30 days for high
severity issues. Credit is given unless you ask otherwise.

Supported versions: the latest minor release receives security fixes.

## Threat model (summary)

Sentrix can change software on many servers, so the design assumes the network, individual
agents and individual user accounts can be compromised, and limits the blast radius of each.

| Asset / boundary | Threat | Mitigation |
|---|---|---|
| Agent ↔ server channel | eavesdropping, impersonation | TLS 1.2+, mutual TLS with per-agent certificates from an internal CA; agents pin the CA by SHA-256 fingerprint at enrolment; agents verify the gateway by chain + `ServerAuth` EKU (agent certs are `ClientAuth`-only and can never impersonate the server) |
| Enrolment | rogue host joins the fleet | one-time, expiring tokens (only the SHA-256 is stored); failed attempts rate-limited per IP |
| Compromised server or UI account | arbitrary code execution on every host | **no remote shell**: agents accept only a closed set of typed actions (`refresh_inventory`, `scan`, `patch_packages`, `patch_security_only`, `patch_all`, `reboot`, `restart_service`) with strictly validated parameters (unknown JSON fields rejected; package and unit names matched against conservative patterns); the executor runs only allow-listed programs with argv (never a shell). Agents can be made read-only with `allow_patching: false`. |
| Compromised agent | attacking the server or other hosts | agents only reach `/agent/v1/*`; each request is bound to the agent's certificate and current serial (revocation); payload sizes are capped; agents never receive data about other hosts |
| Patch causing outage | broken production systems | auto-patching is **off by default**; every plan dry-runs first and needs explicit approval; canary rollout stops on the first failure; optional pre-patch snapshots (Proxmox/webhook) abort the host if the snapshot fails; maintenance windows for policies; full audit log |
| Web UI | session theft, CSRF, XSS, clickjacking | argon2id passwords, optional TOTP 2FA, server-side sessions (only hashes stored), `HttpOnly`+`SameSite=Lax`(+`Secure` on HTTPS) cookies, per-session CSRF tokens + Origin check, strict CSP (`script-src 'self'`, no inline script), `X-Frame-Options: DENY`, login rate limiting, roles (admin/operator/viewer) enforced server-side |
| API tokens | leaked automation credentials | scoped tokens (read/operate/admin, never above the owner's role), optional expiry, only SHA-256 stored, revocable, failed bearer attempts rate-limited |
| Secrets at rest | DB theft exposes channel tokens / Proxmox credentials / TOTP seeds | AES-256-GCM with a server key (`data_dir/secret.key` or `SENTRIX_SECRET_KEY`) — keep the key out of database backups |
| Vulnerability data | poisoned feed / privacy | feeds are fetched over HTTPS from the projects' official locations; matching happens locally, **no host data is sent to third parties** |
| Supply chain | malicious dependency | small dependency set (see `docs/DECISIONS.md`), static binaries, reproducible builds via GoReleaser, CI with race detector and linters |

### Out of scope / known limitations
- The agent runs as root (it has to install packages). Protect `/var/lib/sentrix-agent` (key material, mode 0600).
- The internal CA key lives in `data_dir/pki/ca.key`; anyone with it can mint agent certificates.
- Sentrix trusts the distributions' advisory data; a missing advisory means a missing finding.
- Feed downloads honour standard proxy environment variables; there is no feed signature verification beyond TLS.

See `docs/security-review.md` for the OWASP ASVS Level 1 self-review.
