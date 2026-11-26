# Security self-review — OWASP ASVS 4.0.3, Level 1

Date: 2026-11-27 · Version: v0.1.0 (pre-release) · Reviewer: project maintainers (self-assessment)

Legend: ✅ met · ⚠️ partially met / accepted risk · ➖ not applicable

## V1 Architecture (L1 items are informational)
- ✅ Trust boundaries documented in `SECURITY.md` (threat model) and `docs/architecture.md`.

## V2 Authentication
| ID | Requirement | Status | Notes |
|---|---|---|---|
| 2.1.1 | passwords ≥ 12 chars | ⚠️ | minimum is **10** (ASVS says ≥12 for L1 since 4.0; accepted for small teams, documented). Max 256. |
| 2.1.2 | ≥ 64 chars allowed | ✅ | up to 256 |
| 2.1.3–2.1.4 | no truncation, any Unicode | ✅ | whole password hashed |
| 2.1.5 | users can change password | ✅ | Settings → My account (requires current password, revokes other sessions) |
| 2.1.7 | breached-password check | ⚠️ | not implemented (would need an external service); recommended to enable 2FA |
| 2.1.9 | no composition rules | ✅ | |
| 2.2.1 | anti-automation | ✅ | 5 failures/15 min per username, 20/15 min per IP; same for TOTP; bearer and enrolment failures per IP |
| 2.2.3 | notify on credential change | ⚠️ | audit-logged; no email to the user (users have no email address) |
| 2.4.1 | salted, approved hash | ✅ | argon2id m=64 MiB, t=2, p=2, 16-byte salt |
| 2.5.x | recovery | ✅ | no insecure recovery questions; admins reset via `sentrix-server user reset-password` (clears 2FA, audit-logged) |
| 2.7/2.8 | OTP | ✅ | RFC 6238 TOTP (±1 step), secret sealed at rest, verified via code before enabling |
| 2.10 | service credentials | ✅ | agent mTLS certificates; API tokens hashed, scoped, expiring |

## V3 Session management
| ID | Status | Notes |
|---|---|---|
| 3.1.1 no tokens in URLs | ✅ | |
| 3.2.1 new token on login | ✅ | session rotated at login; pre-login cookie only carries the login CSRF token |
| 3.2.2 ≥ 64 bits entropy | ✅ | 256-bit random IDs, only SHA-256 stored |
| 3.3.1 logout invalidates | ✅ | server-side deletion |
| 3.3.2 idle/absolute timeout | ✅ | 12 h idle, 7 days absolute |
| 3.4.1–3.4.3 cookie attributes | ✅ | `HttpOnly`, `SameSite=Lax`, `Secure` whenever `base_url` is https (warning logged otherwise) |
| 3.7.1 re-auth for sensitive ops | ✅ | password needed to change password / disable 2FA; patch approval needs explicit confirmation |

## V4 Access control
| ID | Status | Notes |
|---|---|---|
| 4.1.1–4.1.3 server-side enforcement, least privilege | ✅ | chi route groups per role; tested (`TestRoleEnforcement`, `TestAPITokenScopes`) |
| 4.2.1 IDOR | ✅ | single-tenant; API tokens can only be deleted by their owner (admins: all) |
| 4.2.2 CSRF | ✅ | synchroniser token + Origin check; tested (`TestCSRF`) |
| 4.3.1 admin interfaces protected | ✅ | admin role + optional 2FA |

## V5 Validation, sanitisation and encoding
| ID | Status | Notes |
|---|---|---|
| 5.1.x input validation | ✅ | typed parsing; package/unit names, roles, scopes, cron expressions validated; agent commands strictly decoded (`DisallowUnknownFields`) |
| 5.2.x sanitisation / no eval | ✅ | no dynamic code; htmx `allowEval: false` |
| 5.3.x output encoding | ✅ | `html/template` contextual escaping everywhere |
| 5.3.4 SQL injection | ✅ | parameterised queries; the only concatenation uses internal constant table names |
| 5.3.8 OS command injection | ✅ | agent executes allow-listed programs with argv only; tested (`TestNoArbitraryExecution`) |
| 5.5 deserialisation | ✅ | JSON only, size-limited bodies (UI 2 MiB, agents 32 MiB, sample/package caps) |

## V6 Stored cryptography
- ✅ AES-256-GCM for secrets at rest (random nonce); ✅ crypto/rand for all tokens; ✅ no custom crypto
  primitives (CVSS calculator and TOTP use standard library HMAC/SHA).
- ⚠️ Key management is file-based (`secret.key`, `pki/ca.key`); documented in SECURITY.md.

## V7 Error handling and logging
- ✅ Generic error pages; internal errors logged server-side only.
- ✅ No secrets/passwords/tokens in logs (tokens are never logged; notification errors redact URLs).
- ✅ Audit log of authentication events, admin actions, plans, commands and results (append-only table).

## V8 Data protection
- ✅ `Cache-Control: no-store` on the page that shows a new API token; enrolment tokens shown once.
- ✅ Agents send only inventory/metrics; no host data leaves the server (feeds are downloaded).

## V9 Communication
- ✅ Agent gateway: TLS 1.2+ with mTLS. ⚠️ The UI listener is plain HTTP by default and must sit behind an
  HTTPS reverse proxy, or be configured with `tls_cert`/`tls_key` (documented in docs/install.md).
- ✅ Outbound connections (feeds, notifications, Proxmox) verify TLS; Proxmox supports certificate pinning;
  "skip verification" is an explicit, documented opt-in.

## V10 Malicious code
- ✅ No remote code loading; dependencies listed and justified in `docs/DECISIONS.md`.

## V11 Business logic
- ✅ Rate limits on login/2FA/enrolment/bearer; patch flow requires dry run → approval; automatic policies
  only inside maintenance windows, once per window, and only after a clean dry run.

## V12 Files and resources
- ➖ No user file uploads. Feed downloads are written to `data_dir/feeds` with fixed names.

## V13 API
- ✅ Same authorisation as the UI; JSON errors; CSRF-exempt only for bearer tokens (not ambient credentials).

## V14 Configuration
- ✅ Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
  COOP, HSTS when served over TLS. ✅ Static assets embedded; ✅ build reproducible; ✅ dependencies pinned in go.sum.

## Findings fixed during this review
1. Cookies were always `Secure`, which silently broke logins on plain-HTTP LAN installs → now derived from
   `base_url` with a startup warning.
2. API bearer-token failures and enrolment failures were not rate limited → per-IP limits added.
3. No global request size limit on the UI/API → 2 MiB `MaxBytesReader`.
4. New API tokens were passed through a flash cookie → now rendered once in the response with `no-store`.
5. Users without the admin role had no way to change their password or enable 2FA → "My account" page.

## Accepted risks
- 10-character minimum password (vs. 12) — recommend 2FA for admins.
- No breached-password lookup (would leak hashes/prefixes to a third party; offline lists are large).
- Plain-HTTP UI by default (expected to run behind a TLS-terminating proxy such as Dokploy/Traefik).
