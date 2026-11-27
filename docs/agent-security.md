[Türkçe](tr/agent-security.md) · **English**

# Agent actions & security model

## The core property: no remote shell

The server can only ask an agent to perform one of these actions:

| Action | Parameters | What runs on the host |
|---|---|---|
| `refresh_inventory`, `scan` | none | inventory collection (+ metadata refresh), upload |
| `patch_security_only` | none | apt: `apt-get install --only-upgrade <security packages>`; dnf: `dnf -y upgrade --security`; (apk: resolved server-side) |
| `patch_packages` | `{"packages": [...]}` (1–500 names) | `apt-get install --only-upgrade …` / `dnf -y upgrade -- …` / `apk upgrade …` |
| `patch_all` | none | `apt-get upgrade --with-new-pkgs` / `dnf -y upgrade` / `apk upgrade` |
| `reboot` | `{"delay_seconds": 0..3600}` | `systemctl reboot` / `shutdown -r +N` |
| `restart_service` | `{"name": "unit"}` | `systemctl restart -- <unit>` |

Guarantees (enforced in `internal/protocol/actions.go` and `internal/agent/executor`, tested by
`TestValidateRejectsUnknownAndRaw`, `TestNoArbitraryExecution`, `TestOnlyAllowedProgramsAndArgvSeparation`):

- Unknown actions are rejected before anything runs. There is no action taking a command string.
- Parameters are decoded strictly (unknown JSON fields → rejected).
- Package names must match `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`, unit names `^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,127}$`
  — they can never start with `-` (no option injection) and contain no shell metacharacters.
- The executor only starts `apt-get`, `dnf`, `yum`, `apk`, `systemctl`, `shutdown`, always with an argv
  array (never through a shell), a fixed `PATH` and `LC_ALL=C`.
- Every action except inventory supports **dry run**; `allow_patching: false` makes an agent refuse all
  changing actions while still answering dry runs.
- Command IDs make delivery idempotent: an agent never runs the same command twice (results of the last 200
  commands are kept in `state_dir/commands.json`).

## Identity and transport

- One-time enrolment tokens; the server stores only their SHA-256 and consumes them in a transaction.
- The agent pins the server CA by fingerprint, then holds a client certificate (ECDSA P-256, 1 year, auto-renewed).
- The server rejects certificates whose serial no longer matches the host record (revocation is immediate).
- Agents only connect outbound; no port is opened on monitored hosts.

## What the agent sends

Metrics, process names and users, systemd unit states, container names/images, installed packages and
versions, pending updates, listening ports with process names, OS/kernel information. No file contents,
no command lines, no environment variables, no credentials.

## Why root?

Reading all package databases and `/proc/*/fd` (for port owners) and applying updates require root. Run the
agent with `allow_patching: false` if you only want monitoring and vulnerability data.

## Self-update

The server can offer a newer agent (`update_agent`, a typed action with a pinned version, architecture and
SHA-256). The agent downloads the manifest and binary over its mTLS connection and installs it only if:

- the manifest is signed with the **Varkhe Digital release key** (Ed25519; the public key is compiled into the
  agent, the private key exists only as a CI secret used when a release tag is built),
- version, architecture and digest match the command and the signed manifest, and the binary matches the digest,
- the version is newer than the running agent (no downgrades).

The binary is replaced atomically and the agent re-executes itself (same PID; the host is not rebooted). A
compromised Sentrix server can therefore *offer* an update but cannot make agents run code that was not
released and signed. Set `allow_self_update: false` to opt a host out; packages (.deb/.rpm) ship with it off
because apt/dnf manage the binary.
