[Türkçe](tr/patch-policies.md) · **English**

# Patch plans & policies

## Manual plans (default)

1. *Patch plans → New* (or *Plan security patch…* on a host, or `sentrix patch plan …`).
2. Choose hosts (or a group), a scope — **security only**, **specific packages**, or **all** — the reboot
   behaviour (`never`, `if_required`, `always`), canary count, parallelism and an optional snapshot hook.
3. Sentrix runs a **dry run** on every host and shows the exact package transitions (`from → to`).
4. An operator reviews and **approves** (explicit confirmation). Nothing changes before that.
5. Rollout: the first *canary* hosts are patched (with snapshot first if configured); the rest start only after
   every canary host finished successfully, at most *max parallel* at a time. **Any failure stops the rollout.**
6. Each host: patch → (reboot if the plan allows and the host needs it; wait until it is back with a new boot
   time) → verify (agent online, fresh inventory, watched services active) → done. CVE counts before/after
   are recorded; everything is in the audit trail.

## Policies (automatic patching)

Without a policy nothing is ever patched automatically (`notify_only`). A policy applies to one host group:

| Field | Meaning |
|---|---|
| mode | `notify_only`, `auto_security` (hosts with pending security updates), `auto_all` |
| window | cron expression with optional time zone, e.g. `CRON_TZ=Europe/Istanbul 0 3 * * SUN`, plus a duration in minutes |
| canary / max parallel | as for manual plans |
| reboot | `never`, `if_required`, `always` |
| snapshot hook | optional; "required" aborts a host whose snapshot fails |

Rules: a policy only starts a plan **inside** its window, **once per window occurrence**, never while its
previous plan is still active, and only for online hosts with applicable updates. The plan still runs a dry
run and is auto-approved (`policy:<name>`) only after the dry run completed. If the window closes, no new hosts
are started. Enabling an automatic mode requires accepting the disclaimer again.

## Reboots

`reboot required` is detected from `/var/run/reboot-required`, `needs-restarting -r`, and a running kernel older
than the newest installed one. The *Reboot pending for 7 days* alert rule reminds you of forgotten reboots.
