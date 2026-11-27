[Türkçe](tr/notifications.md) · **English**

# Alerts & notifications

Notifications are sent in the server's default language: `language` / `SENTRIX_LANGUAGE` (default `tr`;
see [configuration](configuration.md#language)).

## Channels (*Settings → Notification channels*)

| Type | Needs | Notes |
|---|---|---|
| Generic webhook | URL, optional HMAC secret | JSON body `{event, severity, title, body, host, host_id, alert_id, rule, value, url, time}`; header `X-Sentrix-Signature: sha256=<hex HMAC of the body>` |
| Slack | incoming webhook URL | |
| Discord | channel webhook URL | |
| Telegram | bot token (from @BotFather), chat ID | |
| ntfy | server URL (default `https://ntfy.sh`), topic, optional access token | priority 5 for critical, 4 for warning |
| Email | SMTP host, port, STARTTLS/TLS, username/password, from, to | credentials are never sent without TLS |

Use **test** next to a channel to send a test message. Tokens, secrets and passwords are encrypted at rest.
Every delivery attempt is listed in the delivery log.

## Rules (*Alerts*)

Default rules are created on first start: agent offline (5 m), disk > 90 % (5 m), inodes > 90 %, failed
systemd units, watched service down, reboot pending for 7 days, new KEV vulnerability, new critical
vulnerability, patch plan result.

- **threshold** — metric (`disk.used_pct`, `mem.used_pct`, `cpu.usage`, `load.1`, `net.rx_bps`, …), optional
  exact label set (`mount=/`, `iface=eth0`), operator and value.
- **state** — `agent_offline`, `failed_units`, `service_down` (units listed under the host's *watched services*),
  `reboot_pending`.
- **vulnerability** — new findings that are KEV-listed and/or at least a given severity.
- **patch** — plan finished or failed.

Alert lifecycle: a condition must hold for **for** before the alert *fires* (one notification). While firing,
it is repeated only after the **cooldown**; when the condition clears a **resolved** message is sent. If the
same alert flaps back within the cooldown of its last notification, it fires silently.

## Digest

Set a cron schedule (e.g. `CRON_TZ=Europe/Istanbul 0 8 * * MON-FRI`) and channels to receive a
"what needs attention" summary: offline hosts, top risks, pending (security) updates, pending reboots.
