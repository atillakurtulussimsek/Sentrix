[Türkçe](tr/configuration.md) · **English**

# Configuration reference

Both binaries read an optional YAML file (`--config FILE`, or `SENTRIX_CONFIG` / `SENTRIX_AGENT_CONFIG`)
and then apply `SENTRIX_*` environment variables, which win. Durations use Go syntax (`30s`, `5m`, `72h`).
Lists in environment variables are comma separated.

## Server (`sentrix-server`)

| YAML key | Environment | Default | Meaning |
|---|---|---|---|
| `data_dir` | `SENTRIX_DATA_DIR` | `./data` | database, `pki/` (internal CA), `secret.key`, `feeds/` cache |
| `listen` | `SENTRIX_LISTEN` | `:8080` | web UI and REST API |
| `tls_cert`, `tls_key` | `SENTRIX_TLS_CERT`, `SENTRIX_TLS_KEY` | – | serve the UI over HTTPS directly |
| `base_url` | `SENTRIX_BASE_URL` | `http://localhost:8080` | public UI URL (links in notifications, install script, cookie `Secure` flag) |
| `gateway_listen` | `SENTRIX_GATEWAY_LISTEN` | `:8443` | agent gateway (mutual TLS) |
| `gateway_url` | `SENTRIX_GATEWAY_URL` | `https://localhost:8443` | URL agents use (shown in install commands) |
| `gateway_hosts` | `SENTRIX_GATEWAY_HOSTS` | `localhost,127.0.0.1` | names/IPs in the gateway certificate |
| `agent_dir` | `SENTRIX_AGENT_DIR` | – (`/usr/share/sentrix/agents` in the image) | agent binaries served at `/download/` |
| `offline_after` | `SENTRIX_OFFLINE_AFTER` | `60s` | host considered offline after no contact |
| `heartbeat_interval` | `SENTRIX_HEARTBEAT_INTERVAL` | `15s` | told to agents |
| `agent_cert_validity` | `SENTRIX_AGENT_CERT_VALIDITY` | `8760h` | agents renew automatically 30 days before expiry |
| `retention.raw` / `.minute` / `.hour` | `SENTRIX_RETENTION_RAW` / `_MINUTE` / `_HOUR` | `24h` / `168h` / `2160h` | metric retention per tier |
| `feeds.enabled` | `SENTRIX_FEEDS_ENABLED` | `true` | download vulnerability feeds |
| `feeds.interval` | `SENTRIX_FEEDS_INTERVAL` | `6h` | feed refresh interval |
| `feeds.stale_after` | `SENTRIX_FEEDS_STALE_AFTER` | `72h` | show the "data is stale" banner after this |
| `feeds.nvd_api_key` | `SENTRIX_NVD_API_KEY` | – | optional NVD key (faster CVSS enrichment) |
| `feeds.osv_base_url`, `debian_url`, `kev_url`, `epss_url`, `nvd_url` | `SENTRIX_OSV_BASE_URL`, … | official URLs | mirrors / air-gapped setups |
| `language` | `SENTRIX_LANGUAGE` | `tr` | default language: `tr` or `en`. Used for the UI until a user picks their own language (sidebar, sign-in page, *Account* settings), and always for notifications |
| `log_level` | `SENTRIX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `dev_insecure_cookies` | `SENTRIX_DEV_INSECURE_COOKIES` | `false` | never in production |
| – | `SENTRIX_SECRET_KEY` | generated `secret.key` | base64 32-byte key for secrets at rest |

### Commands

```
sentrix-server serve | token create | ca-fingerprint | hosts | findings | stats | sync-feeds
               user create|reset-password | api-token create | audit | channel create | rule create
               healthcheck | version
```

## Agent (`sentrix-agent`)

| YAML key | Environment | Default | Meaning |
|---|---|---|---|
| `state_dir` | `SENTRIX_STATE_DIR` | `/var/lib/sentrix-agent` | identity, key, certificate, metric buffer |
| `server_url` | `SENTRIX_SERVER_URL` | from enrolment | gateway URL |
| `hostname` | `SENTRIX_HOSTNAME` | OS hostname (or `--hostname` at enrolment) | reported hostname |
| `interval` | `SENTRIX_INTERVAL` | `10s` | metric collection interval |
| `send_interval` | `SENTRIX_SEND_INTERVAL` | `30s` | batch upload interval |
| `buffer_max_mb` | `SENTRIX_BUFFER_MAX_MB` | `50` | on-disk buffer cap while the server is unreachable |
| `inventory_interval` | `SENTRIX_INVENTORY_INTERVAL` | `6h` | full inventory (also after every patch/refresh) |
| `watch_services` | `SENTRIX_WATCH_SERVICES` | – | systemd units to watch (also set per host in the UI) |
| `tls_endpoints` | `SENTRIX_TLS_ENDPOINTS` | – | `host:port` certificates to check (also per host in the UI) |
| `allow_patching` | `SENTRIX_ALLOW_PATCHING` | `true` | `false` = read-only agent (dry runs still work) |
| `proc_root` | `SENTRIX_PROC_ROOT` | `/proc` | for containers with the host's /proc mounted |
| `docker_socket` | `SENTRIX_DOCKER_SOCKET` | `/var/run/docker.sock` | container metrics if present |
| `log_level` | `SENTRIX_LOG_LEVEL` | `info` | |

Commands: `sentrix-agent enroll | run | inventory [--refresh] | version`.

## Language

- **UI:** each user picks their language (Turkish or English) from the picker in the sidebar, on the sign-in page
  or in *Account* settings; the choice is stored on the account. Until then the server default applies.
- **Server default:** `language: tr` / `SENTRIX_LANGUAGE=tr` (supported: `tr`, `en`; default `tr`).
  Notifications always use the server default language.
- **Command-line tools:** follow `SENTRIX_LANGUAGE` (default `tr`).
- **Agent installer:** `install.sh --lang tr|en`.
