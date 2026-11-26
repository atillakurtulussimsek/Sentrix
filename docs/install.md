# Installation

## Server

### Docker / Docker Compose (recommended)

```bash
curl -fsSLO https://raw.githubusercontent.com/atillakurtulussimsek/Sentrix/main/docker-compose.yml
SENTRIX_HOST=sentrix.example.com docker compose up -d
```

- Data (SQLite database, internal CA, secret key, feed cache) lives in the `sentrix-data` volume (`/data`).
  **Back it up**, but keep `secret.key` and `pki/ca.key` away from untrusted storage.
- The image runs as an unprivileged user on a distroless base and has a built-in health check.
- The image also contains agent binaries for `linux/amd64` and `linux/arm64`, served at `/download/` for
  the `install.sh` one-liner, so hosts never need to reach GitHub.

### Dokploy / Traefik / other reverse proxies

- Route your HTTPS domain (e.g. `sentrix.example.com`) to container port **8080** (web UI/API) and set
  `SENTRIX_BASE_URL=https://sentrix.example.com`. Cookies become `Secure` automatically.
- Publish port **8443** directly (or as a TCP route / TLS passthrough). It must **not** be terminated by the
  proxy: agents authenticate with client certificates. Set `SENTRIX_GATEWAY_URL=https://sentrix.example.com:8443`.

### Packages (.deb / .rpm) and binaries

Release assets contain `sentrix-server` and `sentrix-agent` packages and plain binaries.

```bash
sudo apt install ./sentrix-server_0.1.0_linux_amd64.deb
sudoedit /etc/sentrix/server.yaml      # base_url, gateway_url, gateway_hosts
sudo systemctl enable --now sentrix-server
```

The server unit runs as the `sentrix` user with systemd sandboxing (`deploy/systemd/sentrix-server.service`).

### TLS for the UI without a proxy

Set `tls_cert` and `tls_key` in `server.yaml` (PEM files). The agent gateway always uses Sentrix's
internal CA.

### First run

Open the UI: the wizard creates the first admin and asks you to accept the disclaimer. Headless
alternative: `sentrix-server user create --username admin --role admin` (password from `SENTRIX_PASSWORD`
or stdin).

## Agent

### One-liner (recommended)

*Settings → Enrolment → Create token* shows a command like:

```bash
curl -fsSL https://sentrix.example.com/install.sh | sudo sh -s -- --token sxe_… --ca-fingerprint …
```

It downloads the agent from your server, writes `/etc/sentrix/agent.yaml`, enrols (one-time token +
CA fingerprint pinning) and installs a systemd unit. Options: `--hostname`, `--no-patching` (read-only agent),
`--server`, `--download-url`.

### Package

```bash
sudo apt install ./sentrix-agent_0.1.0_linux_amd64.deb      # or dnf install ./…rpm
sudo sentrix-agent --config /etc/sentrix/agent.yaml enroll --server https://sentrix.example.com:8443 --token sxe_… --ca-fingerprint …
sudo systemctl enable --now sentrix-agent
```

### Removing a host

*Host → Patches & actions → Danger zone*: **Revoke** locks the agent out immediately (its certificate
serial is rejected), **Delete** removes the host and its data. On the host: `systemctl disable --now
sentrix-agent && rm -rf /var/lib/sentrix-agent /etc/sentrix /usr/local/bin/sentrix-agent`.

## Upgrading

Pull the new image (`docker compose pull && docker compose up -d`) or install the new packages. Database
migrations run automatically at start. Agents are backwards compatible within 0.x minor versions.
