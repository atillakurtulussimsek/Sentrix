#!/bin/sh
if ! getent passwd sentrix >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/sentrix --shell /usr/sbin/nologin sentrix 2>/dev/null || adduser --system --home /var/lib/sentrix sentrix 2>/dev/null || true
fi
mkdir -p /var/lib/sentrix && chown sentrix: /var/lib/sentrix 2>/dev/null || true && chmod 0700 /var/lib/sentrix
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "sentrix-server installed. Edit /etc/sentrix/server.yaml, then: sudo systemctl enable --now sentrix-server"
