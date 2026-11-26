#!/bin/sh
mkdir -p /var/lib/sentrix-agent && chmod 0700 /var/lib/sentrix-agent
chmod 0600 /etc/sentrix/agent.yaml 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "sentrix-agent installed. Enrol with: sudo sentrix-agent --config /etc/sentrix/agent.yaml enroll --server URL --token TOKEN --ca-fingerprint FP && sudo systemctl enable --now sentrix-agent"
