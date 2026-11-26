#!/bin/sh
# stop the service on removal (not on upgrade)
case "$1" in remove|0) systemctl stop sentrix-agent sentrix-server 2>/dev/null || true ;; esac
