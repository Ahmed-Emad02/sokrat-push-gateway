#!/bin/bash
# Periodic reconciliation loop for Sokrat tenant provisioning
set -euo pipefail

RECONCILE_SCRIPT="/usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py"

echo "[reconcile-loop] Starting periodic provisioning reconcile worker (interval: 60s)..."
sleep 10

while true; do
    if [ -f "/etc/sokrat/gateway-provisioning.json" ]; then
        /usr/bin/python3 "$RECONCILE_SCRIPT" --apply || {
            echo "[reconcile-loop] WARNING: reconcile cycle returned non-zero status"
        }
    else
        echo "[reconcile-loop] /etc/sokrat/gateway-provisioning.json not yet created; waiting..."
    fi
    sleep 60
done
