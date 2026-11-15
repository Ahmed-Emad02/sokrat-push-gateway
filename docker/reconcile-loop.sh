#!/bin/bash
# Periodic reconciliation loop for Sokrat tenant provisioning.
set -euo pipefail

RECONCILE_SCRIPT="/usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py"
LOOP_LOCK="/run/sokrat-tenant-reconcile.lock"
INTERVAL="${SOKRAT_RECONCILE_INTERVAL:-60}"
RETRY_DELAY="${SOKRAT_RECONCILE_RETRY_SECONDS:-10}"
RETRIES=6
REPEAT_AFTER="${SOKRAT_RECONCILE_REPEAT_SECONDS:-1800}"

echo "[reconcile-loop] Starting periodic provisioning reconcile worker (interval: ${INTERVAL}s)..."
sleep 10
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

last_report=""
last_report_at=0

while true; do
    if [ -f "/etc/sokrat/gateway-provisioning.json" ]; then
        # One cycle at a time: a run that overruns the interval (an offline PBX
        # makes the worker wait on SSH) must not collide with the next tick.
        if flock -n 9; then
            attempt=1
            while :; do
                : > "$work/stderr"
                status=0
                /usr/bin/python3 "$RECONCILE_SCRIPT" --apply 9>&- 2>"$work/stderr" || status=$?
                [ -s "$work/stderr" ] && cat "$work/stderr" >&2
                [ "$status" -eq 0 ] && break
                # The PBX onboarding service takes the same worker lock while it
                # bootstraps a host. That is a busy system, not a broken cycle.
                if grep -q 'another provisioning run holds the lock' "$work/stderr"; then
                    if [ "$attempt" -lt "$RETRIES" ]; then
                        attempt=$((attempt + 1))
                        sleep "$RETRY_DELAY"
                        continue
                    fi
                    echo "[reconcile-loop] worker busy at $(date -u +%FT%TZ); deferring to the next tick"
                    break
                fi
                # A tenant that stays down keeps the exit status at 1 forever.
                # Report a persistent, unchanged failure once and again every
                # REPEAT_AFTER seconds instead of once a minute.
                now=$(date +%s)
                label="status=${status} attempt=${attempt}"
                if [ "$label" != "$last_report" ] || [ $((now - last_report_at)) -ge "$REPEAT_AFTER" ]; then
                    echo "[reconcile-loop] reconcile cycle returned ${status} at $(date -u +%FT%TZ) after ${attempt} attempt(s)"
                    last_report="$label"
                    last_report_at=$now
                fi
                break
            done
        else
            echo "[reconcile-loop] previous cycle still running at $(date -u +%FT%TZ); skipping this tick"
        fi 9>"$LOOP_LOCK"
    else
        echo "[reconcile-loop] /etc/sokrat/gateway-provisioning.json not yet created; waiting..."
    fi
    # The interval is measured from completion, never before the cycle runs.
    sleep "$INTERVAL"
done
