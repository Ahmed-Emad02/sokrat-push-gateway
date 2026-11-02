#!/bin/bash
# Lightweight gateway health check for a systemd timer. Logs failures only.
set -euo pipefail

failures=()
check_unit() {
    systemctl is-active --quiet "$1" || failures+=("unit:$1")
}
check_http() {
    local expected=$1 url=$2 code
    code=$(curl -ksS -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || true)
    [ "$code" = "$expected" ] || failures+=("http:$url:$code")
}

check_unit frps.service
check_unit sokrat-tunnel-enrollment.service
check_http 200 http://127.0.0.1/health
check_http 200 https://127.0.0.1/control/
[ -f /var/lib/sokrat-gateway/tenant-runtime.json ] || failures+=("manifest:missing")
if docker inspect sokrat-gateway >/dev/null 2>&1; then
    state=$(docker inspect -f '{{.State.Health.Status}}' sokrat-gateway 2>/dev/null || echo unknown)
    [ "$state" = healthy ] || failures+=("container:gateway:$state")
fi
if docker inspect sokrat-gateway-db >/dev/null 2>&1; then
    state=$(docker inspect -f '{{.State.Health.Status}}' sokrat-gateway-db 2>/dev/null || echo unknown)
    [ "$state" = healthy ] || failures+=("container:db:$state")
fi

if [ ${#failures[@]} -gt 0 ]; then
    logger -t sokrat-monitor "FAIL ${failures[*]}"
    printf 'FAIL %s\n' "${failures[*]}" >&2
    exit 1
fi
exit 0
