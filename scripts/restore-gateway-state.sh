#!/bin/bash
# Validate or restore a gateway state backup created by
# backup-gateway-state.sh. Apply requires an explicit confirmation variable.
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "Root is required" >&2
    exit 1
fi

mode=${1:---check}
backup=${2:?usage: restore-gateway-state.sh --check|--apply BACKUP_DIR}
[ -d "$backup" ] || { echo "Backup directory not found: $backup" >&2; exit 2; }
for file in etc-sokrat.tar.gz runtime-state.tar.gz asterisk.sql.gz; do
    [ -s "$backup/$file" ] || { echo "Missing backup file: $file" >&2; exit 2; }
    gzip -t "$backup/$file"
done

if [ "$mode" = "--check" ]; then
    echo "Backup is valid: $backup"
    exit 0
fi
if [ "$mode" != "--apply" ] || [ "${SOKRAT_RESTORE_CONFIRM:-}" != "YES" ]; then
    echo "Refusing to restore. Set SOKRAT_RESTORE_CONFIRM=YES and use --apply." >&2
    exit 2
fi

# Preserve the current state before replacing it.
preserve="/var/backups/sokrat-gateway/pre-restore-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$preserve"
chmod 0700 "$preserve"
tar -czf "$preserve/etc-sokrat.tar.gz" /etc/sokrat
tar -czf "$preserve/runtime-state.tar.gz" /var/lib/sokrat-gateway /var/lib/sokrat-tenant-provisioning/runtime-state
[ -f /opt/sokrat-push-gateway/.env ] && cp -a /opt/sokrat-push-gateway/.env "$preserve/gateway.env"

docker stop sokrat-gateway >/dev/null 2>&1 || true
tar -xzf "$backup/etc-sokrat.tar.gz" -C /
tar -xzf "$backup/runtime-state.tar.gz" -C /
if [ -f "$backup/gateway.env" ]; then
    install -m 0600 "$backup/gateway.env" /opt/sokrat-push-gateway/.env
fi
if [ -f "$backup/letsencrypt.tar.gz" ]; then
    tar -xzf "$backup/letsencrypt.tar.gz" -C /
fi
docker start sokrat-gateway-db >/dev/null 2>&1 || true
for i in $(seq 1 30); do
    docker inspect -f '{{.State.Health.Status}}' sokrat-gateway-db 2>/dev/null | grep -qx healthy && break
    sleep 1
done
gzip -dc "$backup/asterisk.sql.gz" | docker exec -i sokrat-gateway-db sh -c \
    'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" asterisk'
docker start sokrat-gateway >/dev/null 2>&1 || true
for i in $(seq 1 30); do
    curl -fsS http://127.0.0.1/health >/dev/null 2>&1 && break
    sleep 1
done
echo "Restore completed from $backup; previous state preserved at $preserve"
