#!/bin/bash
# Create a root-only, timestamped gateway state backup.
# Never prints credentials or database contents.
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo "Root is required" >&2
    exit 1
fi
for command in docker tar gzip; do
    command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
dest="/var/backups/sokrat-gateway/state-$stamp"
mkdir -p "$dest"
chmod 0700 "$dest"

tar -czf "$dest/etc-sokrat.tar.gz" /etc/sokrat
tar -czf "$dest/runtime-state.tar.gz" \
    /var/lib/sokrat-gateway \
    /var/lib/sokrat-tenant-provisioning/runtime-state
if [ -f /opt/sokrat-push-gateway/.env ]; then
    cp -a /opt/sokrat-push-gateway/.env "$dest/gateway.env"
fi
if [ -d /etc/letsencrypt ]; then
    tar -czf "$dest/letsencrypt.tar.gz" /etc/letsencrypt
fi

if docker inspect sokrat-gateway-db >/dev/null 2>&1; then
    docker exec sokrat-gateway-db sh -c \
        'exec mariadb-dump --single-transaction --routines --triggers -uroot -p"$MARIADB_ROOT_PASSWORD" asterisk' \
        | gzip > "$dest/asterisk.sql.gz"
fi

for file in "$dest"/*.tar.gz "$dest"/*.sql.gz; do
    [ -f "$file" ] || continue
    gzip -t "$file"
done
chmod 0600 "$dest"/*
echo "$dest"
