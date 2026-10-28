#!/bin/bash
set -euo pipefail

echo "[entrypoint] Initializing Sokrat Push Gateway environment..."

chown -R sokrat-push:sokrat-push /var/lib/sokrat-gateway
chmod 0700 /var/lib/sokrat-gateway

chown -R root:root /etc/sokrat
chmod 0755 /etc/sokrat
chmod 0700 /etc/sokrat/ssh

chown root:sokrat-push /var/lib/sokrat-tenant-provisioning
chmod 0750 /var/lib/sokrat-tenant-provisioning

mkdir -p /run/sokrat-tenant-onboarding /run/sokrat-tenant-provisioning /run/sokrat-turn
chown root:sokrat-push /run/sokrat-tenant-onboarding
chmod 0750 /run/sokrat-tenant-onboarding

mkdir -p /var/log/sokrat /var/log/supervisor
chown -R root:root /var/log/sokrat

if [ ! -f "/var/lib/sokrat-gateway/control.json" ]; then
    echo "[entrypoint] Initializing empty control store..."
    cat << 'EOF' > /var/lib/sokrat-gateway/control.json
{
  "schemaVersion": 2,
  "pbx": [],
  "extensions": [],
  "enrollmentTokens": [],
  "devices": [],
  "audit": []
}
EOF
    chown sokrat-push:sokrat-push /var/lib/sokrat-gateway/control.json
    chmod 0600 /var/lib/sokrat-gateway/control.json
fi

if [ ! -f "/var/lib/sokrat-gateway/tenant-runtime.json" ]; then
    echo '{"relays":{},"hookHashes":{}}' > /var/lib/sokrat-gateway/tenant-runtime.json
    chown sokrat-push:sokrat-push /var/lib/sokrat-gateway/tenant-runtime.json
    chmod 0600 /var/lib/sokrat-gateway/tenant-runtime.json
fi

if [ ! -f "/etc/turnserver.conf" ]; then
    TURN_SECRET=${TURN_SHARED_SECRET:-$(head -c 32 /dev/urandom | od -A n -v -t x1 | tr -d ' \n')}
    LISTEN_IP=${GATEWAY_LISTEN_IP:-127.0.0.1}
    RELAY_IP=${GATEWAY_PRIVATE_IP:-127.0.0.1}

    cat << EOF > /etc/turnserver.conf
listening-port=3478
listening-ip=${LISTEN_IP}
listening-ip=${RELAY_IP}
relay-ip=${RELAY_IP}
min-port=49160
max-port=49260
fingerprint
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=sokrat-gateway
server-name=sokrat-gateway
user-quota=12
total-quota=400
max-bps=256000
no-tls
no-dtls
no-tcp-relay
no-multicast-peers
no-cli
no-loopback-peers
log-file=syslog
simple-log
EOF
    chown root:turnserver /etc/turnserver.conf
    chmod 0640 /etc/turnserver.conf
fi

echo "[entrypoint] Environment verified. Starting supervisor..."
exec "$@"
