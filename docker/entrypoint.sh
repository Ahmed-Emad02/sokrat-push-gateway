#!/bin/bash
set -euo pipefail

echo "[entrypoint] Initializing Sokrat Push Gateway environment..."

# Render the nginx site from the shipped template. Only the two port variables
# are substituted, so nginx's own $host/$remote_addr stay intact.
GATEWAY_HTTP_PORT="${GATEWAY_HTTP_PORT:-80}"
GATEWAY_WS_PORT="${GATEWAY_WS_PORT:-8088}"
export GATEWAY_HTTP_PORT GATEWAY_WS_PORT
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
envsubst '${GATEWAY_HTTP_PORT} ${GATEWAY_WS_PORT}' \
    < /etc/nginx/templates/sokrat.conf.template \
    > /etc/nginx/sites-available/sokrat
ln -sf /etc/nginx/sites-available/sokrat /etc/nginx/sites-enabled/sokrat
rm -f /etc/nginx/sites-enabled/default

chown -R sokrat-push:sokrat-push /var/lib/sokrat-gateway
chmod 0700 /var/lib/sokrat-gateway

# /etc/sokrat is a host bind mount. Never recurse here: per-file ownership such
# as the group-readable FCM service account must survive container restarts.
mkdir -p /etc/sokrat/ssh /etc/sokrat/turn
chown root:root /etc/sokrat
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

# Firebase is optional: when a service account is mounted, hand its path to the
# push gateway (supervisord children inherit this environment). Without it the
# gateway still serves and simply reports fcm:false on /health.
if [ -f /etc/sokrat/firebase-service-account.json ]; then
    export GOOGLE_APPLICATION_CREDENTIALS=/etc/sokrat/firebase-service-account.json
    echo "[entrypoint] FCM service account detected"
fi
export FCM_ENABLED="${FCM_ENABLED:-true}"
export APNS_ENABLED="${APNS_ENABLED:-false}"

exec "$@"
