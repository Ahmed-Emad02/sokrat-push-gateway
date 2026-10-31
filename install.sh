#!/bin/bash
# ==============================================================================
# Sokrat Push Gateway & Multi-Tenant Provisioning Container Installer
# Universal Linux VPS Deployment Script (Ubuntu, Debian, Rocky, AlmaLinux)
#
# Usage:
#   bash install.sh
# or One-liner:
#   curl -fsSL https://raw.githubusercontent.com/Ahmed-Emad02/sokrat-push-gateway/main/install.sh | bash
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}===================================================================${NC}"
echo -e "${BLUE}  Sokrat Push Gateway & Tenant Provisioning Container Installer   ${NC}"
echo -e "${BLUE}===================================================================${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" >&2
    exit 1
fi

# This is a first-install path, not an upgrader: it creates credentials and
# changes host permissions. Never run those steps against an existing gateway.
if [ -e /etc/sokrat/gateway-control.env ] || [ -e /etc/sokrat/gateway-runtime.env ] ||
   [ -e /var/lib/sokrat-gateway/control.json ] || [ -e /etc/sokrat/tunnel-enrollment/config.json ]; then
    echo -e "${RED}Existing gateway configuration found. Use the documented container upgrade path; this installer will not overwrite it.${NC}" >&2
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
else
    echo -e "${RED}Cannot determine OS distribution.${NC}" >&2
    exit 1
fi

# If run directly as a one-liner without the repo present
INSTALL_DIR="/opt/sokrat-push-gateway"
if [ ! -f "Dockerfile" ]; then
    echo -e "${YELLOW}Deploying repository to ${INSTALL_DIR}...${NC}"
    mkdir -p "$INSTALL_DIR"
    if command -v git &> /dev/null; then
        if [ ! -d "${INSTALL_DIR}/.git" ]; then
            git clone --branch main https://github.com/Ahmed-Emad02/sokrat-push-gateway.git "$INSTALL_DIR"
        else
            git -C "$INSTALL_DIR" pull origin main
        fi
    else
        echo -e "${YELLOW}Installing git...${NC}"
        if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
            apt-get update && apt-get install -y git
        else
            yum install -y git
        fi
        git clone --branch main https://github.com/Ahmed-Emad02/sokrat-push-gateway.git "$INSTALL_DIR"
    fi
    cd "$INSTALL_DIR"
fi

echo -e "${GREEN}[1/8] Checking and installing dependencies (Docker, Compose, Python)...${NC}"

# Install Docker if missing
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker not found. Installing official Docker Engine...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
fi

# Ensure docker compose plugin exists
if ! docker compose version &> /dev/null; then
    echo -e "${YELLOW}Docker compose plugin not found. Installing...${NC}"
    if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        apt-get update && apt-get install -y docker-compose-plugin
    else
        yum install -y docker-compose-plugin || true
    fi
fi

# Ensure python3 is available on host for credential hashing
if ! command -v python3 &> /dev/null; then
    if [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        apt-get update && apt-get install -y python3
    else
        yum install -y python3
    fi
fi

# Ensure reverse tunnel binaries (frpc / frps) are installed on host
if ! command -v frpc &> /dev/null || ! command -v frps &> /dev/null; then
    echo -e "${YELLOW}Installing Sokrat Reverse Tunnel binaries (frpc / frps)...${NC}"
    ARCH="amd64"
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
    esac
    FRP_TMP="/tmp/frp_install"
    rm -rf "$FRP_TMP" && mkdir -p "$FRP_TMP"
    if curl -fsSL --connect-timeout 5 --max-time 30 -o "$FRP_TMP/frp.tar.gz" "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_${ARCH}.tar.gz" 2>/dev/null; then
        tar -xzf "$FRP_TMP/frp.tar.gz" -C "$FRP_TMP"
        install -m 0755 "$FRP_TMP"/frp_*/frpc /usr/local/bin/frpc
        install -m 0755 "$FRP_TMP"/frp_*/frps /usr/local/bin/frps
        rm -rf "$FRP_TMP"
        echo -e "${GREEN}✓ Installed frpc and frps $(/usr/local/bin/frpc -v 2>/dev/null).${NC}"
    else
        echo -e "${YELLOW}⚠ Could not download frp binaries; tunnel tools can be installed later.${NC}"
    fi
fi

echo -e "${GREEN}[2/8] Detecting Network Configuration...${NC}"

# Auto-detect Public IPv4
DETECTED_PUBLIC_IP=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || curl -4 -s --connect-timeout 5 https://icanhazip.com 2>/dev/null || echo "")
if [ -t 0 ]; then
    read -rp "Enter Gateway Public Host/IP [default: ${DETECTED_PUBLIC_IP}]: " INPUT_PUBLIC_IP
    PUBLIC_HOST=${INPUT_PUBLIC_IP:-$DETECTED_PUBLIC_IP}
else
    PUBLIC_HOST=${GATEWAY_PUBLIC_HOST:-$DETECTED_PUBLIC_IP}
fi
if [ -z "$PUBLIC_HOST" ]; then
    PUBLIC_HOST="127.0.0.1"
fi

# Auto-detect Tailscale IPv4
DETECTED_TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
if [ -t 0 ]; then
    read -rp "Enter Gateway Tailscale IP [default: ${DETECTED_TS_IP}]: " INPUT_TS_IP
    PRIVATE_IP=${INPUT_TS_IP:-$DETECTED_TS_IP}
else
    PRIVATE_IP=${GATEWAY_PRIVATE_IP:-$DETECTED_TS_IP}
fi

# Detect Primary Listening Interface IP
DETECTED_LISTEN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "0.0.0.0")
if [ -t 0 ]; then
    read -rp "Enter Gateway Interface Listening IP [default: ${DETECTED_LISTEN_IP}]: " INPUT_LISTEN_IP
    LISTEN_IP=${INPUT_LISTEN_IP:-$DETECTED_LISTEN_IP}
else
    LISTEN_IP=${GATEWAY_LISTEN_IP:-$DETECTED_LISTEN_IP}
fi

# HTTP/WS ports. Port 80 is frequently already taken on a general-purpose VPS,
# so detect a conflict and fall back to 8080 instead of failing to bind later.
port_in_use() {
    ss -ltnH "sport = :$1" 2>/dev/null | grep -q . && return 0
    return 1
}
if [ -n "${GATEWAY_HTTP_PORT:-}" ]; then
    HTTP_PORT=$GATEWAY_HTTP_PORT
elif port_in_use 80; then
    HTTP_PORT=8080
    echo -e "${YELLOW}Port 80 is already in use; using ${HTTP_PORT} for the gateway API.${NC}"
else
    HTTP_PORT=80
fi
WS_PORT=${GATEWAY_WS_PORT:-8088}
TLS_ENABLED=${GATEWAY_TLS_ENABLED:-auto}
HTTPS_PORT=${GATEWAY_HTTPS_PORT:-443}
WSS_PORT=${GATEWAY_WSS_PORT:-8089}
case "$TLS_ENABLED" in auto|true|false) ;; *) echo 'Invalid GATEWAY_TLS_ENABLED' >&2; exit 1 ;; esac
for port in "$HTTP_PORT" "$WS_PORT" "$HTTPS_PORT" "$WSS_PORT"; do
    if [[ ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || ((port > 65535)); then
        echo 'Invalid gateway port' >&2; exit 1
    fi
done
TLS_READY=false
if [ "$TLS_ENABLED" != false ]; then
    if [ -f /etc/sokrat/tls/fullchain.pem ] && [ -f /etc/sokrat/tls/privkey.pem ]; then
        TLS_READY=true
        if port_in_use "$HTTPS_PORT" || port_in_use "$WSS_PORT"; then
            echo 'HTTPS/WSS port occupied; use reviewed free ports' >&2; exit 1
        fi
    elif [ "$TLS_ENABLED" = true ] || [ -e /etc/sokrat/tls/fullchain.pem ] || [ -e /etc/sokrat/tls/privkey.pem ]; then
        echo 'Trusted TLS certificate/key pair required before installation' >&2; exit 1
    fi
fi
if port_in_use "$WS_PORT"; then
    echo -e "${RED}Port ${WS_PORT} (SIP WebSocket) is already in use. Set GATEWAY_WS_PORT to a free port.${NC}" >&2
    exit 1
fi
if [ "$HTTP_PORT" = "80" ]; then
    GATEWAY_URL="http://${PUBLIC_HOST}"
else
    GATEWAY_URL="http://${PUBLIC_HOST}:${HTTP_PORT}"
fi
echo -e "Gateway API will be served at ${GREEN}${GATEWAY_URL}${NC}"

echo -e "${GREEN}[3/8] Setting Up Control Dashboard Credentials...${NC}"

ADMIN_PASS="${CONTROL_ADMIN_PASSWORD:-}"
if [ -z "$ADMIN_PASS" ]; then
    if [ -t 0 ]; then
        while [ -z "$ADMIN_PASS" ]; do
            read -rsp "Enter Sokrat Gateway Dashboard Admin Password (min 8 chars): " ADMIN_PASS
            echo
            if [ ${#ADMIN_PASS} -lt 8 ]; then
                echo -e "${YELLOW}Password must be at least 8 characters long.${NC}"
                ADMIN_PASS=""
            fi
        done
    else
        # Non-interactive mode fallback: generate strong random password
        ADMIN_PASS=$(head -c 16 /dev/urandom | od -A n -v -t x1 | tr -d ' \n')
        echo -e "${YELLOW}Generated admin password will be saved root-only in /etc/sokrat/gateway-admin-initial-password.${NC}"
        SAVE_INITIAL_PASSWORD=true
    fi
fi

# Generate scrypt hash matching src/control/auth.js
if [ ${#ADMIN_PASS} -lt 8 ]; then echo 'Admin password must contain at least 8 characters' >&2; exit 1; fi
ADMIN_HASH=$(printf '%s' "$ADMIN_PASS" | python3 -c '
import os, base64, hashlib, sys
pwd = sys.stdin.buffer.read()
salt = os.urandom(16)
derived = hashlib.scrypt(pwd, salt=salt, n=16384, r=8, p=1, maxmem=32*1024*1024, dklen=64)
b64_salt = base64.b64encode(salt).decode("ascii")
b64_hash = base64.b64encode(derived).decode("ascii")
print("scrypt$16384$8$1$" + b64_salt + "$" + b64_hash)
')

echo -e "${GREEN}[4/8] Creating Host Directories & Permissions...${NC}"

mkdir -p /etc/sokrat/ssh \
         /etc/sokrat/turn \
         /var/lib/sokrat-gateway/secrets \
         /var/lib/sokrat-tenant-provisioning \
         /var/log/sokrat

# Dedicated service account. GIDs are chosen dynamically because low system
# GIDs such as 999 are frequently already taken (systemd-journal on Ubuntu).
if ! getent group sokrat-push > /dev/null; then
    groupadd --system sokrat-push
fi
SOKRAT_GID=$(getent group sokrat-push | cut -d: -f3)
if ! id -u sokrat-push > /dev/null 2>&1; then
    useradd --system -g "$SOKRAT_GID" -s /usr/sbin/nologin \
        -d /opt/sokrat-push-gateway sokrat-push
fi
SOKRAT_UID=$(id -u sokrat-push)
SOKRAT_GID=$(id -g sokrat-push)
export SOKRAT_UID SOKRAT_GID
echo -e "Service account sokrat-push: uid=${SOKRAT_UID} gid=${SOKRAT_GID}"

chown -R "${SOKRAT_UID}:${SOKRAT_GID}" /var/lib/sokrat-gateway
chmod 0700 /var/lib/sokrat-gateway

# Other Sokrat components may already own files under this shared directory.
chown root:root /etc/sokrat
chmod 0755 /etc/sokrat
chmod 0700 /etc/sokrat/ssh
if [ "${SAVE_INITIAL_PASSWORD:-false}" = true ]; then
    (umask 077; printf '%s\n' "$ADMIN_PASS" > /etc/sokrat/gateway-admin-initial-password)
fi
unset ADMIN_PASS
mkdir -p /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks
chown root:root /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks
chmod 0700 /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks

chown "root:${SOKRAT_GID}" /var/lib/sokrat-tenant-provisioning
chmod 0750 /var/lib/sokrat-tenant-provisioning

echo -e "${GREEN}[5/8] Writing Production Environment & Configs...${NC}"

cat << EOF > /etc/sokrat/gateway-runtime.env
GATEWAY_PUBLIC_HOST=${PUBLIC_HOST}
GATEWAY_HTTP_PORT=${HTTP_PORT}
GATEWAY_WS_PORT=${WS_PORT}
GATEWAY_TLS_ENABLED=${TLS_ENABLED}
GATEWAY_HTTPS_PORT=${HTTPS_PORT}
GATEWAY_WSS_PORT=${WSS_PORT}
GATEWAY_LISTEN_IP=${LISTEN_IP}
GATEWAY_PRIVATE_IP=${PRIVATE_IP}
EOF
chmod 0600 /etc/sokrat/gateway-runtime.env

cat << EOF > /etc/sokrat/gateway-control.env
CONTROL_DATA_FILE=/var/lib/sokrat-gateway/control.json
CONTROL_MAX_ENABLED_PBX=10
# Single-quoted: the scrypt hash contains $N$r$p segments that must not be
# expanded when the container sources this file. Base64 contains no quotes.
CONTROL_ADMIN_PASSWORD_HASH='${ADMIN_HASH}'
TENANT_RUNTIME_FILE=/var/lib/sokrat-gateway/tenant-runtime.json
EOF
chmod 0600 /etc/sokrat/gateway-control.env

cat << 'EOF' > /etc/sokrat/gateway-onboarding.json
{"enabled": true, "serviceUser": "sokrat-push"}
EOF
chmod 0600 /etc/sokrat/gateway-onboarding.json

if [ ! -f /etc/sokrat/gateway-provisioning.json ]; then
    cat << EOF > /etc/sokrat/gateway-provisioning.json
{
  "schemaVersion": 1,
  "lockDir": "/var/lib/sokrat-tenant-provisioning/locks",
  "runtime": {
    "trustedStateDir": "/var/lib/sokrat-tenant-provisioning/runtime-state",
    "syncScript": "/usr/local/lib/sokrat-tenant-provisioning/sync-tenant-runtime.py",
    "envFile": "/etc/sokrat/gateway-runtime.env",
    "gatewayUrl": "${GATEWAY_URL}",
    "serviceUser": "sokrat-push"
  },
  "firewallAdapter": "/usr/local/lib/sokrat-tenant-provisioning/provisioning-firewall-local.py",
  "pbx": {}
}
EOF
    chmod 0600 /etc/sokrat/gateway-provisioning.json
fi

if [ ! -f /etc/sokrat/gateway-provisioning-adapters.json ]; then
    cat << 'EOF' > /etc/sokrat/gateway-provisioning-adapters.json
{
  "pbx": {}
}
EOF
    chmod 0600 /etc/sokrat/gateway-provisioning-adapters.json
fi

cat << EOF > .env
GATEWAY_PUBLIC_HOST=${PUBLIC_HOST}
GATEWAY_HTTP_PORT=${HTTP_PORT}
GATEWAY_WS_PORT=${WS_PORT}
GATEWAY_TLS_ENABLED=${TLS_ENABLED}
GATEWAY_HTTPS_PORT=${HTTPS_PORT}
GATEWAY_WSS_PORT=${WSS_PORT}
GATEWAY_LISTEN_IP=${LISTEN_IP}
GATEWAY_PRIVATE_IP=${PRIVATE_IP}
SOKRAT_UID=${SOKRAT_UID}
SOKRAT_GID=${SOKRAT_GID}
EOF
chmod 0600 .env

echo -e "${GREEN}[6/8] Opening Host Firewall Ports...${NC}"

# The container uses host networking, so the host firewall is authoritative.
# Tenant relay ports (3500-3654) are opened per-PBX by the local adapter.
if command -v ufw > /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${HTTP_PORT}/tcp" > /dev/null
    ufw allow "${WS_PORT}/tcp" > /dev/null
    ufw allow 8002/tcp > /dev/null
    ufw allow 7000/tcp > /dev/null
    ufw allow 7443/tcp > /dev/null
    if [ "$TLS_READY" = true ]; then
        ufw allow "${HTTPS_PORT}/tcp" > /dev/null
        ufw allow "${WSS_PORT}/tcp" > /dev/null
    fi
    ufw allow 3478/tcp > /dev/null
    ufw allow 3478/udp > /dev/null
    ufw allow 3500:3654/tcp > /dev/null
    ufw allow 3500:3654/udp > /dev/null
    echo -e "${GREEN}✓ UFW rules added for ${HTTP_PORT}, ${WS_PORT}, 8002, 7000, 3478 and 3500-3654.${NC}"
else
    echo -e "${YELLOW}⚠ UFW is not active; ensure your provider firewall allows ${HTTP_PORT}, ${WS_PORT}, 8002, 7000, 3478 and 3500-3654.${NC}"
fi

echo -e "${GREEN}[7/8] Building and Starting Container...${NC}"

# Stage the host-only enrollment/firewall broker, then initialize the gateway
# pairing identity so the dashboard's pairing code works immediately after
# installation. This is still a first-install-only path: the guard above refuses
# to overwrite an existing enrollment.
bash scripts/install-reverse-tls-deps.sh
python3 scripts/install-tunnel-enrollment.py --apply
install -m 0755 scripts/deploy-public-certificate.sh /usr/local/bin/sokrat-public-certificate-deploy
install -m 0644 systemd/frps.service /etc/systemd/system/frps.service

if [ ! -x /usr/local/bin/frps ]; then
    echo -e "${RED}frps is required for PBX pairing but was not installed.${NC}" >&2
    exit 1
fi

# The enrollment service signs FRP connections with this host CA, and the FRP
# server passes its auth token to the enrollment plugin. Generate once.
install -d -m 0700 /etc/frp
if [ ! -s /etc/sokrat/gateway-tunnel.token ]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > /etc/sokrat/gateway-tunnel.token)
fi
FRP_TOKEN=$(tr -d '\n' < /etc/sokrat/gateway-tunnel.token)
if [ -f /etc/frp/frps.toml ]; then
    EXISTING_FRP_TOKEN=$(awk -F'"' '/^[[:space:]]*auth\.token[[:space:]]*=/ {print $2; exit}' /etc/frp/frps.toml)
    if [ -n "$EXISTING_FRP_TOKEN" ] && [ "$EXISTING_FRP_TOKEN" != "$FRP_TOKEN" ]; then
        echo -e "${RED}/etc/frp/frps.toml already uses a different auth token; align it with /etc/sokrat/gateway-tunnel.token before installing.${NC}" >&2
        exit 1
    fi
fi

if [ ! -f /etc/frp/frps.toml ]; then
    cat << EOF > /etc/frp/frps.toml
bindPort = 7000
auth.method = "token"
auth.token = "${FRP_TOKEN}"
proxyBindAddr = "127.0.0.1"
transport.tls.force = true

transport.tls.certFile = "/etc/sokrat/tunnel-enrollment/server.crt"
transport.tls.keyFile = "/etc/sokrat/tunnel-enrollment/server.key"

[[httpPlugins]]
name = "sokrat-tenant-enrollment"
addr = "127.0.0.1:7450"
path = "/handler"
ops = ["Login","NewProxy","Ping","NewWorkConn"]
EOF
    chmod 0600 /etc/frp/frps.toml
fi

if [ ! -f /etc/sokrat/tunnel-enrollment/config.json ]; then
    python3 /usr/local/lib/sokrat-tenant-provisioning/tunnel-enrollment.py --init \
        --host "${PUBLIC_HOST}" \
        --pool "${SOKRAT_MEDIA_POOL:-10.253.0.0/22}" \
        --gateway-url "https://${PUBLIC_HOST}:7443" \
        --port 7443 --control-port 8002 --plugin-port 7450 \
        --tunnel-port 7000 --runtime-port 9097 \
        --service-user sokrat-push \
        --trusted-state-dir /var/lib/sokrat-tenant-provisioning/runtime-state
fi

systemctl daemon-reload
systemctl enable sokrat-tunnel-enrollment.service frps.service > /dev/null
systemctl restart sokrat-tunnel-enrollment.service
systemctl restart frps.service
for unit in sokrat-tunnel-enrollment.service frps.service; do
    if ! systemctl is-active --quiet "$unit"; then
        echo -e "${RED}${unit} failed to start; PBX pairing is not ready.${NC}" >&2
        journalctl -u "$unit" -n 20 --no-pager >&2 || true
        exit 1
    fi
done

docker compose build
docker compose up -d

echo -e "${GREEN}[8/8] Verifying System Health...${NC}"

HEALTH_OK=false
for i in {1..15}; do
    if curl -s -f "http://127.0.0.1:${HTTP_PORT}/health" > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    echo -n "."
    sleep 2
done
echo

if [ "$HEALTH_OK" = true ]; then
    echo -e "${GREEN}✓ Push Gateway is healthy at ${GATEWAY_URL}/health${NC}"
else
    echo -e "${YELLOW}⚠ Push Gateway did not respond immediately. Check logs with: docker logs sokrat-gateway${NC}"
fi

echo
echo -e "${BLUE}===================================================================${NC}"
echo -e "${GREEN}  Installation Complete! Sokrat Gateway Container is Running.      ${NC}"
echo -e "${BLUE}===================================================================${NC}"
echo -e "Public Web Ingress:      ${GREEN}${GATEWAY_URL}${NC}"
echo -e "Control Dashboard:       ${GREEN}http://${PUBLIC_HOST}:8002/control/${NC}"
echo -e "SIP WebSocket Ingress:   ${GREEN}ws://${PUBLIC_HOST}:${WS_PORT}/ws${NC}"
if [ "$TLS_READY" = true ]; then
    echo "Employee HTTPS: https://${PUBLIC_HOST}:${HTTPS_PORT}"
    echo "Employee WSS: wss://${PUBLIC_HOST}:${WSS_PORT}/ws"
else
    echo 'Employee public onboarding NOT READY: configure trusted HTTPS/WSS certificates and renewal first.'
fi
echo 'Secure PBX pairing is READY: open the Control Dashboard and use "Show Pairing Code", then paste it in Sokrat VOIP → Settings → Sokrat Gateway.'
echo -e "Reverse Tunnel Ingress:  ${GREEN}${PUBLIC_HOST}:7000 (TLS)${NC}"
echo -e "CoTURN STUN/TURN:        ${GREEN}${PUBLIC_HOST}:3478 (UDP/TCP)${NC}"
echo
echo -e "Access the Control Dashboard directly in your browser:"
echo -e "   ${GREEN}http://${PUBLIC_HOST}:8002/control/${NC}"
echo -e "Log in with your admin password."
echo
echo -e "Useful Commands:"
echo -e "  View container status:  ${BLUE}docker compose ps${NC}"
echo -e "  View combined logs:     ${BLUE}docker compose logs -f${NC}"
echo -e "  View app logs on host:  ${BLUE}tail -f /var/log/sokrat/*.log${NC}"
echo -e "${BLUE}===================================================================${NC}"
