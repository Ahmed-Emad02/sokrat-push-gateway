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
            git clone https://github.com/Ahmed-Emad02/sokrat-push-gateway.git "$INSTALL_DIR"
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
        git clone https://github.com/Ahmed-Emad02/sokrat-push-gateway.git "$INSTALL_DIR"
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
        echo -e "${YELLOW}Generated random admin password: ${ADMIN_PASS}${NC}"
    fi
fi

# Generate scrypt hash matching src/control/auth.js
ADMIN_HASH=$(python3 - << PY
import os, base64, hashlib
pwd = """$ADMIN_PASS""".encode('utf-8')
salt = os.urandom(16)
derived = hashlib.scrypt(pwd, salt=salt, n=16384, r=8, p=1, maxmem=32*1024*1024, dklen=64)
b64_salt = base64.b64encode(salt).decode('ascii')
b64_hash = base64.b64encode(derived).decode('ascii')
print(f"scrypt\$16384\$8\$1\${b64_salt}\${b64_hash}")
PY
)

echo -e "${GREEN}[4/8] Creating Host Directories & Permissions...${NC}"

mkdir -p /etc/sokrat/ssh \
         /etc/sokrat/turn \
         /var/lib/sokrat-gateway/secrets \
         /var/lib/sokrat-tenant-provisioning \
         /var/log/sokrat

if ! id -u sokrat-push &>/dev/null; then
    groupadd -g 999 sokrat-push 2>/dev/null || true
    useradd -u 999 -g 999 -s /usr/sbin/nologin -d /opt/sokrat-push-gateway sokrat-push 2>/dev/null || true
fi

chown -R 999:999 /var/lib/sokrat-gateway
chmod 0700 /var/lib/sokrat-gateway

chown -R root:root /etc/sokrat
chmod 0755 /etc/sokrat
chmod 0700 /etc/sokrat/ssh

chown root:999 /var/lib/sokrat-tenant-provisioning
chmod 0750 /var/lib/sokrat-tenant-provisioning

echo -e "${GREEN}[5/8] Writing Production Environment & Configs...${NC}"

cat << EOF > /etc/sokrat/gateway-runtime.env
GATEWAY_PUBLIC_HOST=${PUBLIC_HOST}
GATEWAY_HTTP_PORT=${HTTP_PORT}
GATEWAY_WS_PORT=${WS_PORT}
GATEWAY_LISTEN_IP=${LISTEN_IP}
GATEWAY_PRIVATE_IP=${PRIVATE_IP}
EOF
chmod 0600 /etc/sokrat/gateway-runtime.env

cat << EOF > /etc/sokrat/gateway-control.env
CONTROL_DATA_FILE=/var/lib/sokrat-gateway/control.json
CONTROL_MAX_ENABLED_PBX=10
CONTROL_ADMIN_PASSWORD_HASH=${ADMIN_HASH}
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
  "runtime": {
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
GATEWAY_LISTEN_IP=${LISTEN_IP}
GATEWAY_PRIVATE_IP=${PRIVATE_IP}
EOF
chmod 0600 .env

echo -e "${GREEN}[6/8] Opening Host Firewall Ports...${NC}"

# The container uses host networking, so the host firewall is authoritative.
# Tenant relay ports (3500-3654) are opened per-PBX by the local adapter.
if command -v ufw > /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${HTTP_PORT}/tcp" > /dev/null
    ufw allow "${WS_PORT}/tcp" > /dev/null
    ufw allow 3478/tcp > /dev/null
    ufw allow 3478/udp > /dev/null
    ufw allow 3500:3654/tcp > /dev/null
    ufw allow 3500:3654/udp > /dev/null
    echo -e "${GREEN}✓ UFW rules added for ${HTTP_PORT}, ${WS_PORT}, 3478 and 3500-3654.${NC}"
else
    echo -e "${YELLOW}⚠ UFW is not active; ensure your provider firewall allows ${HTTP_PORT}, ${WS_PORT}, 3478 and 3500-3654.${NC}"
fi

echo -e "${GREEN}[7/8] Building and Starting Container...${NC}"

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
echo -e "SIP WebSocket Ingress:   ${GREEN}ws://${PUBLIC_HOST}:${WS_PORT}/ws${NC}"
echo -e "CoTURN STUN/TURN:        ${GREEN}${PUBLIC_HOST}:3478 (UDP/TCP)${NC}"
echo
echo -e "${YELLOW}To access the private Admin Control Dashboard:${NC}"
echo -e "1. Create an SSH tunnel from your local machine:"
echo -e "   ${GREEN}ssh -L 9096:127.0.0.1:9096 root@${PUBLIC_HOST}${NC}"
echo -e "2. Open your web browser to:"
echo -e "   ${GREEN}http://localhost:9096/control/${NC}"
echo -e "3. Log in with your admin password."
echo
echo -e "Useful Commands:"
echo -e "  View container status:  ${BLUE}docker compose ps${NC}"
echo -e "  View combined logs:     ${BLUE}docker compose logs -f${NC}"
echo -e "  View app logs on host:  ${BLUE}tail -f /var/log/sokrat/*.log${NC}"
echo -e "${BLUE}===================================================================${NC}"
