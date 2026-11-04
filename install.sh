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

PUBLIC_HOST_ARG=""
ACME_EMAIL="${GATEWAY_ACME_EMAIL:-}"
TLS_MODE="${GATEWAY_TLS_MODE:-existing}"
DB_MODE="${GATEWAY_DB_MODE:-bundled}"
CONTROL_PUBLIC="${GATEWAY_CONTROL_PUBLIC:-true}"
SECRETS_DIR="${GATEWAY_SECRETS_DIR:-/root/sokrat-gateway-secrets}"
TRANSPORT="${SOKRAT_TRANSPORT:-openvpn-frp}"
MEDIA_POOL="${SOKRAT_MEDIA_POOL:-10.253.0.0/22}"
FCM_FILE="${GATEWAY_FCM_FILE:-}"
SHOW_ADMIN_PASSWORD="${SHOW_ADMIN_PASSWORD:-false}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"

while [ $# -gt 0 ]; do
    case "$1" in
        --host) PUBLIC_HOST_ARG="${2:-}"; shift 2 ;;
        --email) ACME_EMAIL="${2:-}"; shift 2 ;;
        --tls) TLS_MODE="${2:-}"; shift 2 ;;
        --db) DB_MODE="${2:-}"; shift 2 ;;
        --control) CONTROL_PUBLIC="${2:-}"; shift 2 ;;
        --transport) TRANSPORT="${2:-}"; shift 2 ;;
        --media-pool) MEDIA_POOL="${2:-}"; shift 2 ;;
        --secrets-dir) SECRETS_DIR="${2:-}"; shift 2 ;;
        --fcm-file) FCM_FILE="${2:-}"; shift 2 ;;
        --show-admin-password) SHOW_ADMIN_PASSWORD=true; shift ;;
        --non-interactive) NON_INTERACTIVE=true; shift ;;
        -h|--help)
            echo "Usage: install.sh [--host IP] [--email EMAIL] [--tls ip|existing] [--db bundled] [--control public|private] [--transport openvpn-frp|legacy] [--media-pool CIDR] [--secrets-dir DIR] [--fcm-file PATH] [--admin-password-file FILE] [--show-admin-password] [--non-interactive]"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$TLS_MODE" in
    ip) export GATEWAY_TLS_ENABLED=true ;;
    existing|auto) : ;;
    none) export GATEWAY_TLS_ENABLED=false ;;
    *) echo "Invalid --tls mode: $TLS_MODE" >&2; exit 2 ;;
esac
case "$DB_MODE" in bundled) : ;; *) echo "Only --db bundled is supported by this installer" >&2; exit 2 ;; esac
case "$CONTROL_PUBLIC" in public) : ;; *) echo "Only --control public is supported by this installer" >&2; exit 2 ;; esac
case "$TRANSPORT" in
    openvpn-frp|legacy) ;;
    *) echo "Invalid --transport mode: $TRANSPORT (use openvpn-frp or legacy)" >&2; exit 2 ;;
esac
if [ -n "$PUBLIC_HOST_ARG" ]; then export GATEWAY_PUBLIC_HOST="$PUBLIC_HOST_ARG"; fi
if [ "$TLS_MODE" = "ip" ] && [ -z "$ACME_EMAIL" ]; then
    echo "TLS mode ip requires --email (ACME account email)" >&2
    exit 2
fi

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
if [ -t 0 ] && [ "$NON_INTERACTIVE" != true ]; then
    read -rp "Enter Gateway Public Host/IP [default: ${DETECTED_PUBLIC_IP}]: " INPUT_PUBLIC_IP
    PUBLIC_HOST=${INPUT_PUBLIC_IP:-$DETECTED_PUBLIC_IP}
else
    PUBLIC_HOST=${GATEWAY_PUBLIC_HOST:-$DETECTED_PUBLIC_IP}
fi
if [ -z "$PUBLIC_HOST" ]; then
    PUBLIC_HOST="127.0.0.1"
fi

# Legacy mode keeps the old provider/private-address behavior. The VPN-free
# path must never auto-detect or require a provider interface.
if [ "$TRANSPORT" = "legacy" ]; then
    DETECTED_TS_IP=$(ip -4 addr show tailscale0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "127.0.0.1")
    if [ -t 0 ] && [ "$NON_INTERACTIVE" != true ]; then
        read -rp "Enter Gateway Tailscale IP [default: ${DETECTED_TS_IP}]: " INPUT_TS_IP
        PRIVATE_IP=${INPUT_TS_IP:-$DETECTED_TS_IP}
    else
        PRIVATE_IP=${GATEWAY_PRIVATE_IP:-$DETECTED_TS_IP}
    fi
    # A public-IP-only gateway has no Tailscale private media address. Use the
    # public address for the media/TURN peer rather than loopback.
    if [ "$PRIVATE_IP" = "127.0.0.1" ] && [ "$PUBLIC_HOST" != "127.0.0.1" ]; then
        PRIVATE_IP="$PUBLIC_HOST"
    fi
else
    # Compatibility value for legacy single-PBX code paths. Per-PBX relays use
    # plan.gatewayIp from /etc/sokrat/media/<pbxId>/plan.json instead.
    PRIVATE_IP="$PUBLIC_HOST"
fi

# Detect Primary Listening Interface IP
DETECTED_LISTEN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "0.0.0.0")
if [ -t 0 ] && [ "$NON_INTERACTIVE" != true ]; then
    read -rp "Enter Gateway Interface Listening IP [default: ${DETECTED_LISTEN_IP}]: " INPUT_LISTEN_IP
    LISTEN_IP=${INPUT_LISTEN_IP:-$DETECTED_LISTEN_IP}
else
    LISTEN_IP=${GATEWAY_LISTEN_IP:-$DETECTED_LISTEN_IP}
fi

# The media allocator is security-sensitive: reject a public, oversized or
# ambiguous pool before it reaches enrollment or any systemd unit.
python3 - "$MEDIA_POOL" <<'PY'
import ipaddress
import sys
pool = ipaddress.ip_network(sys.argv[1], strict=True)
private = tuple(ipaddress.ip_network(cidr) for cidr in
                ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
if (pool.version != 4 or pool.prefixlen > 22
        or not any(pool.network_address in net and pool.broadcast_address in net
                   for net in private)):
    raise SystemExit('SOKRAT_MEDIA_POOL must be a private IPv4 /22 or larger')
PY

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
    elif [ "$TLS_MODE" = "ip" ]; then
        : # certificate is issued later, before the container starts
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
if [ -n "$ADMIN_PASSWORD_FILE" ]; then
    [ -r "$ADMIN_PASSWORD_FILE" ] || { echo "Cannot read admin password file: $ADMIN_PASSWORD_FILE" >&2; exit 1; }
    ADMIN_PASS=$(tr -d '\r\n' < "$ADMIN_PASSWORD_FILE")
fi
if [ -z "$ADMIN_PASS" ]; then
    if [ -t 0 ] && [ "$NON_INTERACTIVE" != true ]; then
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
PUSH_DIR=/var/lib/sokrat-gateway/push
install -d -m 0700 -o "${SOKRAT_UID}" -g "${SOKRAT_GID}" "$PUSH_DIR" "$PUSH_DIR/apns"

# Other Sokrat components may already own files under this shared directory.
chown root:root /etc/sokrat
chmod 0755 /etc/sokrat
chmod 0700 /etc/sokrat/ssh
if [ "${SAVE_INITIAL_PASSWORD:-false}" = true ]; then
    (umask 077; printf '%s\n' "$ADMIN_PASS" > /etc/sokrat/gateway-admin-initial-password)
fi
mkdir -p /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks
chown root:root /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks
chmod 0700 /var/lib/sokrat-tenant-provisioning/runtime-state /var/lib/sokrat-tenant-provisioning/locks

chown "root:${SOKRAT_GID}" /var/lib/sokrat-tenant-provisioning
chmod 0750 /var/lib/sokrat-tenant-provisioning

# Provider credentials are optional at install time. The control dashboard can
# install them later; keep them in the gateway service-owned credential store.
if [ -z "$FCM_FILE" ] && [ -f "$SECRETS_DIR/firebase-service-account.json" ]; then
    FCM_FILE="$SECRETS_DIR/firebase-service-account.json"
fi
if [ -n "$FCM_FILE" ]; then
    install -m 0600 -o "${SOKRAT_UID}" -g "${SOKRAT_GID}" "$FCM_FILE" "$PUSH_DIR/firebase-service-account.json"
    [ -n "${_FCM_TEMP:-}" ] && rm -f "$_FCM_TEMP"
    echo "FCM: service account installed in the dashboard-managed credential store"
fi

if [ "${APNS_ENABLED:-auto}" = true ] || [ -f "$SECRETS_DIR/apns-AuthKey.p8" ]; then
    for f in apns-AuthKey.p8 apns-key-id apns-team-id; do
        [ -f "$SECRETS_DIR/$f" ] || { echo "APNs credential set is incomplete: $SECRETS_DIR/$f is missing" >&2; exit 1; }
    done
    install -m 0600 -o "${SOKRAT_UID}" -g "${SOKRAT_GID}" \
        "$SECRETS_DIR/apns-AuthKey.p8" "$PUSH_DIR/apns/AuthKey.p8"
    python3 - "$PUSH_DIR/apns.json" "$SECRETS_DIR" <<'PY'
import json
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
source = pathlib.Path(sys.argv[2])
metadata = {
    "keyId": (source / "apns-key-id").read_text().strip(),
    "teamId": (source / "apns-team-id").read_text().strip(),
    "topic": (source / "apns-topic").read_text().strip() if (source / "apns-topic").exists() else "com.sokrat.voice.voip",
    "environment": (source / "apns-env").read_text().strip() if (source / "apns-env").exists() else "production",
}
target.write_text(json.dumps(metadata, indent=2) + "\n")
PY
    chown "${SOKRAT_UID}:${SOKRAT_GID}" "$PUSH_DIR/apns/AuthKey.p8" "$PUSH_DIR/apns.json"
    chmod 0600 "$PUSH_DIR/apns/AuthKey.p8" "$PUSH_DIR/apns.json"
fi

# Issue/reuse the IP-only certificate before the container starts.
if [ "$TLS_MODE" = "ip" ]; then
    bash scripts/install-ip-tls.sh "$PUBLIC_HOST" "$ACME_EMAIL" "${GATEWAY_ACME_STAGING:-false}"
    TLS_READY=true
fi

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
SOKRAT_TRANSPORT=${TRANSPORT}
GATEWAY_MEDIA_POOL=${MEDIA_POOL}
EOF
chmod 0600 /etc/sokrat/gateway-runtime.env

cat << EOF > /etc/sokrat/gateway-control.env
CONTROL_DATA_FILE=/var/lib/sokrat-gateway/control.json
CONTROL_MAX_ENABLED_PBX=10
# Single-quoted: the scrypt hash contains dollar-separated parameters that must not be
# expanded when the container sources this file. Base64 contains no quotes.
CONTROL_ADMIN_PASSWORD_HASH='${ADMIN_HASH}'
TENANT_RUNTIME_FILE=/var/lib/sokrat-gateway/tenant-runtime.json
# Server-side liveness watchdog: wake approved Android devices only when their
# heartbeat is older than three minutes. Set false to disable.
SOKRAT_HEARTBEAT_ENABLED=${SOKRAT_HEARTBEAT_ENABLED:-true}
SOKRAT_HEARTBEAT_STALE_MS=${SOKRAT_HEARTBEAT_STALE_MS:-60000}
SOKRAT_HEARTBEAT_TICK_MS=${SOKRAT_HEARTBEAT_TICK_MS:-30000}
SOKRAT_HEARTBEAT_PBX_IDS=${SOKRAT_HEARTBEAT_PBX_IDS:-}
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
    "transport": "${TRANSPORT}",
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

# Bundled database credentials are generated per installation.
DB_PASS=$(openssl rand -hex 24)
DB_ROOT_PASSWORD=$(openssl rand -hex 32)
DB_PORT=${DB_PORT:-3307}

cat << EOF > .env
GATEWAY_PUBLIC_HOST=${PUBLIC_HOST}
GATEWAY_HTTP_PORT=${HTTP_PORT}
GATEWAY_WS_PORT=${WS_PORT}
GATEWAY_TLS_ENABLED=${TLS_ENABLED}
GATEWAY_HTTPS_PORT=${HTTPS_PORT}
GATEWAY_WSS_PORT=${WSS_PORT}
GATEWAY_LISTEN_IP=${LISTEN_IP}
GATEWAY_PRIVATE_IP=${PRIVATE_IP}
SOKRAT_TRANSPORT=${TRANSPORT}
GATEWAY_MEDIA_POOL=${MEDIA_POOL}
SOKRAT_UID=${SOKRAT_UID}
SOKRAT_GID=${SOKRAT_GID}
DB_HOST=127.0.0.1
DB_PORT=${DB_PORT}
DB_USER=sokrat
DB_PASS=${DB_PASS}
DB_NAME=asterisk
DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD}
CONTROL_ALLOW_PUBLIC=$([ "$CONTROL_PUBLIC" = public ] && echo true || echo false)
CONTROL_PORT=8002
FCM_ENABLED=${FCM_ENABLED:-true}
GOOGLE_APPLICATION_CREDENTIALS=${PUSH_DIR}/firebase-service-account.json
APNS_ENABLED=${APNS_ENABLED:-auto}
APNS_KEY_FILE=${PUSH_DIR}/apns/AuthKey.p8
SOKRAT_HEARTBEAT_ENABLED=${SOKRAT_HEARTBEAT_ENABLED:-true}
SOKRAT_HEARTBEAT_STALE_MS=${SOKRAT_HEARTBEAT_STALE_MS:-60000}
SOKRAT_HEARTBEAT_TICK_MS=${SOKRAT_HEARTBEAT_TICK_MS:-30000}
SOKRAT_HEARTBEAT_PBX_IDS=${SOKRAT_HEARTBEAT_PBX_IDS:-}
EOF
chmod 0600 .env

echo -e "${GREEN}[6/8] Configuring Host Firewall...${NC}"

# The container uses host networking, so the host firewall is authoritative.
# Empty VPS images commonly have no firewall manager installed. Install one,
# keep the management SSH port reachable, and default to deny-incoming.
FIREWALL_MANAGER=""
FIREWALL_PORTS=()
FIREWALL_STATUS_FILE=/etc/sokrat/host-firewall.json

SSH_PORT="${GATEWAY_SSH_PORT:-}"
if [ -z "$SSH_PORT" ] && [ -n "${SSH_CONNECTION:-}" ]; then
    read -r _ _ _ SSH_PORT <<< "$SSH_CONNECTION"
fi
if [ -z "$SSH_PORT" ] && command -v sshd > /dev/null; then
    SSH_PORT=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
fi
SSH_PORT="${SSH_PORT:-22}"
if [[ ! "$SSH_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || (( SSH_PORT > 65535 )); then
    echo -e "${RED}Could not determine a safe SSH port; set GATEWAY_SSH_PORT.${NC}" >&2
    exit 1
fi

add_firewall_port() {
    FIREWALL_PORTS+=("$1")
}

add_firewall_port "${SSH_PORT}/tcp"
add_firewall_port "${HTTP_PORT}/tcp"
add_firewall_port "${WS_PORT}/tcp"
add_firewall_port "7000/tcp"
add_firewall_port "7443/tcp"
add_firewall_port "3478/tcp"
add_firewall_port "3478/udp"
add_firewall_port "3500:3654/tcp"
add_firewall_port "3500:3654/udp"
if [ "$TLS_READY" = true ]; then
    add_firewall_port "${HTTPS_PORT}/tcp"
    add_firewall_port "${WSS_PORT}/tcp"
fi

if command -v ufw > /dev/null; then
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw default deny incoming > /dev/null
        ufw default allow outgoing > /dev/null
    fi
    for port in "${FIREWALL_PORTS[@]}"; do
        ufw allow "$port" > /dev/null
    done
    ufw --force enable > /dev/null
    ufw status 2>/dev/null | grep -q "Status: active" || {
        echo -e "${RED}UFW is installed but could not be enabled.${NC}" >&2
        exit 1
    }
    FIREWALL_MANAGER=ufw
elif command -v firewall-cmd > /dev/null; then
    systemctl enable --now firewalld > /dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=ssh > /dev/null
    for port in "${FIREWALL_PORTS[@]}"; do
        firewall-cmd --permanent --add-port="${port/:/-}" > /dev/null
    done
    firewall-cmd --reload > /dev/null
    firewall-cmd --state 2>/dev/null | grep -q "running" || {
        echo -e "${RED}firewalld is present but could not be started.${NC}" >&2
        exit 1
    }
    FIREWALL_MANAGER=firewalld
elif command -v apt-get > /dev/null; then
    apt-get update > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw > /dev/null
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    for port in "${FIREWALL_PORTS[@]}"; do
        ufw allow "$port" > /dev/null
    done
    ufw --force enable > /dev/null
    ufw status 2>/dev/null | grep -q "Status: active" || {
        echo -e "${RED}UFW was installed but could not be enabled.${NC}" >&2
        exit 1
    }
    FIREWALL_MANAGER=ufw
else
    echo -e "${RED}No supported firewall manager found; install UFW or firewalld and rerun.${NC}" >&2
    exit 1
fi

python3 - "$FIREWALL_STATUS_FILE" "$FIREWALL_MANAGER" "$SSH_PORT" "$TLS_READY" "${FIREWALL_PORTS[@]}" <<'PY'
import datetime
import json
import sys

path, manager, ssh_port, tls, *ports = sys.argv[1:]
record = {
    "configured": True,
    "manager": manager,
    "sshPort": int(ssh_port),
    "tls": tls == "true",
    "ports": ports,
    "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(record, handle, separators=(",", ":"))
    handle.write("\n")
PY
chmod 0644 "$FIREWALL_STATUS_FILE"
echo -e "${GREEN}✓ ${FIREWALL_MANAGER} active; SSH ${SSH_PORT}/tcp and gateway ports allowed.${NC}"

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
transport.heartbeatTimeout = 30
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
        --pool "${MEDIA_POOL}" \
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
    echo -e "${YELLOW}⚠ Push Gateway did not respond immediately. Check logs with: docker compose logs -f${NC}"
fi

echo
echo -e "${BLUE}===================================================================${NC}"
echo -e "${GREEN}  Installation Complete! Sokrat Gateway Container is Running.      ${NC}"
echo -e "${BLUE}===================================================================${NC}"
echo -e "Public Web Ingress:      ${GREEN}${GATEWAY_URL}${NC}"
echo -e "Control Dashboard:       ${GREEN}https://${PUBLIC_HOST}/control/${NC}"
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
echo -e "   ${GREEN}https://${PUBLIC_HOST}/control/${NC}"
echo -e "Admin user:             root"
if [ -n "${ADMIN_PASS:-}" ]; then
    echo -e "Admin password:         ${YELLOW}${ADMIN_PASS}${NC}"
fi
if [ -f /etc/sokrat/gateway-admin-initial-password ]; then
    echo -e "Password file:          /etc/sokrat/gateway-admin-initial-password"
fi
echo
echo -e "Useful Commands:"
echo -e "  View container status:  ${BLUE}docker compose ps${NC}"
echo -e "  View combined logs:     ${BLUE}docker compose logs -f${NC}"
echo -e "  View app logs on host:  ${BLUE}tail -f /var/log/sokrat/*.log${NC}"
echo -e "${BLUE}===================================================================${NC}"
