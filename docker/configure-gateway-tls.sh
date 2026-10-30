#!/bin/bash
set -euo pipefail

# Optional TLS is rendered only when certificates exist. Fresh legacy installs
# must still start without TLS; an explicitly requested or partial TLS setup
# fails closed rather than quietly serving only plaintext.
GATEWAY_TLS_ENABLED="${GATEWAY_TLS_ENABLED:-auto}"
GATEWAY_TLS_DIR="${GATEWAY_TLS_DIR:-/etc/sokrat/tls}"
GATEWAY_HTTPS_PORT="${GATEWAY_HTTPS_PORT:-443}"
GATEWAY_WSS_PORT="${GATEWAY_WSS_PORT:-8089}"
template="${GATEWAY_TLS_TEMPLATE:-/etc/nginx/templates/sokrat-tls.conf.template}"
output_dir="${GATEWAY_NGINX_CONF_DIR:-/etc/nginx/conf.d}"
output="$output_dir/sokrat-public-tls.conf"

case "$GATEWAY_TLS_ENABLED" in auto|true|false) ;; *) echo 'Invalid GATEWAY_TLS_ENABLED' >&2; exit 1 ;; esac
for port in "$GATEWAY_HTTPS_PORT" "$GATEWAY_WSS_PORT"; do
    if [[ ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || ((port > 65535)); then
        echo 'Invalid gateway TLS port' >&2; exit 1
    fi
done
if [[ "$GATEWAY_HTTPS_PORT" == "$GATEWAY_WSS_PORT" ]] || [[ ! "$GATEWAY_TLS_DIR" =~ ^/[A-Za-z0-9_./-]+$ ]]; then
    echo 'Invalid gateway TLS configuration' >&2; exit 1
fi
if [[ -e "$output" ]] && ! grep -q '^# Managed by Sokrat configure-gateway-tls.sh$' "$output"; then
    echo 'Refusing to overwrite unmanaged gateway TLS config' >&2; exit 1
fi
if [[ "$GATEWAY_TLS_ENABLED" == false ]]; then
    rm -f "$output"
    exit 0
fi
if [[ ! -f "$GATEWAY_TLS_DIR/fullchain.pem" || ! -f "$GATEWAY_TLS_DIR/privkey.pem" ]]; then
    if [[ "$GATEWAY_TLS_ENABLED" == true || -e "$GATEWAY_TLS_DIR/fullchain.pem" || -e "$GATEWAY_TLS_DIR/privkey.pem" ]]; then
        echo 'Gateway TLS certificate/key pair is required' >&2; exit 1
    fi
    rm -f "$output"
    exit 0
fi
export GATEWAY_TLS_DIR GATEWAY_HTTPS_PORT GATEWAY_WSS_PORT
mkdir -p "$output_dir"
temporary=$(mktemp "$output_dir/.sokrat-tls-XXXXXX")
trap 'rm -f "$temporary"' EXIT
envsubst '${GATEWAY_TLS_DIR} ${GATEWAY_HTTPS_PORT} ${GATEWAY_WSS_PORT}' < "$template" > "$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$output"
