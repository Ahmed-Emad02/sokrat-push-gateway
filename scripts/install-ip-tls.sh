#!/bin/bash
# Issue and deploy a short-lived Let's Encrypt certificate for an IP-only
# gateway. Requires Certbot >= 5.4 (IP address support) and a free TCP/80.
set -euo pipefail

HOST=${1:?gateway public IP required}
EMAIL=${2:?ACME account email required}
STAGING=${3:-false}
CERT_NAME=${CERT_NAME:-sokrat-gateway-ip}
DEST=${GATEWAY_TLS_DIR:-/etc/sokrat/tls}
HOOK=/usr/local/bin/sokrat-cert-deploy

valid_ip_cert() {
    [ -s "$DEST/fullchain.pem" ] && [ -s "$DEST/privkey.pem" ] &&
        openssl x509 -in "$DEST/fullchain.pem" -noout -checkhost "$HOST" >/dev/null 2>&1
}

if valid_ip_cert; then
    echo "TLS: existing IP certificate already valid for $HOST"
    exit 0
fi

if ! command -v certbot >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq snapd
        systemctl enable --now snapd.socket >/dev/null 2>&1 || true
        snap wait system seed.loaded >/dev/null 2>&1 || true
        snap install core >/dev/null 2>&1 || true
        snap refresh core >/dev/null 2>&1 || true
        snap install --classic certbot
        ln -sf /snap/bin/certbot /usr/bin/certbot
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y certbot
    else
        echo "TLS: install Certbot >= 5.4 with IP-address support" >&2
        exit 1
    fi
fi

if ! certbot --help all 2>/dev/null | grep -q -- '--ip-address'; then
    echo "TLS: installed Certbot does not support --ip-address; upgrade Certbot to >= 5.4" >&2
    exit 1
fi

install -d -m 0755 /etc/sokrat
install -d -m 0700 "$DEST"
cat > "$HOOK" <<'HOOK_SCRIPT'
#!/bin/bash
set -euo pipefail
lineage=${RENEWED_LINEAGE:?RENEWED_LINEAGE is required}
dest=${GATEWAY_TLS_DIR:-/etc/sokrat/tls}
install -d -m 0700 "$dest"
install -m 0644 "$lineage/fullchain.pem" "$dest/fullchain.pem"
install -m 0600 "$lineage/privkey.pem" "$dest/privkey.pem"
if docker inspect sokrat-gateway >/dev/null 2>&1; then
    docker exec sokrat-gateway /bin/bash -ec '/usr/local/bin/configure-gateway-tls.sh; nginx -t' >/dev/null 2>&1 || exit 1
    docker exec sokrat-gateway nginx -s reload >/dev/null 2>&1 || exit 1
fi
echo "TLS: certificate deployed to $dest"
HOOK_SCRIPT
chmod 0755 "$HOOK"

ARGS=(certonly --standalone --non-interactive --agree-tos --email "$EMAIL"
      --preferred-profile shortlived --cert-name "$CERT_NAME"
      --ip-address "$HOST" --deploy-hook "$HOOK")
if [ "$STAGING" = true ]; then ARGS+=(--staging); fi
certbot "${ARGS[@]}"

LINEAGE="/etc/letsencrypt/live/$CERT_NAME"
[ -s "$LINEAGE/fullchain.pem" ] && [ -s "$LINEAGE/privkey.pem" ] || {
    echo "TLS: certificate lineage not found at $LINEAGE" >&2
    exit 1
}
install -m 0644 "$LINEAGE/fullchain.pem" "$DEST/fullchain.pem"
install -m 0600 "$LINEAGE/privkey.pem" "$DEST/privkey.pem"
openssl x509 -in "$DEST/fullchain.pem" -noout -checkhost "$HOST" >/dev/null
echo "TLS: valid IP certificate installed for $HOST"
