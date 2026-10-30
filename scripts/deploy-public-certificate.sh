#!/bin/bash
# Certbot deploy hook. No enrollment keys, PBX state or device records touched.
set -euo pipefail
umask 077
if [ "$(id -u)" -ne 0 ]; then echo 'Certificate deployment requires root' >&2; exit 1; fi
lineage=${RENEWED_LINEAGE:?Certbot must supply RENEWED_LINEAGE}
destination=/etc/sokrat/tls
container=sokrat-gateway
test -f "$lineage/fullchain.pem"
test -f "$lineage/privkey.pem"
openssl x509 -in "$lineage/fullchain.pem" -checkend 86400 -noout >/dev/null
cert_public=$(openssl x509 -in "$lineage/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
key_public=$(openssl pkey -in "$lineage/privkey.pem" -pubout -outform DER | sha256sum | cut -d' ' -f1)
if [ "$cert_public" != "$key_public" ]; then echo 'Certificate and private key do not match' >&2; exit 1; fi
for directory in /etc /etc/sokrat "$destination"; do
    if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
        echo 'Unsafe certificate destination' >&2; exit 1
    fi
    if [ -e "$directory" ] &&
       { [ "$(stat -c '%u' "$directory")" != 0 ] || (( (8#$(stat -c '%a' "$directory") & 0022) != 0 )); }; then
        echo 'Certificate directories must be root-owned and not writable by other users' >&2; exit 1
    fi
done
install -d -m 0700 "$destination"
if [ -L "$destination/.deploy.lock" ] || { [ -e "$destination/.deploy.lock" ] && [ ! -f "$destination/.deploy.lock" ]; }; then
    echo 'Unsafe certificate deployment lock' >&2; exit 1
fi
exec 9>"$destination/.deploy.lock"
flock -x 9
# Do not report a renewal as deployed when Docker itself cannot be inspected.
running=$(docker inspect --format '{{.State.Running}}' "$container")
case "$running" in true|false) ;; *) echo 'Unexpected container state' >&2; exit 1 ;; esac
temporary=$(mktemp -d "$destination/.deploy-XXXXXX")
trap 'rm -rf "$temporary"' EXIT
for name in fullchain.pem privkey.pem; do
    if [ -L "$destination/$name" ] || { [ -e "$destination/$name" ] && [ ! -f "$destination/$name" ]; }; then
        echo 'Managed certificate path must be regular' >&2; exit 1
    fi
    if [ -f "$destination/$name" ]; then cp -p "$destination/$name" "$temporary/old-$name"; fi
done
install -m 0600 "$lineage/privkey.pem" "$temporary/privkey.pem"
install -m 0644 "$lineage/fullchain.pem" "$temporary/fullchain.pem"
restore_pair() {
    for name in fullchain.pem privkey.pem; do
        if [ -f "$temporary/old-$name" ]; then
            mv "$temporary/old-$name" "$destination/$name"
        else
            rm -f "$destination/$name"
        fi
    done
}
mv "$temporary/privkey.pem" "$destination/privkey.pem"
if ! mv "$temporary/fullchain.pem" "$destination/fullchain.pem"; then restore_pair; exit 1; fi
if [ "$running" = true ]; then
    if ! docker exec "$container" /bin/bash -ec '/usr/local/bin/configure-gateway-tls.sh; nginx -t' ||
       ! docker exec "$container" nginx -s reload; then
        # Restore only the certificate pair, never tenant/control state. Keep
        # the previously loaded nginx configuration running; do not restart.
        restore_pair
        if ! docker exec "$container" /bin/bash -ec '/usr/local/bin/configure-gateway-tls.sh; nginx -t'; then
            echo 'Restored TLS configuration needs operator review; nginx was not restarted' >&2
        fi
        echo 'TLS deployment failed; previous certificate files restored' >&2
        exit 1
    fi
else
    echo 'Container stopped: certificate staged; live reload remains pending'
fi
echo 'Public certificate deployed; enrollment and device authority unchanged'
