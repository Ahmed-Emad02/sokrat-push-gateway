# Sokrat Push Gateway

Push-to-wake and device gateway for the **Sokrat VOICE** mobile softphone.

It provides:

- FCM / APNs push-to-wake for mobile devices
- device enrollment and administrator approval
- PBX reverse-tunnel pairing and readiness checks
- a public-HTTPS control dashboard
- SIP WebSocket and media-relay routing for approved devices

## One-command install (fresh VPS)

Prerequisites:

- Ubuntu 24.04 / Debian 12 (tested baseline)
- a public IPv4 address
- TCP **80** free for ACME
- the FCM service-account JSON in a root-only directory on the VPS
- an email address for Let's Encrypt

Prepare secrets:

```bash
sudo install -d -m 0700 /root/sokrat-gateway-secrets
sudo install -m 0600 /path/to/firebase-service-account.json \
  /root/sokrat-gateway-secrets/firebase-service-account.json
```

Install:

```bash
PUBLIC_HOST=169.58.109.172
ACME_EMAIL=ops@example.com

curl -fsSL https://raw.githubusercontent.com/Ahmed-Emad02/sokrat-push-gateway/main/install.sh \
  | sudo -E bash -s -- \
      --host "$PUBLIC_HOST" \
      --email "$ACME_EMAIL" \
      --tls ip \
      --db bundled \
      --control public \
      --secrets-dir /root/sokrat-gateway-secrets \
      --non-interactive \
      --show-admin-password
```

For a reproducible production install, replace `main` with a reviewed commit SHA.
The installer refuses to run over an existing gateway configuration; this is a
first-install command, not an upgrader.

The installer:

1. installs Docker and the required host tooling
2. starts a bundled MariaDB instance with a persistent volume
3. installs the FCM service account root-only
4. obtains a short-lived Let's Encrypt certificate for the IP
5. builds and starts the gateway container
6. starts frps and the secure PBX enrollment service
7. verifies database, FCM and gateway readiness
8. prints the control-dashboard password once

Do **not** embed FCM, APNs, admin, database or pairing secrets in the repository or an installer file. The installer reads them from the root-only secret directory.

## Result

```text
Gateway API:        https://169.58.109.172/api/gateway/
Control dashboard:  https://169.58.109.172/control/
SIP WSS:            wss://169.58.109.172:8089/ws
PBX tunnel:         169.58.109.172:7000 (TLS)
STUN/TURN:          169.58.109.172:3478 (UDP/TCP)
```

The admin password is printed in the final installer output and, when generated, saved root-only at:

```text
/etc/sokrat/gateway-admin-initial-password
```

## TLS

`--tls ip` uses a short-lived Let's Encrypt IP certificate. Certbot must support `--ip-address` (5.4 or newer). Renewal is automated; the deploy hook copies the new certificate into `/etc/sokrat/tls` and reloads nginx inside the container.

The control dashboard is reachable only through **HTTPS**:

```text
https://169.58.109.172/control/
```

On a blank VPS the installer installs and enables **UFW** with a default-deny
incoming policy, preserving the SSH management port and opening only the gateway,
TURN, enrollment and TLS ports it needs. If firewalld is present instead, the
installer uses it. Installation stops rather than continuing without a host
firewall. The dashboard’s **Host firewall** card shows the configured manager and
allowed ports. Provider firewalls/security groups must still permit the same
ingress ports; the host firewall is not a substitute for them.

Port `8002` remains bound to loopback inside the container and must not be exposed by the host firewall.

If certificate issuance fails, installation fails. Do not use HTTP-only public onboarding.

## Optional APNs

iOS VoIP push is optional. To enable it, place the following root-only files in the secret directory and set `APNS_ENABLED=true` in `/opt/sokrat-push-gateway/.env`, then recreate the gateway:

```text
apns-AuthKey.p8
apns-key-id
apns-team-id
```

The old production gateway currently has APNs disabled. Do not invent an APNs credential.

## PBX connection

After installation:

1. Open `https://169.58.109.172/control/`.
2. Log in with the printed admin credential.
3. Reveal the secure pairing code.
4. In the PBX dashboard, open **Settings → Sokrat Gateway**.
5. Enter `169.58.109.172` and paste the pairing code.
6. Wait for the tunnel, media and push-hook readiness checks.

The gateway does not replace the PBX SIP password. Device approval remains separate.

## Device connection

1. Point the mobile app at `169.58.109.172`.
2. Sign in with the PBX extension and SIP password.
3. Approve the pending device in the gateway control dashboard.
4. Verify SIP registration and a real push-wake call before moving production devices.

## Upgrade

For an existing installation, use the documented container upgrade path rather than rerunning the fresh installer. Fresh install intentionally refuses to overwrite existing control/tunnel state.

## Health and verification

```bash
curl -fsS https://169.58.109.172/health
curl -fsS https://169.58.109.172/api/gateway/capabilities
docker compose ps
docker compose logs -f
```

`/health` reports database, FCM and APNs readiness. A public deployment is not considered ready if TLS or the required provider credentials are missing.

## Security

- Control dashboard is public by design for this deployment; use a strong unique password.
- Control is served only over TLS.
- FCM/APNs/admin secrets are root-only and never committed.
- Existing gateway control state and pairing records are not copied to a new gateway.
- Keep the old gateway available until the new gateway passes real PBX/device acceptance.

## License

ISC — Sokrat VoIP Suite
