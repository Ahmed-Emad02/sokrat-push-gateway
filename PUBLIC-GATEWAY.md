# Public mobile gateway

## Single-PBX deployment

The phone uses public plain `ws://<gateway>:8088/ws` signaling and HTTP push /
relay bootstrap. These are intentionally cleartext per the deployment choice;
SIP digest is not transport encryption, and HTTP relay/device tokens can be
intercepted. Do not reuse an administrative password as a SIP password. Restrict
administration to a private interface/SSH tunnel; TLS is recommended before
customer deployment.

The gateway proxies only `/ws` to the private PBX. It does not expose PBX ARI,
database, AMI, or the PBX dashboard. Existing PBX extension authentication and
FreePBX routing remain authoritative. No desktop transports or endpoint media
settings are changed.

TURN listens publicly on TCP/UDP 3478. Its **relay address is the gateway's
private Tailscale address**, reachable by the PBX. The phone sends media through
its authenticated TURN connection, not directly to that private address. TURN
peer permissions allow the configured PBX only. The public EC2 security group
does not need a public RTP range for this topology. TCP provides a fallback
where UDP is blocked (networks that also block TCP 3478 are not covered).

### Prerequisites

- Node 22, nginx, coturn and UFW on gateway; existing push service installed.
- Gateway and PBX have private connectivity (for example Tailscale).
- Gateway → PBX TCP 8088 (WS), TCP 8080 (extension HMAC auth API), UDP 10000–20000
  (or the actual PBX RTP range).
- PBX → gateway private UDP 49160–49260 and configured push webhook endpoint.
- Public AWS/security firewall: TCP 8088, TCP/UDP 3478, TCP 80. Keep SSH narrowly
  scoped. Database and AMI stay private, with least-privilege accounts.
- PBX has working WebRTC endpoints, ICE, DTLS-SRTP, `direct_media=no`,
  `max_contacts>=5`, `remove_existing=no`, and `/api/extension/v1/whoami` HMAC auth.

### Configure

Copy `src/mobile-ice.js` and add `require('./mobile-ice')(app)` after Express JSON
middleware. Run `scripts/configure-public-gateway.py` as root with:

```sh
export GATEWAY_PUBLIC_HOST=your.gateway.example
export PBX_PRIVATE_IP=<private-pbx-ip>
export GATEWAY_PRIVATE_IP=<gateway-tailscale-ip>
export GATEWAY_LISTEN_IP=<gateway-local-network-ip>
python3 scripts/configure-public-gateway.py
```

Deployment addresses belong to environment configuration, not application code.
The script preserves the Firebase key and existing database/AMI settings, backs
up modified files, generates a TURN secret on the host, and never prints it.
The HTTP site is currently expected at `/etc/nginx/sites-available/sokrat-push`.

## Validation

1. Public `/ws` returns WebSocket `101` with subprotocol `sip`.
2. Run `test-public-registration.py` on PBX with `GATEWAY_HOST` and
   `TEST_EXTENSION`; it reads the existing fixture credentials locally, tests
   digest registration, and deregisters only its own contact.
3. `/api/mobile/ice` returns 401 unsigned; valid PBX HMAC yields short-lived
   TURN credentials (`Cache-Control: no-store`). Password is never sent in URL.
4. `test-turn-relay.py` takes temporary credentials through stdin and verifies
   authenticated public UDP/TCP allocation plus a roundtrip to a temporary PBX
   echo listener. Do not start an echo listener on an occupied RTP port.
5. Install the matching mobile build. Gateway public host, TLS off. With VPN
   disabled, verify outgoing Echo `*43`, incoming call answer, two-way audio,
   DTMF, hold/resume, transfer, screen-off/cold-process FCM wake, Wi-Fi/cellular
   switch, and concurrent CRM registration. Do not infer success from FCM
   provider acceptance or a WebSocket handshake alone.

## Rollback

Restore timestamped nginx/turn/env backups on the gateway, validate `nginx -t`,
reload nginx and restart coturn/push service. Restore the saved `index.js` if
removing the relay credential route. Remove only the new firewall rules if no
longer required. No PBX dialplan or endpoint rollback is needed for this change.

## Multi-PBX / device approval

The control module and authenticated WebSocket router are implemented separately
from the single-PBX deployment. Do not expose the admin dashboard publicly or
switch live SIP routing until client enrollment, per-PBX push storage, revocation
and per-PBX TURN peer isolation are integrated and tested. UUIDs and SIP instance
IDs are identifiers, not device credentials. Duplicate extension numbers must be
scoped to an approved PBX. Shared TURN secrets that permit every PBX are not
sufficient tenant isolation.

### Control-plane deployment

`src/control-server.js` is a separate administrative service bound to loopback
port 9096. Install `systemd/sokrat-gateway-control.service`, supply a private
`/etc/sokrat/gateway-control.env` with `CONTROL_DATA_FILE` under
`/var/lib/sokrat-gateway` and `CONTROL_ADMIN_PASSWORD_HASH`. Never publish this
listener through the public nginx HTTP site. Access it through an SSH tunnel:

```sh
ssh -L 9096:127.0.0.1:9096 <gateway-ssh-account>
# Browser: http://127.0.0.1:9096/control/
```

`src/tenant-runtime.js` integrates the control store with authenticated SIP,
per-tenant push and per-tenant relay bootstrap. Its explicit factory takes
`control`, `pushFile`, `getRelay(pbxId)`, `authorizePbx(req)`, `sendToDevice`,
and `normalizeCallId`. Mount `runtime.router` under a new versioned public API;
attach `runtime.attach(httpServer)` for approved-device WebSocket upgrades.
Do not leave an unrestricted nginx `/ws` path active when enforcing approval.
The runtime issues a 30-second single-use ticket through authenticated
`POST /sip-ticket`; the client upgrades `/ws?ticket=...`. Permanent device
credentials must never be placed in the WebSocket URL, and nginx access logs
must omit query strings even for temporary tickets. Plain HTTP/WS still permits
on-path interception; short-lived tickets reduce accidental log exposure but
do not replace transport encryption.

For example, use a dedicated nginx log format containing `$uri` rather than
`$request`/`$request_uri` on the authenticated WS location, or disable that
location's access log. Never log Authorization headers or request bodies.

`scripts/provision-tenant-relay.py` provisions separate systemd coturn instances,
listener ports, secrets, and PBX-only peer allowlists from a private manifest.
Use disjoint private relay port ranges and permit each listener in the cloud
security group. `getRelay` must read the corresponding tenant's secret server
side, never a shared secret allowing all PBXs.

The tenant push registry is gateway-local and keyed by approved device plus PBX
and extension. Incoming hooks use POST and `X-Sokrat-Pbx` with a Bearer token;
`tenant-hook-auth.js` verifies a PBX-specific SHA-256 token digest. Hook credentials
must be stored in root/operator-managed configuration and never in a URL.
`scripts/pbx-push-hook.py` sends this POST with a fresh timestamp and nonce;
replayed nonces and timestamps older than one minute are refused. Invoke it from
the existing mobile push hook, not a new wildcard outbound dialplan context.

### Automatic onboarding (no invite / server-code field)

The tenant listener mounts **only** `control.enrollmentRouter` at
`/api/gateway/enrollment`; `/control` administration stays on the other private
listener. Device flow:

1. Discover `/api/gateway/capabilities` from the entered host.
2. Generate and persist a 256-bit random `claimSecret` locally for that gateway
   and account; send it by POST to `/api/gateway/enrollment/enroll` with the stable
   `deviceUuid`, `platform` (`android`, `ios`, or `desktop`) and extension.
3. Keep returned `device.id`. Poll `/api/gateway/enrollment/claim` with `deviceId`
   and `claimSecret`; HTTP 202 means awaiting administrator approval.
4. Administrator chooses PBX and extension. Claim HTTP 200 activates the original
   client-held secret; no one copies a secret from the dashboard.
5. Authenticate ICE, SIP-ticket and mobile push endpoints with
   `X-Sokrat-Device: <device.id>` and `Authorization: Bearer <claimSecret>`.
6. Continue using the SIP password for PBX SIP digest authentication. Approval
   grants routing, not permission to bypass the PBX password.

The server persists only the claim digest. Poll/redeem is idempotent and lost
responses do not lose credentials. UUIDs cannot replace another claim. A revoked
claim stays revoked; do not auto-enroll repeatedly to evade a rejection.
Desktop enrollment does not imply FCM/APNs support: push registration accepts
mobile platforms only. Use fresh one-use upgrade tickets on every reconnect.

### Synchronizing tenant relays

Use `scripts/sync-tenant-runtime.py --dry-run` to validate dashboard PBX records
and preview allocations. Apply as root with `GATEWAY_PUBLIC_HOST`,
`GATEWAY_LISTEN_IP` and `GATEWAY_PRIVATE_IP` supplied in the environment (or
`--env-file` pointing to a private deployment file). This is the preferred
provisioning command; do not also run `provision-tenant-relay.py` for those PBXs.

The command assigns stable listener ports beginning at 3500 and disjoint private
relay ranges beginning at 50000. Deleted and disabled PBXs retain their slots;
ports are never silently reassigned. Each relay runs as its own system account
with private configuration. Hook tokens stay root-only; only token hashes and
service-readable TURN secret copies enter the runtime artifacts.

Set `TENANT_RUNTIME_FILE=/var/lib/sokrat-gateway/tenant-runtime.json` on the
private runtime service and restart it after synchronizing. Permit allocated
TCP/UDP listener ports in the cloud firewall; only the private PBX needs the
relay range. Test every listener externally before cutover. The old single-PBX
3478 listener is not modified by this command.
