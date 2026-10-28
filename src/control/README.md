# Control plane — multi-PBX & device approval dashboard

Self-contained module for `sokrat-push-gateway-master`. It is mounted by the
gateway process and provides:

- a durable registry of **PBX connections** (`id`, `name`, `wsURL`, `apiURL`,
  `mediaIps`, `enabled`) with a backend-enforced cap on enabled connections;
- **automatic device enrollment** (`enrollment.js`): a device that only knows the
  gateway address, its extension and its SIP password announces itself, waits in
  the approval queue, and collects its PBX assignment with a secret it generated
  itself;
- **invite enrollment** (backwards compatible): an operator issues a one-time
  token, approval mints a one-shot device secret;
- an operator console (same-origin HTML/CSS/JS, strict CSP, no external assets).

It **never** proxies SIP or media. The parent process keeps ownership of the
SIP/WebRTC proxy, the inbound-call push pipeline and MySQL access.

> **Exposure policy — read before deploying.** Two routers with opposite
> audiences:
>
> - `control.router` (console + admin API) has no per-user roles and hands out
>   device credentials, so it must stay on `localhost`, a private LAN or a
>   VPN/tailnet. It rejects non-private peers by default.
> - `control.enrollmentRouter` is the **device-facing** endpoint. Unapproved
>   phones must reach it from mobile networks, so it is public by design; it
>   exposes only `POST …/enroll` and `POST …/claim`, never admin data, and it is
>   rate limited. Set `CONTROL_ENROLL_PRIVATE_ONLY=true` if the gateway itself is
>   only reachable through a VPN.
>
> Prefer `ssh -L` / `tailscale serve` for the console. If a reverse proxy is
> unavoidable for the console: terminate TLS, keep it on the private network, and
> set `CONTROL_TRUST_PROXY=true`, `CONTROL_COOKIE_SECURE=true` and
> `CONTROL_ALLOW_PUBLIC=true` deliberately. Put the enrollment router behind the
> same TLS terminator and set `CONTROL_TRUST_PROXY=true` so per-address limits
> see the real client IP.

---

## Integrate with the gateway (parent)

The parent file is `src/index.js`; this module never edits it.

```js
const { createControl } = require('./control');

// Required: durable JSON document (mode 0600). Put it on persistent storage,
// outside the repository if the repository is version controlled.
const control = createControl({
    filePath: process.env.CONTROL_DATA_FILE,      // or CONTROL_DATA_FILE in .env
    maxEnabledPbx: process.env.CONTROL_MAX_ENABLED_PBX
});

await control.init();                            // fail fast on a corrupt store
app.use('/control', control.router);             // operator console (private)
app.use('/connect', control.enrollmentRouter);   // devices (public listener)

// On shutdown:
control.close();                                 // clears the session sweep timer
```

`createControl()` returns:

| Field | Type | Purpose |
| --- | --- | --- |
| `router` | `express.Router` | operator console + admin API (keep private) |
| `enrollmentRouter` | `express.Router` | automatic enrollment for devices (public) |
| `store` | `ControlStore` | programmatic access (see below) |
| `credential` | `{ source, configured, verify }` | resolved admin credential |
| `sessions` | `SessionManager` | in-memory admin sessions |
| `loginLimiter`, `globalLimiter`, `enrollLimiter` | `LoginRateLimiter` | console throttles |
| `limits` | `object` | effective caps |
| `init()` | `Promise` | idempotent store initialisation (routers also self-init) |
| `close()` | `void` | release timers |

Sub-parts are exported individually if the parent wants a different wiring:
`createControlRouter`, `createEnrollmentRouter`, `ControlStore`,
`ControlStoreError`, `SessionManager`, `LoginRateLimiter`, `WindowLimiter`,
`loadAdminCredential`, `hashPassword`, `verifyPasswordHash`.

### Store API (parent-facing)

```js
await store.init();

store.limits                    // { maxEnabledPbx, maxPbx, maxPendingDevices, claimTtlMs, ... }
store.snapshot()                // public projections, digests stripped
store.stats()
store.listPbx() / store.getPbx(id)
store.addPbx({ name, wsURL, apiURL, mediaIps, enabled }, { actor })
store.updatePbx(id, patch, { actor })
store.removePbx(id, { actor })  // revokes approved devices + invites on it
store.listDevices(status) / store.getApprovedDevice(deviceId)
store.verifyDeviceSecret(deviceId, secret)   // { ok, device } | { ok: false }

// operator-driven enrollments (unchanged)
store.createEnrollmentToken({ label, pbxId, extension, maxUses, ttlMs }, { actor })
store.revokeEnrollmentToken(id, { actor })
store.enrollDevice({ token, platform, deviceUuid, instanceId, appVersion, ... }, { requestIp })
store.approveDevice(id, { pbxId, extension }, { actor })  // => { device, secret } | { device, secret: null }
store.rejectDevice(id, { reason }, { actor })
store.revokeDevice(id, { reason }, { actor })

// automatic enrollments
store.enrollClaim({ claimSecret, platform, deviceUuid, extension, deviceName,
                    appVersion, model, osVersion }, { requestIp })
store.redeemClaim({ deviceId, claimSecret })
```

Every mutation throws `ControlStoreError` with `.code` and `.status` on
validation/business-rule failures. Reads and mutations are serialised; a failed
mutation leaves both memory and disk untouched.

`verifyDeviceSecret(deviceId, secret)` is the integration point for binding a
device to its push token: the parent can require the approved device secret
before accepting `POST /api/push/register-device` for the matching
extension/PBX. It works identically for both enrollment modes — for an automatic
device the "secret" is the claim secret the client generated. The device's
`instanceId` and `deviceUuid` are recorded for the operator but are **not**
authentication.

---

## Automatic enrollment — exact contract

Two endpoints on the public router, no cookies, no session, no CSRF token,
secret-free responses, `Cache-Control: no-store`.

Client rules:

- `claimSecret`: **generate on the device**, 32–256 printable characters with no
  whitespace (43-character base64url from 32 CSPRNG bytes is the reference
  value), store it in secure storage, and never log it. The gateway stores only
  its SHA-256 digest and never sends it back.
- `deviceUuid`: the install identity, informational for the operator. Two
  devices that report the same UUID can never read or replace each other's claim
  because the pending row is keyed by the claim digest.
- `extension`: the SIP extension the phone is logging in with. It pre-fills the
  operator's approval form; the operator confirms or overrides it.

### 1. Enroll

```
POST {enrollmentBase}/enroll
Content-Type: application/json

{
  "claimSecret": "…43 chars…",
  "platform": "android" | "ios",
  "deviceUuid": "a9e89b44-cb09-4f7c-a9e5-4da631df95ed",
  "extension": "162",
  "deviceName": "Ahmed's Pixel",       // optional
  "appVersion": "2.1.0",               // optional
  "model": "Pixel 8",                  // optional
  "osVersion": "Android 15"            // optional
}
```

| Status | Meaning |
| --- | --- |
| `201` | pending request created |
| `200` | the same claim re-enrolled (idempotent; `reused: true`) |
| `400` | `invalid_claimSecret` / `invalid_platform` / `invalid_deviceUuid` / `invalid_extension` / `invalid_json` |
| `403` | `device_rejected` or `device_revoked` — enroll again with a new claim secret |
| `409` | `device_uuid_conflict` (another pending claim holds the UUID), `device_already_approved`, `pending_cap_reached`, `device_limit_reached` |
| `413` | `payload_too_large` (8 KB body limit) |
| `429` | `too_many_requests` + `Retry-After` |

```json
{
  "success": true,
  "status": "pending",
  "device": {
    "id": "dev_1f0c…", "status": "pending", "enrollmentMode": "claim",
    "platform": "android", "deviceUuid": "a9e8…", "deviceName": "Ahmed's Pixel",
    "suggestedExtension": "162", "claimExpiresAt": "2026-10-29T09:00:00.000Z",
    "hasClaim": true, "hasSecret": false, "requestedAt": "2026-10-28T09:00:00.000Z"
  },
  "claimExpiresAt": "2026-10-29T09:00:00.000Z",
  "retryAfterMs": 3000,
  "redeemsAutomatically": true,
  "notice": "Request received. Poll POST /claim with the same deviceId and claimSecret."
}
```

### 2. Claim (status + redemption)

```
POST {enrollmentBase}/claim
Content-Type: application/json

{ "deviceId": "dev_1f0c…", "claimSecret": "…the same secret…" }
```

`POST` only — the secret never appears in a URL. Poll every `retryAfterMs`
(3 s by default).

| Status | Meaning |
| --- | --- |
| `202` | still `pending`; `Retry-After` header + `retryAfterMs` |
| `200` | `approved`; the assignment is below |
| `401` | `invalid_claim` (wrong secret or unknown device — indistinguishable) |
| `403` | `device_rejected` / `device_revoked` |
| `409` | `pbx_disabled` (assigned PBX switched off; keep polling or contact the operator) |
| `410` | `claim_expired` — re-run `/enroll` with the same claim secret |
| `429` | `too_many_requests` + `Retry-After` |

```json
{
  "success": true,
  "status": "approved",
  "device": { "id": "dev_1f0c…", "status": "approved", "pbxId": "pbx_b02b…",
              "extension": "162", "claimRedeemedAt": "2026-10-28T09:04:12.000Z" },
  "assignment": {
    "deviceId": "dev_1f0c…", "deviceUuid": "a9e8…", "platform": "android",
    "pbxId": "pbx_b02b…", "pbxName": "HQ", "extension": "162",
    "wsURL": "wss://pbx.example.com:8089/ws",
    "apiURL": "https://pbx.example.com:8080/",
    "mediaIps": ["203.0.113.10"]
  },
  "redeemed": true,
  "credential": {
    "deviceHeader": "X-Sokrat-Device",
    "authorization": "Bearer",
    "note": "Send the same deviceId and claimSecret you enrolled with."
  }
}
```

Redemption is **idempotent**: the first success activates the credential the
device already holds; a retry returns the same assignment with
`redeemed: false`. Nothing is minted or transmitted, so a lost response can
never lock a device out.

### 3. Using the credential

The device presents the pair it already has:

```
X-Sokrat-Device: dev_1f0c…
Authorization: Bearer <claimSecret>
```

The parent verifies it with `store.verifyDeviceSecret(deviceId, secret)`, which
is exactly what `src/tenant-runtime.js` already calls for `sip-ticket`, ICE, push
registration and the SIP WebSocket. **SIP authentication is unchanged**: the
phone still REGISTERs/INVITEs with its extension and SIP password, the selected
PBX validates the digest, and the proxy rejects requests whose SIP identity is
not the assigned extension.

Lifecycle notes:

- Approval issues **no secret** for this mode. The console shows no
  copy-once panel; `POST /control/api/devices/:id/approve` answers
  `{ success, device, enrollmentMode: "claim", notice }` without `secret`.
- Revoking a device drops the stored digest (`verifyDeviceSecret` returns
  `ok: false`) and the claim cannot be redeemed again (`403 device_revoked`).
  The phone must enroll with a **new** claim secret; the operator approves it
  again.
- Rejection (`403 device_rejected`) behaves the same way for the rejected
  secret.
- Expiry (`CONTROL_CLAIM_TTL_MINUTES`, default 24 h) hides the request from the
  approval queue and answers `410 claim_expired`; re-enrolling with the same
  claim secret refreshes the same row. Rows that expired more than one TTL ago
  are pruned opportunistically.

---

## Invite enrollment (unchanged)

Operator creates `sk_enroll_v1_…` tokens in the console; the device redeems the
token and the operator hands over the once-shown `sk_device_v1_…` secret.

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/control/api/enrollment-tokens` | session + CSRF |
| `DELETE` | `/control/api/enrollment-tokens/:id` | session + CSRF |
| `POST` | `/control/api/devices/enroll` | enrollment token (public path, private-network guarded) |

Request body: `{ token, platform, deviceUuid, instanceId?, appVersion?, deviceName?,
model?, osVersion? }` → `201 { success, device, status: "pending" }`. Approval
returns `{ success, device, secret }` **once**; `secret` is stored only as a
SHA-256 digest and revoking drops it.

## Console HTTP surface (mounted at `/control` by default)

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/control` | none (login shell) |
| `GET` | `/control/api/session` | none (reports `configured`) |
| `POST` | `/control/api/session` | password |
| `DELETE` | `/control/api/session` | session + CSRF |
| `GET` | `/control/api/state` | session |
| `POST` | `/control/api/pbx` | session + CSRF |
| `PATCH` | `/control/api/pbx/:id` | session + CSRF |
| `DELETE` | `/control/api/pbx/:id` | session + CSRF |
| `POST` | `/control/api/devices/:id/approve` | session + CSRF |
| `POST` | `/control/api/devices/:id/reject` | session + CSRF |
| `POST` | `/control/api/devices/:id/revoke` | session + CSRF |

The automatic-enrollment router exposes nothing else: `GET /connect/…` and any
admin-looking path answer `404 { success: false, error: "not_found" }`.

---

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `CONTROL_DATA_FILE` | yes* | absolute path of the JSON store (`*` unless passed as `filePath`) |
| `CONTROL_ADMIN_PASSWORD_HASH` | one of | `scrypt$N$r$p$salt$hash` (recommended) |
| `CONTROL_ADMIN_PASSWORD` | one of | bootstrap plaintext, hashed in memory at runtime |
| `CONTROL_MAX_ENABLED_PBX` | no | enabled-PBX cap, default `5`, clamped `1..64` |
| `CONTROL_MAX_PBX` | no | total PBX records, default `25` |
| `CONTROL_MAX_PENDING_DEVICES` | no | pending queue cap (both modes), default `200` |
| `CONTROL_MAX_DEVICES` | no | total device records, default `2000` |
| `CONTROL_MAX_INVITES` | no | active enrollment invites, default `100` |
| `CONTROL_CLAIM_TTL_MINUTES` | no | lifetime of an automatic request, default `1440`, clamped `5..10080` |
| `CONTROL_SESSION_TTL_MINUTES` | no | idle session timeout, default `30` |
| `CONTROL_SESSION_MAX_HOURS` | no | absolute session timeout, default `12` |
| `CONTROL_ALLOW_PUBLIC` | no | `true` disables the console's private-network guard (discouraged) |
| `CONTROL_ENROLL_PRIVATE_ONLY` | no | `true` keeps the enrollment router on private networks only |
| `CONTROL_TRUST_PROXY` | no | honour `X-Forwarded-For` / `-Host` / `-Proto` (both routers) |
| `CONTROL_COOKIE_SECURE` | no | force `Secure` cookies (`auto` by default) |

There is **no default password**. With neither variable set the console starts
in a locked state: `GET /api/session` reports `configured: false`, sign-in
returns `503`, and the login page explains how to set a credential.

Generate a hash without leaking the password into shell history:

```bash
read -r -s -p "Admin password: " P && node -e '
  const { hashPassword } = require("./src/control/auth");
  hashPassword(process.argv[1]).then((h) => console.log(h));
' "$P" && unset P
```

## Security model

- **Store**: single JSON document, atomic write (temp file `0600` + `fsync` +
  rename + directory `fsync`), directory `0700`, existing file permissions
  tightened on load. Corrupt files fail closed and are never rewritten. The
  store is single-writer: never point two gateway processes at the same file.
- **Passwords**: scrypt (`N=16384, r=8, p=1`, 16-byte salt, 64-byte key),
  constant-time comparison. Malformed/absent credentials still burn a scrypt
  round to avoid latency fingerprinting.
- **Sessions**: 256-bit opaque ids, in-memory (restart = sign-out), sliding idle
  timeout plus absolute cap, `HttpOnly` + `SameSite=Strict` + `Secure` (when
  HTTPS), CSRF token per session required for every mutation.
- **Throttling**: console — 5 failures per address per 10 min → 5 min lockout,
  plus a global bucket (25/10 min). Automatic enrollment — 30 requests per
  address per 10 min, 1000 globally; claim polling 120/min per device and
  600/min per address; 20 wrong claim secrets per address per 10 min → 10 min
  lockout. Every throttle answers `429` with `Retry-After`.
- **Secrets**: enrollment tokens and invite-mode device secrets are 256-bit
  CSPRNG values stored as SHA-256 digests. Claim secrets are generated on the
  device and stored as a SHA-256 digest only; they are never returned, logged,
  audited or included in any projection (`hasClaim` is a boolean). Losing a
  response therefore loses nothing: `/claim` is idempotent.
- **Identity**: a device UUID or app instance is informational only. Pending
  automatic rows are keyed by the claim digest, so a forged UUID can neither
  read another claim nor replace it; a UUID that is already pending under a
  different claim or already approved is refused (`409`).
- **Rendering**: no `innerHTML` in the frontend; all API strings are inserted
  with `textContent`. The CSP is `default-src 'none'` with same-origin scripts,
  styles, images and connect-sources — no CDN, font or inline script.
- **Headers**: CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, COOP/CORP same-origin, `Permissions-Policy` locked down,
  `Cache-Control: no-store`, HSTS when HTTPS is detected.

## Tests

```bash
node --test test/control-*.test.js
npm test      # runs the whole suite, including these files
```

The tests use only Node built-ins and `express`, write to `os.tmpdir()`, and
never touch MySQL, APNs, FCM or Asterisk. Coverage: durable atomic store and
permissions, PBX validation/caps, token hashing, enrollment/approval/revoke
transitions, expiry, audit hygiene, scrypt credential handling, session and
CSRF rules, throttling, private-network guard, CSP/asset wiring, the full invite
flow, and the automatic flow (digest-only storage, claim-keyed upsert,
UUID-collision refusal, approval without a secret, idempotent redemption,
expiry/renewal, pruning, caps, PBX availability, public-router limits and the
absence of any admin surface).
