# AGENTS.md

Guidance and operational gotchas for AI agents working in `sokrat-push-gateway-master`
(`~/suite/push-gateway` in WSL, `G:\suite\apps\sokrat-push-gateway-master` on Windows).

> Environment map for all five repos / ports / WSL-VM-Windows access:
> [`../../ACCESS.md`](../../ACCESS.md) — this service belongs on the **Rocky VM** (§2).

---

## 1. What it is

**Zero-background / push-to-wake notification gateway** for the Sokrat VOICE
softphone. Asterisk gets an incoming call → `curl` webhook → this gateway maps the
PBX extension to the active device token (APNs / FCM) → pushes the phone awake, so
it opens a fresh WebSocket and rings natively via CallKit / TelecomManager.

```
Asterisk PBX (incoming call)
      │  curl webhook (asterisk/extensions_custom.conf)
      ▼
 sokrat-push-gateway  ──reads mobile_devices table──▶  ext → iOS/Android tokens
      ├──▶ APNs
      └──▶ FCM
```

Node.js + Express, **`mysql2`**, `firebase-admin`, `apns2`.

---

## 2. Where it runs

The legacy single-PBX service can run alongside Asterisk, or on a dedicated
gateway with private connectivity to both:

1. the local **`asterisk`** MariaDB/MySQL schema, and
2. **Asterisk AMI** at configured `AMI_HOST:AMI_PORT`, with explicitly supplied,
   least-privilege `AMI_USER` and `AMI_PASS` (no default credentials).

It does **not** run in WSL for real traffic (no AMI, no `mobile_devices` there).

Current test deployment runs on EC2 through a private Tailscale link to the PBX.
See `PUBLIC-GATEWAY.md` and `../../CODEX-MAP.md` for the verified state. The
separate private approval dashboard runs on loopback 9096; tenant HTTP/WS runtime
on loopback 9097 is opt-in via `TENANT_RUNTIME_FILE`. Do not expose admin routes
through the public listener or confuse deployed files with activated routing.

---

## 3. Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/push/register-device` | mobile binds a device token to an extension |
| POST | `/api/push/remove-device` | logout / de-register a token |
| GET | `/api/push/incoming-call` | **Asterisk dialplan webhook** |
| GET | `/health` | liveness + provider status |

Port: `PORT` env, **default `8095`** (hardcoded fallback in `src/index.js:69`).

---

## 4. Install & config

```bash
npm install --production
cp .env.example .env          # DB_* + APNS_* + FCM_*
node src/index.js             # listens on :8095
```

**Database** — load into the `asterisk` DB:

```bash
mysql -u root -p asterisk < sql/mobile_devices.sql
```

**Asterisk hook** — append `asterisk/extensions_custom.conf` to
`/etc/asterisk/extensions_custom.conf`. It `curl`s the gateway in a backgrounded
shell (1 s timeout) so the PBX never blocks.

**systemd**:

```bash
sudo cp systemd/sokrat-push-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sokrat-push-gateway.service
```

---

## 5. Commands & tests

```bash
npm start      # node src/index.js
npm run dev    # node --watch src/index.js
npm test       # node --test   → test/index.test.js, test/channel-matching.test.js
```

---

## 6. Gotchas

- **`.env` must be created** from `.env.example` — it is not committed.
- **FCM is enabled by default, APNs is not:** `FCM_ENABLED=true`, `APNS_ENABLED=false`.
  FCM credentials are resolved from the first match of `GOOGLE_APPLICATION_CREDENTIALS`,
  `/etc/sokrat/firebase/service-account.json`, or the bundled
  `config/firebase-service-account.{json,b64}`. If none are found `/health` reports
  `fcm:false` and the gateway logs a warning but keeps serving (calls still work,
  only wake pushes are skipped). iOS pushes stay off until an APNs `.p8`
  (key/team/topic) is installed.
- **Database credentials must be supplied** in deployment environment; the
  template contains no usable password. Preserve existing customer credentials.
- **AMI must be reachable** or the incoming-call webhook silently does nothing
  (it opens `net.createConnection` to `AMI_PORT`).
- **Webhook is firewall/URL sensitive** — the dialplan `curl`s a fixed URL; if you
  move the port, update `asterisk/extensions_custom.conf` too.
- Keep `sql/mobile_devices.sql` in sync with any schema change in the mobile app
  registration flow.

---

## 7. Relationship to the rest of the suite

- **consumer:** `sokrat-mobile-main` registers tokens (§3).
- **producer:** Asterisk / `sokrat-voip-dev-main` dialplan (`AGENTS.md` there).
- Shares the `asterisk` DB with `sokrat-voice-main` (`../../ACCESS.md` §3).
