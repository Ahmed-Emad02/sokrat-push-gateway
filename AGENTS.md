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

**On the Rocky VM** (`ssh rocky`) alongside Asterisk — it needs both:

1. the local **`asterisk`** MariaDB/MySQL schema, and
2. **Asterisk AMI** at `AMI_HOST:AMI_PORT` (default `127.0.0.1:5038`, admin/admin).

It does **not** run in WSL for real traffic (no AMI, no `mobile_devices` there).

> ⛔ The VM currently has **no OS installed** — see `../../ACCESS.md` §5.

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
- **Pushes are disabled by default:** `APNS_ENABLED=false`, `FCM_ENABLED=false`.
  Without an APNs `.p8` (key/team/topic) and an FCM service-account JSON, `/health`
  will report providers disabled and **nothing is actually pushed**. These files are
  referenced at `/etc/sokrat/{apns,firebase}/…` — absolute paths, outside the repo.
- **`DB_PASS=admin` / `root` in `.env.example`** — credentials for the PBX's own
  `asterisk` DB, shared with `sokrat-voice-main`. Change them together.
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
