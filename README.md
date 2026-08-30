# Sokrat Push Gateway

Zero-background / push-to-wake notification gateway for the **Sokrat VOICE**
mobile softphone. It maps PBX extensions to their active APNs (Apple) / FCM
(Google) device tokens so an incoming Asterisk call can wake a mobile app from
a cold kill and ring natively via CallKit / TelecomManager.

```
Asterisk PBX (incoming call)
      │  curl webhook (extensions_custom.conf)
      ▼
 sokrat-push-gateway  ──reads mobile_devices table──▶  "ext 150 → iOS + Android tokens"
      │
      ├──▶ APNs (Apple)   → wakes iPhone
      └──▶ FCM (Google)   → wakes Android
```

## Why

Mobile OSs kill background sockets within seconds, so the classic persistent
SIP connection fails on iOS 13+ / Android 10+. This service fires a *push*
instead; the app wakes, opens a fresh WebSocket to Asterisk, and bridges native
WebRTC audio.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/push/register-device` | Mobile app binds a device token to an extension |
| POST | `/api/push/remove-device` | Logout / de-register a token |
| GET | `/api/push/incoming-call` | **Asterisk dialplan webhook** |
| GET | `/health` | Liveness + provider status |

## Install

```bash
git clone https://github.com/Ahmed-Emad02/sokrat-push-gateway /opt/sokrat-push-gateway
cd /opt/sokrat-push-gateway
npm install --production
cp .env.example .env      # set DB creds + APNs/FCM keys
node src/index.js         # listens on :8095
```

### Database
```sql
source sql/mobile_devices.sql;   -- in the asterisk database
```

### Asterisk dialplan hook
Add `asterisk/extensions_custom.conf` to `/etc/asterisk/extensions_custom.conf`
and invoke the macro before bridging to a mobile extension (see comments in file).
It `curl`s the gateway in a backgrounded shell (1s timeout) so it never blocks
the PBX.

### systemd
```bash
sudo cp systemd/sokrat-push-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sokrat-push-gateway.service
```

## Push credentials (required for real pushes)

- **iOS**: Apple Developer account → a **VoIP Services** (`.p8`) key. Set
  `APNS_ENABLED=true` + `APNS_KEY_FILE/KEY_ID/TEAM_ID/TOPIC`.
- **Android**: Firebase project → service-account JSON. Set
  `FCM_ENABLED=true` + `GOOGLE_APPLICATION_CREDENTIALS`.

Both providers are optional and fail-open: the gateway runs without them and
reports `apns:false` / `fcm:false` on `/health`.

## Config (.env)

See `.env.example` for the full list (`PORT`, `DB_*`, `APNS_*`, `FCM_*`).

## License

ISC — Sokrat VoIP Suite
