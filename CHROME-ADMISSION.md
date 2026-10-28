# Chrome admission support

The control store now accepts `platform: chrome` for both invitation and anonymous
claim enrollment. The dashboard and per-extension platform policy already expose
Chrome; their existing approval, device limits and suspension rules remain in force.
Unsupported platform values still fail closed, including persisted documents.
No public routing, enforcement flag, TURN allocation, PBX configuration or push
provider behavior is changed.

Chrome client 1.15.0 implements enrollment, durable claims, fresh SIP tickets on
automatic recovery and tenant relay-only media. Existing direct clients coexist.
See the Chrome repository's `GATEWAY-RELEASE.md` for remaining REST-feature limits.

Deployed 2026-10-28 by promoting only `src/control/store.js` and restarting
`sokrat-gateway-control.service` after confirming no established tenant9097
connections. Backup:
`/var/backups/sokrat-gateway/chrome-admission-20261028T133926Z/store.js`.
Deployed SHA256:
`2b15a86039484f85dc249bfdac8fd00fc1c2497fb8b80bb54a6b49ffc29df69c`.
Control, push, onboarding and provisioning timer active; capabilities responds.
No real Chrome device enrolled or approved by the agent. Real three-PBX audio,
hold/transfers and simultaneous mobile/desktop/Chrome require operator testing.
