# VPN-Free PBX Implementation Plan

**Status:** plan only. The implementation changes were reverted.

## Goal

New PBX servers must connect to the gateway using only:

- FRP reverse TLS tunnel for control/API/WebSocket traffic
- OpenVPN for the isolated media/TURN path

No Tailscale or ZeroTier installation, service, interface, route, firewall rule, TURN listener, or management dependency for the new PBX path.

## Constraints

- Do not modify the four existing PBX servers or their live gateway records.
- Do not change existing PBX media/TURN records while validating the new path.
- Test with a disposable test PBX and an isolated test gateway first.
- Keep legacy provider support available for existing PBXs until they are deliberately migrated.

## Current blockers

- Gateway host still runs `tailscaled` and `zerotier-one`, with `tailscale0` and ZeroTier interfaces active.
- Gateway runtime still has `GATEWAY_PRIVATE_IP=100.68.53.59` (Tailscale).
- Gateway TURN listens on Tailscale/ZeroTier addresses.
- Gateway `AMI_HOST` points at a ZeroTier address.
- PBX installers still install and enable Tailscale/ZeroTier.
- Provisioning scripts still default to `tailscale0`.
- Existing PBX administration uses provider IPs.

## Phase 0 — Baseline and isolation

1. Capture read-only baselines:
   - Gateway control store, provisioning status, runtime manifest.
   - Existing PBX service/interface/route state.
   - Existing call and push health.
2. Use a new disposable test PBX VM, or a clone of the test PBX.
3. Use an isolated test gateway instance; do not add test records to the production gateway.
4. Define the VPN-free management path:
   - Restricted public SSH from operator addresses, or
   - SSH exposed through FRP.
5. Do not use the live test PBX enrollment as the test target unless it is first cloned and isolated.

## Phase 1 — Transport mode

Add an explicit mode:

```text
SOKRAT_TRANSPORT=openvpn-frp
```

Keep `legacy` as the default for existing-server upgrade paths. Fresh VPN-free installations must explicitly use `openvpn-frp`.

### PBX installer

- Skip installing and enabling Tailscale and ZeroTier.
- Do not create provider interfaces, routes, or firewall rules.
- Install/verify OpenVPN and Python cryptography dependencies.
- Keep FRPC installation and secure gateway pairing.
- Keep the existing reverse TLS media-link installer.

### Gateway installer

- Require an explicit `GATEWAY_PRIVATE_IP` for VPN-free mode.
- Do not auto-detect or require `tailscale0`.
- Require an explicit OpenVPN/public relay interface.

## Phase 2 — Gateway runtime

- Add `transport` and `iface` to the gateway provisioning/runtime configuration.
- For `openvpn-frp`, require `GATEWAY_PRIVATE_IFACE`; never silently fall back to `tailscale0`.
- Generate TURN units without `After=tailscaled.service`.
- Bind new TURN listeners to public/OpenVPN addresses only.
- Use per-PBX media-plan `relayIp` and `interface` values.
- Keep existing PBX relay/TURN records unchanged.

## Phase 3 — Test deployment

1. Deploy a fresh isolated test gateway with:
   - FRPS and enrollment service
   - Per-PBX OpenVPN media links
   - TURN on public/OpenVPN addresses
   - No Tailscale or ZeroTier
2. Deploy a fresh test PBX with:
   - FRPC active
   - OpenVPN media service active
   - No Tailscale/ZeroTier packages, services, interfaces, or routes
   - Restricted public SSH or FRP SSH
3. Enroll the test PBX only into the isolated test gateway.
4. Do not modify production gateway records or existing PBX configuration.

## Phase 4 — Verification

| Test | Required result |
|---|---|
| Provider removal | No `tailscaled`/`zerotier-one`; no `tailscale0`/`zt*` interfaces |
| Reverse tunnel | FRPC active; FRPS sees the test PBX; API/WS proxy works |
| OpenVPN | Media unit active; OpenVPN peer reachable; no provider route |
| TURN/ICE | TURN listens on public/OpenVPN only; WebRTC media works |
| SIP | Test extension registers through the gateway |
| Inbound call | Notification, answer, media, hangup |
| Outbound call | Dial, media, hangup |
| Push wake | FCM wake and SIP bootstrap work |
| Restart | Test PBX and gateway restart; FRP/OpenVPN recover |
| Firewall | Only required public/OpenVPN/FRP ports are open |
| Existing servers | Control records, services, calls, and push unchanged |

Repeat the call tests with provider networks deliberately blocked.

## Phase 5 — Promotion

Only after the isolated test passes:

1. Update the production installer for new PBXs only.
2. Add the first new PBX to the production gateway with per-PBX VPN-free configuration.
3. Leave existing PBX records, interfaces, and provider services untouched.
4. Keep the isolated test gateway available for rollback comparison.

## Rollback

- Delete the isolated test gateway and test PBX.
- No production changes are made during validation.
- If promotion fails, remove only the new PBX record and its media/TURN units.

## Out of scope for the first pass

- Migrating existing PBXs away from Tailscale/ZeroTier.
- Removing legacy provider code from the repository.
- Changing existing gateway AMI, TURN, or management access.
