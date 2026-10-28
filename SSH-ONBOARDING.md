# Dashboard SSH onboarding

## Single-address connection settings

Enter **PBX address** once (Tailscale IPv4 or a hostname/MagicDNS name resolving
from the gateway to exactly one Tailscale IPv4). **Resolve address** derives
`ws://<ip>:8088/ws`, `http://<ip>:8080`, the media IP and SSH target. Saving in
automatic mode also resolves it if needed. DNS resolution is session/CSRF protected,
bounded, and rejects public/private non-Tailscale, mixed-family and ambiguous
answers. The returned numeric IP is pinned for host-key probing and SSH submission;
the hostname is not re-resolved while sending credentials.

These are standard defaults, not discovery of listening ports or proof of service
readiness. Check the provisioning result and actual SIP/API connectivity. A domain
behind a public proxy cannot reveal the PBX's Tailscale/media address: supply its
Tailscale address instead. No new arbitrary DNS-to-SSH access is permitted.

Uncheck **Derive standard connection settings** to edit **Advanced connection
settings** for custom ports, TLS or separate hosts. Existing records open with
automatic derivation disabled so their endpoints are never silently rewritten.
Custom SSH onboarding still requires all endpoint hosts and the single media peer
to match the resolved Tailscale IP. Changing the primary address invalidates the
confirmed fingerprint. New managed PBXs still require save → manual approval →
edit/SSH setup; device admission remains a separate manual decision.

In Add/Edit PBX, select **Automatic SSH setup** and enter its Tailscale IPv4,
root SSH username, and one-time password. Select **Check SSH host key**, compare
the fingerprint with the PBX host key over a trusted channel, and confirm it.
The probe does not send the password. Passwords are not saved to dashboard state,
root configuration, a queue, logs, or command arguments; the browser clears the
field after submission.

## One-time gateway setup

Install distribution package `python3-paramiko`, promote the reviewed bundle,
and create `/etc/sokrat/gateway-onboarding.json` (0600 root:root):

```json
{"enabled": true, "serviceUser": "sokrat-push"}
```

Explicitly enable `sokrat-tenant-onboarding.service`. The root broker accepts only
the dashboard uid on a fixed Unix socket. The API requires session, CSRF, and TLS
or a local SSH tunnel. Root opt-in deliberately delegates narrow SSH bootstrap
authority to dashboard administrators; this is separate from the read-only
provisioning status API. No arbitrary command/path/SSH target overrides.

## Current requirements

- Tailscale IPv4, port22, root SSH password authentication.
- WS/API host and the single media peer must exactly match that Tailscale IP.
- A managed PBX must already be manually approved. Save it first, approve it,
  then edit to run SSH setup. Unmanaged PBXs can be explicitly opted in too.
- Existing `[sub-sokrat-push-send]` in `extensions_sokrat.conf` or
  `extensions_custom.conf`; this does not install a fresh PBX stack.
- Non-root/sudo accounts, arbitrary hostname targets, Tailscale IPv6, and
  automatic extension synchronization are not implemented.

The broker installs a per-PBX dedicated key with forwarding/PTY restrictions,
checks key-only login, saves root-private identity/known-host files under
`/etc/sokrat/ssh`, and pins the PBX for reconciliation. The timer provisions the
relay, cloud rules, and additive hook. Device approval stays manual.

If a later stage fails, an added authorized key may remain on the PBX. Retry is
idempotent, not a cross-host atomic rollback. Retiring access requires revoking
the dedicated key on the PBX. PBX responses are treated as untrusted discovery
data; only known dialplan paths and validated variable names are accepted.

## Multi-PBX acceptance

Use two different actual PBX hosts and test extensions on each, including an
overlapping number. Verify separate relay ports/peers, incoming/outgoing calls,
tenant-scoped push and concurrent registrations. Two records pointing at the
same host are not proof of multi-server isolation. Unit isolation coverage does
not prove live audio or killed-app wake.
