# Dashboard SSH onboarding

## Add a server

Enter **PBX address** and **Root SSH password**, then select **Add server**.
All dashboard servers are managed. No mode switch, SSH opt-in, fingerprint
confirmation, required name or separate PBX approval is needed. The name defaults
to the address. Successful SSH verification approves the server automatically;
the background worker configures its relay, firewall and push hook.

The address must be a Tailscale IPv4 or a hostname/MagicDNS name resolving from
the gateway to exactly one Tailscale IPv4. The gateway derives
`ws://<ip>:8088/ws`, `http://<ip>:8080`, media and SSH settings. It pins the resolved
numeric IP while sending credentials. Public/proxied domains cannot reveal a
server's Tailscale address; use its Tailscale IP instead. Resolution rejects
non-Tailscale, ambiguous and mixed-family answers.

SSH uses **trust on first use**: the first observed host key is accepted
automatically and saved after verified enrollment. This does not independently
authenticate the first connection; use a trusted Tailscale network. Later setup
attempts on that record must match the saved key before any password is sent.
An explicitly supplied fingerprint is still checked by the broker. Genuine
host-key rotations require an administrator to verify the new identity before
resetting its saved trust; changed keys are never silently overwritten.

Passwords are not saved to dashboard state, root configuration, a queue, logs or
command arguments. The browser clears the field after submission. Failed setup
keeps the saved server record pending so entering the password again retries
that same record, rather than creating a duplicate.

Existing approved servers can be edited without re-entering the password;
their existing connection settings are preserved unless the address is changed.
Optional connection details remain collapsed under Advanced. Settings alone do
not prove readiness: check the provisioning result and actual SIP/API connectivity.
Device admission and per-extension access remain separate from server setup.

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
- A managed PBX may be pending or approved. The broker accepts a pending identity
  without activating it; the enrollment API approves it only after host-key,
  password and key-only login verification succeeds and the saved PBX record is
  still unchanged. Failed setup leaves it pending. Suspended/retired PBXs are
  refused. Old unmanaged records migrate to managed/pending at control startup;
  migration does not invent ownership approval. They need one verified SSH setup.
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

## Removing and re-adding a PBX

Removal immediately revokes its devices and invites. On the next reconciliation
(normally within 60 seconds), its relay is stopped, local firewall rules and
service-readable relay secret are removed, and its runtime manifest entry is
dropped—even if it was the last PBX. Allocation slots are retained, never reused.
Cloud firewall rules are currently additive and are not removed automatically.

Adding the same physical server again uses a new PBX identity and dedicated SSH
key. Setup replaces a stale push-hook config only when its previous PBX was
deleted from this gateway and its gateway URL still matches; backups are kept.
No manual deletion of the old hook config is needed. A live PBX's hook is never
overwritten. Dedicated SSH keys already installed on a removed PBX remain until
explicitly revoked there; removal does not edit the PBX's desktop SIP dialplan.

## Multi-PBX acceptance

Use two different actual PBX hosts and test extensions on each, including an
overlapping number. Verify separate relay ports/peers, incoming/outgoing calls,
tenant-scoped push and concurrent registrations. Two records pointing at the
same host are not proof of multi-server isolation. Unit isolation coverage does
not prove live audio or killed-app wake.
