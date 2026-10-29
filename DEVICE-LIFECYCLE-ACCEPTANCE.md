# PBX retirement and device reassignment acceptance

Lifecycle changes must preserve active tenants and require explicit approval for
new assignments. They are not permission to move existing PBXs to a second gateway.

## Required invariants

- Deleting/retiring a PBX removes its routing eligibility and revokes its device
  access. Previously issued tickets, active signaling authorization and push rows
  must not restore that access. Other PBXs and their contacts remain unchanged.
- Re-adding the same server address creates a new PBX identity with verified SSH
  onboarding. Old device approval must not migrate by matching host/IP alone.
- Disabled PBXs may retain administrative records, but cannot route calls or
  receive push dispatch while disabled.
- A device's new extension/PBX assignment is approved deliberately. An old cached
  assignment or an in-flight claim/ICE/ticket response cannot activate the old
  extension after switching accounts or signing out.
- FCM tokens identify an app installation, not a permanent extension. An approved
  installation can recover its token from its own inactive/revoked old record;
  a token belonging to a different active device/tenant cannot be stolen.
- Push eligibility compares the current device, PBX, extension and authorization
  revision. Registration against an old assignment must not survive reassignment.
- Logout cancels retry work and removes the device's registration after any
  already-running registration finishes. It does not clear unrelated accounts.

## Regression / operator matrix

1. Approve two devices on different PBXs. Retire one PBX; ensure only its device
   loses ticket, SIP, ICE and push authorization.
2. Retire the last PBX; confirm provisioning reconciliation still runs and removes
   retired relays, without deleting unrelated firewall/customer rules.
3. Re-add the same host: fresh PBX approval and fresh device assignment required.
4. Same installation signs in under a different extension: require approval, then
   register its FCM token once; calls/push to the old extension must not reach it.
5. Reassign an approved device in the dashboard: old tickets/active connections
   must be invalidated; the client must obtain the new assignment/credentials.
6. Attempt token collision from a different active installation: reject it.
7. Race account switch/logout with claim, ticket, media and push registration
   completion; late results must not restore the previous identity.
8. Restart/reload and confirm private registry persistence, permissions and active
   tenant isolation remain correct.

Do not test retirement by deleting a live customer's PBX. Use isolated temporary
store fixtures; physical verification requires an explicitly selected test tenant.
Provider HTTP acceptance is separate from real phone wake and audio acceptance.
