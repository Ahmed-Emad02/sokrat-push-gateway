# Automated provisioning rollout gates

Provisioning success means that the configured host operations completed. It
does **not** prove audible two-way audio, cellular reachability, killed-app wake,
or that an additional real PBX has been tested.

## Before activation

- Review the root-owned access profiles. No deployment passwords, private keys,
  hook tokens, or cloud credentials belong in dashboard state or source control.
- Pin each PBX's reviewed routing/media identity. A dashboard edit must not
  redirect a privileged SSH operation to a different host.
- Install the reviewed worker bundle with
  `sudo python3 scripts/install-provisioning-worker.py --apply`. This stops only
  the dedicated worker/timer and leaves the timer stopped; it does not restart
  the tenant runtime, nginx, the legacy gateway, or Asterisk.
- Confirm immutable root ownership of the bundle and all executable ancestors.
- Treat the existing dashboard/control state as untrusted input even when it
  resides on the same host. Automation authorization comes from root-owned
  pinned profiles, not a dashboard-provided command, path, or SSH destination.
- Provide a host-verified, noninteractive PBX access profile. Never disable SSH
  host verification to make onboarding pass.
- Provide authorized, least-privilege cloud access. A missing adapter or denied
  permission must remain blocked/error, never implicitly ready.
- Current test gateway preflight (2026-10-28): AWS CLI absent and no instance
  role available through IMDS. No cloud-rule automation has been activated or
  claimed verified on that host.
- Back up the control store, allocation plan, manifest, hook tokens and existing
  PBX hook/config/dialplan. Preserve file permissions and do not print contents.
- Run the reconciliation dry-run before enabling its timer. Review listener
  assignments and confirm existing allocations cannot be reassigned or revoked
  by an incomplete automation allowlist.
- A failed stage may leave earlier successful stages in place. Retry is
  idempotent; this is not a cross-host atomic transaction. In particular, an
  additive cloud firewall rule is retained rather than deleting an operator's
  potentially shared rule during rollback or disablement.

## First existing-PBX reconciliation

- Ensure no active calls before performing any required initial application
  rollout. Runtime hot reload only avoids *subsequent* call-service restarts.
- Confirm credentials and allocation remain unchanged on repeated runs.
- Confirm the additive push line remains singular and legacy dispatch remains.
- Confirm unrelated PBXs, outbound routing, endpoint settings and audio gains
  remain unchanged.
- Confirm blocked cloud/hook stages remain visible and free of secret material.
- Stop the timer to halt future jobs. Do not reset shared firewall rules or
  delete tenant secrets as a rollback shortcut.

## Second real PBX acceptance

- Test gateway-to-PBX connectivity before enrolling employees.
- Verify authenticated UDP **and** TCP TURN allocation and PBX peer roundtrips
  from outside the gateway's network; an accepted cloud API call is not proof of
  reachability.
- Check tenant isolation: another PBX's peer IPs and credentials must not work.
- Enroll and manually approve a test device with an extension scoped to that PBX.
- Test incoming/outgoing calls, audible two-way audio, background/killed-process
  wake, hangup cleanup, hold/transfers and concurrent mobile/CRM registration.
- Revoke the test device and verify new tickets are refused.
- Ensure the dashboard displays only a recent reconciliation of the exact PBX
  record revision. Editing a PBX after reconciliation must show pending until
  that new revision has been checked; old success is not current readiness.
- Keep legacy coexistence and public plain WS/TCP8088 unchanged unless a separate
  fleet-migration or TLS decision has been authorized.
