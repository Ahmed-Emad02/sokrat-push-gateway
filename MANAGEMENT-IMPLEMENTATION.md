# PBX → extension → device management

Implementation branch: `feature/gateway-extension-management`.

Status: deployed to the live private EC2 control/tenant service on 2026-10-28
10:31 UTC; source changes remain uncommitted on the feature branch. Backup:
`/var/backups/sokrat-gateway/management-20261028-103146` (root-only, includes
prior code, control data, runtime manifest and control environment). Only
`sokrat-gateway-control.service` was restarted; the public push process, nginx
configuration, public routing and existing unmanaged PBX were not changed.
Authenticated dashboard/state/extension GETs pass, unauthenticated extension GET
returns401, dashboard assets include management controls, and FCM health is true.
Candidate suite on EC2:147 passed/0 failed/0 skipped; local:148/0/0 (platform
conditional suite count differs). Store remains byte-identical schema1 on disk;
the next dashboard mutation writes schema2. Live schema2 mutation/real-device
acceptance remains untested intentionally; no synthetic production records added.

Latest complete local
gateway verification: **148 tests passed, 0 failed, 0 skipped**; dashboard JS
syntax and `git diff --check` pass. Coverage includes schema migration/persistence,
session/CSRF, quotas under concurrent approval, suspension/claim/runtime checks,
platform validation on reload and approval resets. Dashboard wiring has static
tests and a mocked DOM smoke run, not a live production browser acceptance test.

## Scope

Standard SIP/UDP/TCP proxying and RTPengine are explicitly out of scope. This
management model governs the existing gateway clients and WebSocket SIP runtime.
It does not change local PBX extensions, trunk routing or desktop SIP workflows.

The first increment adds opt-in management metadata to PBXs, unique customer
login hostname reservations, independent PBX-scoped extension access policies,
manual device approval enforcement and private dashboard controls. Legacy PBXs
without management metadata preserve their existing authorization behavior.

An administrator-marked PBX approval is a manual review decision, **not** proof
that automated installation ownership verification has run. Customer labels and
hostname reservations are not tenant RBAC. DNS, reverse-proxy mapping and scoped
client enrollment require separate validated activation before hostname-based
tenant discovery can be claimed operational.

## Safety boundaries

- Keep the console private. Do not expose it via public nginx routes.
- Do not activate public approval enforcement or alter current SIP routing.
- Keep automatic device approval unavailable until assigned-PBX credential proof
  exists. Manual approval is routing permission, not SIP password verification.
- SIP credentials remain authenticated by the PBX; no gateway password directory.
- Extension policy changes affect gateway authorization only, not PBX config.
- The atomic JSON store remains single-writer. Database migration, multi-admin
  tenant RBAC, directory synchronization, ownership challenges and provisioning
  reconciliation remain subsequent increments of `APPROVAL-SCALING-PLAN.md`.

## Initial API and behavior

Authenticated private console routes (existing session and CSRF controls):

- `GET /control/api/extensions?pbxId=…` — list configured gateway access policies.
- `POST /control/api/extensions` — add `{pbxId, extension, name, status,
  maxDevices, allowedPlatforms}`. Policy defaults to disabled, five devices.
- `PATCH /control/api/extensions/:id` — edit name/status/limit/platforms only;
  PBX and extension identity cannot be reassigned.
- Existing PBX create/edit routes accept optional `management` containing
  customer, loginHostname, approvalStatus, extensionPolicyRequired and
  reviewedInstallationId. Hostnames are canonical and unique across PBXs.

The displayed platform policy may reserve `chrome` for client parity, but the
existing enrollment service still accepts android/ios/desktop only. This change
does not make the Chrome extension tenant-enrollment compatible. Extension
identifiers also retain the existing SIP identity validator; policies do not
expand the set of identities the SIP proxy accepts.

Opting a PBX into management requires explicit manual approval before its devices
can authorize. When extensionPolicyRequired is true, an enabled matching policy
is mandatory. When false, an existing policy still applies, but missing policies
preserve legacy extension access. Device platform restrictions are checked both
at approval and authorization. Device limits count approved device bindings,
including approved claims not yet redeemed, atomically with approval.

Suspension denies claim redemption and runtime device authorization; existing
SIP sockets inherit periodic authorization checks. It does not clear SIP passwords
or terminate already-issued TURN allocations immediately. Re-enabling restores
access for still-approved bindings; use device revocation for permanent removal.
Lowering device limits below approved usage requires explicit device revocation
first. Removing a PBX removes its policies and uses the existing device cascade.

Changing a managed PBX API/WS destination, media allowlist, login hostname or
reviewed installation ID returns its approval to pending, even if the same
request asks for approval. Changing endpoints while first opting into management
also requires a subsequent approval action. Equivalent normalized values do not
reset approval. Manual approval can be performed in a subsequent action.
Malformed persisted management/policies or unsupported device platforms fail
closed at initialization; the file is never rewritten or restrictions silently
discarded. This intentionally makes corrupt state unavailable until an operator
repairs it offline or restores a compatible backup; there is no dashboard bypass.
Future persisted management fields require a coordinated schema-version change.

`CONTROL_MAX_EXTENSIONS` is an admission limit (default 5000). Reducing it below
stored usage preserves all policies and allows editing/revocation, while blocking
new policies until usage is below the limit. It does not make the store unloadable.

## Store upgrade / rollback

Schema2 adds management fields and extension policy rows; schema1 files load
without changing legacy PBXs and persist as schema2 on the next mutation.
Back up the data file before deployment. An older schema1 binary must refuse a
schema2 file rather than silently dropping policies. Rollback requires a
coordinated backup restoration/write freeze, not just replacing server source.
Deployment leaves the existing live file unchanged until the next mutation.

## Remaining production gates

Complete customer routing scope and client enrollment parity, transactional
storage, extension directory sync, RBAC/audit, transport security decision,
revocation/media expiry testing and real-device call compatibility gates.
Do not treat this initial management increment as the full scaling rollout.
# Provisioning automation boundary

Additional-PBX host provisioning is handled by the separate worker documented
in [`PROVISIONING.md`](PROVISIONING.md), not by privileged dashboard actions.
The dashboard reads sanitized reconciliation results through its authenticated
`GET /control/api/provisioning` endpoint. Missing, invalid, or stale worker
results must not be represented as readiness. Manual PBX approval is not proof
of ownership and does not itself supply SSH or cloud authorization.
