# Gateway approval and onboarding plan

Status: proposed, 2026-10-28. This document does not activate public tenant routing.

## 1. Current implementation and limits

The private control plane already records PBXs, pending devices, operator approval,
claim redemption and revocation. A client generates a random claim secret; only
its hash is stored. After approval and redemption, the server-issued device ID
and claim bearer authorize assigned-PBX APIs and single-use SIP tickets. The PBX
still authenticates the SIP extension/password. Approval is not SIP authentication.

`src/control/store.js:approveDevice()` currently assigns a device directly to an
enabled PBX and extension. It does not establish an independently approved
extension record or verify PBX ownership. The console has one admin credential,
not tenant-scoped RBAC. Automatic enrollment does not establish tenant identity.

The atomic JSON store is a single-writer pilot implementation, not a shared
database. Default caps are 5 enabled PBXs, 25 total PBXs, 200 pending devices,
2,000 devices and 200 audit entries. These are guardrails, not measured capacity.
SIP proxy limits are currently 1,000 sessions plus pending upgrades and three
sockets per device. Per-PBX TURN processes/ports isolate relay credentials and
peer access; they also consume a finite port and process budget.

Legacy public SIP and contacts routing remains separate from the private tenant
runtime. Chrome has caller-name fixes but must not be assumed tenant-enrollment
compatible before its enrollment/ticket path is implemented and tested.

## 2. Identity and the three-field login

Use immutable IDs and tenant-scoped relationships:

- Tenant: customer organization.
- PBX: belongs to one tenant; verified installation identity, not merely a URL.
- Extension: unique `(tenant_id, pbx_id, extension)` identity.
- Device/account binding: references that extension and installation identity.
- Credentials, contacts cache, push registrations, tickets and quotas inherit the
  same scope. Never use extension or installation UUID alone as a tenant key.

Recommended discovery: give each customer a gateway hostname such as
`customer.gateway.example.com`. All hostnames may reach the same gateway fleet.
Login remains **gateway address + extension + password**, with no invite/server
code. Validate the hostname against a configured registry; never trust arbitrary
Host or forwarded-host headers as tenant authorization.

If a tenant has duplicate extensions across PBXs, bind its login hostname to a
specific PBX, or have an administrator preassign the pending request. With one
shared address and identical extension/password tuples, automatic identification
is impossible without another trusted context. Never broadcast credentials or
signed login probes to every PBX, and never select the first matching extension.

Before activation, version the enrollment contract to include an opaque,
server-validated gateway scope. Client storage keys must use canonical gateway
scope plus assigned PBX/extension, not collapse distinct accounts sharing a host.
Existing ambiguous accounts require explicit admin reassignment, not guessing.

## 3. Three approval scopes

### PBX — platform administrator

Lifecycle: pending verification → verified → enabled → suspended → retired.
Keep operational health separate: an unreachable enabled PBX is degraded, not
silently unapproved. Reactivation after address/key changes requires revalidation.

1. Create the tenant and PBX record with allowed private endpoints/media peers.
2. Complete a short-lived, one-time ownership challenge from the PBX installer
   over the private link. Rotate the resulting per-PBX hook/control credential.
3. Check installation identity, API compatibility, WS connectivity, media ACLs,
   relay allocation and quota. Reject conflicting installation claims.
4. Approve and provision idempotently. Do not mark ready until runtime acknowledges
   the desired configuration revision. Roll back only resources created by this
   attempt if provisioning fails.

Endpoint changes need SSRF controls: explicit approved destinations, bounded
timeouts, no redirects, DNS/address revalidation and prevention of access to
metadata, control-plane and unrelated private services. Private PBX addresses
are intentional, so a blanket private-address ban is not the solution.

### Extension — tenant administrator

Sync extension metadata from that PBX through a scoped authenticated API; do not
copy SIP passwords to the gateway. Maintain a separate remote-access policy:
disabled, enabled, suspended, retired. PBX creation remains independent of gateway
approval, so local SIP service continues unchanged.

Support bulk enablement, group policies and automatic enablement for newly created
eligible WebRTC users after tenant opt-in. Store per-extension device/session
limits and allowed platforms. The tenant administrator may delegate within their
own tenant only; platform operators set maximum quotas.

Creation/synchronization must be idempotent. Use a source extension identifier or
generation where available so deleting and recreating the same extension number
does not silently restore old device access. Directory staleness is visible;
automatic onboarding fails closed when identity cannot be verified.

### Device — policy, not mandatory manual work for every employee

Policy modes: manual review (initial default), or automatic approval for an
enabled extension after a scoped PBX credential proof. Proof must bind nonce,
expiry, gateway scope, extension and claim digest, and be verified by the assigned
PBX; a typed extension/device name or valid claim secret is not sufficient proof.
Do not send plaintext SIP passwords to the gateway for storage or discovery.

Manual approval assigns routing but still requires PBX SIP authentication. A
lost device can be revoked individually. Reinstallation produces a new claim and
does not replace a prior device based on UUID alone. Device limits allow mobile
and CRM/desktop/browser use together; they must not evict existing PBX contacts.

Approval UI: tenant/PBX/extension, request age, platform, last activity, credential
proof status, reason and quota usage. Batch actions have preview, authorization
checks per row and explicit partial-failure results. No secret values in the UI.

## 4. Revocation and authorization

Every API and new SIP ticket checks tenant, PBX, extension and device state.
Tickets bind route, device and authorization revision, expire quickly and are
consumed atomically once. Never allow assignment changes to repurpose old tickets.

Publish revocation events to runtimes, with periodic checks as a fallback. Target
new authorization denial immediately after commit and existing WS closure within
10 seconds; measure this rather than assuming it. Emergency revocation closes
active calls; a separate maintenance drain stops new sessions but lets calls end.

Stop push dispatch/registration for revoked assignments. Existing TURN credentials
may remain usable until expiry: WS closure alone does not revoke allocations.
Use bounded credential lifetimes and test allocation termination; emergency
per-PBX relay shutdown is disruptive to that PBX and requires an explicit action.

PBX-local MicroSIP/Zoiper/IP phones and CRM registrations outside the gateway are
not subject to gateway revocation. No global dialplan, trunk, DSP, transport or
contact-eviction changes are part of this plan.

## 5. Storage, runtime and operational scaling

Move the control model to a transactional relational database before multiple
writers or replicas. Suggested tables: tenants, gateway_scopes, pbxs, extensions,
devices, device_bindings, credentials, policies, relay_allocations, audit_events
and an outbox. Enforce tenant-scoped foreign keys, uniqueness, row revisions and
atomic device/session quota reservations. Archive audit history with configured
retention; a 200-entry ring is not a commercial audit log.

Use Redis or equivalent shared atomic storage for single-use tickets, distributed
rate limits and revocation fan-out, not as the sole durable approval database.
Migrate tenant push bindings as well; leaving a shared JSON writer there would
preserve the same scaling bottleneck. Prevent token collisions crossing tenants.

Separate control API, enrollment API, SIP/HTTP workers, push workers and relay
provisioning workers. A durable outbox delivers versioned desired-state updates;
reconcilers retry idempotently and report applied revisions. No concurrent scripts
editing the same JSON files. Existing sessions stay pinned to their gateway/PBX
route; reconnects obtain new tickets. No automatic cross-PBX failover by extension.

Retain isolated per-PBX relays initially. Plan host/IP/port allocation centrally,
measure bandwidth, allocations, CPU and file descriptors, and place tenants across
relay nodes before exhausting host capacity. Do not promise scale merely by
raising the five-PBX cap or sharing TURN secrets across customers.

RBAC: platform admin, tenant admin, delegated extension manager, read-only auditor.
Require MFA for administrators, tenant-filtered paginated APIs and append-only
actor/reason/before-after audit events. Keep the console private through SSH/VPN.
Encrypt backups, test restore, and keep signing/hook secrets outside audit logs.

Track pending age, approval rate, failed credential proofs, rejected routes,
revocation delay, active sessions, relay utilization, provisioning failures and
push failures. Configure per-tenant quotas and global admission control with
fairness under enrollment floods; use jittered exponential polling/backoff.

## 6. Transport caveat — unchanged by this plan

The requested public plain WS on TCP8088 remains unchanged. HTTP/WS does not
provide confidentiality or tamper protection. Claim secrets, bearer credentials
and SIP tickets can be captured on an untrusted path; SIP digest/HMAC does not
solve that. Short ticket lifetime and hashed storage do not protect transit.
This is an explicit security limitation, not a production-security claim.
Production approval rollout needs a separate transport decision; this plan does
not silently enable TLS or require client VPN.

## 7. Delivery order and acceptance gates

1. Preserve legacy routing; publish reproducible client/gateway feature branches.
2. Add tenant/gateway scope and versioned contracts; test duplicate extensions on
   two PBXs including identical passwords, forged Host and cross-tenant cache use.
3. Add verified PBX enrollment, extension policy and tenant-scoped RBAC/audit.
4. Add automatic device policy with assigned-PBX proof, quotas and lost-device
   handling. Cover expired claims, replay, concurrent approval and reinstallation.
5. Migrate stores with a write freeze, backup/checksums, reconciliation and rollback
   before admitting multiple writers. Test restart and database outage behavior.
6. Complete client parity and private canary: desktop, mobile, Chrome and concurrent
   CRM. Verify real cellular incoming wake/Answer/two-way audio, outgoing naming,
   recents, hold, transfer, reconnect, PBX outage and revocation. Keep native SIP
   endpoints and routing unchanged and confirm they still work.
7. Benchmark expected tenant/device/concurrent-call targets and a reconnect storm;
   agree SLOs and headroom from measurements. Validate relay-node exhaustion.
8. Activate public enforcement only with explicit approval and a maintenance plan.
   Canary by validated hostname, never unauthenticated tenant input. Remove legacy
   bypasses for cut-over scopes; do not leave the same PBX publicly accessible by
   an unapproved fallback. Preserve non-migrated customer paths separately.

Before cutover, migrate the authenticated PBX push hook and all required client
API paths, including contacts and transfer directory. Current GET-only contacts
support is not full contacts CRUD/chat/video/status parity. Record endpoint
compatibility explicitly so a successful SIP registration does not hide API loss.

Rollback: retain previous runtime/nginx configuration and store backup, stop new
enrollment during rollback, drain where feasible, and reconcile devices/push state.
Any temporary restoration of legacy access weakens enforcement and must be an
explicit operator decision, not an automatic fail-open on authorization failure.
