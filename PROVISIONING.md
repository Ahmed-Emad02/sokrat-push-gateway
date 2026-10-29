# Tenant provisioning reconcile worker

Status: provisioning worker/timer deployed on the test gateway; AWS configured,
SSH authorization remains per PBX. Source uncommitted. Verify the suite map for
the current deployment state. The acceptance record is in
[`PROVISIONING-ACCEPTANCE.md`](PROVISIONING-ACCEPTANCE.md).

`scripts/reconcile-tenant-provisioning.py` is a bounded, root-run, one-shot
worker. It reconciles the three provisioning planes for a customer PBX:

1. the isolated TURN relay (local systemd unit, ufw rules, runtime manifest),
2. the cloud firewall (provider adapter),
3. the customer PBX push hook (SSH/PBX-API adapter).

It is normally started by `systemd/sokrat-tenant-provisioning.timer` every 60
seconds. It is **not** a dashboard feature: the web dashboard can create PBX
records, but only a root operator can authorize provisioning of a specific
identity.

---

## 1. Authority model (read this first)

| Thing | Owner | Executed by root worker? |
| --- | --- | --- |
| `/opt/sokrat-push-gateway` (app dir) | service user (`sokrat-push`) | **Never** |
| `/usr/local/lib/sokrat-tenant-provisioning` (bundle) | root, immutable | **Only this** |
| `/etc/sokrat/gateway-provisioning.json` | root, `0600` | read |
| `/etc/sokrat/gateway-runtime.env` | root, `0600` | read (passed to sync) |
| `/var/lib/sokrat-gateway/control.json` | service user | read as untrusted input |
| `/var/lib/sokrat-gateway/tenant-plan.json` | service user | read as untrusted input |
| `/run/sokrat-tenant-provisioning` | root, `0700` | lock + private snapshot |
| `/var/lib/sokrat-tenant-provisioning/status.json` | root `0640` root:`<service group>` | written |

The live finding that drives this: `/opt/sokrat-push-gateway` is uid 999/service
owned and the sync script there is uid 1000. Root must not execute anything from
a service-writable path. The installer copies the reviewed worker, sync script,
adapters and hook installer into the root bundle; the worker refuses to run from
anywhere else in production (no `--allow-unprivileged`).

Every helper, the worker itself, the config and the env file must be regular
files, not symlinks, root-owned, not writable by group/other, with root-owned
non-mutable ancestors. The status parent must be root-owned as well; a custom
service-owned status directory is rejected (not chowned, not written).

This is **not a one-click flow**: a one-time root setup (bundle install, adapter
authorization, pinned config) is required before the timer can be enabled.

---

## 2. One-time root setup

```bash
# 1. Review the bundle and units. Dry-run only validates destinations.
sudo /usr/bin/python3 scripts/install-provisioning-worker.py
sudo /usr/bin/python3 scripts/install-provisioning-worker.py --apply
```

The installer (owned by the deployment agent) copies:

```
/usr/local/lib/sokrat-tenant-provisioning/
  reconcile-tenant-provisioning.py
  sync-tenant-runtime.py
  provisioning-firewall-aws.py     # cloud firewall adapter (operator-specific)
  provisioning-hook-ssh.py         # PBX hook adapter (operator-specific)
  install-tenant-push-hook.py
  pbx-tenant-push-hook.py
/etc/systemd/system/sokrat-tenant-provisioning.{service,timer}
```

It stops only these units (timer first), backs up prior files under
`/var/backups/sokrat-gateway/provisioning-*`, runs `systemctl daemon-reload`,
and **does not enable the timer**. After successful promotion it restarts the
onboarding service and timer only if each was already active; it never directly
starts the oneshot worker. On a failed promotion, stopped units remain stopped
and an operator must inspect and recover them. It refuses to promote while a
manual run holds the worker lock or while either persistent unit is changing state.
Restoring the timer preserves reconciliation, but does not establish that a PBX
call path invokes push or that mobile wake works.

The adapters are trusted root executables. They are referenced by the root
config (`firewallAdapter` globally, `hookAdapter` per PBX) and are the explicit
mechanism by which the operator authorizes the worker to touch a provider API or
a customer PBX. They may use operator-managed deployment credentials and SSH
configuration. The worker itself never supplies deployment credentials, never
guesses a target and never reads customer secrets; the only private runtime
material it reads is the gateway-owned hook-token file, solely to place that
token in the hook adapter's stdin. If an adapter is missing, the affected PBX is
blocked (`firewall_required` / `hook_required`) rather than reported ready.

```bash
# 2. Write the root-private config (example in §3), mode 0600 root:root.
sudo install -m 0600 -o root -g root /dev/null /etc/sokrat/gateway-provisioning.json
sudoedit /etc/sokrat/gateway-provisioning.json

# 3. Validate before enabling anything. Dry-run writes nothing and runs nothing.
sudo /usr/bin/python3 /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --dry-run

# 4. Enable the timer explicitly (60 s cadence, first run after 90 s).
sudo systemctl enable --now sokrat-tenant-provisioning.timer
```

---

## 3. Root config

`/etc/sokrat/gateway-provisioning.json` (schema 1, `0600 root:root`):

```json
{
  "schemaVersion": 1,
  "lockDir": "/run/sokrat-tenant-provisioning",
  "statusFile": "/var/lib/sokrat-tenant-provisioning/status.json",
  "controlFile": "/var/lib/sokrat-gateway/control.json",
  "runtime": {
    "syncScript": "/usr/local/lib/sokrat-tenant-provisioning/sync-tenant-runtime.py",
    "envFile": "/etc/sokrat/gateway-runtime.env",
    "gatewayUrl": "https://gateway.customer.example",
    "stateDir": "/var/lib/sokrat-gateway",
    "turnRoot": "/etc/sokrat/turn",
    "unitDir": "/etc/systemd/system",
    "iface": "tailscale0",
    "serviceUser": "sokrat-push"
  },
  "firewallAdapter": "/usr/local/lib/sokrat-tenant-provisioning/provisioning-firewall-aws.py",
  "pbx": {
    "pbx_customer": {
      "wsURL": "wss://pbx.customer.example:8089/ws",
      "apiURL": "https://pbx.customer.example:8080/",
      "mediaIps": ["192.0.2.10"],
      "approval": "approved",
      "fingerprint": "<sha256 of the four fields above>",
      "hookAdapter": "/usr/local/lib/sokrat-tenant-provisioning/provisioning-hook-ssh.py"
    }
  }
}
```

* `runtime.envFile` must be a root-private `KEY=VALUE` file (mode `0600`) that
  sets `GATEWAY_PUBLIC_HOST`, `GATEWAY_LISTEN_IP` and `GATEWAY_PRIVATE_IP`. The
  worker reads `GATEWAY_PUBLIC_HOST` to verify the manifest relay host.
* `runtime.gatewayUrl` is passed to both adapters as `gatewayUrl`.
* `firewallAdapter` is global. Absent means no PBX can become ready.
* `hookAdapter` is per PBX. Absent means that PBX is blocked.
* `statusFile` must never be `control.json`. Default:
  `/var/lib/sokrat-tenant-provisioning/status.json` (parent `0750 root:<service
  group>`, file `0640 root:<service group>`). The gateway service can read it;
  it cannot write it.
* Unknown config/pin fields are rejected, so a typo cannot silently drop a pin.

### Pin fingerprint

The pin covers exactly the routing identity and approval status:

```
sha256(JSON({"apiURL": <canonical>, "approval": "approved"|"unmanaged",
             "mediaIps": [<sorted canonical IPs>], "wsURL": <canonical>}))
```

with Python's `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
URLs are canonicalised like the dashboard (`scheme://host[:port]/path`; default
ports dropped; no credentials/fragment; empty path becomes `/`). Media IPs must
be plain IPv4/IPv6 addresses (the relay cannot use CIDR blocks).

Print a pin to paste into the config:

```bash
sudo python3 - <<'PY'
import hashlib, json
ws, api = "wss://pbx.customer.example:8089/ws", "https://pbx.customer.example:8080/"
media, approval = ["192.0.2.10"], "approved"
doc = {"wsURL": ws, "apiURL": api, "mediaIps": sorted(media), "approval": approval}
print(json.dumps(doc, sort_keys=True, separators=(",", ":")))
print(hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
```

**Scope of the pin:** endpoints (`wsURL`, `apiURL`), media peers and the
management approval status. It deliberately does **not** pin
`loginHostname` or `reviewedInstallationId`: those are dashboard assertions, not
proof of installation identity, and the dashboard may change them together with
an approval in one action. The precise, independently pinned claim is the
endpoint/media identity plus the approved status. Privileged PBX access is
pinned separately inside the hook adapter (root-owned, operator-authorized).

---

## 4. Eligibility and global refusal

A PBX is **eligible** only when all of these hold:

* it exists in `control.json` and is `enabled: true`;
* it is pinned in the config and its canonical `wsURL`, `apiURL`, `mediaIps`
  and approval status match the pin (and the pin's own fingerprint matches);
* managed record (`management` present): pin `approval` is `approved` and the
  dashboard `approvalStatus` is `approved`;
* unmanaged record (`management` absent): pin `approval` is `unmanaged`
  (presence in the root config is the explicit opt-in);
* it has at least one media peer;
* the global firewall adapter and its per-PBX hook adapter exist.

### Global refusal (exit 2, no changes)

The whole run is refused — no sync, no adapters — when any of these is true:

* an **existing allocation** in `tenant-plan.json` is not pinned in the config;
* an existing allocation has no dashboard record (the record was deleted or is
  unknown to the dashboard);
* a PBX with an existing allocation fails its identity pin or its approval gate;
* an eligible PBX with an existing allocation has no firewall/hook adapter.

A pinned record that is absent from the dashboard **without** an existing
allocation is only blocked for itself (`not_configured`); the rest of the run
proceeds, because sync never touches a PBX that has no allocation.

Why so strict: `sync-tenant-runtime.py` revokes (stops the unit, removes ufw
rules and the service secret copy) every allocation that is not an enabled
record in its input. A filtered snapshot that omitted an allocation would
silently take another customer's relay down. Refusing is the safe answer; the
status document tells the operator which PBX is at fault, and every other PBX is
marked `blocked` (`stale` if it had previously been ready).

A PBX with **no** existing allocation does not affect sync: a pin/approval
problem there blocks only that PBX and the rest of the run proceeds. Unknown/new
dashboard records are never provisioned until the operator pins them.

### Disabled records

A **pinned** record with `enabled: false` that already has an allocation is
passed to sync as `enabled: false` (documented sync behaviour: stop/disable the
isolated unit, remove ufw rules and the service secret copy; the allocation,
TURN secret and hook token are retained). It is reported `blocked`
(`not_configured`) with stages `skipped`. **No hook is installed.** Cloud
firewall policy is intentionally **retained**: the provider adapter is additive,
and this worker does not claim to deallocate cloud rules for a disabled PBX.

Unpinned existing allocations are never revoked: they trigger the global refusal
above.

---

## 5. One reconcile run

1. Load config, control store, plan, manifest, tokens. Capture the control-store
   byte SHA-256.
2. Preflight: helper/config ownership, status target, adapter presence, plan
   arithmetic, pins.
3. Decide whether work is needed. A PBX is skipped only if the previous status
   is root-owned and private, says `ready`, its fingerprint is unchanged, and
   the root-owned evidence still verifies: manifest relay host/port/peers,
   `hookHashes[pbx] == sha256(token)`, the private relay secret at the derived
   path, and the isolated unit is `active`.
4. If any PBX needs work, run the reviewed `sync-tenant-runtime.py` as a
   subprocess (never a shell) with a root-private filtered snapshot
   (`<lockDir>/control.snapshot.json`, `0600`, deleted afterwards). Zero
   warnings required; any warning aborts before adapters.
5. Verify the manifest again: relay host equals `GATEWAY_PUBLIC_HOST`, port
   equals the allocation listener, peers equal the pinned media IPs,
   `secretFile` is the derived `secrets/<slug>.secret` and is private,
   `hookHashes[pbx]` equals `sha256(token)`, unit `sokrat-tenant-turn@<slug>`
   is `active`.
6. Call the firewall adapter (`enabled: true`), then the hook adapter (token in
   stdin only).
7. Re-read the control-store SHA-256 **before every privileged stage and before
   reporting ready**. A mismatch aborts the run: no PBX is reported ready and
   every PBX becomes `error` / `worker_failed` with stages `pending`.
8. Write the sanitized status atomically (`0640 root:<service group>`), with a
   fresh `updatedAt` on every timer run — including a fully skipped/idempotent
   run.

The worker never restarts the shared gateway/control runtime. A manifest change
is picked up for new relay and hook lookups by the tenant runtime's manifest
loader. Established WebSocket connections are not restarted.

---

## 6. Adapter contract

Both adapters are root-owned executables inside the bundle, not writable by
group/other, with safe root-owned ancestors. They are selected only by the
root-private config (`firewallAdapter`, `hookAdapter`); the dashboard cannot name
an executable. The installer copies `provisioning-firewall-aws.py` and
`provisioning-hook-ssh.py` from the reviewed source snapshot.

```
argv:   [adapter, pbxId]
stdin:  one JSON object
env:    PATH, LANG, LC_ALL only
stdout/stderr: /dev/null (never logged, never buffered)
timeout: 360 s (allows the SSH adapter's configured 30–300 s deadline)
exit:   0 = success, anything else = failure
shell:  never
```

Request keys:

```json
{
  "pbxId": "pbx_customer",
  "gatewayUrl": "https://gateway.customer.example",
  "listenerPort": 3500,
  "peerIps": ["192.0.2.10"],
  "enabled": true,
  "token": "…"
}
```

* `token` is present **only** in the hook request. It never appears in argv, the
  firewall request, the status file, logs or error messages.
* The firewall adapter is called only for enabled PBXs. Disabled PBXs are not
  sent (cloud policy retained).
* The hook adapter is the explicit operator authorization to SSH to the PBX and
  install the additive push hook using the supplied token. The local sync stage
  owns the manifest's `hookHashes[pbx]`; the SSH adapter does not edit it.
* The relay port range is derivable from `listenerPort` (slot = port − 3500,
  relay = 50000 + slot×100 … +99) if an adapter needs it.

---

## 7. Status document

`statusFile` (default `/var/lib/sokrat-tenant-provisioning/status.json`,
`0640 root:<service group>`):

```json
{
  "schemaVersion": 1,
  "updatedAt": "2026-10-28T12:00:00Z",
  "pbx": {
    "pbx_customer": {
      "state": "ready",
      "stages": { "relay": "ready", "firewall": "ready", "hook": "ready" },
      "reason": "ready",
      "fingerprint": "9f2c…",
      "capturedUpdatedAt": "2026-10-28T10:00:00Z"
    }
  }
}
```

* `state`: `ready` | `blocked` | `error` | `planned` (dry-run only).
* stage values: `pending` | `ready` | `blocked` | `error` | `planned` | `skipped`.
* `reason` (allowlist): `not_configured`, `identity_mismatch`,
  `approval_required`, `relay_failed`, `firewall_required`, `firewall_failed`,
  `hook_required`, `hook_failed`, `ready`, `planned`, `stale`, `worker_failed`,
  `configuration_invalid`.
* `fingerprint`: SHA-256 of the dashboard routing identity
  (`wsURL`/`apiURL`/`mediaIps`/approval), or the pinned value when the record is
  unavailable; `null` only when neither exists.
* `capturedUpdatedAt`: the PBX record's `updatedAt` **as read for this run**. A
  UI should compare it with the current record's `updatedAt`; a mismatch means
  the dashboard changed during/after the run and the entry is stale, regardless
  of `updatedAt` (which is only the run timestamp).
* `stale` is emitted for a previously-ready PBX whose status could not be
  refreshed because the run was globally refused. Consumers should also treat
  `updatedAt` older than ~2 minutes as stale (the timer runs every 60 s).

No secrets, URLs, IPs, tokens or adapter output are written to this file.

---

## 8. Locking and concurrency

* Lock: `flock(LOCK_EX | LOCK_NB)` on `<lockDir>/lock` (default
  `/run/sokrat-tenant-provisioning/lock`, dir `0700 root`). The descriptor is
  held for the whole run and released by the kernel even after `SIGKILL`, so a
  crashed run cannot permanently block the timer. The file is never deleted.
* `--dry-run` never creates the lock directory or file; it only probes an
  existing lock read-only.
* The control store is hashed before privileged stages; dashboard edits abort
  the run without stale ready.
* The installer refuses to replace the bundle while a run holds the lock.

---

## 9. Dry-run, exit codes, tests

```bash
# Default mode: no writes, no commands, no lock creation.
sudo /usr/bin/python3 /usr/local/lib/sokrat-tenant-provisioning/reconcile-tenant-provisioning.py --dry-run
```

| exit | meaning |
| --- | --- |
| 0 | no error state: `ready` / `planned` / per-PBX `blocked` |
| 1 | at least one PBX `error`, or the worker failed (`worker_failed`) |
| 2 | global refusal before any change (`configuration_invalid`, allocation/identity/approval gate) |

`--allow-unprivileged` exists only for staging fixtures and the test suite; it
relaxes root/bundle ownership checks and permits `--apply` without root. Never
pass it in the systemd unit.

Tests:

```bash
node --test test/provisioning-worker.test.js
```

They run the real worker against throwaway directories with a fake sync script,
fake `systemctl` and fake adapters (no root, no network, no live state) and
cover: dry-run purity, ready path and adapter payloads, 0640 status, token
redaction, idempotent skip with a fresh `updatedAt`, retry after adapter
failure, pin mismatch, approval mismatch, unlisted/orphan allocations, unknown
records, missing firewall adapter, disabled records (no hook, cloud retained),
invalid plan arithmetic, dashboard edits mid-run, `flock` refusal and SIGKILL
release, untrusted status files and status-parent rejection, and
`capturedUpdatedAt`.

---

## 10. Explicit non-goals

* Never writes `control.json` (status is a separate file, checked not to be a
  control store).
* Never approves devices, never enables global routing, never changes tenant
  routing.
* Never restarts the shared runtime, nginx, Asterisk or the call path.
* Never invokes a shell, never passes tokens on argv, never logs adapter output.
* Never provisions a dashboard record that the root config has not pinned.
* Never revokes an existing allocation that is not pinned; it refuses instead.
* Cloud firewall deallocation for disabled PBXs is not performed (policy is
  retained; the adapter is additive).

## 11. Deployment state

Local files only: `scripts/reconcile-tenant-provisioning.py`,
`test/provisioning-worker.test.js`, `systemd/sokrat-tenant-provisioning.service`,
`systemd/sokrat-tenant-provisioning.timer`, this document. The installer is
maintained separately. Nothing was deployed, enabled or committed; the timer is
stopped and no live mutation was requested pending review.
