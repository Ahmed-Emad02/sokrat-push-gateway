# Gateway Upgrade Media Convergence Implementation Plan

> **For agentic workers:** Execute this plan task-by-task in the current session. Write a failing test before each change (`skill://test-driven`) and cite fresh evidence before claiming a task done (`skill://verification-before-completion`). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an upgrade converge persisted, active Sokrat-managed media configurations to the promoted renderer without changing tenant identity, transport choice or credentials.

**Architecture:** Reuse the promoted media installer and authoritative enrollment material after host-bundle promotion. Validate registry/disk plan and transport agreement and credential equality before changing generated configuration. Restart only an active managed link whose generated configuration/unit changed; do not enable stopped links or rewrite authority. Enforce the existing legacy TCP proxy contract in enrollment authorization.

**Tech Stack:** Python root upgrade/install helpers; Node test runner with isolated Python/filesystem/process fixtures.

**Spec:** User requests fixing the upgrader so updated PBXs can connect to a gateway seamlessly. Independently observed Sales `hook_failed`: readiness API/identity checks pass, but the deployed gateway renderer and `media.conf` use `proto udp` toward 127.0.0.1:22002, where FRP listens only on TCP; Sales uses `proto tcp-server`. Canonical source already renders legacy TCP correctly. Existing container upgrades promote scripts but do not regenerate previously written media configuration, allowing the bad configuration to survive an otherwise successful upgrade.

## Global Constraints

- No hardcoded Sales/test identity, slot, extension, interface, public host or UDP port in implementation.
- Preserve registry records, installation identity, plan, selected transport, certificates, keys, hook tokens and FRP configuration.
- Skip stopped links; never overwrite an unmanaged unit or an externally changed identity/credential set.
- Preflight all selected links before mutation. Snapshot generated configuration/unit files privately; restore the affected generated files if refresh/restart fails, without overwriting concurrent changes.
- Existing active links already matching the promoted configuration must not be restarted or newly enabled.
- No new gateway trust, device approval, phone upgrade, port selection or firewall permission is part of this code change.
- Legacy transport remains TCP; explicitly selected plain/direct UDP remains selected. Do not silently migrate transport modes.
- Live deployment is Sales-only during an idle window; other gateway tenants must remain untouched.

## Review Focus

- Stale legacy UDP client configuration with a TCP media proxy: refresh produces TCP client configuration with identical authority/material.
- Correct active plain-UDP link: generated files and running process remain unchanged.
- Stopped or unmanaged link: no implicit start or overwrite.
- Plan/transport/credential drift: fail before changing any selected link.
- Failed configuration refresh/restart: restore only affected generated files and report failure; never claim readiness.

---

### Task 1: Refresh persisted managed media after gateway upgrade

**Files:**
- Modify: `scripts/upgrade-container-gateway.py`
- Modify: `test/container-upgrade.test.js`

**Interfaces:** Add an internal `refresh_enrolled_media(env)` phase after host-bundle promotion and before tenant reconciliation. Reuse existing promoted `install-media-link.py` installation behavior and root enrollment readers rather than inventing new trust or material generation APIs.

- [x] Add behavioral fixture coverage for stale legacy configuration, unchanged active UDP, stopped/unmanaged links, identity drift and rollback. Test actual rendered/written configuration and preserved credentials, not source text or forwarded mock arguments.
- [x] Implement the bounded refresh phase with the constraints above.
- [x] Integrate it into the existing upgrade sequence, keeping failures fatal and sanitized.
- [x] Parent runs the focused upgrade tests once the implementation is ready.

### Task 2: Reject incompatible FRP proxy protocols

**Files:**
- Modify: `scripts/tunnel-enrollment.py`
- Modify: `test/tunnel-enrollment.test.js`

**Interfaces:** Existing `authorize_plugin` signature and registration/enrollment schema remain unchanged.

- [x] Add behavioral authorization cases: WS/API require TCP; legacy media requires TCP; explicit direct/plain UDP transport forbids the FRP media proxy.
- [x] Enforce those protocol constraints without changing login credentials, proxy naming, port ownership or transport selection.
- [x] Parent runs the focused enrollment tests with the upgrade tests.

### Task 3: Review, document and verify the existing Sales repair

**Files:**
- Modify: `REVERSE-TLS-ONBOARDING.md`

- [x] Obtain focused independent review of both changes and fix material findings.
- [x] Document upgrade convergence, maintenance-window requirements, rollback and the distinction between configuration repair and real media acceptance.
- [x] Apply only reviewed runtime changes required by Sales; preserve dirty gateway checkout changes and unrelated tenants.
- [x] Verify the actual Sales media nonce and provisioning worker result. Do not hand-edit the status snapshot or claim UDP acceptance from a legacy repair.
