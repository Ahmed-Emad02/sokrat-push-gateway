# Sales UDP Flow Recovery Implementation Plan

> **For agentic workers:** Execute this plan task-by-task in the current session. Write a failing test before each change (`skill://test-driven`) and cite fresh evidence before claiming a task done (`skill://verification-before-completion`). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover a stalled PBX UDP flow without changing the gateway destination, protocol, identity or media transport.

**Architecture:** Preserve the existing authenticated UDP protocol and TUN device. The PBX creates a fresh ephemeral UDP socket after three keepalive intervals without authenticated session reception, then starts a fresh handshake. Bind the replacement before closing the old socket so the source port necessarily changes. Gateway sockets remain fixed.

**Tech Stack:** Python 3.6-compatible daemon; existing Node/Python protocol fixtures; native two-sided media transaction.

**Spec:** User requires UDP-only call media, HTTPS/WSS unchanged, Sales first. Live native-class probes on the authorized UDP endpoint sometimes exchanged all packets and sometimes completed authentication before going silent. The current daemon creates one socket for its entire lifetime; ClientLink.start changes only the nonce, never the source tuple. The responsible network device is unproven. This fix addresses the demonstrated inability to escape a stalled tuple, not an asserted DPI cause.

## Global Constraints

- No gateway port, firewall, cloud rule, protocol/key/identity or other-tenant change.
- Keep the phone on APK 1.2.24; no account, permission, audio-route or DND changes.
- Recovery timeout is `3 * KEEPALIVE_INTERVAL` (30 seconds); only authenticated session reception extends it.
- Fresh replacement socket binds before the old socket closes. Close the replacement on setup failure.
- Do not recreate the TUN device, rerun hooks or restart the daemon for socket recovery.
- No TCP fallback and no permanent per-packet telemetry.
- Keep canonical and PBX daemon copies byte-identical; do not add source-copy assertion tests.

## Review Focus

- A blackholed first flow recovers bidirectional authenticated DATA on a different source port.
- Healthy keepalive traffic preserves its source socket beyond the recovery deadline.
- Invalid/replayed packets cannot indefinitely postpone recovery.
- Repeated stalls remain bounded; a failed replacement does not leak a socket.
- Gateway listener, virtual addresses, key and TUN/hook lifecycle remain unchanged.

### Task 1: Recover stale client UDP tuples

**Files:** `scripts/udp-media-link.py` in this gateway repository and `/mnt/g/suite/worktrees/sokrat-voip-cold-wake/scripts/udp-media-link.py`; `test/udp-media-link.test.js` in this gateway repository.

**Interfaces:** Add private `_rebind_client_socket(sock)` returning a bound, nonblocking replacement. In `serve`, keep a socket-created timestamp; for role `pbx`, renew when `now - max(socket_created, link.last_received) >= 3 * KEEPALIVE_INTERVAL`, update the timestamp and call `link.start()` before selecting on the replacement. Gateway role never follows this branch.

- [ ] Add behavioral recovery/healthy-session regressions using existing deterministic fixture conventions, not source text or mock forwarding.
- [ ] Implement the narrow client socket recovery and synchronize the tracked PBX copy.
- [ ] Parent runs `node --test test/udp-media-link.test.js`; compile both copies with Python 3.6-compatible syntax and request focused review.

### Task 2: Verify Sales-only UDP transition

- [x] Deploy the tested client daemon to Sales, preserving ownership and unrelated services.
- [x] Prepare both native transaction roles, transfer the peer document without exposing credentials, apply only during an idle window and verify the actual media nonce.
- [ ] Verify retained UDP operation and real outgoing/incoming phone audio. A failed transition is not UDP acceptance; explicitly report any rollback.
- [ ] Retire only Sales' obsolete FRP media proxy after acceptance, retaining WSS/API and a private rollback path.
- [ ] Update existing operational documentation with the observed recovery and UDP result; no repo-wide migration claim before its separate implementation.

## Measured path behavior (Sales, 2026-11-15)

The Sales gateway endpoint drops datagrams whose UDP payload is 64-68 bytes
(92-96-byte IP) after roughly nine packets on a flow, in both directions, while
payloads of 32, 60, 62, 80, 96, 112 and 116 bytes sustain one packet per second
for at least sixty seconds. A fresh source port works immediately, so the
filter is per flow and stateful, not per host or destination port.

Consequences encoded above: every unpadded control frame (HELLO, ACK,
KEEPALIVE) was exactly 64 bytes, so each handshake completed and then went
silent; the link now pads control payloads to `CONTROL_PADDING` (48 bytes of
payload; 112-byte datagrams) and keeps its original ten-second keepalive.
A 70-second capture at that cadence shows sixteen packets on one unchanged
source port with no loss, and the readiness echo still passes 6/6 after 75
seconds of silence, so the cadence was never the defect.

The gateway readiness endpoint answers 503 while a probe is in flight
(`readinessBusy`), so transaction verification must not overlap another probe;
a concurrent diagnostic makes a healthy link look failed.

