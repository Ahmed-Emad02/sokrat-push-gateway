# Session-bound mobile route — synthetic experiment only

Run from the gateway repository (requires its installed `ws` dependency):

```sh
node --test prototypes/freepbx-wake/route-experiment/guarded-route.test.js
```

No Asterisk, JsSIP UA, actual device, live registration or real call is used.
Nothing here is wired to the production proxy, PBX dialplan, identity service,
or installers. This is **not** a working SIP proxy, an acceptance test, or an
automatic deployment trigger.

## Intended signaling boundary

The experiment assumes a trusted connection factory has already:

1. consumed a one-use ticket and bound its approved Android/iOS UUID, PBX,
   extension, device ID and revision to one downstream mobile WebSocket;
2. opened **one distinct upstream PJSIP SIP-over-WebSocket connection to that
   same PBX** for that session, authenticated the PBX transport and provided the
   resulting PBX identity independently of SIP headers; and
3. established that the PBX will route the mobile-specific dial leg's INVITE to
   that exact upstream connection, not merely to an address/URI which another
   client can register or replace.

Only then does the synthetic path look like this:

```text
PBX SIP transport -> session-specific upstream WS -> guarded route
    -> that session's downstream WS -> mobile
PBX <- same upstream WS <- mobile response <- same downstream WS
```

The gateway reauthorizes immediately before forwarding each supported frame,
including an initial INVITE. It rechecks local session/socket state after the
async authorization and calls `send` without another await. A pending initial
INVITE is suppressed if a matching CANCEL or disconnect occurs first. Each
route is permanently associated with its socket pair and cannot share a socket
with another route. PBX-side messages have to originate on the paired PBX
socket; a matching URI, tag, extension or Call-ID alone never selects a mobile
socket. In the loopback harness, PBX identity and the ticket authority are
synthetic trusted inputs; this code does **not** implement TLS peer validation,
the PBX connection factory, or the real gateway's ticket lifecycle.

Once the synthetic PBX delivers an initial INVITE to the correct connection,
the test routes selected provisional/final responses, ACK, CANCEL/487, and BYE
and its response through that pair. It copies SDP bytes unchanged but does not
process, establish or test media. Separate synthetic Call-IDs can be in flight
simultaneously; their state is per route and call. The code checks basic branch,
Call-ID and CSeq consistency, but deliberately rejects much valid SIP.

## What the tests demonstrate—and do not

The tests use four or more loopback WS endpoints per scenario, a one-use fake
ticket and fake authorization. They exercise two simultaneous synthetic calls,
two mobile socket pairs sharing an extension, a separate desktop socket that is
never connected to a route, revocation, failure/timeout, disconnect, mismatched
transactions and cancellation both before and after forwarding. They confirm
that **this lab route** does not send a frame to the other mobile or desktop
socket. They do not prove FreePBX's original Dial and late Local leg cannot
both dial the same device, or that a PBX will not route a request directly to a
different contact before it reaches this gateway. Distinct legitimate incoming
calls must not be deduplicated globally. Per-call deduplication needs a trusted
linked-call identity and an atomically consistent original-Dial baseline; neither
is implemented here.

## Concrete blockers to actual operation

* **Routing/ownership:** prove with version-matched isolated Asterisk that a
  mobile-specific Dial targets the gateway's *existing* registered PJSIP WS
  transport. `rewrite_contact`, WSS vs WS, NAT host/port rewriting, connection
  reuse, contact replacement, path/URI normalization, and direct PBX clients may
  cause Asterisk to use a different transport or send before the gateway sees
  anything. The tags in the neighboring experiment are observable and do not
  prove ownership. A target that routes around the guard is unacceptable. Do not
  confuse PJSIP SIP-over-WebSocket with Asterisk's separate WebSocket **media**
  channel. End-to-end authenticated WSS or an equivalently authenticated
  private transport and proper PBX identity binding are still required.
* **Revocation atomicity:** this experiment's authority is an async callback.
  A revocation can happen just after it returns or after `send` queues bytes;
  there is no atomic authority/transport commit or delivery recall. A bounded
  timeout and local close help but do not eliminate that race. Real lifecycle,
  authorization-revision propagation, process restarts, reconnect and shared
  multi-process state need a defined enforcement boundary.
* **SIP transactions and dialogs:** only a narrow happy-path subset is parsed.
  Retransmits, forking and multiple To tags, overlapping re-INVITE/UPDATE,
  authentication, redirect, route sets and Record-Route, reliable provisional
  responses, glare, 2xx/CANCEL race, transaction timers, retransmitted ACK,
  hold/transfer, and client-initiated requests beyond BYE are not implemented.
  Headers, URI, Via, Contact and dialog routing are not rewritten. Compatibility
  with actual JsSIP and Asterisk is not tested.
* **Failure/cancel:** CANCEL before the INVITE is forwarded only suppresses both
  frames; it does **not** synthesize SIP 200/487. On revocation, timeout, bad
  signaling or socket loss the lab closes sockets; it does not generate 4xx/5xx,
  CANCEL, BYE, or a full PBX/mobile transaction cleanup. Unrelated calls on the
  same transport can consequently be affected. A real implementation needs a
  standards-compliant proxy/B2BUA or equivalent transaction layer and explicit
  policy for established calls.
* **Original call semantics:** FreePBX dial status, answer/cancel race, forwarding,
  DND, voicemail, push identity, duplicate suppression, headers, media and audio
  remain unvalidated. The existing late-leg adapter remains disabled.

The next decisive experiment is a disposable version-matched Asterisk instance
with synthetic PJSIP clients and isolated credentials: observe which physical
upstream socket receives an INVITE after contact registration, replacement,
NAT rewrite and reconnect, then verify the entire dialog. Until then, this
experiment cannot establish a safe delivery guarantee or justify deployment.
