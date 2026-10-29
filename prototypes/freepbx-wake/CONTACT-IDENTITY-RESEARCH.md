# Contact identity investigation — blocked, not deployable

This is research for the isolated prototype, not an identity service or a
provisioning instruction. No SIP registration, call, configuration change,
deployment, or Asterisk write was performed as part of this investigation.
Observations are snapshots; contact/device identifiers are deliberately omitted.

## Evidence

* Mobile enrollment and `JsSipService.ts` both call `getDeviceUuid()` from
  `src/storage/deviceId.ts`. The latter supplies it as JsSIP `instance_id` when
  available; UUID failure is caught and does not prevent the UA from starting.
  The enrolled gateway route uses a one-use ticket; the current proxy does not
  observe successful REGISTER transactions. `tenant-runtime.js` supplies the
  UUID, PBX, extension and authorization revision, but not approved platform.
* Installed JsSIP `lib/Registrator.js` emits the instance as a **Contact header
  parameter** `+sip.instance`, not a URI parameter, together with `reg-id=1`.
  It reuses a randomly generated registration Call-ID while increasing CSeq;
  authentication retries also increase CSeq. On 2xx it matches instance/reg-id
  or falls back to the Contact URI user. A UUID or Call-ID supplied by a client
  is not a credential, and an upstream 2xx alone can be a query, unregister, or
  a response listing other contacts.
* Through the authorized EC2 hop and each PBX's pinned SSH profile, read-only
  Asterisk CLI inspection found Asterisk 18.19.0 on all three. At inspection,
  PBX1/PBX2/PBX3 had respectively 2/0/3 CLI contacts. On PBX3 two dynamic
  AstDB contact objects contained nonempty `call_id` and `uri` and no instance
  field; they had no duplicate nonempty Call-ID or URI within that tiny sample.
  The remaining CLI contact was not established to be a dynamic AstDB object.
  Other PBXs had no parseable dynamic AstDB objects in this snapshot; that is
  not proof that no dynamic contacts exist, nor evidence about other backends.
  We did not establish that any sampled object was a mobile registration.
* The local `ContactStatusDetail` AMI event documentation on all three mentions
  Call-ID but not instance. This was **documentation inspection**, not an AMI
  login or proof of the fields in a live AMI event. The live 18.19
  `PJSIP_CONTACT` function output did not mention `call_id` or instance; whether
  the function is actually available there was not separately established.
* [Asterisk 18.19.0 registrar source](https://github.com/asterisk/asterisk/blob/18.19.0/res/res_pjsip_registrar.c)
  compares existing contacts by URI, stores the request Call-ID when **creating**
  a contact, and on refresh copies the old object without replacing its Call-ID.
  Its response reconstruction uses stored URI and expiration, rather than the
  original `+sip.instance` Contact header parameter. A successful registration
  and matching stored Call-ID thus do not prove current transport ownership if a
  different registration later refreshes the same URI. A 200 response can list
  all contacts and is not by itself proof that the intended one was created.
  [NAT source](https://github.com/asterisk/asterisk/blob/18.19.0/res/res_pjsip_nat.c)
  also shows `rewrite_contact` can change host/port and add URI parameters.
  Source behavior must still be verified against actual builds and configuration.

`test/identity_counterexamples.py` is an intentionally simplified model of two
failure modes, **not** an Asterisk integration test or proof of a solution.

## Candidate: gateway-minted per-session URI tag

A possible controlled experiment is for the ticket-authenticated gateway to
assign a cryptographically random, per-upstream-WebSocket nonce, insert it as a
URI parameter *inside* the sole REGISTER Contact URI, and bind that nonce to the
approved Android/iOS device, PBX, extension and authorization revision. The
nonce must be gateway-generated, not accepted from the client. A strict observer
would match a successful transaction by upstream socket, Via branch, Call-ID,
CSeq and method, independently recheck approval/platform, and require exactly one
unexpired PBX contact with the authenticated session's tag and expected
endpoint/AOR. It would reject malformed or multiple Contacts, wildcard/query and
unregisters as positive evidence, ambiguous mappings, unsupported rewrites,
stale data and closed sessions. Never authorize a different tenant based on an
extension or UUID alone. Existing desktop/CRM requests must not be rewritten.

This is **not yet verified feasible**. In particular:

1. Determine whether URI parameters survive each actual Asterisk NAT/registrar
   transformation and appear in the exact dialable contact returned by
   `PJSIP_DIAL_CONTACTS` and/or live AMI. Header parameters do not suffice.
2. The proxy must preserve JsSIP's response matching, SIP transaction/digest
   semantics, unregister and refresh behavior, routing of incoming requests to
   the original WebSocket, and all dialog traffic. Whether bidirectional rewriting
   is required, safe, and compatible with all supported versions is unproven.
3. A tag is not enough if another client with extension credentials can copy or
   claim it, or if a refresh transfers a matching contact to another transport.
   An unpredictable tag reduces guessing but must not be treated as a secret
   once exposed in signaling. Establish an independently verified, current
   contact-to-proxy-transport binding and define how ownership changes are
   observed and invalidated, including direct PBX clients outside the gateway.
4. A contact can change between select and Dial. A snapshot match, even with a
   nonce, is not atomic with routing. Prove a safe Asterisk/transport boundary
   that prevents stale or replaced contact ownership from reaching desktop/CRM.
5. Establish a mutually authenticated, tenant-scoped PBX-to-gateway service
   channel, reliable approval/revocation and disconnect invalidation, consistent
   contact snapshots, and explicit handling of restart, expiry and reconnect.
   A root-owned Unix socket alone only authenticates the local peer; the current
   AGI request has no tenant identifier and assumes a trusted PBX-local mapping.
6. Validate per-call snapshot/deduplication with multiple concurrent calls,
   identical contacts in different forms/AORs, registrations racing the initial
   Dial, device revocation, and same-extension desktop and CRM. Separate incoming
   calls must not be globally suppressed merely because they share an extension.

Until these conditions are demonstrated on an isolated, version-matched
Asterisk system with synthetic clients, there is no sound implementation of the
identity-service contract. Keep the prototype disabled; do not wire an installer,
enable a marker, alter PBX hooks, or claim no-duplicate or tenant-isolation proof.
