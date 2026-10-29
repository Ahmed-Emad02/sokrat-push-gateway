# Synthetic tagged REGISTER experiment — do not deploy

Run from the gateway repository:

```sh
node --test prototypes/freepbx-wake/tag-experiment/correlator.test.js
```

`ws` must already be installed. The integration test uses loopback WebSockets,
a synthetic ticket store and a synthetic registrar. No actual PBX, mobile,
gateway service, device, call or live SIP registration is contacted. This is
not an identity socket server, production proxy, installer, or deployment gate.

## What it demonstrates

* `open` consumes a test ticket via an injected authority, independently
  reauthorizes, and requires Android/iOS, a UUID, PBX, extension, device ID and
  approval revision. A gateway-generated 192-bit random tag is unique per
  session; it is not derived from or supplied by the device UUID. UUID is
  checked against the REGISTER instance as a consistency check, not a secret.
* A narrowly parsed single-contact REGISTER receives the tag **inside the URI**.
  A single outstanding transaction is correlated on the same object/session by
  Via branch, Call-ID, CSeq and REGISTER. Only a matching 2xx containing exactly
  one tagged Contact with an explicit positive expiration creates an observation.
  The response restores that contact's original URI for the client, preserving
  the other synthetic contacts. 401/other failures do not create observations.
* Before each operation, authoritative device scope is rechecked; revision,
  platform, UUID, extension, PBX or device change closes the session. Starting
  another REGISTER, unregister, disconnect, timeout, parsing failure or expiry
  invalidates the previous observation. The expiry is conservatively measured
  from request time. Independent sessions get different tags. Test calls do not
  consume a shared per-extension flag.
* `observe` checks tenant/extension/endpoint, exact URI, unique tag and baseline;
  it **always returns `dialable: false`**, even for a positive observation. It
  intentionally does not implement the existing AGI identity-service contract.

## Important non-claims and fail-closed limitations

This is a research parser, not a general SIP implementation. It rejects folded
headers, unknown Contact syntax, multiple request Contacts, wildcard/query
registrations, URI headers, missing Contact expiry/instance and replays including
retransmits. It requires equal numeric extension/AOR/endpoint, which is not a
general FreePBX mapping. It assumes a trusted authority validates a ticket's
**issuance** scope and consumes it once; the injected test store does this, but
the existing production ticket route does not carry platform and its current
issuance comparison does not include UUID or platform. This experiment cannot
change or certify the production ticket implementation.

The test registrar deliberately behaves as expected. It is not Asterisk: no
claim is made about URI parameter survival under `rewrite_contact`, NAT, URI
normalization, response restoration, authentication/digest, unregister, timer,
incoming INVITE routing, JsSIP interoperability, or actual AMI fields. The test
does not exercise desktop/CRM traffic through the real proxy. Non-REGISTER and
in-dialog traffic are not implemented. On non-2xx or unregister responses this
experiment forwards the synthetic response unchanged, which could expose a tag
in a real multi-contact response; that must be resolved before any trial.

Most importantly, a URI tag is observable signaling data, not proof of current
transport ownership. On Asterisk 18.19 a different authenticated client may
refresh the same contact URI while the original Call-ID remains stored. A
snapshot can also change between `observe` and `Dial`. Positive `observed` does
not authorize a call, even in tests. No claim is made that desktop/CRM can never
be duplicated, or that concurrent calls are safe, in Asterisk.

## Best next boundary to investigate

Prototype a proxy-owned, uniquely routed mobile leg whose gateway checks the
current approved ticket/session **when forwarding the actual INVITE** and cannot
route it to another session. The PBX-to-gateway route and the session's transport
ownership must be authenticated; lost/reconnected sessions must fail closed.
Alternatively, investigate a dedicated mobile AOR/endpoint with per-device
authentication and a separately reviewed PBX mapping, without overriding
desktop routing. Neither alternative is implemented or proven here.

Before enabling anything, use isolated version-matched Asterisk and actual JsSIP
to verify all transformations and routing, prove a safe ownership boundary,
test stale/replaced/revoked contacts and same-extension desktop/CRM, multiple
simultaneous incoming calls, call cancellation/answer, DND/forwarding/voicemail,
and two-way media. Installer work and any authorized deployment come only after
those compatibility acceptance tests pass.
