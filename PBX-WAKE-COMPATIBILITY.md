# PBX push-to-wake compatibility guard (not deployed)

The schema 1 provisioning worker's `hook=ready` means only that the push
sender appears in the loaded dialplan. It does not establish that an ordinary
extension call reaches the sender, that a recipient is eligible, or that a
newly registered contact can receive the active call. The worker can also
reuse a previously ready result without another SSH check. The control API
therefore exposes the worker's original verdict as `infrastructureState` and
keeps the sender stage, but reports `state=blocked`, `effectiveState=blocked`, `reason=wake_unverified` and
`wake=unverified` whenever infrastructure would otherwise be ready. These
values do not change relay, device admission or PBX configuration. Stale,
pending and error states remain distinct. No schema 1 field can assert wake
readiness; a future implementation needs a separately reviewed evidence and
freshness contract. Readiness here still would not prove phone delivery or audio.

The fail-closed, read-only diagnostic accepts a *running* Asterisk listing:

```sh
asterisk -rx 'dialplan show macro-dial-one' | python3 scripts/check-pbx-wake-compatibility.py
```

It prints only a fixed JSON verdict and returns 2, even for the observed layout.
It does not contact Asterisk itself or modify anything. Its structural match is
diagnostic only, not a version fingerprint or authorization to patch a dialplan.
An unknown, reordered, malformed or oversized input also refuses. The checker
is not wired to automatically provision or attest a PBX. If deployed, the
control status guard does not depend on this checker running and therefore also
downgrades cached historical `ready` snapshots.

## Findings and candidate design

On two test PBXs the active `macro-dial-one` checks forwarding and DND before
building `DSTRING` from `PJSIP_DIAL_CONTACTS`; `Dial` then uses that snapshot.
The third PBX currently has a different priority 1: it invokes
`sokrat-wake-dial` before those checks. Its nested hook waits up to five seconds
only while *no* contact exists. It can therefore run before DND/forwarding,
delay a PJSIP call, and cannot wait for a sleeping mobile when another contact
already exists. The compatibility checker intentionally refuses that layout.
These are observations, not permission to modify that PBX or customer hooks.

One hypothetical approach is a Local-channel companion leg alongside the
ordinary, unmodified dial string, introduced only after applicable forwarding,
DND, call waiting and call-forward-unavailable decisions. It must send only to
currently authorized mobile recipients, snapshot contacts already dialed,
wait for a bounded time without blocking existing desktop legs, and dial only
newly registered eligible mobile contacts. It must propagate cancellation and
call identity safely and retain standard ringback, SIP headers, timeouts,
voicemail and transfer semantics. Contact URI changes, simultaneous new
registrations, token revocation and same-endpoint desktop/mobile registrations
make contact identity and eligibility nontrivial. The current gateway has no
proven PBX-side recipient eligibility or contact-to-device identity contract.

No supported insertion seam or regeneration-safe installer has been verified.
The loaded `macro-dial-one` is generated, and its `-custom` include alone does
not demonstrate an insertion into the existing `s` extension. Replacing a
priority or copying a generated macro can override customer code or drift on
FreePBX regeneration. A future installer must positively identify an approved
version and loaded call path, preserve all customer customizations, detect drift
on every reconciliation, and fail without writes if any check is ambiguous.
It must be tested against actual Asterisk, regeneration, DND/forwarding, mobile
eligibility, duplicate contacts, caller hangup and desktop/mobile concurrent
answer before activation. This prototype intentionally installs no dialplan.
