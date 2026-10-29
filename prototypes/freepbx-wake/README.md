# FreePBX extension wake prototype — NOT deployable

This isolated proof of concept is **not an operational push-to-wake solution**.
It does not ship the trusted contact identity service and has not been executed
in Asterisk. No installer, upgrader, or live PBX configuration is changed.

## Generation adapter

`module/functions.inc.php` is a legacy `sokratwake_hookGet_config` callback at
FreePBX's default hook priority 600. It uses `extensions::splice` on a recognized
FreePBX 16/17 `macro-dial-one` shape after policy checks and contact resolution,
before the empty dial-string exit. The complete policy prefix and `dstring`
routine are fingerprinted, including labels, with accepted hashes for the
upstream DAHDI and non-DAHDI variants. Any different layout is left unchanged;
the callback's boolean result is **not** itself a dashboard readiness signal.
The generated instruction additionally requires all of:

* A numeric extension, not an external forwarding leg ending in `#`.
* AstDB `SOKRAT_WAKE/<extension>/enabled` exactly `1`.
* Both the wake prepare and existing Sokrat push-send contexts present.

The marker is not installed or populated here. It must be synchronized from
current approved mobile enrollment, not a hardcoded extension. Installation must
prove the loaded module and effective Asterisk instruction after regeneration;
file presence alone is insufficient. A changed policy or customer fork needs
individual review, not a fallback override. PBX1's pre-existing early hook also
needs an ownership-aware migration before activation; this prototype does not
edit it or customer predial hooks.

`runtime/extensions_sokrat_wake.conf` describes the prospective execution:
ask an AGI whether the extension is eligible, dispatch the existing shared push,
then add one Local leg while preserving all pre-existing contacts. The Local leg
waits at most eight seconds and resolves one attested new mobile contact, while
the outer Dial rings pre-existing devices immediately. This is intentionally a
private context, not an outbound pattern or a `[from-internal-custom]` override.

**Important:** adding a waiting Local leg can alter Dial status, voicemail or
forward-on-unavailable timing for enabled extensions; nested `Dial` may affect
headers, call screening, timeout, caller cancellation, call confirmation and
feature flags. It is not proven compatible with those behaviors. The existing
push sender also needs cancellation/answer correlation validation to avoid stale
notifications. Do not enable a marker until those issues and the tests below
have passed. Queue, ring group, follow-me and alternate extension-call paths
are explicitly not supported by this prototype.

## Identity-service / provisioning contract

The AGI uses newline-delimited JSON over `/run/sokrat-wake/identity.sock`.
Its parent directories and socket must be root-owned; directories must not be
group/other-writable; the socket must not be world-accessible; the connected
peer must have UID 0 (`SO_PEERCRED`). It times out each request after 150 ms and
fails closed. The service is **not implemented**. Its required API is:

* `{"operation":"prepare","extension":"..."}` →
  `{"eligible":true,"endpoint":"..."}` only for currently approved mobile
  registrations and the uniquely associated PJSIP endpoint; false otherwise.
* `{"operation":"select","extension":"...","endpoint":"...","contacts":[...]}` →
  `{"eligible":true,"endpoint":"...","contact":"PJSIP/.../sip:..."}` only
  when the contact is positively bound to that approved mobile device. An empty
  contact means keep waiting; false means stop. No token, credential or caller
  data is returned to the dialplan.

The service must establish and refresh contact-to-device binding from an
authenticated, tenant-scoped registration identity, revoke it on logout, device
revocation, expiry, socket loss and PBX migration, and handle concurrent calls.
User-Agent, WSS transport, contact order, endpoint name, a newly appearing contact,
or SIP URI alone **are not proof of mobile identity**. In particular CRM and
mobile can use the same endpoint and transport. The AGI independently requires
the selected exact contact to appear in current `PJSIP_DIAL_CONTACTS` and not in
the original `DSTRING`, validates its syntax and endpoint, and never selects a
desktop/CRM by itself. This only holds if the service's asserted binding is sound.

Provisioning must install verified module/runtime artifacts and a secured service,
confirm the local extension-to-PJSIP mapping, authoritatively manage eligibility
and revocation, gate on the actual generated/live call path, preserve unrelated
content, and provide a rollback that removes only owned artifacts and markers.
It must not enable the feature merely because the push context is visible. The
installer/upgrader integration belongs to separate work and is deliberately not
part of this directory. Install the AGI in Asterisk's configured AGI directory as
an immutable executable only after review; the sample dialplan is not activated.

## Offline tests

Run `./run-tests.sh` with PHP and Python 3 installed. If PHP is unavailable, set
`PHP_TEST_IMAGE` to a **locally available** Docker image containing PHP; tests
run with networking disabled. The PHP tests run the copied upstream generator
and actual extensions implementation, including regeneration, DAHDI, rejection,
policy ordering and preservation. Python tests exercise AGI protocol and the
contact selector with a simulated identity service. They are not Asterisk,
FCM, or integration tests.

Upstream test fixtures (GPL; corresponding license files are included):

* FreePBX framework 16 `8d033dfa95bcbf692c95c06fa3a714b115557483` and 17
  `7dde21b81e4dd6416018ebb7a102df231503ddbd`, `extensions.class.php`.
* FreePBX core 16 `0b38b6a9e6d10bf562abab51146eeb0721aea2f6` and 17
  `fb43dea0ba9133319a21e6ea9e2ee3c6f7bc61f0`, `Dialplan/macroDialone.php`.

Before any deployment, add fixtures from each actual PBX and prove module hook
ordering and loaded dialplan on isolated, version-matched FreePBX/Asterisk.
Exercise offline mobile, desktop + CRM, already registered mobile, late mobile,
concurrent calls, cancellation/answer races, DND, all forwards, call waiting,
voicemail, call screening, timeout, headers, media and regeneration. Verify
actual provider delivery, SIP registration, INVITE, answer and two-way audio.
Only then can an operator evaluate a reversible test rollout.
