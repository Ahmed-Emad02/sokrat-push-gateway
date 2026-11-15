# Reverse-TLS onboarding — acceptance and operator runbook

## Release status

**Feature release; production phone acceptance is not complete.** Do not treat
unit tests or dashboard “ready” as employee-call acceptance. On2026-10-30 the
operator explicitly authorized production `higher-travel-2` enrollment. Published
PBX feature commit `f19fdd493be0caca62efe02b6e8e20304605e6af` is activated there;
tenant `pbx_785030b5a94a3eec` has real relay/firewall/hook readiness and verified
public UDP/TCP reverse-media probes. Existing test-tenant/device authority is
unchanged. Production has no WebRTC employee extensions yet; no production phone
was approved or call-tested. Normal production incoming-call macros do not invoke
push wake; WebRTC-only call-path integration and physical phone acceptance remain
required. Do not replace shared desktop macros. Full inventory/backups/evidence:
suite `PRODUCTION-REVERSE-TLS-ROLLOUT-20261030.md`.

Validated on the selected test PBX:

- Pinned HTTPS enrollment with a PBX-generated persistent installation identity.
- Existing tenant adoption with an explicitly reviewed public-record digest.
- Tenant ID and all existing phone approval/revocation states preserved.
- Live FRPS authorization: exactly the assigned API, WS and media proxies.
- OpenVPN 2.4 PBX ↔ OpenVPN 2.6 gateway, mutually authenticated AES-256-GCM,
  MTU 1400; PBX connects outbound through FRP, no office/default routes.
- Reconciler verifies the installed hook token and a fresh UDP nonce roundtrip.
- Public UDP **and** TCP TURN allocation and PBX UDP echo over the media link.
- Public TURN rejects loopback, metadata, gateway and another tenant's peers.
- A real PBX listener outside its RTP range cannot be reached through TURN.
- FRPC restart recovers actual readiness without changing tenant/device authority.
- Asterisk-user hook reaches the pinned HTTPS gateway endpoint (no-device fixture;
  **not** evidence of a delivered wake notification).
- WordPress on port 80, control dashboard on 8002 and FCM initialization preserved.
- Reconnected Android phone reuses its saved approved account and registers through
  the migrated reverse WS route. Existing revoked phones remain revoked. A
  later internal echo call was answered and SIP-confirmed, with ICE connected and
  bidirectional call traffic captured on the isolated media link. Local hangup
  ended the phone session cleanly; later PBX check found no remaining channels.
  User confirmed clear audible echo (microphone → PBX → phone) on Wi-Fi with
  no active VPN transport. A second call verified remote PBX hangup: phone received
  BYE and closed the connected session; PBX had no remaining channels.
- Outgoing internal `*43` echo: user confirmed connection and audible echo; PBX
  executed Answer, prompt and Echo. Phone hung up with ICE completed/connection
  connected; PBX channels cleared. This does not test an external trunk call.
- One killed-app Android wake through the existing internal extension route:
  process absent and package not force-stopped before calling; a new process
  handled headless push, registered, received INVITE and confirmed the answered
  call. Remote hangup removed all PBX channels. Background calling also passed.
  This is one Wi-Fi test on the approved Honor phone, not universal wake proof.
- Mobile-data cold wake on Vodafone LTE: Wi-Fi off, mobile data on (IPv4
  `10.232.10.118`), phone locked, app absent. Push started a new process, which
  registered over mobile data; push and SIP used the same scoped ID
  `3685354d-…`; the call answered, ICE relay connected and remote hangup cleared
  the PBX channel (495/498 opus, no loss). One Android device, not universal.
- Cold decline on mobile data: push started a new process, registered, INVITE
  matched scoped ID `21fab798-…`; the user declined, the app dispatched the
  decline, and the PBX ended the ringing channel with no answer or media.
- Push/SIP application-call correlation on the live deployed fix: PBX raw
  `26b526d7-…` mapped to `f5b6cda8-1b56-5278-ae07-db900eab3e13` in the push
  payload, the phone's SIP INVITE log, and a gateway wire capture of
  `X-Sokrat-Call-ID`. The call answered, ICE connected and the scheduled remote
  BYE ended it cleanly; protocol Call-ID/SDP were untouched. A post-fix killed-app
  wake at01:42 also answered and cleared remotely, but its phone log rotated
  before IDs could be read; the01:48 capture supplies the ID proof.
- Employee SIP over trusted WSS: Let's Encrypt IP certificate for
  `89.117.54.235` (shortlived profile, SAN IP, valid2026-10-29→11-05), issued
  through the existing WordPress webroot and renewed by snap certbot with a
  deploy hook that copies the cert to `/etc/sokrat/tls` and reloads nginx.
  WSS listens on8089, proxies `/ws` to the tenant runtime, and rejects
  unauthenticated upgrades. UFW8089 is open. Phone TLS toggle and registration
  verified08:17 EET (established8089 socket, no8088 connection). An answered
  incoming echo call confirmed08:19:01, relay ICE connected, remote BYE ended it
  after10s, and PBX channels cleared (477/479 opus packets). Push/SIP application
  IDs matched. User confirmed audible clear echo but intermittent stutters.
  Read-only follow-up found variable network RTT (actual media tunnel59–139ms,
  40/40 UDP echoes), healthy server capacity and zero tunnel-interface drops.
  Network jitter/TCP stalls are plausible, not a proven cause; receiver
  concealment/jitter-buffer stats during a stutter remain needed. See suite
  `VOICE-STUTTER-REPORT-20261030.md`; user deferred this investigation, not a
  claim that audio-quality acceptance is complete.
- Trusted employee HTTPS443 now routes only `/api/gateway/*` to tenant9097.
  Public capabilities200, unauthenticated ICE/contacts403, admin/legacy webhook
  paths404. WordPress80/dashboard8002 and device authority are unchanged.
- Updated test APK installed in place at09:20:36 EET without clearing accounts:
  saved approved identity reused, push token confirmed and Asterisk registered.
  Gateway sockets show phone HTTPS443/WSS8089. Both revoked phones stay revoked.
  Evidence: suite `/tmp/opencode/mobile-https-installed-20261030.log` and
  `gateway-https-phone-sockets-20261030.log`. This APK remains debug/test-signed.

Not yet established:

- Fresh phone enrollment → approval → SIP registration over the migrated route
  (existing approved-account registration is verified).
- External outbound trunk calling and real two-party conversation; incoming and
  outgoing internal echo audio and both local/remote hangup are verified.
- Repeat cold wake across supported Android OEMs and locked-idle variations;
  APNs is disabled, so iOS wake is not accepted.
- Fresh-host bootstrap beyond the isolated fresh-filesystem container test (which
  passed clean init, second-init refusal, interrupted no-config and retry with
  the local fixed scripts) and recovery from every PBX-side partial enrollment
  failure. The deployed host scripts are still the older ordering.
- Updated-APK answered-call/media and cold-wake acceptance: HTTPS push-token
  registration and WSS registration are verified, but the final call was not
  answered. Push/SIP ID matched; remote CANCEL ended ringing09:47:59 EET.
  Earlier APK echo/wake acceptance does not establish this updated build's full
  acceptance. Fresh production signer and first employee enrollment remain open.
- Live certificate-renewal and complete container upgrade/rollback acceptance.

## Deployment boundaries

Latest test deployment applies the reviewed call-ID source overlay to the running
container and restarts only its control process (no container recreation). The
matching derivative image is tagged `sokrat/push-gateway:latest` for recreation;
backup `/var/backups/sokrat-gateway/call-correlation-20261029T233742Z`. The host
checkout differs from deployed source and was not overwritten. Do not rebuild
from that stale checkout and assume the correlation fix is included. The separate
bootstrap activation-marker recovery fix is still local and was not deployed.

Employee HTTPS deployment (2026-10-30): current next-recreate image is
`sokrat/push-gateway:employee-https-20261030T063617Z` (also tagged `latest`),
backup `/var/backups/sokrat-gateway/employee-https-20261030T063617Z`. It includes
the call-ID fix plus conditional HTTPS/WSS rendering. No container recreation
was performed. `configure-gateway-tls.sh` reads mounted `/etc/sokrat/tls`:
`GATEWAY_TLS_ENABLED=auto` skips TLS when both cert/key are absent, `true`
requires both, and partial pairs fail startup. HTTPS443 and WSS8089 are defaults;
port overrides are validated. This does not issue certificates or open firewall
ports; those remain explicit host installation tasks. The bootstrap-marker fix
is separate and still not promoted. Local regressions after the HTTPS change:
gateway390/390; mobile21 suites/196 tests; TypeScript and diff checks pass. The
new standalone APK is signed with the existing Android Debug test key, so this
is not a production-signed app release.

Gateway host bundle:

```sh
python3 scripts/install-tunnel-enrollment.py
```

### Direct-UDP media transport

New enrollments default to the authenticated plain-UDP wire-v2 transport on the
tenant's canonical `26000 + slot` gateway endpoint, using the configured public
host and a per-tenant `udp.key`; the endpoint and key persist in the registry and
material file so retries reuse the exact identity. Existing registry rows with
no `mediaTransport` remain on the legacy reverse-TLS path and are never migrated
implicitly. An explicit direct/plain row keeps its persisted endpoint and key.
The enrollment broker reconciles the exact gateway UDP firewall endpoint after
registry persistence and before starting the media unit. Port collision with an
already-assigned tenant fails closed before any write. HTTPS/WSS/control remain
TCP, and there is no TCP media fallback.

### Opt-in direct-UDP media cutover

**Encrypted OpenVPN acceptance failed (2026-11-12).** The OpenVPN 2.6.19 gateway /
2.4.12 PBX direct-UDP trial did not establish a tunnel and was rolled back on
both hosts; the original reverse-media link reinitialized successfully.
Captures showed server handshake replies leaving the gateway but not appearing
at the PBX. Independent 54-byte UDP requests / 66-byte replies passed 5/5 on
the same port. The exact filtering element is unidentified; do not label this
a TLS-certificate failure or claim encrypted OpenVPN is live. The isolated two-host
OpenVPN lab passed, including interrupted-write rollback, but does not establish
acceptance on this deployment's actual network path.

**Plain-UDP live acceptance passed (2026-11-13).** The test installation uses
wire version 2 on gateway UDP26154, transaction
`plain-v2-trace-20261113-093645`. Its real installed-hook identity and
bidirectional media nonce passed. A subsequent actual-tenant 20ms stream sent
500 voice-sized packets: the PBX received all 500 and all 500 echoes returned.
The largest echo-arrival gap was 97.68ms, so this is not a claim that audible
choppiness is fixed. FRP files, installation authority and existing app,
Asterisk and TURN process identities remained unchanged. Preserve the private
transaction snapshot for rollback and compare a real phone call next.

**Encrypted retrial failed (2026-11-14).** Transaction
`direct-udp-20261114123131` switched the existing endpoint on UDP26154 from
plain UDP to OpenVPN, but did not pass bidirectional readiness. Both hosts
rolled back. The restored plain-UDP link subsequently passed the installed
bidirectional readiness check, including a second check after 50 seconds idle
with the gateway media process unchanged. This is not encrypted-transport
acceptance or proof that the reported muted 150-to-102 call is fixed. A mixed
call recording does not establish delivery to either endpoint independently.
In a subsequent live 150-to-102 call, the user confirmed audio in both
directions. The matching PBX observation showed `ulaw` (PCMU), bidirectional
UDP media on the restored interface and zero reported RTP loss in the sampled
channel statistics. This short call does not establish prolonged-call quality
or cold-wake acceptance.
The installed Android 1.2.24/code 84 was then tested process-cold: its PID
was absent and the active Android user had `stopped=false` before the call.
The user confirmed wake, Answer, two-way audio and hangup; a separate cold
unanswered call cleared ringing/UI after caller cancellation. A new app PID
and the matching PCMU call were observed. These results apply only to that
installed APK/device/tenant, not the uninstalled 1.2.25/code 85 source changes.

**Control-frame size band identified (2026-11-15).** Transaction
`sales-udp-20261115-123535` moved the Sales tenant to verified plain UDP on its
canonical `26002` endpoint. Earlier attempts authenticated and then went silent:
captures on both WANs showed a handshake complete and every later datagram
disappear in both directions, while a new source port worked immediately. A
sweep of sustained one-packet-per-second echo flows isolated the cause to
datagram size: 92-96-byte IP packets (64-68-byte UDP payload) stop after about
nine packets, while 32, 60, 62, 80, 96, 112 and 116-byte payloads sustain at
least sixty seconds. Every unpadded control frame sat exactly in that band.
`udp-media-link.py` now pads control payloads to `CONTROL_PADDING` (48 bytes,
112-byte datagrams) and keeps its original ten-second keepalive; the cadence was
never the problem, and a one-second cadence added traffic without changing the
outcome. A 70-second capture at ten seconds shows sixteen packets on one
unchanged source port, and the readiness echo still passes 6/6 after 75 seconds
of silence. The client also rebinds its socket after three unanswered
keepalives. A 40-second
post-change capture shows 81 packets from one unchanged source port. Audio on a
real call has not yet been confirmed for this tenant, and no other tenant was
changed.

The legacy media link carries RTP/UDP inside OpenVPN over FRP's **TCP** connection;
an FRP proxy labelled `udp` is not an end-to-end datagram transport. Direct
mode bypasses FRP only for media. Gateway TLS-server/PBX TLS-client roles use
fresh tenant-specific certificates, `tls-crypt`, pinned peer names and the
existing isolated addresses/interface. The PBX connects outbound: it needs no
public listener or office port forwarding. SIP/API FRP, TURN relay bindings,
readiness keys and installation/device authority remain unchanged.

Only an explicitly selected registered tenant is changed. Its default gateway
UDP port is `26000 + slot`; gateway `prepare --udp-port PORT` selects a different
unprivileged port when needed. Prepare and apply reject endpoints assigned to
another tenant. A different target port must be free before stopping media;
the selected tenant's validated current UDP port may remain occupied during
prepare. Apply stops only its media unit, then rechecks that the target port is
free before committing registry or key changes. Approve the exact host/provider
firewall rule only when opening a new port. On a fresh host pass the same endpoint to
`install.sh --media-udp-ports PORT` (comma-separated ports or `start:end`
ranges). On an existing host run
`/usr/local/lib/sokrat-tenant-provisioning/media-udp-firewall.py --apply` after
review; it records only persisted `mediaTransport` ports, is additive and
idempotent, and never deletes or flushes a firewall rule. Container upgrades and
bundle promotion do not open an unrecorded port; closing one is explicit.
Do not open a whole range for one test. No TCP fallback. Leave the old FRP media mapping in
place during acceptance so the reviewed snapshot can restore it without
restarting FRP.

Promote the updated shared media scripts, `media-transport-transaction.py` and
`udp-media-link.py` to both reviewed root-owned bundles. Promote enrollment
without overwriting unrelated deployed authorization changes; restart only the
enrollment broker so it preserves the selected transport on future enrollment.
The PBX enrollment module must pass/persist `mediaTransport`; it rejects a
response that would silently downgrade an already-direct installation.

Run with no active calls. Set `PBX_ID` to the reviewed enrolled identity and
`TX` to a new bounded transaction name. On the gateway:

```sh
python3 /usr/local/lib/sokrat-tenant-provisioning/media-transport-transaction.py prepare \
  --role gateway --pbx-id "$PBX_ID" --transaction-id "$TX"
```

An existing `plain-udp` or `direct-udp` installation can also switch modes with
this transaction. Specify its **current** port explicitly, for example
`--transport direct-udp --udp-port 26154`; omitting the port selects
`26000 + slot`, not a noncanonical persisted endpoint. The switch retains the
private media plan, readiness key and old credentials for rollback, while
creating new mode-specific media material. Selecting the exact already-active
mode/host/port is refused before generating keys. A same-port UDP mode switch
does not invoke the firewall manager on apply or rollback. Ensure there are no
active calls before applying either role.

For the explicitly authorized **unencrypted** test fallback, instead prepare
with `--transport plain-udp --udp-port 26154`. The private peer bundle carries
that exact endpoint to the PBX; do not specify a separate PBX port or expose its
listener publicly. This mode authenticates packets but provides no media
confidentiality. SIP/API HTTPS and phone-to-TURN SRTP are not downgraded.

The plaintext daemon uses a tenant-specific root-only `udp.key`, directional
HMAC-SHA256 keys, a nonce challenge bound to the peer endpoint, session IDs,
and a 128-packet replay window. It never retransmits voice data or falls back to
TCP. Wire version 2 carries the IPv4 packet with address bytes 12–19 omitted:
both addresses are implicit in the authenticated tenant plan. The receiver
restores the original packet exactly, including IP/UDP checksums and options,
before applying the existing media-only firewall. The 1400-byte TUN MTU remains
unchanged. Both hosts must load the same wire version; version 1 is not accepted.

Actual-network isolation found content-dependent loss: a slot154 stream passed
150/150 roundtrips, but changing only its embedded addresses to the slot0 pair
lost every reply. Omitting those redundant addresses restored 150/150.
WireGuard did not handshake even on the alternate port with the PBX initiating.
The intervening filtering device is unidentified; these results do not establish
encryption CPU overhead as the cause. An unused-interface success alone is not
live acceptance: the actual tenant must pass the full readiness check below.

Transfer `/var/backups/sokrat-media/$PBX_ID/$TX/peer-bundle.json` privately over
SSH to the PBX (root-owned `0600`); never print it or put it in the repository.
Feed it to the PBX's reviewed `scripts/media-transport-transaction.py prepare
--role pbx --pbx-id "$PBX_ID" --transaction-id "$TX"` through stdin. Prepare
validates the installed identity, host/version/material and snapshots old
media/unit/authority state without stopping the live link.

After both hosts prepare, run the same tool's `apply` action first on the
gateway, then on the PBX, retaining their respective role and transaction flags.
Only `sokrat-media-$PBX_ID.service` is stopped/restarted. Gateway registry and
material, plus PBX saved transport, are updated under their coordination locks.
Run `verify --role gateway` after both apply: it requires the installed hook
identity and a real authenticated UDP nonce roundtrip, not merely active units.

`BlockingIOError` means an enrollment/reconciliation operation owns the shared
lock, not that media readiness failed. Wait for that operation to finish and
retry the same action/transaction; do not roll back only one host because of
lock contention. Rollback also needs that coordination lock.

If either apply or readiness fails, run `rollback` on **both** hosts with that
transaction identity. Rollback restores the old media files/certificates/unit
and the selected registry entry/material or PBX settings; unrelated tenants
remain unchanged. It also recovers private installer staging files left by an
interrupted write. Repeating completed rollback is safe. Rollback removes only
new material files generated for that role; unknown files still stop recovery.
For a new/different-port cutover the gateway reconciles the additive firewall
manifest; close a previously opened UDP rule explicitly. A same-port mode switch
does not modify firewall state.

Do not re-enroll, retire the old FRP media mapping, or make unrelated changes to
the selected installation during the acceptance window. Authority/configuration
changes are refused rather than overwritten during cutover or rollback. After
successful readiness, repeat a phone call with synchronized packet/PCM capture;
a working tunnel or source test is not evidence that audible choppiness is fixed.


### Installer and upgrader coverage

- Fresh `install.sh` refuses existing control/root enrollment state; it carries
  TLS mode/ports, validates and opens operator-approved gateway UDP media ports,
  prepares a root-only shared lock/trusted-state directory, verifies host
  OpenVPN/Python dependencies, stages the enrollment broker, generates the FRP
  token, writes and enables `frps.service`, initializes the enrollment
  CA/pairing identity, and starts both host services. New enrollments default to
  authenticated plain UDP on their canonical slot endpoint; legacy rows remain
  unchanged. The dashboard pairing code is therefore available immediately after
  install. Public employee onboarding is still explicitly reported not-ready
  without TLS.
- Re-running `scripts/install-tunnel-enrollment.py --apply` alone remains a
  non-activating promotion: it does not initialize secrets, open ports, migrate
  tenants or enable the broker. The fresh-install path performs those steps
  explicitly after promotion.
- `scripts/upgrade-container-gateway.py` defaults to a read-only preflight. It
  preserves mounted authority/credentials, permits only the newly introduced
  default TLS environment options on older containers, and runs authority-aware
  tenant reconciliation after an explicit recreation. When root enrollment is
  mounted, it also promotes the reviewed host bundle with the existing
  provisioning installer after the new container is running; preflight refuses
  an incomplete bundle before build. Under the shared provisioning lock it
  validates enrolled active managed links against their persisted plan,
  transport and credential material, then regenerates their non-secret media
  configuration using the promoted installer. PKI, credentials and transport
  selection are preserved. Unchanged links are not restarted; stopped links
  remain stopped, and unmanaged active units or identity drift refuse the
  refresh. Use an idle maintenance window: changed active links are restarted.
  Refresh/restart failure restores only generated files still matching this
  refresh's writes and attempts to recover the previous service configuration;
  incomplete recovery is a fatal error, not readiness. A successful upgrade is
  not proof of a passing media nonce, delivered push or employee-call acceptance.
- `scripts/deploy-public-certificate.sh` is installed as
  `/usr/local/bin/sokrat-public-certificate-deploy`. Set that path as the Certbot
  deploy hook. Certbot supplies `RENEWED_LINEAGE`; the hook checks expiry and
  certificate/key agreement, locks concurrent deployment, installs the pair,
  tests nginx and gracefully reloads. Private keys are0600, directory0700.
  Inspection failure refuses deployment; nginx validation/reload failure restores
  previous files and re-renders the prior TLS config without restarting nginx.
  A failed first activation removes new files. A stopped container is explicitly
  reported as staged, not live-reloaded. No enrollment/device records are touched.
  Concurrent/power-loss atomic activation is not established by these tests.
- The existing test VPS still uses its previously installed renewal hook until
  this new generic hook is promoted explicitly; do not assume source updates
  have replaced live host scripts.
  Container upgrades deliberately do not overwrite host hooks. Promote this
  reviewed script separately (private backup first), then update the specific
  certificate lineage's deploy hook and verify renewal/live certificate output.
- PBX root/bundle installers accept `SOKRAT_PBX_BRANCH`; safe upgrade defaults
  to the selected local branch, refuses dirty tracked work, requires a clean
  fast-forward and backs up `/etc/sokrat` and `/etc/frp` root-only. Do not run a
  broad PBX updater during calls or confuse source tests with live upgrade proof.

Latest local validation: gateway408/408, including15 focused installer/renewal
checks with real ephemeral certs and mocked Docker; mobile196/196; native JVM2/2;
desktop154 passed/2 skipped; Chrome61/61; test-PBX gateway16/16. Full evidence and
unchanged-source standalone VOICE fixture failures are recorded in suite
`REVERSE-TLS-RELEASE-CHECKLIST.md`. The new hook has not been live-promoted or
ACME-renewal-tested; passing regressions do not close the production gates.

This is a **dry run**. `--apply` promotes reviewed root-owned scripts but does not
initialize secrets, open ports, migrate tenants, activate scoped FRPS or enable
the enrollment service. Stop the broker explicitly before promoting a new bundle.
Keep Docker without `NET_ADMIN`; firewall requests are authenticated and delegated
to the host broker, restricted to the trusted tenant listener allocation.

Keep allocation plans/hook tokens in `runtime.trustedStateDir` under root-owned,
non-writable ancestors, separate from the dashboard-writable control store. The
broker and reconciler must point to the same trusted directory. Do not restore
obsolete service-writable plan/token copies over current trusted state.

The FRP token must be a securely generated base64url credential of at least
32 characters before enrollment. Rotate an old short token as a coordinated
change to FRPS and all explicitly reviewed clients; never print it in logs.

PBX installer and safe-upgrade entrypoints must install the media dependencies and
the shared scripts. OpenVPN 2.4's `--version` may return 1 even with valid version
output; preflight validates output and bounded status, not success status alone.

## New PBX (only after acceptance gates pass)

1. Upgrade the PBX from the reviewed feature release; confirm no active calls.
2. Sign in to the gateway dashboard and reveal/copy its **secure pairing code**
   (`sk_pair_v2_…`). Do not use the historical shared FRP token as a pairing code.
3. In the PBX's **Sokrat Gateway** settings, enter the gateway host matching the
   pairing code and paste the code. The server supplies its allocated tunnel port.
4. Wait for actual hook/media reconciliation. A running FRPC service alone is not
   readiness. Review relay, firewall and hook stages separately.
5. Employee signs into the mobile app using the deployed public gateway endpoint
   and their extension/SIP password. Approve the phone deliberately and assign it
   to the correct PBX and extension in the dashboard. The gateway never replaces
   the PBX's SIP password authentication.
6. Verify wake, answer, both audio directions, remote/local hangup and reconnect
   over mobile data with no commercial overlay running on the phone.

### Current test-gateway endpoints (IP-based)

- PBX enrollment: `https://89.117.54.235:7443` with the dashboard pairing code.
- Employee SIP: `wss://89.117.54.235:8089/ws`; enable **TLS / WSS** in the app
  account so it uses port8089.
- Employee gateway API: `https://89.117.54.235` (updated test APK required).
  Old APKs still use `http://89.117.54.235`; HTTP routes remain temporarily for
  compatibility. The updated public gateway client does not fall back to HTTP.
- Certificate: Let's Encrypt IP certificate (shortlived, auto-renewed). Do not
  pin it in the app; Android trusts the Let's Encrypt chain.
- The gateway public host is the VPS IP by explicit operator choice. If a domain
  is introduced later, reissue the certificate and update the app host; the WSS
  architecture stays the same.

Do not hardcode extension numbers. Do not restore revoked phones. Keep simultaneous
mobile and CRM registrations (`max_contacts >= 5`, `remove_existing = no`).

## Existing PBX migration

A PBX with an existing `/etc/sokrat/gateway-hook.json` must not silently join a
second gateway. Review ownership, current tenant ID, approved routes and devices.
Back up FRP, media, hook, root registry/pins and control state privately on both
hosts. Generate the installation identity on the PBX and stage adoption using:

```sh
# Private JSON via stdin; never put installation secrets in argv or Git.
python3 scripts/tunnel-enrollment.py --stage-migration
```

The input includes the existing `pbxId`, generated `installationId` and
`installationSecret`, display `name`, and `expectedDigest`: SHA256 of the exact
Node `JSON.stringify(publicPbx)` reviewed record. Do not approximate its field order
with Python serialization. Staging does not switch live routes.

Activate the pinned FRPS certificate/plugin and enroll the selected PBX as a
coordinated, backed-up maintenance operation. Recheck the control record after
every failed attempt: a later client-side error may occur after the gateway has
adopted new routes. Restoring FRPS alone is **not** a complete rollback.

## Rollback and evidence

### Interrupted setup and retry

Initialization validates the service account before creating credentials and
writes `config.json` last, after the private pairing/bridge files and permissions.
That config is the service activation marker. If first initialization fails before
it exists, correct the cause and rerun initialization **before distributing a
pairing code**; incomplete bootstrap credentials can be replaced during that
retry. An existing config causes initialization to refuse without rotating secrets.
This does not repair an already initialized deployment with missing credential
files; retain its private backup and investigate rather than removing its config.

Broker retries use the same PBX installation identity and reserved allocation.
Mocked failure-injection regressions cover lost/failed bridge, pin and media-start
steps while retaining media keys and hook token; disabled/retired control records
still block service activation. They do **not** establish fresh-host installation,
every PBX-side failure, power-loss durability or live coordinated rollback.

The bootstrap activation-marker fix and recovery tests are local feature changes,
not deployed to the currently initialized gateway. Latest gateway suite:385 passed,
0 failed. Live test-PBX gateway-focused regressions:8 passed,0 failed. The existing
broader PBX22-test evidence remains separate from this narrower rerun.

### Coordinated rollback

Never copy an old entire control store over newer approvals, revocations or
unrelated tenant work. Restore reviewed route/config fields while preserving
current device authority, with the control writer stopped or through its API.
Restore compatible FRPS/FRPC credentials, media PKI/configuration and root pins as
one coordinated set; mismatched keys will not reconnect. Reconcile TURN against
the restored peer and verify its bind address, listener gate and hook delivery.

Retain private backup inventories and secret-free test logs outside Git. Re-run
the suites, inspect `git diff --check`, and commit/push server changes only to the
feature branch after review. Never push experimental PBX changes to `main`.
