# Incoming caller address-book lookup

Clients check saved contacts (desktop/Chrome: domain-scoped PBX cache), then
authenticated PBX contacts, then display `Unknown`. Raw caller numbers remain
separate. SIP/trunk display names are not trusted as address-book names.

The legacy runtime exposes read-only `GET /api/extension/v1/contacts` using
`PBX_AUTH_URL` as the operator-controlled destination. The PBX verifies the
original extension/password HMAC, including the exact query string.

The tenant runtime exposes `GET /api/gateway/contacts`. It requires an approved
device bearer and control device ID, routes only to the assigned PBX, and
requires the HMAC extension to match that assignment. The HMAC canonical path
is still `/api/extension/v1/contacts` with the identical query string. Device
bearers are never forwarded to PBXs. Responses are `no-store`; upstream
redirects are rejected and requests have a five-second timeout.

Deployment must explicitly proxy these GET paths to the appropriate runtime.
Adding source files does not activate public routing or the tenant cutover.
Do not expose control/admin routes or add an unauthenticated address book.

## Test deployment — 2026-10-28

The legacy GET route is deployed on the test gateway. Unsigned requests return
401; a real PBX-signed request returned200 with16 contacts. Gateway health and
FCM remain healthy. Timestamped index/nginx backups precede the change. The
tenant route remains local source pending the explicit approval cutover; no
public tenant or SIP routing change was made as part of this deployment.
