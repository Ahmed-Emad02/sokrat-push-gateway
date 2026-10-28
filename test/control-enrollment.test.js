'use strict';

/**
 * Automatic (claim) enrollment: the store contract and the public router.
 *
 * Invariants under test:
 * - the client-generated claim secret is never stored, echoed or logged;
 * - pending rows are keyed by the claim digest, so a forged UUID cannot read
 *   or replace another device's claim;
 * - approval preserves the claim and issues nothing for the operator to copy;
 * - redemption activates the device- held credential exactly once and is safe
 *   to retry (a lost response never locks a device out);
 * - caps, expiry and throttling still apply;
 * - the invite flow keeps minting its one-time device secret.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fsp = require('node:fs').promises;
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const express = require('express');

const { ControlStore, hashSecret } = require('../src/control/store');
const { createEnrollmentRouter, WindowLimiter } = require('../src/control/enrollment');
const { createControl } = require('../src/control');
const { LoginRateLimiter } = require('../src/control/auth');

const DEVICE_UUID = 'a9e89b44-cb09-4f7c-a9e5-4da631df95ed';
const OTHER_UUID = '2f1c7f9e-8a4d-4c2b-9f3e-5b6a7c8d9e0f';

function newClaimSecret() {
    return crypto.randomBytes(32).toString('base64url');
}

async function makeStore(options = {}) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-control-claim-'));
    const filePath = path.join(dir, 'control.json');
    const store = new ControlStore({ filePath, ...options });
    await store.init();
    return {
        dir,
        filePath,
        store,
        close: () => fsp.rm(dir, { recursive: true, force: true })
    };
}

function pbxInput(name, overrides = {}) {
    return {
        name,
        wsURL: 'wss://pbx.example.com:8089/ws',
        apiURL: 'https://pbx.example.com:8080',
        mediaIps: '203.0.113.10',
        enabled: true,
        ...overrides
    };
}

function claimBody(secret, overrides = {}) {
    return {
        claimSecret: secret,
        platform: 'android',
        deviceUuid: DEVICE_UUID,
        extension: '162',
        deviceName: 'Pixel 8',
        ...overrides
    };
}

async function rawDocument(filePath) {
    return JSON.parse(await fsp.readFile(filePath, 'utf8'));
}

// ---------------------------------------------------------------------------
// store: enrollment
// ---------------------------------------------------------------------------

test('claim enrollment stores only a digest and is keyed by it, not by UUID', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const claimSecret = newClaimSecret();
        const first = await store.enrollClaim(claimBody(claimSecret), { requestIp: '203.0.113.7' });

        assert.equal(first.created, true);
        assert.equal(first.reused, false);
        assert.equal(first.status, 'pending');
        assert.equal(first.device.enrollmentMode, 'claim');
        assert.equal(first.device.hasClaim, true);
        assert.equal(first.device.hasSecret, false);
        assert.equal(first.device.suggestedExtension, '162');
        assert.equal(first.device.requestIp, '203.0.113.7');
        assert.ok(Date.parse(first.device.claimExpiresAt) > Date.now());

        const onDisk = await fsp.readFile(filePath, 'utf8');
        assert.equal(onDisk.includes(claimSecret), false, 'plaintext claim must never hit disk');
        assert.ok(onDisk.includes(hashSecret(claimSecret)), 'the digest is stored');

        const snapshot = JSON.stringify(store.snapshot());
        assert.equal(snapshot.includes(claimSecret), false);
        assert.equal(snapshot.includes('claimHash'), false, 'digest is not part of the public projection');
        assert.equal(snapshot.includes('secretHash'), false);

        // Same claim, same device: idempotent re-enrollment.
        const again = await store.enrollClaim(
            claimBody(claimSecret, { deviceName: 'Pixel 8 (renamed)' }),
            { requestIp: '203.0.113.8' }
        );
        assert.equal(again.reused, true);
        assert.equal(again.created, false);
        assert.equal(again.device.id, first.device.id);
        assert.equal(again.device.deviceName, 'Pixel 8 (renamed)');
        assert.equal(again.device.requestIp, '203.0.113.8');
        assert.equal(store.listDevices('pending').length, 1);

        // A different claim that reports the same UUID cannot take over.
        await assert.rejects(
            store.enrollClaim(claimBody(newClaimSecret(), { deviceName: 'Impostor' })),
            (error) => error.code === 'device_uuid_conflict' && error.status === 409
        );

        const pending = store.listDevices('pending');
        assert.equal(pending.length, 1);
        assert.equal(pending[0].deviceName, 'Pixel 8 (renamed)');
    } finally {
        await close();
    }
});

test('claim enrollment validates its anonymous body', async () => {
    const { store, close } = await makeStore();
    try {
        const cases = [
            [claimBody(newClaimSecret().slice(0, 31)), 'invalid_claimSecret'],
            [claimBody(`${newClaimSecret()} `), 'invalid_claimSecret'],
            [claimBody(newClaimSecret(), { claimSecret: undefined }), 'invalid_claimSecret'],
            [claimBody(newClaimSecret(), { platform: 'windows' }), 'invalid_platform'],
            [claimBody(newClaimSecret(), { deviceUuid: 'not-a-uuid' }), 'invalid_deviceUuid'],
            [claimBody(newClaimSecret(), { extension: '' }), 'invalid_extension'],
            [claimBody(newClaimSecret(), { extension: 'has space' }), 'invalid_extension']
        ];
        for (const [body, code] of cases) {
            await assert.rejects(store.enrollClaim(body), (error) => error.code === code, code);
        }

        // A 32-character secret is the documented floor and is accepted.
        const minimal = newClaimSecret().slice(0, 32);
        assert.equal(minimal.length, 32);
        const accepted = await store.enrollClaim(claimBody(minimal));
        assert.equal(accepted.status, 'pending');
    } finally {
        await close();
    }
});

// ---------------------------------------------------------------------------
// store: approval + redemption
// ---------------------------------------------------------------------------

test('approval preserves the claim and redemption activates the client credential once', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const claimSecret = newClaimSecret();
        const enrolled = await store.enrollClaim(claimBody(claimSecret));

        const pending = await store.redeemClaim({
            deviceId: enrolled.device.id,
            claimSecret
        });
        assert.equal(pending.status, 'pending');
        assert.equal(pending.assignment, null);
        assert.ok(pending.retryAfterMs >= 250);
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, claimSecret).ok, false);

        const approved = await store.approveDevice(
            enrolled.device.id,
            { pbxId: pbx.id, extension: '162' },
            { actor: 'admin@127.0.0.1' }
        );
        assert.equal(approved.secret, null, 'automatic approval issues no secret');
        assert.equal(approved.enrollmentMode, 'claim');
        assert.equal(approved.device.status, 'approved');
        assert.equal(approved.device.extension, '162');
        assert.equal(approved.device.hasSecret, false, 'credential is inactive until redemption');
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, claimSecret).ok, false);

        const redeemed = await store.redeemClaim({ deviceId: enrolled.device.id, claimSecret });
        assert.equal(redeemed.status, 'approved');
        assert.equal(redeemed.redeemedNow, true);
        assert.equal(redeemed.assignment.pbxId, pbx.id);
        assert.equal(redeemed.assignment.extension, '162');
        assert.equal(redeemed.assignment.wsURL, 'wss://pbx.example.com:8089/ws');
        assert.equal(redeemed.assignment.apiURL, 'https://pbx.example.com:8080/');
        assert.equal(redeemed.device.hasSecret, true);
        assert.ok(redeemed.device.claimRedeemedAt);
        assert.equal(JSON.stringify(redeemed).includes(claimSecret), false, 'never echo the secret');

        // The parent integration hook now accepts (deviceId, claimSecret).
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, claimSecret).ok, true);
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, newClaimSecret()).ok, false);
        assert.equal(store.getApprovedDevice(enrolled.device.id).extension, '162');

        // Retrying redemption is safe and returns no new material.
        const retried = await store.redeemClaim({ deviceId: enrolled.device.id, claimSecret });
        assert.equal(retried.status, 'approved');
        assert.equal(retried.redeemedNow, false);
        assert.deepEqual(retried.assignment, redeemed.assignment);
        assert.equal(retried.device.claimRedeemedAt, redeemed.device.claimRedeemedAt);
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, claimSecret).ok, true);

        // Wrong or unknown credentials are indistinguishable.
        await assert.rejects(
            store.redeemClaim({ deviceId: enrolled.device.id, claimSecret: newClaimSecret() }),
            (error) => error.code === 'invalid_claim' && error.status === 401
        );
        await assert.rejects(
            store.redeemClaim({ deviceId: 'dev_0123456789abcdef0123', claimSecret }),
            (error) => error.code === 'invalid_claim' && error.status === 401
        );

        // A second pending claim cannot be opened for an approved device.
        await assert.rejects(
            store.enrollClaim(claimBody(newClaimSecret(), { deviceName: 'Clone' })),
            (error) => error.code === 'device_already_approved' && error.status === 409
        );

        await store.revokeDevice(enrolled.device.id, { reason: 'lost phone' });
        assert.equal(store.verifyDeviceSecret(enrolled.device.id, claimSecret).ok, false);
        await assert.rejects(
            store.redeemClaim({ deviceId: enrolled.device.id, claimSecret }),
            (error) => error.code === 'device_revoked' && error.status === 403
        );
    } finally {
        await close();
    }
});

test('rejected claims are terminal until the device enrolls with a new secret', async () => {
    const { store, close } = await makeStore();
    try {
        const claimSecret = newClaimSecret();
        const { device } = await store.enrollClaim(claimBody(claimSecret));
        await store.rejectDevice(device.id, { reason: 'unknown employee' });

        await assert.rejects(
            store.redeemClaim({ deviceId: device.id, claimSecret }),
            (error) => error.code === 'device_rejected' && error.status === 403
        );
        await assert.rejects(
            store.enrollClaim(claimBody(claimSecret)),
            (error) => error.code === 'device_rejected' && error.status === 403
        );

        // A fresh claim secret (same phone) starts a new request.
        const replacement = newClaimSecret();
        const retried = await store.enrollClaim(claimBody(replacement));
        assert.equal(retried.created, true);
        assert.notEqual(retried.device.id, device.id);
        assert.equal(store.listDevices('pending').length, 1);
    } finally {
        await close();
    }
});

test('expired claim requests are hidden, refused and can be renewed', async () => {
    let now = Date.parse('2026-03-01T09:00:00.000Z');
    const { store, close } = await makeStore({ now: () => now, claimTtlMs: 5 * 60 * 1000 });
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const claimSecret = newClaimSecret();
        const { device } = await store.enrollClaim(claimBody(claimSecret));
        assert.equal(Date.parse(device.claimExpiresAt), now + 5 * 60 * 1000);

        now += 5 * 60 * 1000 + 1000;

        assert.equal(store.listDevices('pending').length, 0, 'expired requests leave the queue');
        assert.equal(store.stats().pendingDevices, 0);
        assert.equal(store.snapshot().devices.length, 0);

        await assert.rejects(
            store.redeemClaim({ deviceId: device.id, claimSecret }),
            (error) => error.code === 'claim_expired' && error.status === 410
        );
        await assert.rejects(
            store.approveDevice(device.id, { pbxId: pbx.id, extension: '162' }),
            (error) => error.code === 'claim_expired' && error.status === 409
        );

        // The same device (same claim secret) simply enrolls again.
        const renewed = await store.enrollClaim(claimBody(claimSecret));
        assert.equal(renewed.reused, true);
        assert.equal(renewed.status, 'pending');
        assert.equal(renewed.device.id, device.id);
        assert.ok(Date.parse(renewed.device.claimExpiresAt) > now);
        assert.equal(store.listDevices('pending').length, 1);

        // ... and can then be approved and redeemed normally.
        await store.approveDevice(device.id, { pbxId: pbx.id, extension: '162' });
        const redeemed = await store.redeemClaim({ deviceId: device.id, claimSecret });
        assert.equal(redeemed.status, 'approved');
    } finally {
        await close();
    }
});

test('abandoned requests are pruned once they are a full TTL past expiry', async () => {
    let now = Date.parse('2026-03-02T09:00:00.000Z');
    const ttl = 5 * 60 * 1000;
    const { store, close } = await makeStore({ now: () => now, claimTtlMs: ttl });
    try {
        const abandoned = newClaimSecret();
        const { device } = await store.enrollClaim(claimBody(abandoned));

        now += ttl * 2 + 1000;
        await store.enrollClaim(claimBody(newClaimSecret(), { deviceUuid: OTHER_UUID }));

        const devices = store.snapshot().devices;
        assert.equal(devices.some((item) => item.id === device.id), false, 'pruned');
        assert.equal(devices.length, 1);
        assert.match(JSON.stringify(store.auditLog(50)), /claim\.expired/);
    } finally {
        await close();
    }
});

test('automatic enrollment keeps the pending cap and follows the assigned PBX', async () => {
    const { store, close } = await makeStore({ maxPendingDevices: 1 });
    try {
        await store.enrollClaim(claimBody(newClaimSecret()));
        await assert.rejects(
            store.enrollClaim(claimBody(newClaimSecret(), { deviceUuid: OTHER_UUID })),
            (error) => error.code === 'pending_cap_reached' && error.status === 409
        );
    } finally {
        await close();
    }

    const second = await makeStore();
    try {
        const record = await second.store.addPbx(pbxInput('HQ'));
        const claimSecret = newClaimSecret();
        const { device } = await second.store.enrollClaim(claimBody(claimSecret));
        await second.store.approveDevice(device.id, { pbxId: record.id, extension: '162' });

        await second.store.updatePbx(record.id, { enabled: false });
        await assert.rejects(
            second.store.redeemClaim({ deviceId: device.id, claimSecret }),
            (error) => error.code === 'pbx_disabled' && error.status === 409
        );

        await second.store.updatePbx(record.id, { enabled: true });
        const redeemed = await second.store.redeemClaim({ deviceId: device.id, claimSecret });
        assert.equal(redeemed.status, 'approved');

        await second.store.removePbx(record.id);
        await assert.rejects(
            second.store.redeemClaim({ deviceId: device.id, claimSecret }),
            (error) => error.code === 'device_revoked' && error.status === 403
        );
        assert.equal(second.store.verifyDeviceSecret(device.id, claimSecret).ok, false);
    } finally {
        await second.close();
    }
});

test('invite enrollment still mints a one-time device secret', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const { token } = await store.createEnrollmentToken({ label: 'invite' });
        const { device } = await store.enrollDevice({
            token,
            platform: 'ios',
            deviceUuid: DEVICE_UUID
        });
        assert.equal(device.enrollmentMode, 'invite');
        assert.equal(device.hasClaim, false);

        const approved = await store.approveDevice(device.id, { pbxId: pbx.id, extension: '150' });
        assert.match(approved.secret, /^sk_device_v1_[A-Za-z0-9_-]{43}$/);
        assert.equal(approved.enrollmentMode, 'invite');
        assert.equal(store.verifyDeviceSecret(device.id, approved.secret).ok, true);

        // An invite device has no claim to redeem.
        await assert.rejects(
            store.redeemClaim({ deviceId: device.id, claimSecret: approved.secret }),
            (error) => error.code === 'invalid_claim' && error.status === 401
        );
    } finally {
        await close();
    }
});

// ---------------------------------------------------------------------------
// public router
// ---------------------------------------------------------------------------

async function createHarness(options = {}) {
    const { dir, filePath, store, close } = await makeStore(options.storeOptions);
    const app = express();
    app.disable('x-powered-by');
    if (options.peerAddress) {
        app.use((req, res, next) => {
            Object.defineProperty(req.socket, 'remoteAddress', {
                value: options.peerAddress,
                configurable: true
            });
            next();
        });
    }
    app.use(
        '/connect',
        createEnrollmentRouter({
            store,
            ...(options.routerOptions || {})
        })
    );

    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;

    async function request(pathSuffix, requestOptions = {}) {
        const headers = { ...(requestOptions.headers || {}) };
        if (requestOptions.body !== undefined || requestOptions.raw !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        const response = await fetch(`${origin}${pathSuffix}`, {
            method: requestOptions.method || 'GET',
            headers,
            body:
                requestOptions.raw !== undefined
                    ? requestOptions.raw
                    : requestOptions.body === undefined
                        ? undefined
                        : JSON.stringify(requestOptions.body),
            redirect: 'manual'
        });
        const type = response.headers.get('content-type') || '';
        let body = null;
        let text = null;
        if (type.includes('application/json')) {
            try {
                body = await response.json();
            } catch {
                body = null;
            }
        } else {
            text = await response.text();
        }
        return { status: response.status, headers: response.headers, body, text };
    }

    return {
        store,
        filePath,
        origin,
        request,
        close: async () => {
            await new Promise((resolve) => {
                server.close(resolve);
                if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
            });
            await close();
        }
    };
}

test('the public endpoint enrolls, waits and redeems with no admin surface', async () => {
    const harness = await createHarness();
    try {
        const pbx = await harness.store.addPbx(pbxInput('HQ'));
        const claimSecret = newClaimSecret();

        const enrolled = await harness.request('/connect/enroll', {
            method: 'POST',
            body: claimBody(claimSecret)
        });
        assert.equal(enrolled.status, 201);
        assert.equal(enrolled.headers.get('cache-control'), 'no-store');
        assert.equal(enrolled.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(enrolled.headers.get('set-cookie'), null, 'no session cookie is issued');
        assert.equal(enrolled.body.status, 'pending');
        assert.equal(enrolled.body.device.enrollmentMode, 'claim');
        assert.equal(JSON.stringify(enrolled.body).includes(claimSecret), false);
        assert.equal(JSON.stringify(enrolled.body).includes('claimHash'), false);

        const deviceId = enrolled.body.device.id;

        const waiting = await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        });
        assert.equal(waiting.status, 202);
        assert.ok(Number(waiting.headers.get('retry-after')) >= 1);
        assert.equal(waiting.body.status, 'pending');
        assert.equal(waiting.body.assignment, null);

        // No operator endpoints exist on this router.
        for (const path of ['/connect/', '/connect/api/state', '/connect/api/session', '/connect/api/pbx']) {
            const probe = await harness.request(path);
            assert.equal(probe.status, 404, `${path} must not be exposed`);
            assert.deepEqual(probe.body, { success: false, error: 'not_found' });
        }

        // A claim secret does not carry into a GET query string surface.
        const getClaim = await harness.request('/connect/claim');
        assert.equal(getClaim.status, 404);

        await harness.store.approveDevice(deviceId, { pbxId: pbx.id, extension: '162' }, { actor: 'admin' });

        const redeemed = await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        });
        assert.equal(redeemed.status, 200);
        assert.equal(redeemed.body.status, 'approved');
        assert.equal(redeemed.body.assignment.pbxId, pbx.id);
        assert.equal(redeemed.body.assignment.extension, '162');
        assert.equal(redeemed.body.assignment.wsURL, 'wss://pbx.example.com:8089/ws');
        assert.equal(redeemed.body.credential.deviceHeader, 'X-Sokrat-Device');
        assert.equal(JSON.stringify(redeemed.body).includes(claimSecret), false);
        assert.equal(harness.store.verifyDeviceSecret(deviceId, claimSecret).ok, true);

        const retried = await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        });
        assert.equal(retried.status, 200);
        assert.equal(retried.body.redeemed, false);
        assert.deepEqual(retried.body.assignment, redeemed.body.assignment);

        const wrong = await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret: newClaimSecret() }
        });
        assert.equal(wrong.status, 401);
        assert.equal(wrong.body.error, 'invalid_claim');

        const invalidJson = await harness.request('/connect/enroll', {
            method: 'POST',
            raw: '{ not json'
        });
        assert.equal(invalidJson.status, 400);
        assert.equal(invalidJson.body.error, 'invalid_json');

        const huge = await harness.request('/connect/enroll', {
            method: 'POST',
            raw: JSON.stringify(claimBody(newClaimSecret(), { deviceName: 'x'.repeat(20_000) }))
        });
        assert.equal(huge.status, 413);
        assert.equal(huge.body.error, 'payload_too_large');

        const missing = await harness.request('/connect/enroll', {
            method: 'POST',
            body: { platform: 'android', deviceUuid: DEVICE_UUID, extension: '162' }
        });
        assert.equal(missing.status, 400);
        assert.equal(missing.body.error, 'invalid_claimSecret');
    } finally {
        await harness.close();
    }
});

test('the public endpoint throttles enrollment, claims and wrong secrets', async () => {
    const now = Date.parse('2026-04-01T12:00:00.000Z');
    const harness = await createHarness({
        routerOptions: {
            now: () => now,
            enrollLimiter: new WindowLimiter({ limit: 2, windowMs: 60_000, now: () => now }),
            claimLimiter: new WindowLimiter({ limit: 2, windowMs: 60_000, now: () => now }),
            claimFailureLimiter: new LoginRateLimiter({
                maxFailures: 2,
                windowMs: 60_000,
                lockoutMs: 60_000,
                now: () => now
            })
        }
    });
    try {
        const claimSecret = newClaimSecret();

        const first = await harness.request('/connect/enroll', { method: 'POST', body: claimBody(claimSecret) });
        assert.equal(first.status, 201);
        const deviceId = first.body.device.id;

        const second = await harness.request('/connect/enroll', {
            method: 'POST',
            body: claimBody(newClaimSecret(), { deviceUuid: OTHER_UUID })
        });
        assert.equal(second.status, 201);

        const third = await harness.request('/connect/enroll', {
            method: 'POST',
            body: claimBody(newClaimSecret(), {
                deviceUuid: '5c1c7f9e-8a4d-4c2b-9f3e-5b6a7c8d9e0f'
            })
        });
        assert.equal(third.status, 429);
        assert.equal(third.body.error, 'too_many_requests');
        assert.ok(Number(third.headers.get('retry-after')) >= 1);

        // Per-device claim budget.
        assert.equal((await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        })).status, 202);
        assert.equal((await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        })).status, 202);
        const overBudget = await harness.request('/connect/claim', {
            method: 'POST',
            body: { deviceId, claimSecret }
        });
        assert.equal(overBudget.status, 429);

        // Wrong secrets lock the address out after `maxFailures`.
        const other = await createHarness({
            routerOptions: {
                now: () => now,
                claimFailureLimiter: new LoginRateLimiter({
                    maxFailures: 2,
                    windowMs: 60_000,
                    lockoutMs: 60_000,
                    now: () => now
                })
            }
        });
        try {
            const enrolled = await other.request('/connect/enroll', {
                method: 'POST',
                body: claimBody(newClaimSecret())
            });
            const id = enrolled.body.device.id;
            for (let attempt = 0; attempt < 2; attempt += 1) {
                const denied = await other.request('/connect/claim', {
                    method: 'POST',
                    body: { deviceId: id, claimSecret: newClaimSecret() }
                });
                assert.equal(denied.status, 401);
            }
            const locked = await other.request('/connect/claim', {
                method: 'POST',
                body: { deviceId: id, claimSecret: newClaimSecret() }
            });
            assert.equal(locked.status, 429);
            assert.ok(Number(locked.headers.get('retry-after')) >= 1);
        } finally {
            await other.close();
        }
    } finally {
        await harness.close();
    }
});

test('the public endpoint can be pinned to private networks', async () => {
    const privateHarness = await createHarness({
        peerAddress: '203.0.113.99',
        routerOptions: { privateOnly: true }
    });
    try {
        const denied = await privateHarness.request('/connect/enroll', {
            method: 'POST',
            body: claimBody(newClaimSecret())
        });
        assert.equal(denied.status, 403);
        assert.equal(denied.body.error, 'network_not_allowed');
    } finally {
        await privateHarness.close();
    }

    const loopback = await createHarness({ routerOptions: { privateOnly: true } });
    try {
        const accepted = await loopback.request('/connect/enroll', {
            method: 'POST',
            body: claimBody(newClaimSecret())
        });
        assert.equal(accepted.status, 201);
    } finally {
        await loopback.close();
    }
});

test('the console approves an automatic device without showing a secret', async () => {
    const { store, close } = await makeStore();
    const { createControlRouter } = require('../src/control/router');
    const app = express();
    app.disable('x-powered-by');
    app.use(
        '/control',
        createControlRouter({
            store,
            credential: { source: 'test', configured: true, verify: async (password) => password === 'test-password' },
            loginFailureDelayMs: 0
        })
    );
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const claimSecret = newClaimSecret();
        const enrolled = await store.enrollClaim(claimBody(claimSecret));

        const login = await fetch(`${origin}/control/api/session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: 'test-password' })
        });
        assert.equal(login.status, 200);
        const cookie = login.headers.getSetCookie().map((raw) => raw.split(';')[0]).join('; ');
        const { csrfToken } = await login.json();

        const state = await fetch(`${origin}/control/api/state`, { headers: { Cookie: cookie } });
        assert.equal(state.status, 200);
        const stateBody = await state.json();
        assert.equal(JSON.stringify(stateBody).includes(claimSecret), false);
        assert.equal(JSON.stringify(stateBody).includes('claimHash'), false);
        assert.equal(stateBody.devices[0].enrollmentMode, 'claim');

        const approve = await fetch(
            `${origin}/control/api/devices/${enrolled.device.id}/approve`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Cookie: cookie,
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ pbxId: pbx.id, extension: '162' })
            }
        );
        assert.equal(approve.status, 200);
        const approved = await approve.json();
        assert.equal(approved.secret, undefined, 'automatic mode never returns a secret');
        assert.equal(approved.enrollmentMode, 'claim');
        assert.equal(approved.device.status, 'approved');
        assert.match(approved.notice, /redeems its claim/i);

        const redeemed = await store.redeemClaim({
            deviceId: enrolled.device.id,
            claimSecret
        });
        assert.equal(redeemed.status, 'approved');
    } finally {
        await new Promise((resolve) => {
            server.close(resolve);
            if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
        });
        await close();
    }
});

test('createControl exposes the enrollment router on the shared store', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-control-facade-'));
    try {
        const control = createControl({
            filePath: path.join(dir, 'control.json'),
            env: {}
        });
        await control.init();
        assert.equal(typeof control.enrollmentRouter, 'function');
        assert.equal(control.enrollmentRouter.enrollment.store, control.store);
        assert.equal(typeof control.router, 'function');
        assert.notEqual(control.router, control.enrollmentRouter);
    } finally {
        await fsp.rm(dir, { recursive: true, force: true });
    }
});
