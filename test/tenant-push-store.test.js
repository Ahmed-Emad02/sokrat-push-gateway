'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createTenantPushStore, TOKEN_TTL_MS } = require('../src/tenant-push-store');
const { fingerprintToken } = require('../src/push-errors');

function device(overrides = {}) {
    return { deviceId: 'current', deviceUuid: 'installation-a', pbxId: 'current-pbx', extension: '111',
        platform: 'android', token: 'test-token', voipToken: '', updatedAt: Date.now(), ...overrides };
}
const oldDevice = overrides => device({ deviceId: 'old', pbxId: 'retired-pbx', extension: '103', ...overrides });
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}
async function fixture(t, rows = [], approved = [], lookup) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-push-test-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'devices.json');
    await fs.writeFile(file, JSON.stringify({ version: 1, devices: rows }), { mode: 0o600 });
    const assignments = new Map(approved.map(row => [row.deviceId, { ...row }]));
    const approvedAssignment = lookup ? id => lookup(id, assignments) : async id => assignments.get(id) || null;
    return { file, assignments, approvedAssignment, store: createTenantPushStore(file, approvedAssignment),
        read: async () => JSON.parse(await fs.readFile(file, 'utf8')).devices };
}

test('push registry is durable, private, serialized and tenant scoped', async t => {
    const rows = ['A', 'B'].map(pbxId => device({ deviceId: pbxId, pbxId, extension: 'same', token: pbxId }));
    const { store, file, approvedAssignment } = await fixture(t, [], rows);
    await Promise.all(rows.map(row => store.savePush(row)));
    assert.equal((await store.listPush('A', 'same')).length, 1);
    assert.equal((await store.listPush('B', 'same')).length, 1);
    const second = createTenantPushStore(file, approvedAssignment);
    assert.equal((await second.listPush('A', 'same'))[0].deviceId, 'A');
    assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
    await assert.rejects(store.savePush(device({ deviceId: 'attacker', token: 'A' })), { status: 409 });
    assert.equal((await store.listPush('A', 'same')).length, 1);
    await store.removePush('A');
    assert.equal((await store.listPush('A', 'same')).length, 0);
});

for (const platform of ['android', 'ios']) {
    test(`${platform}: approved same installation recovers token from revoked/deleted owner`, async t => {
        const old = oldDevice({ platform, voipToken: platform === 'ios' ? 'test-voip' : '' });
        const current = device({ platform, voipToken: old.voipToken });
        const { store, read } = await fixture(t, [old], [current]);
        await store.savePush(current);
        assert.deepEqual(await read(), [current]);
        assert.deepEqual(await store.listPush(old.pbxId, old.extension), []);
        assert.deepEqual(await store.listPush(current.pbxId, current.extension), [current]);
        await store.savePush(current);
        assert.deepEqual(await read(), [current]);
    });
}

for (const pbxId of ['current-pbx', 'other-tenant']) {
    test(`approved owner in ${pbxId} cannot lose a token even to same UUID`, async t => {
        const old = oldDevice({ pbxId });
        const current = device();
        const { store, read } = await fixture(t, [old], [old, current]);
        await assert.rejects(store.savePush(current), { status: 409 });
        assert.deepEqual(await read(), [old]);
    });
}

test('unapproved owner cannot lose token to a different or missing installation UUID', async t => {
    for (const deviceUuid of ['other-installation', undefined, '']) {
        const old = oldDevice({ deviceUuid });
        if (deviceUuid === undefined) delete old.deviceUuid;
        const current = device();
        const { store, read } = await fixture(t, [old], [current]);
        await assert.rejects(store.savePush(current), { status: 409 });
        assert.deepEqual(await read(), [old]);
    }
});

test('matching UUID does not authorize an unapproved destination or stale assignment', async t => {
    const current = device();
    for (const assignment of [null, ...['deviceId', 'deviceUuid', 'pbxId', 'extension'].map(key => ({ ...current, [key]: 'changed' }))]) {
        const old = oldDevice();
        const { store, read } = await fixture(t, [old], [], async id => id === current.deviceId ? assignment : null);
        await assert.rejects(store.savePush(current), /approval changed/);
        assert.deepEqual(await read(), [old]);
    }
});

test('all conflicting regular/VoIP owners must be inactive; failure removes neither row', async t => {
    const old = oldDevice();
    const active = oldDevice({ deviceId: 'active', token: 'other-token', voipToken: 'test-voip', platform: 'ios' });
    const current = device({ platform: 'ios', voipToken: 'test-voip' });
    const { store, read, assignments } = await fixture(t, [old, active], [active, current]);
    await assert.rejects(store.savePush(current), { status: 409 });
    assert.deepEqual(await read(), [old, active]);
    assignments.delete(active.deviceId);
    await store.savePush(current);
    assert.deepEqual(await read(), [current]);
});

test('an active owner stays protected even if its stored PBX/extension is stale', async t => {
    const old = oldDevice();
    const current = device();
    const approvedOld = { ...old, pbxId: 'new-pbx', extension: '999' };
    const { store, read } = await fixture(t, [old], [approvedOld, current]);
    await assert.rejects(store.savePush(current), { status: 409 });
    assert.deepEqual(await read(), [old]);
});

test('lookup errors fail closed without changing registry; subsequent retry works', async t => {
    const old = oldDevice();
    const current = device();
    let fail = true;
    const { store, read } = await fixture(t, [old], [current], async (id, assignments) => {
        if (fail) throw new Error('approval store unavailable');
        return assignments.get(id) || null;
    });
    await assert.rejects(store.savePush(current), /unavailable/);
    assert.deepEqual(await read(), [old]);
    fail = false;
    await store.savePush(current);
    assert.deepEqual(await read(), [current]);
});

test('destination approval lookup failure also preserves revoked owner row', async t => {
    const old = oldDevice();
    const current = device();
    const { store, read } = await fixture(t, [old], [current], async id => {
        if (id === current.deviceId) throw new Error('destination lookup unavailable');
        return null;
    });
    await assert.rejects(store.savePush(current), /lookup unavailable/);
    assert.deepEqual(await read(), [old]);
});

test('missing approval lookup cannot transfer or create registrations', async t => {
    const old = oldDevice();
    const { file, read } = await fixture(t, [old]);
    const store = createTenantPushStore(file);
    await assert.rejects(store.savePush(device()), { status: 409 });
    await assert.rejects(store.savePush(device({ token: 'new-token' })), /approval/);
    await assert.rejects(store.pruneInvalidPush(), /lookup unavailable/);
    assert.deepEqual(await read(), [old]);
});

test('destination approval is rechecked after asynchronous old-owner lookup', async t => {
    const entered = deferred();
    const resume = deferred();
    const old = oldDevice();
    const current = device();
    const { store, read, assignments } = await fixture(t, [old], [current], async (id, assignments) => {
        if (id === old.deviceId) { entered.resolve(); await resume.promise; }
        return assignments.get(id) || null;
    });
    const saving = store.savePush(current);
    const rejected = assert.rejects(saving, /approval changed/);
    await entered.promise;
    assignments.delete(current.deviceId);
    resume.resolve();
    await rejected;
    assert.deepEqual(await read(), [old]);
});

test('old owner reapproved while its asynchronous lookup waits retains the token', async t => {
    const entered = deferred();
    const resume = deferred();
    const old = oldDevice();
    const current = device();
    const { store, read, assignments } = await fixture(t, [old], [current], async (id, assignments) => {
        if (id === old.deviceId) { entered.resolve(); await resume.promise; }
        return assignments.get(id) || null;
    });
    const rejected = assert.rejects(store.savePush(current), { status: 409 });
    await entered.promise;
    assignments.set(old.deviceId, old);
    resume.resolve();
    await rejected;
    assert.deepEqual(await read(), [old]);
});

test('async ownership lookup holds mutation queue; competing approved destination cannot steal token', async t => {
    const entered = deferred();
    const resume = deferred();
    const old = oldDevice();
    const current = device();
    const competitor = device({ deviceId: 'competitor', pbxId: 'another-tenant' });
    const { store, read } = await fixture(t, [old], [current, competitor], async (id, assignments) => {
        if (id === old.deviceId) { entered.resolve(); await resume.promise; }
        return assignments.get(id) || null;
    });
    const saving = store.savePush(current);
    await entered.promise;
    const blocked = assert.rejects(store.savePush(competitor), { status: 409 });
    resume.resolve();
    await Promise.all([saving, blocked]);
    assert.deepEqual(await read(), [current]);
});

test('queued reassignment rejects old extension, replaces same device row, and copies caller input', async t => {
    const entered = deferred();
    const resume = deferred();
    const current = device();
    const next = device({ pbxId: 'replacement-pbx', extension: '222' });
    const { store, assignments, read } = await fixture(t, [current], [current], async (id, assignments) => {
        if (id === 'unrelated') { entered.resolve(); await resume.promise; }
        return assignments.get(id) || null;
    });
    const unrelated = device({ deviceId: 'unrelated', pbxId: 'unrelated-pbx', token: 'unrelated-token' });
    assignments.set(unrelated.deviceId, unrelated);
    const blocking = store.savePush(unrelated);
    await entered.promise;
    const queued = assert.rejects(store.savePush(current), /approval changed/);
    assignments.set(current.deviceId, next);
    current.extension = next.extension;
    current.pbxId = next.pbxId;
    resume.resolve();
    await Promise.all([blocking, queued]);
    assert.deepEqual(await store.listPush('current-pbx', '111'), []);
    await store.savePush(next);
    assert.deepEqual((await read()).filter(row => row.deviceId === next.deviceId), [next]);
    assert.deepEqual(await store.listPush(next.pbxId, next.extension), [next]);
});

test('retired PBX/reassigned extensions are excluded immediately and explicitly pruned', async t => {
    const retired = oldDevice();
    const reassigned = device();
    const valid = device({ deviceId: 'valid', deviceUuid: 'installation-b', token: 'valid-token' });
    const { store, read, assignments } = await fixture(t, [retired, reassigned, valid], [reassigned, valid]);
    assignments.set(reassigned.deviceId, { ...reassigned, extension: '222' });
    assert.deepEqual(await store.listPush(retired.pbxId, retired.extension), []);
    assert.deepEqual(await store.listPush(valid.pbxId, valid.extension), [valid]);
    assert.deepEqual(await read(), [retired, reassigned, valid]);
    assert.equal(await store.pruneInvalidPush(), 2);
    assert.deepEqual(await read(), [valid]);
    assert.equal(await store.pruneInvalidPush(), 0);
});

for (const change of [{ extension: '222' }, { pbxId: 'replacement-pbx' }, { deviceUuid: 'replacement-installation' }]) {
    test(`same device ${Object.keys(change)[0]} change invalidates old row and requires current registration`, async t => {
        const old = device();
        const current = device(change);
        const { store, read } = await fixture(t, [old], [current]);
        assert.deepEqual(await store.listPush(old.pbxId, old.extension), []);
        await assert.rejects(store.savePush(old), /approval changed/);
        assert.deepEqual(await read(), [old]);
        await store.savePush(current);
        assert.deepEqual(await read(), [current]);
        assert.deepEqual(await store.listPush(current.pbxId, current.extension), [current]);
    });
}

test('prune lookup errors preserve all rows and cannot poison subsequent mutations', async t => {
    const old = oldDevice();
    const current = device();
    let fail = true;
    const { store, read } = await fixture(t, [old, current], [current], async (id, assignments) => {
        if (fail && id === current.deviceId) throw new Error('approval unavailable');
        return assignments.get(id) || null;
    });
    await assert.rejects(store.pruneInvalidPush(), /unavailable/);
    assert.deepEqual(await read(), [old, current]);
    await assert.rejects(store.listPush(current.pbxId, current.extension), /unavailable/);
    fail = false;
    assert.equal(await store.pruneInvalidPush(), 1);
    assert.deepEqual(await read(), [current]);
});

test('reapproval of the same device and route invalidates the old push authorization revision', async t => {
    const old = device();
    const current = device({ authorizationRevision: 2 });
    const { store, read } = await fixture(t, [old], [current]);
    assert.deepEqual(await store.listPush(old.pbxId, old.extension), []);
    await assert.rejects(store.savePush(old), /approval changed/);
    await store.savePush(current);
    assert.deepEqual(await read(), [current]);
});
test('approval reassignment preserves an existing token for the same installation', async t => {
    const old = device({ deviceId: 'current', pbxId: 'old-pbx', extension: '111', authorizationRevision: 1 });
    const next = device({ deviceId: 'current', pbxId: 'new-pbx', extension: '333', authorizationRevision: 2 });
    const { store, assignments, read } = await fixture(t, [old], [old]);
    assignments.set('current', next);

    assert.equal(await store.reassign('current', next), true);
    const rows = await read();
    assert.equal(rows[0].pbxId, 'new-pbx');
    assert.equal(rows[0].extension, '333');
    assert.equal(rows[0].authorizationRevision, 2);
    assert.equal((await store.listPush('new-pbx', '333'))[0].deviceId, 'current');
    assert.deepEqual(await store.listPush('old-pbx', '111'), []);
});

test('reassignment is a no-op for an installation without a registered token', async t => {
    const current = device({ deviceId: 'missing', pbxId: 'new-pbx', extension: '333', authorizationRevision: 1 });
    const { store } = await fixture(t, [], [current]);
    assert.equal(await store.reassign('missing', current), false);
});

test('invalid token is quarantined until the device registers again', async t => {
    const current = device();
    const { store, read } = await fixture(t, [current], [current]);

    assert.equal(await store.markInvalid(current.deviceId, fingerprintToken(current.token), 'messaging/registration-token-not-registered'), true);
    const [invalid] = await read();
    assert.equal(invalid.pushState, 'invalid');
    assert.match(invalid.lastError, /registration-token-not-registered/);
    assert.equal(typeof invalid.invalidAt, 'number');
    assert.deepEqual(await store.listPush(current.pbxId, current.extension), []);
    assert.deepEqual(await store.listAllPush(), []);

    await store.savePush(current);
    assert.deepEqual(await read(), [current]);
    assert.deepEqual(await store.listPush(current.pbxId, current.extension), [current]);
});

test('a delayed old-token failure cannot invalidate a newly registered token', async t => {
    const now = Date.now();
    const first = device({ token: 'token-a', updatedAt: now - 1000 });
    const second = device({ token: 'token-b', updatedAt: now });
    const { store, read } = await fixture(t, [first], [second]);
    await store.savePush(first);
    await store.savePush(second);

    assert.equal(await store.markInvalid(first.deviceId, fingerprintToken(first.token), 'messaging/registration-token-not-registered'), false);
    const [row] = await read();
    assert.equal(row.token, 'token-b');
    assert.notEqual(row.pushState, 'invalid');
    assert.deepEqual(await store.listPush(second.pbxId, second.extension), [second]);

    assert.equal(await store.markInvalid(second.deviceId, fingerprintToken(second.token), 'messaging/registration-token-not-registered'), true);
    assert.deepEqual(await store.listPush(second.pbxId, second.extension), []);
});

test('records sanitized telemetry before a push token exists and preserves it on registration', async t => {
    const current = device();
    const { store, read } = await fixture(t, [], [current]);
    assert.equal(await store.recordTelemetry(current.deviceId, {
        sipState: 'registered',
        fcmTokenPresent: 'false',
        pushLastError: 'x'.repeat(500),
        token: 'must-not-be-stored',
    }), true);
    const before = (await read())[0];
    assert.equal(before.token, undefined);
    assert.equal(before.telemetry.sipState, 'registered');
    assert.equal(before.telemetry.fcmTokenPresent, 'false');
    assert.equal(before.telemetry.pushLastError.length, 256);
    assert.equal(before.telemetry.token, undefined);
    assert.equal(typeof before.telemetryAt, 'number');

    await store.savePush(current);
    const after = (await read())[0];
    assert.equal(after.token, current.token);
    assert.deepEqual(after.telemetry, before.telemetry);
    assert.equal(after.telemetryAt, before.telemetryAt);

    assert.equal(await store.recordTelemetry(current.deviceId, { sipState: 'failed' }), true);
    assert.equal((await read())[0].telemetry.sipState, 'failed');
});

test('expired registrations are pruned and fresh registrations survive', async t => {
    const now = Date.now();
    const expired = device({ deviceId: 'expired', token: 'expired-token', updatedAt: now - TOKEN_TTL_MS - 1 });
    const fresh = device({ deviceId: 'fresh', token: 'fresh-token', updatedAt: now - 1000 });
    const { store, read } = await fixture(t, [expired, fresh], [expired, fresh]);
    assert.equal(await store.pruneExpiredPush(now), 1);
    assert.deepEqual(await read(), [fresh]);
    assert.equal(await store.pruneExpiredPush(now), 0);
});

test('a successful delivery refreshes TTL even when registration is old', async t => {
    const now = Date.now();
    const row = device({ deviceId: 'delivered', token: 'delivered-token', updatedAt: now - TOKEN_TTL_MS - 1 });
    const { store, read } = await fixture(t, [row], [row]);
    assert.equal(await store.markDelivered(row.deviceId, fingerprintToken(row.token)), true);
    const [fresh] = await read();
    assert.equal(typeof fresh.lastSuccessAt, 'number');
    assert.equal(await store.pruneExpiredPush(now), 0);
    assert.deepEqual(await store.listPush(row.pbxId, row.extension), [fresh]);
});

test('telemetry without an approved assignment is rejected without writing', async t => {
    const { store, read } = await fixture(t, [], []);
    assert.equal(await store.recordTelemetry('missing-device', { sipState: 'failed' }), false);
    assert.deepEqual(await read(), []);
});

test('pruning removes a quarantined token even when its approval is still current', async t => {
    const current = device();
    const { store, read } = await fixture(t, [current], [current]);
    await store.markInvalid(current.deviceId, fingerprintToken(current.token), 'unregistered');
    assert.equal(await store.pruneInvalidPush(), 1);
    assert.deepEqual(await read(), []);
});
