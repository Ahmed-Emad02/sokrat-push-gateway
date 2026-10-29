'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createTenantPushStore } = require('../src/tenant-push-store');

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
