'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs').promises;
const os = require('node:os');
const path = require('node:path');

const {
    ControlStore,
    ControlStoreError,
    hashSecret,
    normalizeMediaIps
} = require('../src/control/store');

const DEVICE_UUID = 'a9e89b44-cb09-4f7c-a9e5-4da631df95ed';
const OTHER_UUID = '2f1c7f9e-8a4d-4c2b-9f3e-5b6a7c8d9e0f';

async function makeStore(options = {}) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-control-store-'));
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
        mediaIps: '203.0.113.10, 198.51.100.0/24',
        enabled: true,
        ...overrides
    };
}

async function rawDocument(filePath) {
    return JSON.parse(await fsp.readFile(filePath, 'utf8'));
}

test('creates the durable store with 0600 file and 0700 directory', async () => {
    const { dir, filePath, close } = await makeStore();
    try {
        const fileMode = (await fsp.stat(filePath)).mode & 0o777;
        const dirMode = (await fsp.stat(dir)).mode & 0o777;
        assert.equal(fileMode, 0o600);
        assert.equal(dirMode, 0o700);
        const document = await rawDocument(filePath);
        assert.equal(document.schemaVersion, 1);
        assert.deepEqual(document.pbx, []);
        assert.deepEqual(document.devices, []);
    } finally {
        await close();
    }
});

test('persists PBX records across store instances', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const created = await store.addPbx(pbxInput('Head office'), { actor: 'admin@127.0.0.1' });
        assert.match(created.id, /^pbx_[0-9a-f]{16}$/);

        const reloaded = new ControlStore({ filePath });
        await reloaded.init();
        const list = reloaded.listPbx();
        assert.equal(list.length, 1);
        assert.deepEqual(list[0].mediaIps, ['203.0.113.10', '198.51.100.0/24']);
        assert.equal(list[0].enabled, true);
        assert.equal(list[0].wsURL, 'wss://pbx.example.com:8089/ws');
        assert.equal(list[0].apiURL, 'https://pbx.example.com:8080/');
    } finally {
        await close();
    }
});

test('serialises concurrent writes without leaving temp files', async () => {
    const { dir, filePath, store, close } = await makeStore();
    try {
        await Promise.all(
            Array.from({ length: 8 }, (_, index) =>
                store.addPbx(pbxInput(`Branch ${index}`, { enabled: false }))
            )
        );
        const entries = await fsp.readdir(dir);
        assert.deepEqual(entries, ['control.json']);

        const reloaded = new ControlStore({ filePath });
        await reloaded.init();
        assert.equal(reloaded.listPbx().length, 8);
    } finally {
        await close();
    }
});

test('fails closed on a corrupt store and never overwrites it', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-control-corrupt-'));
    const filePath = path.join(dir, 'control.json');
    const corrupt = '{ this is not json';
    await fsp.writeFile(filePath, corrupt, 'utf8');
    try {
        const store = new ControlStore({ filePath });
        await assert.rejects(store.init(), (error) => {
            assert.ok(error instanceof ControlStoreError);
            assert.equal(error.code, 'control_store_corrupt');
            assert.equal(error.status, 500);
            return true;
        });
        assert.equal(await fsp.readFile(filePath, 'utf8'), corrupt);
    } finally {
        await fsp.rm(dir, { recursive: true, force: true });
    }
});

test('enforces the enabled-PBX cap on create and on re-enable', async () => {
    const { store, close } = await makeStore({ maxEnabledPbx: 2 });
    try {
        const first = await store.addPbx(pbxInput('PBX one'));
        const second = await store.addPbx(pbxInput('PBX two'));

        await assert.rejects(store.addPbx(pbxInput('PBX three')), (error) => {
            assert.equal(error.code, 'pbx_cap_reached');
            assert.equal(error.status, 409);
            return true;
        });

        const disabled = await store.addPbx(pbxInput('PBX standby', { enabled: false }));
        await assert.rejects(
            store.updatePbx(disabled.id, { enabled: true }),
            (error) => error.code === 'pbx_cap_reached'
        );

        await store.updatePbx(first.id, { enabled: false });
        const enabled = await store.updatePbx(disabled.id, { enabled: true });
        assert.equal(enabled.enabled, true);
        assert.equal(store.stats().enabledPbx, 2);

        // Updating an already-enabled record does not consume another slot.
        const renamed = await store.updatePbx(second.id, { name: 'PBX two renamed' });
        assert.equal(renamed.name, 'PBX two renamed');
    } finally {
        await close();
    }
});

test('validates PBX names, URLs, media IPs and duplicates', async () => {
    const { store, close } = await makeStore();
    try {
        await assert.rejects(store.addPbx(pbxInput('x', { wsURL: 'https://pbx' })), /must use ws:/);
        await assert.rejects(store.addPbx(pbxInput('x', { apiURL: 'wss://pbx' })), /must use http:/);
        await assert.rejects(
            store.addPbx(pbxInput('x', { wsURL: 'wss://user:pass@pbx.example.com/ws' })),
            /must not embed credentials/
        );
        await assert.rejects(store.addPbx(pbxInput('x', { mediaIps: 'not-an-ip' })), /not an IP address/);
        await assert.rejects(store.addPbx(pbxInput('x', { mediaIps: '10.0.0.0/99' })), /prefix length/);
        await assert.rejects(store.addPbx(pbxInput('   ')), /PBX name/);
        await assert.rejects(store.addPbx(pbxInput('x', { enabled: 'maybe' })), /must be a boolean/);

        await store.addPbx(pbxInput('Duplicate'));
        await assert.rejects(store.addPbx(pbxInput('duplicate')), (error) => {
            assert.equal(error.code, 'pbx_name_conflict');
            assert.equal(error.status, 409);
            return true;
        });
    } finally {
        await close();
    }
});

test('normalizes media IP lists and rejects malformed entries', () => {
    assert.deepEqual(normalizeMediaIps('10.0.0.1, 192.168.0.0/24 10.0.0.1'), [
        '10.0.0.1',
        '192.168.0.0/24'
    ]);
    assert.deepEqual(normalizeMediaIps(['2001:db8::1']), ['2001:db8::1']);
    assert.deepEqual(normalizeMediaIps(''), []);
    assert.throws(() => normalizeMediaIps('10.0.0.1/'), /invalid prefix length/);
    assert.throws(() => normalizeMediaIps('1.2.3.4.5'), /not an IP address/);
});

test('stores enrollment tokens only as digests', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const { token, record } = await store.createEnrollmentToken(
            { label: 'Reception phone', maxUses: 3 },
            { actor: 'admin' }
        );
        assert.match(token, /^sk_enroll_v1_[A-Za-z0-9_-]{43}$/);
        assert.equal(record.tokenHash, undefined);
        assert.equal(record.usedCount, 0);
        assert.equal(record.maxUses, 3);

        const onDisk = await fsp.readFile(filePath, 'utf8');
        assert.equal(onDisk.includes(token), false, 'plaintext token must not be persisted');
        assert.ok(onDisk.includes(hashSecret(token)), 'digest should be persisted');

        const state = store.snapshot();
        assert.equal(JSON.stringify(state).includes(token), false);
        assert.equal(JSON.stringify(state).includes(hashSecret(token)), false);
    } finally {
        await close();
    }
});

test('device UUID and instance id alone are not authentication', async () => {
    const { store, close } = await makeStore();
    try {
        await assert.rejects(
            store.enrollDevice({
                platform: 'ios',
                deviceUuid: DEVICE_UUID,
                instanceId: 'install-123'
            }),
            (error) => error.code === 'invalid_token' && error.status === 400
        );

        await assert.rejects(
            store.enrollDevice({
                token: `sk_enroll_v1_${'a'.repeat(43)}`,
                platform: 'ios',
                deviceUuid: DEVICE_UUID,
                instanceId: 'install-123'
            }),
            (error) => error.code === 'invalid_enrollment_token' && error.status === 401
        );
        assert.equal(store.listDevices().length, 0);
    } finally {
        await close();
    }
});

test('enrollment tokens are single use and re-enrolling a pending device is idempotent', async () => {
    const { store, close } = await makeStore();
    try {
        const { token, record } = await store.createEnrollmentToken({ label: 'one-shot' });
        const first = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: DEVICE_UUID,
            deviceName: 'Pixel 8'
        });
        assert.equal(first.device.status, 'pending');
        assert.equal(first.reused, false);

        const again = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: DEVICE_UUID,
            deviceName: 'Pixel 8 (renamed)'
        });
        assert.equal(again.reused, true);
        assert.equal(again.device.id, first.device.id);
        assert.equal(again.device.deviceName, 'Pixel 8 (renamed)');

        await assert.rejects(
            store.enrollDevice({ token, platform: 'android', deviceUuid: OTHER_UUID }),
            (error) => error.code === 'enrollment_token_exhausted' && error.status === 401
        );

        const stored = store.listEnrollmentTokens().find((item) => item.id === record.id);
        assert.equal(stored.usedCount, 1);

        const otherInvite = await store.createEnrollmentToken({ label: 'other' });
        await assert.rejects(
            store.enrollDevice({
                token: otherInvite.token,
                platform: 'android',
                deviceUuid: DEVICE_UUID
            }),
            (error) => error.code === 'device_uuid_conflict' && error.status === 409
        );
    } finally {
        await close();
    }
});

test('expired enrollment tokens are refused', async () => {
    let now = Date.parse('2026-01-01T00:00:00.000Z');
    const { store, close } = await makeStore({ now: () => now });
    try {
        const { token } = await store.createEnrollmentToken({ label: 'short', ttlMs: 60_000 });
        now += 61_000;
        await assert.rejects(
            store.enrollDevice({ token, platform: 'ios', deviceUuid: DEVICE_UUID }),
            (error) => error.code === 'enrollment_token_expired' && error.status === 401
        );
    } finally {
        await close();
    }
});

test('approval binds PBX + extension and issues a one-time device secret', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const { token } = await store.createEnrollmentToken({ label: 'invite' });
        const { device } = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: DEVICE_UUID,
            appVersion: '1.4.2'
        });

        const approved = await store.approveDevice(device.id, {
            pbxId: pbx.id,
            extension: '150'
        }, { actor: 'admin@127.0.0.1' });

        assert.equal(approved.device.status, 'approved');
        assert.equal(approved.device.pbxId, pbx.id);
        assert.equal(approved.device.extension, '150');
        assert.equal(approved.device.hasSecret, true);
        assert.match(approved.secret, /^sk_device_v1_[A-Za-z0-9_-]{43}$/);

        assert.equal(store.verifyDeviceSecret(device.id, approved.secret).ok, true);
        assert.equal(store.verifyDeviceSecret(device.id, `sk_device_v1_${'b'.repeat(43)}`).ok, false);
        assert.equal(store.verifyDeviceSecret('dev_missing', approved.secret).ok, false);

        const onDisk = await fsp.readFile(filePath, 'utf8');
        assert.equal(onDisk.includes(approved.secret), false);
        assert.ok(onDisk.includes(hashSecret(approved.secret)));

        const snapshot = JSON.stringify(store.snapshot());
        assert.equal(snapshot.includes(approved.secret), false);
        assert.equal(snapshot.includes('secretHash'), false);

        await assert.rejects(
            store.approveDevice(device.id, { pbxId: pbx.id, extension: '151' }),
            (error) => error.code === 'invalid_device_state' && error.status === 409
        );
    } finally {
        await close();
    }
});

test('cannot approve onto a disabled PBX or with a bad extension', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Disabled', { enabled: false }));
        const { token } = await store.createEnrollmentToken({ label: 'invite' });
        const { device } = await store.enrollDevice({
            token,
            platform: 'ios',
            deviceUuid: DEVICE_UUID
        });

        await assert.rejects(
            store.approveDevice(device.id, { pbxId: pbx.id, extension: '150' }),
            (error) => error.code === 'pbx_disabled' && error.status === 409
        );

        const enabled = await store.addPbx(pbxInput('Enabled'));
        await assert.rejects(
            store.approveDevice(device.id, { pbxId: enabled.id, extension: 'bad extension!' }),
            (error) => error.code === 'invalid_extension'
        );
        assert.equal(store.listDevices('pending').length, 1);
    } finally {
        await close();
    }
});

test('reject and revoke transitions clear the device secret', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const { token } = await store.createEnrollmentToken({ label: 'invite', maxUses: 2 });
        const pending = await store.enrollDevice({
            token,
            platform: 'ios',
            deviceUuid: DEVICE_UUID
        });
        const approvedSource = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: OTHER_UUID
        });

        const rejected = await store.rejectDevice(pending.device.id, { reason: 'unknown person' });
        assert.equal(rejected.status, 'rejected');
        assert.equal(rejected.reviewReason, 'unknown person');
        await assert.rejects(
            store.approveDevice(pending.device.id, { pbxId: pbx.id, extension: '150' }),
            (error) => error.code === 'invalid_device_state'
        );

        const approved = await store.approveDevice(approvedSource.device.id, {
            pbxId: pbx.id,
            extension: '151'
        });
        const revoked = await store.revokeDevice(approvedSource.device.id, { reason: 'lost phone' });
        assert.equal(revoked.status, 'revoked');
        assert.equal(revoked.hasSecret, false);
        assert.equal(store.verifyDeviceSecret(approvedSource.device.id, approved.secret).ok, false);
        await assert.rejects(
            store.revokeDevice(approvedSource.device.id),
            (error) => error.code === 'invalid_device_state'
        );
    } finally {
        await close();
    }
});

test('removing a PBX revokes its devices and invites', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const { token } = await store.createEnrollmentToken({
            label: 'hq invite',
            pbxId: pbx.id,
            extension: '150'
        });
        const { device } = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: DEVICE_UUID
        });
        const approved = await store.approveDevice(device.id, {
            pbxId: pbx.id,
            extension: '150'
        });

        await assert.rejects(
            store.enrollDevice({ token, platform: 'android', deviceUuid: OTHER_UUID }),
            (error) => error.code === 'enrollment_token_exhausted'
        );

        const secondInvite = await store.createEnrollmentToken({
            label: 'unused invite',
            pbxId: pbx.id
        });

        const result = await store.removePbx(pbx.id, { actor: 'admin' });
        assert.equal(result.pbx.id, pbx.id);
        assert.equal(result.revokedDevices, 1);
        assert.equal(result.revokedInvites, 2);

        const revokedDevice = store.listDevices('revoked')[0];
        assert.equal(revokedDevice.id, device.id);
        assert.equal(revokedDevice.reviewReason, 'pbx-removed');
        assert.equal(store.verifyDeviceSecret(device.id, approved.secret).ok, false);

        await assert.rejects(
            store.enrollDevice({ token: secondInvite.token, platform: 'ios', deviceUuid: OTHER_UUID }),
            (error) => error.code === 'enrollment_token_revoked'
        );
    } finally {
        await close();
    }
});

test('caps pending devices and refuses enrollment beyond the queue', async () => {
    const { store, close } = await makeStore({ maxPendingDevices: 1 });
    try {
        const { token } = await store.createEnrollmentToken({ label: 'many', maxUses: 5 });
        await store.enrollDevice({ token, platform: 'ios', deviceUuid: DEVICE_UUID });
        await assert.rejects(
            store.enrollDevice({ token, platform: 'android', deviceUuid: OTHER_UUID }),
            (error) => error.code === 'pending_cap_reached' && error.status === 409
        );
    } finally {
        await close();
    }
});

test('audit entries never contain secrets or token material', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('HQ'));
        const { token } = await store.createEnrollmentToken({ label: 'invite' });
        const { device } = await store.enrollDevice({
            token,
            platform: 'ios',
            deviceUuid: DEVICE_UUID
        });
        const approved = await store.approveDevice(device.id, {
            pbxId: pbx.id,
            extension: '150'
        });
        await store.revokeDevice(device.id);

        const audit = JSON.stringify(store.auditLog(50));
        assert.equal(audit.includes(token), false);
        assert.equal(audit.includes(approved.secret), false);
        assert.match(audit, /device\.approved/);
        assert.match(audit, /device\.revoked/);
    } finally {
        await close();
    }
});
