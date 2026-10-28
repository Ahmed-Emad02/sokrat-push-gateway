'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { ControlStore } = require('../src/control/store');
const { createTenantRuntime } = require('../src/tenant-runtime');

test('runtime and claim redemption inherit managed PBX/extension suspension', async t => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'managed-runtime-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const pbx = await store.addPbx({ name: 'Managed', wsURL: 'ws://pbx.example.com:8088/ws',
        apiURL: 'http://pbx.example.com:8080', management: { approvalStatus: 'approved', extensionPolicyRequired: true } });
    const policy = await store.addExtension({ pbxId: pbx.id, extension: '0012', status: 'enabled' });
    const claimSecret = crypto.randomBytes(32).toString('base64url');
    const { device } = await store.enrollClaim({ claimSecret, platform: 'android', deviceUuid: crypto.randomUUID(), extension: '0012' });
    await store.approveDevice(device.id, { pbxId: pbx.id, extension: '0012' });
    await store.redeemClaim({ deviceId: device.id, claimSecret });
    const runtime = createTenantRuntime({ control: { store }, pushFile: path.join(dir, 'push.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: value => value });
    assert.equal((await runtime.authorize(device.id, claimSecret)).pbxId, pbx.id);
    await store.updateExtension(policy.id, { status: 'suspended' });
    assert.equal(runtime.assignment(device.id), null);
    assert.equal(await runtime.authorize(device.id, claimSecret), null);
    await assert.rejects(store.redeemClaim({ deviceId: device.id, claimSecret }), { code: 'extension_not_approved' });
    await store.updateExtension(policy.id, { status: 'enabled' });
    assert.ok(await runtime.authorize(device.id, claimSecret));
    await store.updatePbx(pbx.id, { management: { approvalStatus: 'suspended' } });
    assert.equal(await runtime.authorize(device.id, claimSecret), null);
});
