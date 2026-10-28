'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const { createTenantRuntime } = require('../src/tenant-runtime');
test('runtime requires approval, device secret and an enabled assigned PBX', async () => {
    let enabled = true, approved = true;
    const control = { store: {
        getApprovedDevice: id => approved && id === 'device' ? { id, deviceUuid: 'uuid', pbxId: 'pbx', extension: 'fixture' } : null,
        getPbx: id => ({ id, enabled, wsURL: 'ws://pbx.example:8088/ws', apiURL: 'http://pbx.example:8080' }),
        verifyDeviceSecret: (id, token) => ({ ok: id === 'device' && token === 'valid-secret' })
    } };
    const runtime = createTenantRuntime({ control, pushFile: path.join(os.tmpdir(), 'unused-tenant-runtime.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    assert.equal(await runtime.authorize('device', 'wrong'), null);
    assert.equal((await runtime.authorize('device', 'valid-secret')).extension, 'fixture');
    enabled = false;
    assert.equal(await runtime.authorize('device', 'valid-secret'), null);
    enabled = true; approved = false;
    assert.equal(await runtime.authorize('device', 'valid-secret'), null);
});
