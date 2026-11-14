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

test('assignment carries only the enabled PBX direct fallback', async () => {
    const pbx = {
        id: 'pbx', enabled: true,
        wsURL: 'ws://pbx.example:8088/ws',
        apiURL: 'http://pbx.example:8080',
        directWsURL: 'wss://public-pbx.example:8089/ws',
        directApiURL: 'https://public-pbx.example:8080',
        allowDirectFallback: true,
    };
    const control = { store: {
        getApprovedDevice: id => id === 'device' ? { id, deviceUuid: 'uuid', pbxId: 'pbx', extension: '102' } : null,
        getPbx: id => id === 'pbx' ? pbx : null,
        verifyDeviceSecret: () => ({ ok: true }),
    } };
    const runtime = createTenantRuntime({ control, pushFile: path.join(os.tmpdir(), 'unused-tenant-runtime.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    assert.deepEqual(runtime.assignment('device').directFallback, {
        wsURL: 'wss://public-pbx.example:8089/ws',
        apiURL: 'https://public-pbx.example:8080',
    });
    pbx.allowDirectFallback = false;
    assert.equal(runtime.assignment('device').directFallback, undefined);
    pbx.allowDirectFallback = true;
    pbx.directWsURL = '';
    assert.equal(runtime.assignment('device').directFallback, undefined);
});
