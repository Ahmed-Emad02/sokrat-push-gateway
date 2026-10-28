'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { installTenantPush } = require('../src/tenant-push');
test('same-number extensions cannot cross PBX push boundaries', async () => {
    const routes = {};
    const sent = [];
    const assignments = { a: { pbxId: 'A', extension: 'same', deviceUuid: 'uuid-a' }, b: { pbxId: 'B', extension: 'same', deviceUuid: 'uuid-b' } };
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: { listPush: async () => [{ deviceId: 'a' }, { deviceId: 'b' }], approvedAssignment: async id => assignments[id] },
        authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value, sendToDevice: async device => sent.push(device.device_uuid)
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/incoming-call']({ body: { callee: 'same', callId: 'call' } }, res);
    assert.deepEqual(sent, ['uuid-a']);
    assert.equal(res.body.callId, 'A:call');
    await routes['/register-device']({ body: {} }, res);
    assert.equal(res.code, 403);
});
