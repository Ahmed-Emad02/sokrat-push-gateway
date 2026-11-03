'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { installTenantPush } = require('../src/tenant-push');
const { fingerprintToken } = require('../src/push-errors');
test('permanently invalid FCM token is quarantined instead of remaining dispatchable', async () => {
    const routes = {};
    const marked = [];
    let pruned = 0;
    const store = {
        listPush: async () => [{ deviceId: 'a', token: 'dead-token' }],
        approvedAssignment: async () => ({ pbxId: 'A', extension: '100', deviceUuid: 'uuid-a' }),
        markInvalid: async (deviceId, tokenFingerprint, code) => marked.push({ deviceId, tokenFingerprint, code }),
        pruneInvalidPush: async () => { pruned += 1; },
    };
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store, authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value,
        sendToDevice: async () => { const error = new Error('dead'); error.code = 'messaging/registration-token-not-registered'; throw error; },
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/incoming-call']({ body: { callee: '100', callId: 'invalid-token-1' } }, res);
    assert.equal(res.body.status, 'partial');
    assert.equal(res.body.failed, 1);
    assert.deepEqual(marked, [{ deviceId: 'a', tokenFingerprint: fingerprintToken('dead-token'), code: 'messaging/registration-token-not-registered' }]);
    assert.equal(pruned, 1);
});

test('two valid devices on one extension both receive the incoming-call push', async () => {
    const routes = {};
    const sent = [];
    const devices = [
        { deviceId: 'phone-a', token: 'token-a' },
        { deviceId: 'phone-b', token: 'token-b' },
    ];
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: {
            listPush: async () => devices,
            approvedAssignment: async id => ({ pbxId: 'A', extension: '100', deviceUuid: `uuid-${id}` }),
        },
        authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value,
        sendToDevice: async device => sent.push(device.device_uuid),
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/incoming-call']({ body: { callee: '100', callId: 'multi-device' } }, res);
    assert.equal(res.body.dispatched ?? res.body.count, 2);
    assert.deepEqual(sent, ['uuid-phone-a', 'uuid-phone-b']);
});

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

test('cancel-call sends cancel push scoped to the correct PBX', async () => {
    const routes = {};
    const sent = [];
    const assignments = { a: { pbxId: 'A', extension: '100', deviceUuid: 'uuid-a' }, b: { pbxId: 'B', extension: '100', deviceUuid: 'uuid-b' } };
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: { listPush: async () => [{ deviceId: 'a' }, { deviceId: 'b' }], approvedAssignment: async id => assignments[id] },
        authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value, sendToDevice: async (device, call) => sent.push({ uuid: device.device_uuid, msg: call.msg })
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/cancel-call']({ body: { callee: '100', callId: 'cancel-1' } }, res);
    assert.equal(res.body.status, 'cancelled');
    assert.equal(res.body.callId, 'A:cancel-1');
    assert.equal(res.body.count, 1);
    assert.deepEqual(sent, [{ uuid: 'uuid-a', msg: 'cancel-call' }]);
});

test('cancel-call rejects missing callId', async () => {
    const routes = {};
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: {}, authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value, sendToDevice: async () => {}
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/cancel-call']({ body: { callee: '100' } }, res);
    assert.equal(res.code, 400);
    assert.equal(res.body.error, 'Invalid callId');
});

test('cancel-call rejects invalid callee', async () => {
    const routes = {};
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: {}, authorizePbx: async () => ({ id: 'A' }), authorizeDevice: async () => null,
        normalizeCallId: value => value, sendToDevice: async () => {}
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/cancel-call']({ body: { callee: '', callId: 'c1' } }, res);
    assert.equal(res.code, 400);
    assert.equal(res.body.error, 'Invalid callee');
});

test('cancel-call requires PBX authentication', async () => {
    const routes = {};
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: {}, authorizePbx: async () => null, authorizeDevice: async () => null,
        normalizeCallId: value => value, sendToDevice: async () => {}
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/cancel-call']({ body: { callee: '100', callId: 'c1' } }, res);
    assert.equal(res.code, 403);
});
