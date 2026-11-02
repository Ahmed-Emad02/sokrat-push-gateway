'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHeartbeatScheduler } = require('../src/heartbeat-scheduler');
const { fingerprintToken } = require('../src/push-errors');

function device(overrides = {}) {
    return {
        deviceId: 'device-a',
        deviceUuid: 'uuid-a',
        pbxId: 'pbx-test',
        extension: '223',
        platform: 'android',
        token: 'fcm-token-a',
        updatedAt: Date.now(),
        ...overrides,
    };
}

test('heartbeat scheduler is disabled by default and sends nothing', async () => {
    const sent = [];
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device()],
        sendToDevice: async () => sent.push('sent'),
        now: () => 1000,
        sleep: async () => {},
    });
    await scheduler.run();
    assert.deepEqual(sent, []);
});

test('sends one data-only wake to a stale approved Android device', async () => {
    const sent = [];
    let now = 1_000_000;
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device()],
        sendToDevice: async (dev, payload) => sent.push({ dev, payload }),
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => now,
        sleep: async () => {},
    });

    assert.deepEqual(await scheduler.run(), { sent: 1, failed: 0, skipped: 0 });
    assert.equal(sent.length, 1);
    assert.equal(sent[0].dev.token, 'fcm-token-a');
    assert.deepEqual(sent[0].payload, { msg: 'wake', type: 'keepalive', timestamp: '1000000' });

    now += 179_999;
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 0, skipped: 1 });
    now += 1;
    assert.deepEqual(await scheduler.run(), { sent: 1, failed: 0, skipped: 0 });
});

test('fresh heartbeat, iOS, and other PBX devices are skipped', async () => {
    let now = 1_000_000;
    const sent = [];
    const devices = [
        device({ deviceId: 'fresh' }),
        device({ deviceId: 'ios', platform: 'ios' }),
        device({ deviceId: 'other-pbx', pbxId: 'pbx-other' }),
    ];
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => devices,
        sendToDevice: async dev => sent.push(dev.deviceId),
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => now,
        sleep: async () => {},
    });
    scheduler.markSeen('fresh', now);
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 0, skipped: 3 });
    assert.deepEqual(sent, []);

    now += 180_000;
    assert.deepEqual(await scheduler.run(), { sent: 1, failed: 0, skipped: 2 });
    assert.deepEqual(sent, ['fresh']);
});

test('failed wake backs off and is not retried on the next tick', async () => {
    let now = 1_000_000;
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device()],
        sendToDevice: async () => { throw new Error('fcm unavailable'); },
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => now,
        sleep: async () => {},
        logger: { log() {}, warn() {}, error() {} },
    });
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 1, skipped: 0 });
    now += 60_000;
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 0, skipped: 1 });
});

test('quarantined invalid token is never retried by the heartbeat scheduler', async () => {
    const sent = [];
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device({ pushState: 'invalid' })],
        sendToDevice: async dev => sent.push(dev.deviceId),
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => 1_000_000,
        sleep: async () => {},
    });
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 0, skipped: 1 });
    assert.deepEqual(sent, []);
});

test('permanent token failure marks invalid once and stops retrying', async () => {
    let now = 1_000_000;
    const marked = [];
    const warnings = [];
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device({ token: 'dead-token' })],
        sendToDevice: async () => { const error = new Error('dead'); error.code = 'messaging/registration-token-not-registered'; throw error; },
        markInvalid: async (...args) => marked.push(args),
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => now,
        sleep: async () => {},
        logger: { log() {}, warn: message => warnings.push(message), error() {} },
    });
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 1, skipped: 0 });
    assert.deepEqual(marked, [['device-a', fingerprintToken('dead-token'), 'messaging/registration-token-not-registered']]);
    assert.equal(warnings.filter(message => message.includes('token invalid')).length, 1);
    now += 180_000;
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 0, skipped: 1 });
    assert.equal(marked.length, 1);
});

test('transient heartbeat failure remains retryable and is not marked invalid', async () => {
    let now = 1_000_000;
    const marked = [];
    let attempts = 0;
    const scheduler = createHeartbeatScheduler({
        listDevices: async () => [device()],
        sendToDevice: async () => { attempts++; const error = new Error('network'); error.code = 'messaging/server-unavailable'; throw error; },
        markInvalid: async (...args) => marked.push(args),
        enabled: true,
        staleMs: 180_000,
        pbxIds: ['pbx-test'],
        now: () => now,
        sleep: async () => {},
        logger: { log() {}, warn() {}, error() {} },
    });
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 1, skipped: 0 });
    assert.deepEqual(marked, []);
    now += 120_001;
    assert.deepEqual(await scheduler.run(), { sent: 0, failed: 1, skipped: 0 });
    assert.equal(attempts, 2);
});

test('device heartbeat endpoint records liveness using the approved device identity', async () => {
    const http = require('node:http');
    const express = require('express');
    const { once } = require('node:events');
    const { createTenantRuntime } = require('../src/tenant-runtime');
    const control = { store: {
        getApprovedDevice: id => id === 'deviceA' ? { id, deviceUuid: 'uuid-a', pbxId: 'pbx-test', extension: '223' } : null,
        getPbx: id => ({ id, enabled: true, wsURL: 'ws://pbx.example/ws' }),
        verifyDeviceSecret: (id, token) => ({ ok: id === 'deviceA' && token === '0123456789abcdef' }),
    } };
    const runtime = createTenantRuntime({
        control, pushFile: '/not-used', getRelay: async () => null,
        authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x,
        heartbeatOptions: { enabled: true, now: () => 1000, sleep: async () => {}, pbxIds: ['pbx-test'] },
    });
    const app = express(); app.use('/api/gateway', runtime.router);
    const server = http.createServer(app); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    try {
        const base = `http://127.0.0.1:${server.address().port}/api/gateway/device/heartbeat`;
        assert.equal((await fetch(base, { method: 'POST' })).status, 403);
        const response = await fetch(base, {
            method: 'POST',
            headers: { Authorization: 'Bearer 0123456789abcdef', 'X-Sokrat-Device': 'deviceA', 'Content-Type': 'application/json' },
            body: JSON.stringify({ sipState: 'wake' }),
        });
        assert.equal(response.status, 200);
        assert.equal((await response.json()).ok, true);
        assert.equal(runtime.heartbeat.getState('deviceA').lastSeenAt, 1000);
    } finally { server.close(); }
});
