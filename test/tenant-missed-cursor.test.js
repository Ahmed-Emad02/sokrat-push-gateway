'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createTenantPushStore } = require('../src/tenant-push-store');
const { installTenantPush } = require('../src/tenant-push');

function response() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    set(key, value) { this.headers[key] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

function request(routes, method, pathname, { body, query = {}, headers = {} } = {}) {
  const route = routes[`${method} ${pathname}`];
  assert.ok(route, `missing ${method} ${pathname}`);
  const req = {
    body,
    query,
    get(name) { return headers[String(name).toLowerCase()] || ''; },
  };
  const res = response();
  return Promise.resolve(route(req, res)).then(() => res);
}

test('sync while ringing does not hide a later cancel', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-tenant-cursor-'));
  const pushFile = path.join(dir, 'push.json');
  const assignment = {
    deviceId: 'device-a',
    deviceUuid: '00000000-0000-4000-8000-000000000001',
    pbxId: 'pbx-a',
    extension: '111',
    authorizationRevision: 1,
  };
  const store = createTenantPushStore(pushFile, async id => id === assignment.deviceId ? assignment : null);
  await store.savePush({
    deviceId: assignment.deviceId,
    deviceUuid: assignment.deviceUuid,
    pbxId: assignment.pbxId,
    extension: assignment.extension,
    platform: 'android',
    token: 'test-token',
    voipToken: '',
    authorizationRevision: 1,
    updatedAt: Date.now(),
  });
  const routes = {};
  const sent = [];
  installTenantPush({
    post(route, handler) { routes[`POST ${route}`] = handler; },
    get(route, handler) { routes[`GET ${route}`] = handler; },
  }, {
    store,
    authorizeDevice: req => req.get('authorization') === 'Bearer secret' ? assignment : null,
    authorizePbx: async () => ({ id: assignment.pbxId }),
    normalizeCallId: value => value,
    sendToDevice: async (device, payload) => {
      sent.push({ device: device.deviceUuid, msg: payload.msg || 'incoming-call' });
      return 'message-id';
    },
  });

  const callId = '00000000-0000-4000-8000-000000000099';
  const incoming = await request(routes, 'POST', '/incoming-call', {
    body: { callee: '111', caller: '100', callerName: 'Alice', callId },
  });
  assert.equal(incoming.statusCode, 200);
  assert.equal(incoming.body.count, 1);

  // A sync can run while the call is still ringing. It must return a cursor
  // that is not later than the eventual cancellation record.
  const firstRead = await request(routes, 'GET', '/missed-calls', {
    query: { since: '2000-01-01T00:00:00.000Z' },
    headers: { authorization: 'Bearer secret' },
  });
  assert.equal(firstRead.statusCode, 200);
  assert.equal(firstRead.body.missedCalls.length, 0);
  assert.match(firstRead.body.nextSince, /^\d{4}-\d{2}-\d{2}T/);

  const cancel = await request(routes, 'POST', '/cancel-call', {
    body: { callee: '111', callId },
  });
  assert.equal(cancel.statusCode, 200);
  assert.equal(cancel.body.status, 'cancelled');
  assert.deepEqual(sent.map(item => item.msg), ['incoming-call', 'cancel-call']);

  const secondRead = await request(routes, 'GET', '/missed-calls', {
    query: { since: firstRead.body.nextSince },
    headers: { authorization: 'Bearer secret' },
  });
  assert.equal(secondRead.statusCode, 200);
  assert.equal(secondRead.body.missedCalls.length, 1);
  const missed = secondRead.body.missedCalls[0];
  assert.equal(missed.callId, `pbx-a:${callId}`);
  assert.equal(missed.callerName, 'Alice');
  assert.ok(missed.startedAt > 0);
  assert.ok(missed.recordedAt >= missed.startedAt);
  assert.ok(missed.recordedAt >= new Date(firstRead.body.nextSince).getTime());

  // A second cancel must not create a duplicate.
  await request(routes, 'POST', '/cancel-call', { body: { callee: '111', callId } });
  const thirdRead = await request(routes, 'GET', '/missed-calls', {
    query: { since: firstRead.body.nextSince },
    headers: { authorization: 'Bearer secret' },
  });
  assert.equal(thirdRead.body.missedCalls.length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('unauthenticated missed-call read is rejected', async () => {
  const routes = {};
  installTenantPush({
    post(route, handler) { routes[`POST ${route}`] = handler; },
    get(route, handler) { routes[`GET ${route}`] = handler; },
  }, {
    store: { listMissed: async () => [] },
    authorizeDevice: async () => null,
    authorizePbx: async () => null,
    normalizeCallId: value => value,
    sendToDevice: async () => 'message-id',
  });
  const res = await request(routes, 'GET', '/missed-calls', { query: { since: new Date().toISOString() } });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, 'Device approval required');
});
