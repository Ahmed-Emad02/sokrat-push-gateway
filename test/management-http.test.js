'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const express = require('express');
const { ControlStore } = require('../src/control/store');
const { createControlRouter } = require('../src/control/router');

test('extension management API requires session and CSRF, validates and persists policies', async t => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-management-http-'));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const password = crypto.randomBytes(32).toString('hex');
    const app = express();
    app.use('/control', createControlRouter({ store, loginFailureDelayMs: 0,
        credential: { configured: true, source: 'test', verify: async value => value === password } }));
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(async () => {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
        await fs.rm(dir, { recursive: true, force: true });
    });
    const origin = `http://127.0.0.1:${server.address().port}/control/api`;
    const anonymous = await fetch(`${origin}/extensions`);
    assert.equal(anonymous.status, 401);
    const session = await fetch(`${origin}/session`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
    assert.equal(session.status, 200);
    const cookie = session.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    const { csrfToken } = await session.json();
    const headers = { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken };
    const pbx = await store.addPbx({ name: 'Managed PBX', wsURL: 'ws://pbx.example.com:8088/ws',
        apiURL: 'http://pbx.example.com:8080', enabled: true,
        management: { customer: 'Customer', approvalStatus: 'approved', extensionPolicyRequired: true } });
    const input = { pbxId: pbx.id, extension: '0012', name: '<script>not markup</script>',
        status: 'enabled', maxDevices: 2, allowedPlatforms: ['android', 'desktop'] };
    const denied = await fetch(`${origin}/extensions`, { method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
    assert.equal(denied.status, 403);
    const created = await fetch(`${origin}/extensions`, { method: 'POST', headers, body: JSON.stringify(input) });
    assert.equal(created.status, 201);
    const body = await created.json();
    assert.equal(body.extension.extension, '0012');
    const updated = await fetch(`${origin}/extensions/${body.extension.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ status: 'suspended' }) });
    assert.equal(updated.status, 200);
    assert.equal((await updated.json()).extension.status, 'suspended');
    const invalid = await fetch(`${origin}/extensions/${body.extension.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ maxDevices: 0 }) });
    assert.equal(invalid.status, 400);
    const listed = await fetch(`${origin}/extensions?pbxId=${encodeURIComponent(pbx.id)}`, { headers });
    assert.equal(listed.status, 200);
    assert.equal((await listed.json()).extensions.length, 1);
    assert.equal(store.snapshot().extensions[0].name, input.name);
    const badQuery = await fetch(`${origin}/extensions?pbxId[x]=invalid`, { headers });
    assert.equal(badQuery.status, 400);
    const reassigned = await fetch(`${origin}/extensions/${body.extension.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ pbxId: 'another-pbx' }) });
    assert.equal(reassigned.status, 400);
    const malformedManagement = await fetch(`${origin}/pbx/${pbx.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ management: null }) });
    assert.equal(malformedManagement.status, 400);
    const before = JSON.stringify(store.snapshot().pbx);
    const unknown = await fetch(`${origin}/pbx/${pbx.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ management: { verified: true } }) });
    assert.equal(unknown.status, 400);
    assert.equal(JSON.stringify(store.snapshot().pbx), before);
    const sourceChanged = await fetch(`${origin}/pbx/${pbx.id}`, { method: 'PATCH', headers,
        body: JSON.stringify({ management: { reviewedInstallationId: 'replacement-installation', approvalStatus: 'approved' } }) });
    assert.equal(sourceChanged.status, 200);
    assert.equal((await sourceChanged.json()).pbx.management.approvalStatus, 'pending');
});
