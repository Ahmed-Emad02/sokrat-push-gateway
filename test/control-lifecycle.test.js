'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { ControlStore } = require('../src/control/store');
const { createTenantRuntime } = require('../src/tenant-runtime');
const { createDeviceTickets } = require('../src/device-tickets');

async function fixture(t) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-control-lifecycle-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const addPbx = (name, overrides = {}) => store.addPbx({ name,
        wsURL: 'ws://pbx.example.test:8088/ws', apiURL: 'http://pbx.example.test:8080',
        mediaIps: ['203.0.113.19'], ...overrides });
    const enroll = async (pbxId, extension = 'line-a', overrides = {}) => {
        const claimSecret = crypto.randomBytes(32).toString('base64url');
        const body = { claimSecret, deviceUuid: crypto.randomUUID(), platform: 'android', extension, pbxId, ...overrides };
        const { device } = await store.enrollClaim(body);
        return { body, device, claimSecret };
    };
    const approve = async (client, pbxId, extension = client.body.extension) => {
        await store.approveDevice(client.device.id, { pbxId, extension });
        return store.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret });
    };
    return { dir, store, addPbx, enroll, approve };
}

test('remove/re-add same address retires approved and pending access without affecting another PBX', async t => {
    const { store, addPbx, enroll, approve } = await fixture(t);
    const pbx = await addPbx('Retiring');
    const other = await addPbx('Preserved');
    const active = await enroll(pbx.id);
    await approve(active, pbx.id);
    const unaffected = await enroll(other.id);
    await approve(unaffected, other.id);
    const pending = await enroll(pbx.id, 'line-b');
    const invite = await store.createEnrollmentToken({ pbxId: pbx.id, maxUses: 2 });
    const invited = await store.enrollDevice({ token: invite.token, platform: 'ios', deviceUuid: crypto.randomUUID() });

    const result = await store.removePbx(pbx.id);
    assert.equal(result.revokedDevices, 3);
    assert.equal(result.revokedInvites, 1);
    const replacement = await addPbx('Retiring');
    assert.notEqual(replacement.id, pbx.id);
    for (const client of [active, pending]) {
        await assert.rejects(store.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret }), { code: 'device_revoked' });
        await assert.rejects(store.approveDevice(client.device.id, { pbxId: replacement.id, extension: 'line-a' }), { code: 'invalid_device_state' });
    }
    await assert.rejects(store.approveDevice(invited.device.id, { pbxId: replacement.id, extension: 'line-a' }), { code: 'invalid_device_state' });
    await assert.rejects(store.enrollDevice({ token: invite.token, platform: 'ios', deviceUuid: crypto.randomUUID() }), { code: 'enrollment_token_revoked' });
    assert.equal(store.verifyDeviceSecret(active.device.id, active.claimSecret).ok, false);
    assert.equal(store.verifyDeviceSecret(unaffected.device.id, unaffected.claimSecret).ok, true);
    const fresh = await enroll(replacement.id, 'line-a', { deviceUuid: active.body.deviceUuid });
    assert.equal(fresh.device.status, 'pending');
    assert.equal(store.verifyDeviceSecret(fresh.device.id, fresh.claimSecret).ok, false);
    await approve(fresh, replacement.id);
    assert.equal(store.verifyDeviceSecret(fresh.device.id, fresh.claimSecret).ok, true);
});

test('retired management state revokes access permanently; disable remains reversible and isolated', async t => {
    const { store, addPbx, enroll, approve } = await fixture(t);
    const pbx = await addPbx('Managed', { management: { approvalStatus: 'approved' } });
    const client = await enroll(pbx.id);
    await approve(client, pbx.id);
    await store.updatePbx(pbx.id, { enabled: false });
    assert.equal(store.verifyDeviceSecret(client.device.id, client.claimSecret).ok, false);
    assert.equal(store.getApprovedDevice(client.device.id), null);
    await store.updatePbx(pbx.id, { enabled: true });
    assert.equal(store.verifyDeviceSecret(client.device.id, client.claimSecret).ok, true);
    await store.updatePbx(pbx.id, { management: { approvalStatus: 'retired' } });
    assert.equal(store.listDevices('revoked')[0].reviewReason, 'pbx-retired');
    await store.updatePbx(pbx.id, { management: { approvalStatus: 'approved' } });
    await assert.rejects(store.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret }), { code: 'device_revoked' });
});

test('same-claim extension and PBX changes return to pending with inactive credentials and durable authorization revision', async t => {
    const { store, addPbx, enroll, approve } = await fixture(t);
    const first = await addPbx('First');
    const second = await addPbx('Second');
    const client = await enroll(first.id);
    await approve(client, first.id);
    const retry = await store.enrollClaim({ ...client.body, deviceName: 'Renamed' });
    assert.equal(retry.status, 'approved');
    assert.equal(retry.device.authorizationRevision, 0);

    const changed = await store.enrollClaim({ ...client.body, extension: 'line-b' });
    assert.equal(changed.status, 'pending');
    assert.equal(changed.device.pbxId, null);
    assert.equal(changed.device.extension, null);
    assert.equal(changed.device.hasSecret, false);
    assert.equal(changed.device.claimRedeemedAt, null);
    assert.equal(changed.device.authorizationRevision, 1);
    assert.equal(store.verifyDeviceSecret(client.device.id, client.claimSecret).ok, false);
    assert.equal((await store.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret })).assignment, null);
    await approve(client, first.id, 'line-b');

    const moved = await store.enrollClaim({ ...client.body, extension: 'line-b', pbxId: second.id });
    assert.equal(moved.status, 'pending');
    assert.equal(moved.device.suggestedPbxId, second.id);
    assert.equal(moved.device.authorizationRevision, 2);
    await approve(client, second.id, 'line-b');
    const reloaded = new ControlStore({ filePath: store.filePath });
    await reloaded.init();
    assert.equal(reloaded.getApprovedDevice(client.device.id).authorizationRevision, 2);
    assert.equal((await reloaded.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret })).assignment.pbxId, second.id);
    assert.match(JSON.stringify(store.auditLog()), /claim.reapproval_requested/);
});

test('claim possession cannot silently change the installation identity or platform', async t => {
    const { store, addPbx, enroll, approve } = await fixture(t);
    const pbx = await addPbx('PBX');
    const client = await enroll(pbx.id);
    await approve(client, pbx.id);
    for (const change of [{ platform: 'desktop' }, { deviceUuid: crypto.randomUUID() }]) {
        await assert.rejects(store.enrollClaim({ ...client.body, ...change }), { code: 'claim_identity_mismatch' });
    }
    assert.equal(store.verifyDeviceSecret(client.device.id, client.claimSecret).ok, true);
});

test('pending account edits remain pending and never activate a credential', async t => {
    const { store, addPbx, enroll } = await fixture(t);
    const first = await addPbx('First');
    const second = await addPbx('Second');
    const client = await enroll(first.id);
    const changed = await store.enrollClaim({ ...client.body, extension: 'line-b', pbxId: second.id });
    assert.equal(changed.device.id, client.device.id);
    assert.equal(changed.status, 'pending');
    assert.equal(changed.device.suggestedExtension, 'line-b');
    assert.equal(changed.device.suggestedPbxId, second.id);
    assert.equal(changed.device.hasSecret, false);
    await store.removePbx(first.id);
    assert.equal(store.listDevices('pending').length, 1, 'pending request now belongs to the second PBX');
    await store.removePbx(second.id);
    await assert.rejects(store.redeemClaim({ deviceId: client.device.id, claimSecret: client.claimSecret }), { code: 'device_revoked' });
});

test('outstanding ticket is refused after retirement/re-add; unrelated tenant ticket remains valid', async t => {
    const { dir, store, addPbx, enroll, approve } = await fixture(t);
    const retiring = await addPbx('Retiring');
    const retained = await addPbx('Retained');
    const old = await enroll(retiring.id);
    const other = await enroll(retained.id);
    await approve(old, retiring.id);
    await approve(other, retained.id);
    const runtime = createTenantRuntime({ control: { store }, pushFile: path.join(dir, 'push.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    const tickets = createDeviceTickets({ authorize: runtime.authorize });
    const oldTicket = tickets.issue(old.device.id, old.claimSecret, await runtime.authorize(old.device.id, old.claimSecret));
    const otherTicket = tickets.issue(other.device.id, other.claimSecret, await runtime.authorize(other.device.id, other.claimSecret));
    await store.removePbx(retiring.id);
    await addPbx('Retiring');
    assert.equal(await tickets.consume(oldTicket), null);
    assert.equal((await tickets.consume(otherTicket)).route.pbxId, retained.id);
    assert.equal(await tickets.consume(otherTicket), null, 'still single use');
});

test('tickets cannot survive reapproval to the original route; live WS is revoked without closing unrelated devices', { timeout: 20000 }, async t => {
    const { dir, store, addPbx, enroll, approve } = await fixture(t);
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(upstream, 'listening');
    upstream.on('connection', ws => ws.on('message', data => ws.send(data.toString())));
    const pbx = await addPbx('SIP', { wsURL: `ws://127.0.0.1:${upstream.address().port}/ws` });
    const client = await enroll(pbx.id);
    const other = await enroll(pbx.id);
    await approve(client, pbx.id);
    await approve(other, pbx.id);
    const runtime = createTenantRuntime({ control: { store }, pushFile: path.join(dir, 'push.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    const app = express();
    app.use('/api/gateway', runtime.router);
    const server = http.createServer(app);
    const proxy = runtime.attach(server);
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `127.0.0.1:${server.address().port}`;
    const issue = async c => {
        const response = await fetch(`http://${base}/api/gateway/sip-ticket`, { method: 'POST',
            headers: { 'X-Sokrat-Device': c.device.id, Authorization: `Bearer ${c.claimSecret}` } });
        assert.equal(response.status, 200);
        return (await response.json()).ticket;
    };
    const open = async ticket => {
        const ws = new WebSocket(`ws://${base}/ws?ticket=${ticket}`, 'sip');
        await once(ws, 'open');
        return ws;
    };
    const sockets = [];
    t.after(() => { for (const ws of sockets) ws.terminate(); proxy.close(); upstream.close(); server.closeAllConnections(); server.close(); });
    const live = await open(await issue(client)); sockets.push(live);
    const unaffected = await open(await issue(other)); sockets.push(unaffected);
    const staleTicket = await issue(client);
    const closed = once(live, 'close');
    await store.enrollClaim({ ...client.body, extension: 'line-b' });
    await approve(client, pbx.id, 'line-b');
    await store.enrollClaim(client.body);
    await approve(client, pbx.id);
    const denied = new WebSocket(`ws://${base}/ws?ticket=${staleTicket}`, 'sip');
    denied.on('error', () => {});
    const [, response] = await once(denied, 'unexpected-response');
    assert.equal(response.statusCode, 403);
    response.resume(); denied.terminate();
    await closed;
    assert.equal(unaffected.readyState, WebSocket.OPEN);
    const message = 'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:line-a@gateway>\r\n\r\n';
    const echoed = once(unaffected, 'message');
    unaffected.send(message);
    assert.equal((await echoed)[0].toString(), message);
    const fresh = await open(await issue(client)); sockets.push(fresh);
    assert.equal(fresh.readyState, WebSocket.OPEN);
});
