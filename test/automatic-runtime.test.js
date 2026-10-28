'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { ControlStore, createEnrollmentRouter } = require('../src/control');
const { createTenantRuntime } = require('../src/tenant-runtime');

test('automatic desktop enrollment requires approval and claim before ticket-only SIP', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-auto-runtime-'));
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(upstream, 'listening');
    upstream.on('connection', ws => ws.on('message', data => ws.send(data.toString())));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const pbx = await store.addPbx({ name: 'Fixture', wsURL: `ws://127.0.0.1:${upstream.address().port}/ws`,
        apiURL: 'http://pbx.example:8080', mediaIps: ['10.0.0.2'], enabled: true });
    const runtime = createTenantRuntime({ control: { store }, pushFile: path.join(dir, 'push.json'),
        getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    const app = express();
    app.use('/api/gateway/enrollment', createEnrollmentRouter({ store }));
    app.use('/api/gateway', runtime.router);
    const server = http.createServer(app);
    const proxy = runtime.attach(server);
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}/api/gateway`;
    const post = (route, body, headers = {}) => fetch(base + route, { method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    let client;
    try {
        const claimSecret = crypto.randomBytes(32).toString('base64url');
        const enrolled = await post('/enrollment/enroll', { platform: 'desktop', deviceUuid: crypto.randomUUID(),
            extension: 'fixture', claimSecret });
        assert.equal(enrolled.status, 201);
        const deviceId = (await enrolled.json()).device.id;
        const headers = { 'X-Sokrat-Device': deviceId, Authorization: `Bearer ${claimSecret}` };
        assert.equal((await post('/sip-ticket', {}, headers)).status, 403);
        assert.equal((await post('/enrollment/claim', { deviceId, claimSecret })).status, 202);
        await store.approveDevice(deviceId, { pbxId: pbx.id, extension: 'fixture' });
        assert.equal((await post('/sip-ticket', {}, headers)).status, 403);
        assert.equal((await post('/enrollment/claim', { deviceId, claimSecret })).status, 200);
        const ticketResponse = await post('/sip-ticket', {}, headers);
        assert.equal(ticketResponse.status, 200);
        const ticket = (await ticketResponse.json()).ticket;
        client = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?ticket=${ticket}`, 'sip');
        await once(client, 'open');
        const message = 'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:fixture@gateway>\r\n\r\n';
        client.send(message);
        assert.equal((await once(client, 'message'))[0].toString(), message);
        await store.revokeDevice(deviceId);
        assert.equal((await post('/sip-ticket', {}, headers)).status, 403);
    } finally {
        client?.terminate(); proxy.close(); upstream.close(); server.close();
        await fs.rm(dir, { recursive: true, force: true });
    }
});
