'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { once } = require('node:events');
const { createTenantRuntime } = require('../src/tenant-runtime');
test('HTTP runtime gates relay and SIP tickets by approved device secret', async () => {
    const control = { store: {
        getApprovedDevice: id => id === 'deviceA' ? { id, deviceUuid: 'uuid', pbxId: 'A', extension: 'fixture' } : null,
        getPbx: id => ({ id, enabled: true, wsURL: 'ws://pbx.example:8088/ws' }),
        verifyDeviceSecret: (id, token) => ({ ok: id === 'deviceA' && token === '0123456789abcdef' })
    } };
    const runtime = createTenantRuntime({ control, pushFile: '/not-used', getRelay: async () => ({ host: 'gateway.example', port: 3500, secret: 'fixture-secret' }),
        authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
    const app = express(); app.use('/api/gateway', runtime.router);
    const server = http.createServer(app); server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}/api/gateway`;
    try {
        assert.equal((await fetch(base + '/ice')).status, 403);
        const headers = { Authorization: 'Bearer 0123456789abcdef', 'X-Sokrat-Device': 'deviceA' };
        const response = await fetch(base + '/ice', { headers });
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('cache-control'), 'no-store');
        assert.ok((await response.json()).iceServers[0].urls[0].includes(':3500'));
        const ticket = await fetch(base + '/sip-ticket', { method: 'POST', headers });
        assert.equal(ticket.status, 200);
        assert.equal((await ticket.json()).expiresIn, 30);
        assert.equal((await fetch(base + '/sip-ticket', { method: 'POST' })).status, 403);
    } finally { server.close(); }
});
