'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy } = require('../src/sip-proxy');
const { installTenantPush } = require('../src/tenant-push');
const { tenantCallId } = require('../src/tenant-call-id');

function normalize(value) {
    const bytes = crypto.createHash('sha1').update(value).digest().subarray(0, 16);
    bytes[6] = (bytes[6] & 15) | 0x50;
    bytes[8] = (bytes[8] & 63) | 0x80;
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

test('tenant push and incoming SIP application header share a scoped id without changing SDP/dialog bytes', { timeout: 5000 }, async () => {
    const original = '19794da4-3dbf-506d-80a9-c03becc92570';
    const pbxId = 'pbx_0123456789abcdef';
    const routes = {};
    let payload;
    installTenantPush({ post: (path, handler) => { routes[path] = handler; } }, {
        store: { listPush: async () => [{ deviceId: 'phone' }], approvedAssignment: async () => ({ pbxId, extension: 'fixture' }) },
        authorizePbx: async () => ({ id: pbxId }), authorizeDevice: async () => null,
        normalizeCallId: normalize, sendToDevice: async (_, value) => { payload = value; }
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; } };
    await routes['/incoming-call']({ body: { callee: 'fixture', callId: original } }, res);
    assert.equal(payload.callId, tenantCallId(normalize, pbxId, original));
    assert.notEqual(payload.callId, tenantCallId(normalize, 'other', original));
    const body = Buffer.from('v=0\r\ns=écho\r\na=X-Sokrat-Call-ID: leave-body-alone\r\n');
    const header = `INVITE sip:fixture@gateway SIP/2.0\r\nFrom: <sip:caller@pbx>;tag=remote\r\nCall-ID: protocol-dialog\r\nX-Sokrat-Call-ID: ${original}\r\nContent-Length: ${body.length}\r\n\r\n`;
    const message = Buffer.concat([Buffer.from(header), body]);
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(upstream, 'listening');
    upstream.on('connection', ws => ws.send(message, { binary: false }));
    const server = http.createServer();
    const proxy = attachSipProxy(server, {
        authorize: async () => ({ pbxId, extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` }),
        isAuthorized: async () => true,
        scopeIncomingCallId: (value, route) => tenantCallId(normalize, route.pbxId, value)
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?device=fixture&token=fixture`, 'sip');
    try {
        const [received, binary] = await once(client, 'message');
        assert.equal(binary, false);
        assert.deepEqual(received, Buffer.concat([Buffer.from(header.replace(original, payload.callId)), body]));
    } finally { client.terminate(); proxy.close(); upstream.close(); server.close(); }
});

for (const kind of ['duplicate', 'oversized', 'folded']) {
    test(`tenant SIP correlation refuses ${kind} application ids without forwarding an ambiguous INVITE`, { timeout: 5000 }, async () => {
        const original = '19794da4-3dbf-506d-80a9-c03becc92570';
        const app = kind === 'duplicate' ? `X-Sokrat-Call-ID: ${original}\r\nX-Sokrat-Call-ID: other` :
            kind === 'oversized' ? `X-Sokrat-Call-ID: ${'a'.repeat(97)}` : `X-Sokrat-Call-ID: ${original}\r\n continued`;
        const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 }); await once(upstream, 'listening');
        upstream.on('connection', ws => ws.send(`INVITE sip:fixture@gateway SIP/2.0\r\nFrom: <sip:caller@pbx>;tag=remote\r\nCall-ID: protocol-dialog\r\n${app}\r\nContent-Length: 0\r\n\r\n`));
        const server = http.createServer();
        const proxy = attachSipProxy(server, {
            authorize: async () => ({ extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` }),
            isAuthorized: async () => true,
            scopeIncomingCallId: value => tenantCallId(normalize, 'tenant', value)
        });
        server.listen(0, '127.0.0.1'); await once(server, 'listening');
        const client = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?device=fixture&token=fixture`, 'sip');
        let forwarded = false;
        client.on('message', () => { forwarded = true; });
        try { await once(client, 'close'); assert.equal(forwarded, false); }
        finally { client.terminate(); proxy.close(); upstream.close(); server.close(); }
    });
}
