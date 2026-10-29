'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { WebSocket, WebSocketServer } = require('ws');
const { once } = require('node:events');
const { attachSipProxy } = require('../src/sip-proxy');

test('SIP proxy fails closed, forwards approved sessions and blocks extension substitution', async () => {
    const upstream = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await once(upstream, 'listening');
    upstream.on('connection', socket => socket.on('message', d => socket.send(d.toString())));
    const server = http.createServer();
    const proxy = attachSipProxy(server, { isAuthorized: async () => true, authorize: async (id, token) =>
        id === 'device' && token === 'secret' ? { extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` } : null });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `ws://127.0.0.1:${server.address().port}/ws`;
    let client;
    try {
        const rejected = new WebSocket(base, 'sip');
        await new Promise((resolve, reject) => { rejected.on('unexpected-response', (req, res) => {
            try { assert.equal(res.statusCode, 401); res.resume(); rejected.terminate(); resolve(); } catch (e) { reject(e); }
        }); rejected.on('error', () => {}); });
        client = new WebSocket(`${base}?device=device&token=secret`, 'sip');
        await once(client, 'open');
        const message = 'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:fixture@gateway>\r\n\r\n';
        client.send(message);
        assert.equal((await once(client, 'message'))[0].toString(), message);
        const response = 'SIP/2.0 200 OK\r\nFrom: <sip:caller@gateway>\r\n\r\n';
        client.send(response);
        assert.equal((await once(client, 'message'))[0].toString(), response);

        // Incoming dialog test: upstream sends INVITE, client replies with BYE with ephemeral contact URI
        const invite = 'INVITE sip:fixture@gateway SIP/2.0\r\nFrom: "Caller" <sip:102@gateway>;tag=t1\r\nCall-ID: test-call-123\r\n\r\n';
        // Send from upstream to proxy/client
        for (const ws of upstream.clients) ws.send(invite);
        assert.equal((await once(client, 'message'))[0].toString(), invite);

        // Client hangs up with BYE where From is ephemeral contact user (e.g. n45ubo3e) and To is caller (102)
        const bye = 'BYE sip:102@gateway SIP/2.0\r\nFrom: <sip:n45ubo3e@gateway>;tag=t2\r\nTo: "Caller" <sip:102@gateway>;tag=t1\r\nCall-ID: test-call-123\r\n\r\n';
        client.send(bye);
        assert.equal((await once(client, 'message'))[0].toString(), bye);

        client.send('REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:other@gateway>\r\n\r\n');
        await once(client, 'close');
    } finally {
        client?.terminate(); proxy.close(); upstream.close(); server.close();
    }
});
