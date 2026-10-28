'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy } = require('../src/sip-proxy');

test('SIP framing prevents leading-CRLF, concatenated-message and auth identity bypasses', async () => {
    const upstream = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await once(upstream, 'listening');
    upstream.on('connection', socket => socket.on('message', d => socket.send(d.toString())));
    const server = http.createServer();
    const proxy = attachSipProxy(server, { authorize: async () => ({ extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` }), isAuthorized: async () => true });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `ws://127.0.0.1:${server.address().port}/ws?device=fixture&token=secret`;
    const bad = [
        '\r\nREGISTER sip:gateway SIP/2.0\r\nFrom: <sip:other@gateway>\r\n\r\n',
        'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:fixture@gateway>\r\nTo: <sip:fixture@gateway>;tag=fake\r\nAuthorization: Digest username="other"\r\n\r\n',
        'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:fixture@gateway>\r\n\r\nREGISTER sip:gateway SIP/2.0\r\nFrom: <sip:other@gateway>\r\n\r\n',
        'REGISTER sip:gateway SIP/2.0\r\nFrom: <sip:fixture@gateway>\r\nFrom: <sip:other@gateway>\r\n\r\n'
    ];
    try {
        for (const payload of bad) {
            const client = new WebSocket(base, 'sip'); await once(client, 'open');
            let forwarded = false;
            client.on('message', () => { forwarded = true; });
            client.send(payload); await once(client, 'close');
            assert.equal(forwarded, false);
        }
        const client = new WebSocket(base, 'sip'); await once(client, 'open');
        const folded = 'REGISTER sip:gateway SIP/2.0\r\nFrom:\r\n <sip:fixture@gateway>\r\n\r\n';
        client.send(folded); assert.equal((await once(client, 'message'))[0].toString(), folded);
        client.terminate();
    } finally { proxy.close(); upstream.close(); server.close(); }
});
