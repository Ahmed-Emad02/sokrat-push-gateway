'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy } = require('../src/sip-proxy');

test('incoming dialog keeps caller From for client BYE without allowing another registration', async () => {
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 }); await once(upstream, 'listening');
    upstream.on('connection', ws => {
        ws.send('INVITE sip:fixture@gateway SIP/2.0\r\nFrom: <sip:caller@pbx>;tag=remote\r\nCall-ID: incoming\r\n\r\n');
        ws.on('message', data => ws.send(data.toString()));
    });
    const server = http.createServer();
    const proxy = attachSipProxy(server, { authorize: async () => ({ extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` }), isAuthorized: async () => true });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?device=fixture&token=secret`, 'sip');
    try {
        await once(client, 'message');
        const bye = 'BYE sip:caller@pbx SIP/2.0\r\nFrom: <sip:caller@pbx>;tag=remote\r\nTo: <sip:fixture@pbx>;tag=local\r\nCall-ID: incoming\r\n\r\n';
        client.send(bye);
        assert.equal((await once(client, 'message'))[0].toString(), bye);
        client.send(bye.replace('BYE ', 'REGISTER '));
        await once(client, 'close');
    } finally { client.terminate(); proxy.close(); upstream.close(); server.close(); }
});
