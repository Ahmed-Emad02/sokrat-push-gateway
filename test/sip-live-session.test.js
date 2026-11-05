'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy, SIP_LIVE_CLIENT_MS } = require('../src/sip-proxy');

test('live-session query follows client activity, not the PBX contact', { timeout: 5000 }, async t => {
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(upstream, 'listening');
    upstream.on('connection', socket => socket.on('message', data => socket.send(data.toString())));
    const route = {
        pbxId: 'pbx_live', extension: '100', authorizationRevision: 1,
        wsUrl: `ws://127.0.0.1:${upstream.address().port}`,
    };
    const server = http.createServer();
    const proxy = attachSipProxy(server, {
        liveClientMs: 40,
        authorize: async (device, token) => device === 'device' && token === 'secret' ? route : null,
        isAuthorized: async () => true,
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const client = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?device=device&token=secret`, 'sip');
    t.after(() => {
        client.terminate();
        proxy.close();
        upstream.close();
        server.close();
    });
    await once(client, 'open');
    assert.equal(proxy.hasLiveSession('pbx_live', '100'), true);
    assert.equal(proxy.hasLiveSession('pbx_other', '100'), false);
    assert.equal(proxy.hasLiveSession('pbx_live', '101'), false);
    await delay(60);
    assert.equal(proxy.hasLiveSession('pbx_live', '100'), false, 'silent open socket must age out');
    client.send('REGISTER sip:pbx SIP/2.0\r\nFrom: <sip:100@pbx>\r\n\r\n');
    await delay(10);
    assert.equal(proxy.hasLiveSession('pbx_live', '100'), true, 'client traffic refreshes liveness');
    client.terminate();
    await delay(20);
    assert.equal(proxy.hasLiveSession('pbx_live', '100'), false, 'closed client is not live');
});

test('live-client threshold covers the gateway ping interval', () => {
    assert.ok(SIP_LIVE_CLIENT_MS >= 25000);
});
