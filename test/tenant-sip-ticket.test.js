'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy } = require('../src/sip-proxy');
const { createDeviceTickets } = require('../src/device-tickets');
test('ticket-only SIP upgrade rejects permanent token URLs and replayed tickets', async () => {
    const upstream = new WebSocketServer({ port: 0, host: '127.0.0.1' }); await once(upstream, 'listening');
    const authorize = async () => ({ extension: 'fixture', wsUrl: `ws://127.0.0.1:${upstream.address().port}` });
    const tickets = createDeviceTickets({ authorize });
    const server = http.createServer();
    const proxy = attachSipProxy(server, { authorize, isAuthorized: async () => true, consumeTicket: tickets.consume });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `ws://127.0.0.1:${server.address().port}/ws`;
    const refuse = url => new Promise((resolve, reject) => {
        const ws = new WebSocket(url, 'sip');
        ws.on('error', () => {});
        ws.on('unexpected-response', (req, res) => { try { assert.equal(res.statusCode, 403); res.resume(); ws.terminate(); resolve(); } catch (e) { reject(e); } });
        ws.on('open', () => { ws.terminate(); reject(new Error('Unexpected upgrade')); });
    });
    try {
        await refuse(base + '?device=device&token=permanent-secret');
        const ticket = tickets.issue('device', 'permanent-secret');
        const client = new WebSocket(base + '?ticket=' + ticket, 'sip'); await once(client, 'open');
        client.terminate(); await once(client, 'close');
        await refuse(base + '?ticket=' + ticket);
    } finally { proxy.close(); upstream.close(); server.close(); }
});
