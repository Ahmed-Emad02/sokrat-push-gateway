'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocket, WebSocketServer } = require('ws');
const { attachSipProxy } = require('../src/sip-proxy');

const FLOW = 'a'.repeat(32);
const REGISTER = 'REGISTER sip:pbx SIP/2.0\r\nFrom: <sip:fixture@pbx>\r\nCall-ID: registration\r\nContent-Length: 0\r\n\r\n';
const INVITE = 'INVITE sip:fixture@pbx SIP/2.0\r\nFrom: <sip:caller@pbx>;tag=remote\r\nCall-ID: incoming\r\nContent-Length: 0\r\n\r\n';
const BYE = 'BYE sip:caller@pbx SIP/2.0\r\nFrom: <sip:contact@pbx>;tag=local\r\nTo: <sip:caller@pbx>;tag=remote\r\nCall-ID: incoming\r\nContent-Length: 0\r\n\r\n';

async function fixture(t, handoverGraceMs = 1000) {
    const upstream = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(upstream, 'listening');
    const connections = [];
    upstream.on('connection', ws => { connections.push(ws); ws.on('message', data => ws.send(data)); });
    const route = { pbxId: 'pbx_fixture', extension: 'fixture', authorizationRevision: 1,
        wsUrl: `ws://127.0.0.1:${upstream.address().port}` };
    const tickets = new Map();
    let authorized = true;
    const server = http.createServer();
    const proxy = attachSipProxy(server, {
        handoverGraceMs, authorize: async () => route,
        consumeTicket: async ticket => {
            const value = tickets.get(ticket); tickets.delete(ticket);
            return authorized ? value : null;
        }, isAuthorized: async () => authorized,
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const clients = [];
    let serial = 0;
    function dial({ flow = FLOW, device = 'device-1', customRoute = route, ticket } = {}) {
        if (!ticket) {
            ticket = `ticket-${++serial}`;
            tickets.set(ticket, { deviceId: device, token: 'device-secret', route: { ...customRoute } });
        }
        const ws = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws?ticket=${ticket}${flow ? `&flow=${flow}` : ''}`, 'sip');
        clients.push(ws);
        return ws;
    }
    async function open(options) {
        const ws = dial(options); await once(ws, 'open');
        // SIP roundtrip ensures the upstream connection is open as well.
        const response = once(ws, 'message'); ws.send(REGISTER); await response;
        return ws;
    }
    t.after(() => { for (const ws of clients) ws.terminate(); proxy.close(); upstream.close(); server.close(); });
    return { dial, open, connections, route, revoke: () => { authorized = false; } };
}

test('authenticated flow resumes same PBX connection and incoming-dialog validation after disconnect', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    const first = await f.open();
    const invite = once(first, 'message'); f.connections[0].send(INVITE); await invite;
    const lost = once(first, 'close'); first.terminate(); await lost; await delay(20);
    assert.equal(f.connections[0].readyState, WebSocket.OPEN);
    const next = await f.open();
    assert.equal(f.connections.length, 1);
    const response = once(next, 'message'); next.send(BYE);
    assert.equal((await response)[0].toString(), BYE);
    const closed = once(next, 'close'); next.send(BYE.replace('BYE ', 'REGISTER ')); await closed;
});

test('handover replaces an old apparently-live phone socket but ignores its late close', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    const first = await f.open();
    const lost = once(first, 'close');
    const next = await f.open(); await lost;
    await delay(20);
    assert.equal(next.readyState, WebSocket.OPEN);
    assert.equal(f.connections.length, 1);
});

test('remote hangup arriving during handover is buffered then delivered, not resurrected', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    const first = await f.open();
    const lost = once(first, 'close'); first.terminate(); await lost; await delay(20);
    f.connections[0].send(BYE); await delay(20);
    const next = f.dial();
    const response = once(next, 'message');
    assert.equal((await response)[0].toString(), BYE);
    assert.equal(f.connections.length, 1);
});

test('new UA flow or another device never inherits an existing PBX connection', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    await f.open();
    await f.open({ flow: 'b'.repeat(32) });
    await f.open({ device: 'device-2' });
    assert.equal(f.connections.length, 3);
});

test('flow expiry closes PBX connection; ordinary non-flow clients retain immediate cleanup', { timeout: 5000 }, async t => {
    const f = await fixture(t, 50);
    const first = await f.open();
    const closed = once(f.connections[0], 'close'); first.terminate(); await closed;
    const normal = await f.open({ flow: null });
    const normalClosed = once(f.connections[1], 'close'); normal.terminate(); await normalClosed;
});

test('revocation, replayed tickets and malformed flow IDs cannot resume a flow', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    await f.open();
    for (const options of [{ ticket: 'ticket-1' }, { flow: 'not-hex' }]) {
        const refused = f.dial(options);
        await assert.rejects(once(refused, 'open'), /403/);
    }
    f.revoke();
    await assert.rejects(once(f.dial(), 'open'), /403/);
    assert.equal(f.connections.length, 1);
});

test('changed assignment/revision cannot attach to a previous flow', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    const first = await f.open();
    for (const change of [{ pbxId: 'pbx_other' }, { extension: 'other' }, { authorizationRevision: 2 }]) {
        const refused = f.dial({ customRoute: { ...f.route, ...change } });
        await assert.rejects(once(refused, 'open'), /403/);
    }
    assert.equal(first.readyState, WebSocket.OPEN);
    assert.equal(f.connections.length, 1);
});

test('handover backlog is byte-bounded and closes both sides on overflow', { timeout: 5000 }, async t => {
    const f = await fixture(t);
    const first = await f.open();
    const lost = once(first, 'close'); first.terminate(); await lost; await delay(20);
    const closed = once(f.connections[0], 'close');
    f.connections[0].send('x'.repeat(200000));
    f.connections[0].send('x'.repeat(100000));
    await closed;
});

test('revocation closes a detached PBX flow at authorization check, without waiting for grace', { timeout: 15000 }, async t => {
    const f = await fixture(t, 20000);
    const first = await f.open();
    const lost = once(first, 'close'); first.terminate(); await lost; await delay(20);
    const closed = once(f.connections[0], 'close');
    f.revoke();
    await closed;
    await assert.rejects(once(f.dial(), 'open'), /403/);
});
