'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { WebSocket, WebSocketServer } = require('ws');
const { GuardedRoute } = require('./guarded-route');

const SCOPE = { deviceId: 'device-a', deviceUuid: '123e4567-e89b-42d3-a456-426614174000',
    platform: 'android', pbxId: 'pbx-a', extension: '123', authorizationRevision: 1 };
function request(method, id, cseq, branch, body = '') {
    return [`${method} sip:123@synthetic.invalid SIP/2.0`, `Via: SIP/2.0/WSS synthetic.invalid;branch=${branch}`,
        'From: <sip:caller@synthetic.invalid>;tag=caller', 'To: <sip:123@synthetic.invalid>;tag=callee',
        `Call-ID: ${id}`, `CSeq: ${cseq} ${method}`, `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n');
}
function response(code, method, id, cseq, branch, body = '') {
    return [`SIP/2.0 ${code} Synthetic`, `Via: SIP/2.0/WSS synthetic.invalid;branch=${branch}`,
        'From: <sip:caller@synthetic.invalid>;tag=caller', 'To: <sip:123@synthetic.invalid>;tag=callee',
        `Call-ID: ${id}`, `CSeq: ${cseq} ${method}`, `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n');
}
const B = 'z9hG4bK-one', B2 = 'z9hG4bK-two', BB = 'z9hG4bK-bye';
async function pair(t) {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const incoming = once(server, 'connection');
    const peer = new WebSocket(`ws://127.0.0.1:${server.address().port}`);
    const [socket] = await incoming;
    if (peer.readyState !== WebSocket.OPEN) await once(peer, 'open');
    t.after(() => { peer.terminate(); socket.terminate(); server.close(); });
    return { peer, socket };
}
async function waitFor(fn) {
    for (let i = 0; i < 200; i++) { if (fn()) return; await delay(5); }
    assert.fail('timed out waiting for condition');
}
async function setup(t, options = {}) {
    const pbx = await pair(t), mobile = await pair(t);
    let current = { ...SCOPE, ...options.scope }, available = true, gate = null;
    const tickets = new Map([['ticket', { ...current }]]);
    const consumeTicket = async ticket => { const s = tickets.get(ticket); tickets.delete(ticket); return s; };
    const authorize = async () => { if (gate) await gate; return available ? current : null; };
    const route = await GuardedRoute.open({ ticket: 'ticket', consumeTicket, authorize, pbx: pbx.socket, mobile: mobile.socket,
        pbxIdentity: { authenticated: true, pbxId: current.pbxId } });
    t.after(() => route.close());
    return { pbx, mobile, route, consumeTicket, authorize,
        set: s => { current = s; }, unavailable: () => { available = false; }, setGate: p => { gate = p; } };
}
function next(ws) { return once(ws, 'message').then(([b]) => b.toString()); }
async function relay(from, to, msg) { const got = next(to); from.send(msg); assert.equal(await got, msg); }

test('synthetic two-call SIP signaling preserves responses, ACK, BYE and SDP bytes', async t => {
    const x = await setup(t);
    const a = request('INVITE', 'call-a', 1, B, 'v=0\r\n');
    const b = request('INVITE', 'call-b', 1, B2, 'v=0\r\n');
    await relay(x.pbx.peer, x.mobile.peer, a);
    await relay(x.pbx.peer, x.mobile.peer, b);
    await relay(x.mobile.peer, x.pbx.peer, response(180, 'INVITE', 'call-b', 1, B2));
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'INVITE', 'call-a', 1, B, 'v=0\r\n'));
    await relay(x.pbx.peer, x.mobile.peer, request('ACK', 'call-a', 1, 'z9hG4bK-ack'));
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'INVITE', 'call-b', 1, B2));
    await relay(x.pbx.peer, x.mobile.peer, request('ACK', 'call-b', 1, 'z9hG4bK-ack2'));
    await relay(x.mobile.peer, x.pbx.peer, request('BYE', 'call-a', 2, BB));
    await relay(x.pbx.peer, x.mobile.peer, response(200, 'BYE', 'call-a', 2, BB));
    assert.equal(x.route.dialogs.has('call-a'), false);
    assert.equal(x.route.dialogs.has('call-b'), true);
    await relay(x.pbx.peer, x.mobile.peer, request('BYE', 'call-b', 2, BB));
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'BYE', 'call-b', 2, BB));
    assert.equal(x.route.dialogs.size, 0);
});

test('two same-extension mobile transports stay separate; desktop is never a route target', async t => {
    const a = await setup(t), b = await setup(t, { scope: { deviceId: 'device-b' } });
    const desktop = await pair(t);
    const unexpectedB = [], unexpectedDesktop = [];
    b.mobile.peer.on('message', x => unexpectedB.push(x.toString()));
    desktop.peer.on('message', x => unexpectedDesktop.push(x.toString()));
    await relay(a.pbx.peer, a.mobile.peer, request('INVITE', 'same-extension', 1, B));
    await delay(30);
    assert.deepEqual(unexpectedB, []);
    assert.deepEqual(unexpectedDesktop, []);
    await relay(b.pbx.peer, b.mobile.peer, request('INVITE', 'same-extension', 1, B2));
    assert.deepEqual(unexpectedDesktop, []);
});

test('CANCEL before asynchronous approval completes suppresses the unsent INVITE', async t => {
    const x = await setup(t);
    let release;
    x.setGate(new Promise(r => { release = r; }));
    const received = [];
    x.mobile.peer.on('message', b => received.push(b.toString()));
    x.pbx.peer.send(request('INVITE', 'pending', 7, B));
    await waitFor(() => x.route.dialogs.get('pending')?.state === 'checking');
    x.pbx.peer.send(request('CANCEL', 'pending', 7, B));
    await waitFor(() => !x.route.dialogs.has('pending'));
    release();
    await delay(30);
    assert.deepEqual(received, []);
    assert.equal(x.route.active, true);
});

test('forwarded CANCEL, 200 CANCEL, 487 INVITE and failure ACK remain on the same route', async t => {
    const x = await setup(t);
    await relay(x.pbx.peer, x.mobile.peer, request('INVITE', 'cancel', 3, B));
    await relay(x.pbx.peer, x.mobile.peer, request('CANCEL', 'cancel', 3, B));
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'CANCEL', 'cancel', 3, B));
    await relay(x.mobile.peer, x.pbx.peer, response(487, 'INVITE', 'cancel', 3, B));
    await relay(x.pbx.peer, x.mobile.peer, request('ACK', 'cancel', 3, B));
    assert.equal(x.route.dialogs.size, 0);
});

test('revocation during approval and disconnect before approval do not forward INVITE', async t => {
    for (const disconnect of [false, true]) {
        const x = await setup(t);
        let release;
        x.setGate(new Promise(r => { release = r; }));
        const received = [];
        x.mobile.peer.on('message', b => received.push(b.toString()));
        x.pbx.peer.send(request('INVITE', 'late', 1, B));
        await waitFor(() => x.route.dialogs.get('late')?.state === 'checking');
        if (disconnect) { x.mobile.peer.terminate(); await waitFor(() => !x.route.active); }
        else x.set({ ...SCOPE, authorizationRevision: 2 });
        release();
        await waitFor(() => !x.route.active);
        assert.deepEqual(received, []);
    }
});

test('revocation after answer closes both transports and prevents further signaling', async t => {
    const x = await setup(t);
    await relay(x.pbx.peer, x.mobile.peer, request('INVITE', 'revoke', 1, B));
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'INVITE', 'revoke', 1, B));
    x.unavailable();
    const received = [];
    x.mobile.peer.on('message', b => received.push(b.toString()));
    x.pbx.peer.send(request('ACK', 'revoke', 1, B));
    await waitFor(() => !x.route.active);
    assert.deepEqual(received, []);
    assert.equal(x.route.dialogs.size, 0);
});

test('a delayed provisional response cannot follow a final response', async t => {
    const x = await setup(t);
    await relay(x.pbx.peer, x.mobile.peer, request('INVITE', 'order', 1, B));
    let release, calls = 0;
    x.route.authorize = async () => {
        if (++calls === 1) await new Promise(r => { release = r; });
        return { ...SCOPE };
    };
    const seen = [];
    x.pbx.peer.on('message', b => seen.push(b.toString()));
    x.mobile.peer.send(response(180, 'INVITE', 'order', 1, B));
    await waitFor(() => calls === 1);
    await relay(x.mobile.peer, x.pbx.peer, response(200, 'INVITE', 'order', 1, B));
    release();
    await delay(30);
    assert.deepEqual(seen, [response(200, 'INVITE', 'order', 1, B)]);
});

test('replayed ticket, nonmobile scope, forged response and mismatched CANCEL fail closed', async t => {
    const x = await setup(t);
    await assert.rejects(GuardedRoute.open({ ticket: 'ticket', consumeTicket: x.consumeTicket,
        authorize: x.authorize, pbx: x.pbx.socket, mobile: x.mobile.socket, pbxIdentity: { authenticated: true, pbxId: 'pbx-a' } }));
    const bad = await pair(t), badMobile = await pair(t);
    await assert.rejects(GuardedRoute.open({ ticket: 'new', consumeTicket: async () => ({ ...SCOPE, platform: 'desktop' }),
        authorize: async () => ({ ...SCOPE, platform: 'desktop' }), pbx: bad.socket, mobile: badMobile.socket,
        pbxIdentity: { authenticated: true, pbxId: 'pbx-a' } }));
    for (const pbxIdentity of [null, { authenticated: false, pbxId: 'pbx-a' }, { authenticated: true, pbxId: 'other-pbx' }]) {
        await assert.rejects(GuardedRoute.open({ ticket: 'new', consumeTicket: async () => ({ ...SCOPE }),
            authorize: async () => ({ ...SCOPE }), pbx: bad.socket, mobile: badMobile.socket, pbxIdentity }));
    }
    await assert.rejects(GuardedRoute.open({ ticket: 'new', consumeTicket: async () => ({ ...SCOPE }),
        authorize: async () => ({ ...SCOPE }), pbx: x.pbx.socket, mobile: badMobile.socket,
        pbxIdentity: { authenticated: true, pbxId: 'pbx-a' } }));
    await relay(x.pbx.peer, x.mobile.peer, request('INVITE', 'leg', 1, B));
    x.mobile.peer.send(response(200, 'INVITE', 'leg', 1, B2));
    await waitFor(() => !x.route.active);
    const y = await setup(t);
    await relay(y.pbx.peer, y.mobile.peer, request('INVITE', 'leg', 1, B));
    y.pbx.peer.send(request('CANCEL', 'leg', 1, B2));
    await waitFor(() => !y.route.active);
});

test('authorization timeout and wrong target extension never forward an INVITE', async t => {
    const x = await setup(t);
    x.setGate(new Promise(() => {}));
    const incoming = [];
    x.mobile.peer.on('message', b => incoming.push(b.toString()));
    x.pbx.peer.send(request('INVITE', 'timeout', 1, B));
    await waitFor(() => !x.route.active);
    assert.deepEqual(incoming, []);
    const y = await setup(t);
    const other = request('INVITE', 'other', 1, B).replace('To: <sip:123@', 'To: <sip:999@');
    const received = [];
    y.mobile.peer.on('message', b => received.push(b.toString()));
    y.pbx.peer.send(other);
    await waitFor(() => !y.route.active);
    assert.deepEqual(received, []);
});
