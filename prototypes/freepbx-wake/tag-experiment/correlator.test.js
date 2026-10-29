'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const { TagExperiment } = require('./correlator');

const UUID = '123e4567-e89b-42d3-a456-426614174000';
const SCOPE = { deviceId: 'device-a', deviceUuid: UUID, platform: 'android', pbxId: 'tenant-a', extension: '123', authorizationRevision: 1 };
const contactUri = 'sip:mobile@synthetic.invalid;transport=ws';
function register(seq = 1, opts = {}) {
    const uri = opts.uri || contactUri;
    return [ `REGISTER sip:pbx.invalid SIP/2.0`, `Via: SIP/2.0/WS client.invalid;branch=z9hG4bK-${seq}`,
        `From: <sip:123@pbx.invalid>;tag=from`, `To: <sip:123@pbx.invalid>`, 'Call-ID: synthetic-call',
        `CSeq: ${seq} REGISTER`, `Contact: <${uri}>;reg-id=1;+sip.instance="<urn:uuid:${opts.uuid || UUID}>";expires=${opts.expires ?? 120}`,
        'Content-Length: 0', '', '' ].join('\r\n');
}
function reply(seq, taggedUri, options = {}) {
    const contacts = options.contacts || `<${taggedUri}>;expires=${options.expires ?? 90}`;
    return [ `SIP/2.0 ${options.code || 200} OK`, `Via: SIP/2.0/WS client.invalid;branch=z9hG4bK-${seq}`,
        'Call-ID: synthetic-call', `CSeq: ${seq} REGISTER`, ...(options.noContact ? [] : [`Contact: ${contacts}`]),
        'Content-Length: 0', '', '' ].join('\r\n');
}
function tagged(raw) { return /Contact: <([^>]+)>/.exec(raw)[1]; }
function ctx(initial = SCOPE) {
    let current = { ...initial }, time = 1000;
    const tickets = new Map([['once', { ...initial }]]);
    return { consume: async t => { const v = tickets.get(t); tickets.delete(t); return v; },
        authorize: async () => current, set: x => { current = x; }, now: () => time, tick: n => { time += n; } };
}
async function setup() { const c = ctx(); const s = await TagExperiment.open('once', c.consume, c.authorize, c.now); return { c, s }; }
function observed(s, uri, changes = {}) { return s.observe({ pbxId: 'tenant-a', extension: '123', endpoint: '123', contacts: [uri], ...changes }); }

test('ticket scope, UUID, platform and current authorization gate tagging', async () => {
    for (const changes of [{ platform: 'desktop' }, { platform: 'chrome' }, { deviceUuid: 'invalid' }, { authorizationRevision: -1 }]) {
        const c = ctx({ ...SCOPE, ...changes });
        await assert.rejects(TagExperiment.open('once', c.consume, c.authorize, c.now));
    }
    const c = ctx();
    const s = await TagExperiment.open('once', c.consume, c.authorize, c.now);
    await assert.rejects(TagExperiment.open('once', c.consume, c.authorize, c.now));
    await assert.rejects(s.register(register(1, { uuid: '123e4567-e89b-42d3-a456-426614174001' })));
    c.set({ ...SCOPE, authorizationRevision: 2 });
    await assert.rejects(s.register(register(2)));
    await assert.rejects(s.register(register(3)));
});

test('REGISTER/2xx round trip preserves unrelated contacts and rejects duplicate selection', async () => {
    const { s } = await setup();
    const r = await s.register(register());
    const uri = tagged(r);
    assert.match(uri, /;sokrat-wake=[0-9a-f]{48}$/);
    const desktop = 'sip:desktop@synthetic.invalid';
    const crm = 'sip:crm@synthetic.invalid;transport=ws';
    const result = await s.response(reply(1, uri, { contacts: `<${desktop}>;expires=60, <${uri}>;expires=90, <${crm}>;expires=60` }));
    assert.match(result, /<sip:mobile@synthetic\.invalid;transport=ws>;expires=90/);
    assert.ok(result.includes(`<${desktop}>;expires=60`) && result.includes(`<${crm}>;expires=60`));
    assert.deepEqual(await observed(s, uri, { contacts: [desktop, crm, uri] }), { observed: true, dialable: false });
    assert.deepEqual(await observed(s, uri, { baseline: [uri] }), { observed: false, dialable: false });
    assert.deepEqual(await observed(s, uri, { contacts: [uri, uri] }), { observed: false, dialable: false });
    assert.deepEqual(await observed(s, uri, { contacts: [uri, uri + ';other=1'] }), { observed: false, dialable: false });
    assert.deepEqual(await observed(s, uri, { pbxId: 'tenant-b' }), { observed: false, dialable: false });
    assert.deepEqual(await observed(s, uri, { endpoint: 'other' }), { observed: false, dialable: false });
    // Separate calls are not consumed globally, but no candidate is dialable.
    const calls = await Promise.all([observed(s, uri), observed(s, uri)]);
    assert.ok(calls.every(x => x.observed && !x.dialable));
});

test('401 retry, transaction mismatch, missing and ambiguous responses fail closed', async () => {
    const { s } = await setup();
    let uri = tagged(await s.register(register(1)));
    assert.equal(await s.response(reply(1, uri, { code: 401, noContact: true })), reply(1, uri, { code: 401, noContact: true }));
    uri = tagged(await s.register(register(2)));
    await assert.rejects(s.response(reply(3, uri)));
    assert.equal((await observed(s, uri)).observed, false);
    uri = tagged(await s.register(register(3)));
    await assert.rejects(s.response(reply(3, uri, { noContact: true })));
    uri = tagged(await s.register(register(4)));
    await assert.rejects(s.response(reply(4, uri, { contacts: `<${uri}>;expires=90, <${uri}>;expires=90` })));
    assert.equal((await observed(s, uri)).observed, false);
});

test('expiry, refresh, unregister, disconnect and reauthorization clear evidence', async () => {
    const { c, s } = await setup();
    let uri = tagged(await s.register(register(1)));
    await s.response(reply(1, uri, { expires: 1 }));
    c.tick(1000);
    assert.equal((await observed(s, uri)).observed, false);
    uri = tagged(await s.register(register(2)));
    await s.response(reply(2, uri));
    await s.register(register(3, { expires: 0 }));
    assert.equal((await observed(s, uri)).observed, false);
    await s.response(reply(3, uri, { noContact: true }));
    uri = tagged(await s.register(register(4)));
    await s.response(reply(4, uri));
    c.set({ ...SCOPE, platform: 'desktop' });
    await assert.rejects(observed(s, uri));
    s.close();
    await assert.rejects(observed(s, uri));
});

test('unsupported syntax, spoofed tag, wrong To and replay fail closed', async () => {
    for (const bad of [
        register(1, { uri: contactUri + ';sokrat-wake=forged' }),
        register(1, { uri: contactUri + ';sokrat-wake' }),
        register(1).replace('To: <sip:123@', 'To: <sip:999@'),
        register(1).replace('From: <sip:123@', 'From: <sip:999@'),
        register(1).replace('Content-Length: 0', 'Authorization: Digest username="999",realm="example"\r\nContent-Length: 0'),
        register(1).replace('Content-Length: 0', 'Content-Length: 1'),
        register(1).replace('Contact: <', 'Contact: *, <'),
        register(1).replace('Content-Length: 0', 'Content-Length: 0\r\nl: 0'),
    ]) {
        const { s } = await setup();
        await assert.rejects(s.register(bad));
    }
    const { s } = await setup();
    await s.register(register(1));
    await assert.rejects(s.register(register(1)));
});

test('same extension across tenants is scoped by the authorized PBX', async () => {
    const a = await setup();
    const c = ctx({ ...SCOPE, pbxId: 'tenant-b' });
    const b = await TagExperiment.open('once', c.consume, c.authorize, c.now);
    const ua = tagged(await a.s.register(register()));
    const ub = tagged(await b.register(register()));
    await a.s.response(reply(1, ua));
    await b.response(reply(1, ub));
    assert.deepEqual(await observed(a.s, ua, { pbxId: 'tenant-b' }), { observed: false, dialable: false });
    assert.deepEqual(await observed(b, ub, { pbxId: 'tenant-b' }), { observed: true, dialable: false });
    assert.deepEqual(await observed(b, ub), { observed: false, dialable: false });
});

test('reconnects get different tags; cross-tenant and cross-session evidence is rejected', async () => {
    const a = await setup(), b = await setup();
    const uriA = tagged(await a.s.register(register()));
    const uriB = tagged(await b.s.register(register()));
    assert.notEqual(uriA, uriB);
    await a.s.response(reply(1, uriA));
    await b.s.response(reply(1, uriB));
    assert.equal((await observed(a.s, uriA, { contacts: [uriB] })).observed, false);
    assert.equal((await observed(a.s, uriA, { pbxId: 'tenant-b' })).observed, false);
    a.s.close();
    await assert.rejects(observed(a.s, uriA));
    assert.equal((await observed(b.s, uriB)).observed, true);
});

test('a copied tag or changed owner cannot make an observation dialable', async () => {
    const { s } = await setup();
    const uri = tagged(await s.register(register()));
    await s.response(reply(1, uri));
    // Asterisk can retain the URI after a different transport refreshes it.
    // This model deliberately provides the same snapshot for both owners.
    for (const owner of ['mobile', 'other-client']) {
        const result = await observed(s, uri);
        assert.equal(result.observed, true, owner);
        assert.equal(result.dialable, false, owner);
    }
});

test('close during asynchronous reauthorization cannot resurrect a session', async () => {
    let release;
    let delayed = false;
    const c = ctx();
    const authorize = async scope => delayed ? await new Promise(resolve => { release = resolve; }) : c.authorize(scope);
    const s = await TagExperiment.open('once', c.consume, authorize, c.now);
    delayed = true;
    const pending = s.register(register());
    await Promise.resolve();
    s.close();
    release({ ...SCOPE });
    await assert.rejects(pending);
});

test('timed out transactions, malformed responses and unavailable authorization invalidate evidence', async () => {
    const { c, s } = await setup();
    let uri = tagged(await s.register(register(1)));
    c.tick(10000);
    await assert.rejects(s.response(reply(1, uri)));
    uri = tagged(await s.register(register(2)));
    await assert.rejects(s.response('bad response'));
    await assert.rejects(s.response(reply(2, uri)));
    assert.equal((await observed(s, uri)).observed, false);
    c.set(null);
    await assert.rejects(s.register(register(3)));
});

test('loopback WebSockets exercise synthetic ticket, proxy, registrar and correlation', async t => {
    const registrar = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(registrar, 'listening');
    const proxy = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(proxy, 'listening');
    t.after(() => { for (const w of registrar.clients) w.terminate(); for (const w of proxy.clients) w.terminate(); registrar.close(); proxy.close(); });
    const c = ctx();
    let stored, s;
    registrar.on('connection', ws => ws.on('message', data => {
        const request = data.toString(); stored = tagged(request);
        ws.send(reply(1, stored));
    }));
    proxy.on('connection', async (ws, req) => {
        try { s = await TagExperiment.open(new URL(req.url, 'http://test.invalid').searchParams.get('ticket'), c.consume, c.authorize, c.now); }
        catch (_) { ws.close(); return; }
        const up = new WebSocket(`ws://127.0.0.1:${registrar.address().port}`);
        ws.on('message', async data => {
            try { const rewritten = await s.register(data.toString()); if (up.readyState !== WebSocket.OPEN) await once(up, 'open'); up.send(rewritten); }
            catch (_) { ws.close(); }
        });
        up.on('message', async data => { try { ws.send(await s.response(data.toString())); } catch (_) { ws.close(); } });
        ws.on('close', () => { s.close(); up.terminate(); });
    });
    const client = new WebSocket(`ws://127.0.0.1:${proxy.address().port}/?ticket=once`);
    await once(client, 'open');
    client.send(register());
    const [data] = await once(client, 'message');
    assert.ok(data.toString().includes(`<${contactUri}>;expires=90`));
    assert.deepEqual(await observed(s, stored), { observed: true, dialable: false });
    c.set(null);
    await assert.rejects(observed(s, stored));
    client.terminate();
});
