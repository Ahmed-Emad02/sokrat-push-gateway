'use strict';
// Executed only inside the isolated Asterisk network namespace.
const fs = require('node:fs');
const net = require('node:net');
const crypto = require('node:crypto');
const { WebSocket, WebSocketServer } = require('ws');
const { GuardedRoute } = require('/route/guarded-route');
const secrets = JSON.parse(fs.readFileSync('/run/lab-secrets.json', 'utf8'));
const md5 = s => crypto.createHash('md5').update(s).digest('hex');
const random = () => crypto.randomBytes(12).toString('hex');
let stage = 'startup';
function check(v, label) { if (!v) throw new Error(label); }
function header(raw, name) {
    const block = raw.split('\r\n\r\n')[0].replace(/\r\n[ \t]+/g, ' ');
    const m = new RegExp('^' + name + ':[ \\t]*(.*)$', 'im').exec(block);
    return m ? m[1].trim() : '';
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

class Queue {
    constructor() { this.entries = []; this.waiters = []; }
    push(value) {
        const i = this.waiters.findIndex(w => w.test(value));
        if (i >= 0) { const w = this.waiters.splice(i, 1)[0]; clearTimeout(w.timer); w.resolve(value); }
        else this.entries.push(value);
    }
    take(test, timeout = 5000) {
        const i = this.entries.findIndex(test);
        if (i >= 0) return Promise.resolve(this.entries.splice(i, 1)[0]);
        return new Promise((resolve, reject) => {
            const w = { test, resolve, timer: null };
            w.timer = setTimeout(() => { this.waiters = this.waiters.filter(x => x !== w); reject(new Error('timeout')); }, timeout);
            this.waiters.push(w);
        });
    }
}

class Ami {
    constructor() { this.events = new Queue(); this.n = 0; this.buffer = ''; }
    async connect() {
        this.socket = net.connect(5038, '127.0.0.1');
        this.socket.on('data', data => {
            this.buffer += data.toString();
            let i;
            while ((i = this.buffer.indexOf('\r\n\r\n')) >= 0) {
                const part = this.buffer.slice(0, i); this.buffer = this.buffer.slice(i + 4);
                const obj = {};
                for (const line of part.split('\r\n')) { const j = line.indexOf(':'); if (j > 0) obj[line.slice(0, j).toLowerCase()] = line.slice(j + 1).trim(); }
                this.events.push(obj);
            }
        });
        this.socket.on('error', () => {});
        await new Promise((resolve, reject) => { this.socket.once('connect', resolve); this.socket.once('error', reject); });
        const res = await this.action({ Action: 'Login', Username: 'lab', Secret: secrets.ami, Events: 'on' });
        check(res.response === 'Success', 'AMI login refused');
    }
    async action(fields) {
        const id = 'lab' + (++this.n);
        const result = this.events.take(o => o.actionid === id && !!o.response);
        this.socket.write(Object.entries({ ...fields, ActionID: id }).map(([k, v]) => `${k}: ${v}\r\n`).join('') + '\r\n');
        return result;
    }
    async contacts() {
        const id = 'lab' + (++this.n);
        this.socket.write(`Action: PJSIPShowRegistrationInboundContactStatuses\r\nActionID: ${id}\r\n\r\n`);
        const rows = [];
        while (true) {
            const event = await this.events.take(o => o.actionid === id);
            if ((event.event || '').toLowerCase() === 'contactstatusdetailcomplete') return rows;
            if ((event.event || '').toLowerCase() === 'contactstatusdetail') rows.push(event);
            if (event.response === 'Error') throw new Error('AMI contact list unavailable');
        }
    }
}

class Sip {
    constructor(label, tagged) {
        this.label = label; this.tagged = tagged; this.queue = new Queue(); this.id = random(); this.tag = random(); this.uriTag = random();
    }
    async connect(url = 'ws://127.0.0.1:8088/ws') {
        this.ws = new WebSocket(url, 'sip');
        this.ws.on('message', data => this.queue.push(data.toString()));
        this.ws.on('error', () => {});
        await new Promise((resolve, reject) => { this.ws.once('open', resolve); this.ws.once('error', reject); });
    }
    async register() {
        const make = (n, auth) => [
            'REGISTER sip:127.0.0.1 SIP/2.0', `Via: SIP/2.0/WS client.invalid;branch=z9hG4bK-${this.id}-${n};rport`,
            'Max-Forwards: 70', `From: <sip:321@127.0.0.1>;tag=${this.tag}`, 'To: <sip:321@127.0.0.1>',
            `Call-ID: ${this.id}`, `CSeq: ${n} REGISTER`,
            `Contact: <sip:${this.label}@client.invalid;transport=ws${this.tagged ? ';sokrat-wake=' + this.uriTag : ''}>;reg-id=1;+sip.instance="<urn:uuid:123e4567-e89b-42d3-a456-426614174000>";expires=120`,
            'Expires: 120', ...(auth ? [auth] : []), 'Content-Length: 0', '', '' ].join('\r\n');
        this.ws.send(make(1));
        const challenge = await this.queue.take(s => /^SIP\/2\.0 401/.test(s));
        const auth = header(challenge, 'WWW-Authenticate');
        const get = key => { const m = new RegExp(key + '="([^"]+)"', 'i').exec(auth); return m && m[1]; };
        const realm = get('realm'), nonce = get('nonce'), qop = get('qop');
        check(realm && nonce && (!qop || qop.split(',').includes('auth')), 'unsupported digest challenge');
        const uri = 'sip:127.0.0.1', cnonce = random(), nc = '00000001';
        const ha1 = md5(`321:${realm}:${secrets.password}`), ha2 = md5(`REGISTER:${uri}`);
        const digest = qop ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);
        const line = `Authorization: Digest username="321", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${digest}", algorithm=MD5` +
            (qop ? `, qop=auth, nc=${nc}, cnonce="${cnonce}"` : '');
        this.ws.send(make(2, line));
        const result = await this.queue.take(s => /^SIP\/2\.0 (?:200|403|404|401)/.test(s));
        if (!/^SIP\/2\.0 200/.test(result)) console.log(JSON.stringify({ registerStatus: Number(result.slice(8, 11)), challengeQop: !!qop, opaquePresent: !!get('opaque'), challengeMd5: /algorithm\s*=\s*MD5/i.test(auth), challengeSha256: /algorithm\s*=\s*SHA-256/i.test(auth), challengeQopToken: /qop\s*=/i.test(auth) }));
        check(/^SIP\/2\.0 200/.test(result), 'REGISTER rejected');
        return result;
    }
    async invite() { return this.queue.take(s => /^INVITE /.test(s)); }
    async method(method, callId) { return this.queue.take(s => s.startsWith(method + ' ') && header(s, 'Call-ID') === callId); }
    answer(req, status, body = '') {
        const to = header(req, 'To');
        const list = [`SIP/2.0 ${status} Lab`, `Via: ${header(req, 'Via')}`, `From: ${header(req, 'From')}`,
            `To: ${/;tag=/i.test(to) ? to : to + ';tag=' + this.tag}`, `Call-ID: ${header(req, 'Call-ID')}`,
            `CSeq: ${header(req, 'CSeq')}`, `Contact: <sip:${this.label}@127.0.0.1;transport=ws>`,
            ...(body ? ['Content-Type: application/sdp'] : []), `Content-Length: ${Buffer.byteLength(body)}`, '', body];
        this.ws.send(list.join('\r\n'));
    }
    terminate() { if (this.ws) this.ws.terminate(); }
}

async function syntheticGateway() {
    const scope = { deviceId: 'synthetic-mobile', deviceUuid: '123e4567-e89b-42d3-a456-426614174000',
        platform: 'android', pbxId: 'synthetic-pbx', extension: '321', authorizationRevision: 1 };
    const state = { approved: true, route: null, inviteChecks: 0 };
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise(resolve => server.once('listening', resolve));
    server.on('connection', mobile => {
        const upstream = new WebSocket('ws://127.0.0.1:8088/ws', 'sip');
        const pending = [];
        const fromMobile = raw => { if (upstream.readyState === WebSocket.OPEN) upstream.send(raw); else pending.push(raw); };
        const fromPbx = async raw => {
            const text = raw.toString();
            if (/^SIP\/2\.0 200/.test(text) && /REGISTER$/i.test(header(text, 'CSeq'))) {
                mobile.off('message', fromMobile); upstream.off('message', fromPbx);
                try {
                    state.route = await GuardedRoute.open({ ticket: 'synthetic-once',
                        consumeTicket: async t => t === 'synthetic-once' ? scope : null,
                        authorize: async () => { state.inviteChecks++; return state.approved ? scope : null; },
                        pbx: upstream, mobile, pbxIdentity: { authenticated: true, pbxId: scope.pbxId } });
                    upstream.on('message', data => {
                        const frame = data.toString();
                        if (/^INVITE /.test(frame)) {
                            const to = header(frame, 'To');
                            console.log(JSON.stringify({ realInviteSeenOnGuardedUpstream: true,
                                toMatchesGuard: /^<sip:321@[^>]+>(?:;.*)?$/i.test(to),
                                hasFoldedHeaders: /\r\n[ \t]/.test(frame.split('\r\n\r\n')[0]),
                                callIdMatchesGuard: /^[a-z0-9_.@-]{1,128}$/i.test(header(frame, 'Call-ID')),
                                branchMatchesGuard: /(?:^|;)\s*branch=(z9hG4bK[a-z0-9_.-]+)(?:;|$)/i.test(header(frame, 'Via')) }));
                        }
                    });
                    mobile.send(raw);
                } catch (_) { mobile.terminate(); upstream.terminate(); }
            } else if (mobile.readyState === WebSocket.OPEN) mobile.send(raw);
        };
        mobile.on('message', fromMobile);
        upstream.on('message', fromPbx);
        upstream.on('open', () => { for (const raw of pending) upstream.send(raw); });
        upstream.on('error', () => mobile.terminate());
        mobile.on('close', () => upstream.terminate());
    });
    return { state, url: `ws://127.0.0.1:${server.address().port}`, close: () => { for (const c of server.clients) c.terminate(); server.close(); } };
}

async function originate(ami, id, caller, uri = '') {
    const r = await ami.action({ Action: 'Originate', Channel: `Local/${uri ? '322' : '321'}@lab/n`, Application: 'Wait', Data: '30',
        Async: 'true', ChannelId: id, CallerID: caller, ...(uri ? { Variable: '__LAB_URI=' + uri } : {}) });
    check(r.response === 'Success', 'originate refused');
}
async function hangup(ami, id) {
    const r = await ami.action({ Action: 'Hangup', Channel: id });
    check(r.response === 'Success', 'hangup refused');
}
async function cancelled(client, invite) {
    const id = header(invite, 'Call-ID');
    const cancel = await client.method('CANCEL', id);
    client.answer(cancel, 200);
    client.answer(invite, 487);
    await client.method('ACK', id);
}

async function main() {
    const ami = new Ami(), desktop = new Sip('desktop', false), mobile = new Sip('mobile', true);
    let mobile2, gateway;
    try {
        stage = 'AMI connection'; await ami.connect();
        stage = 'WebSocket connections'; await Promise.all([desktop.connect(), mobile.connect()]);
        stage = 'desktop registration'; await desktop.register();
        stage = 'mobile registration'; const registered = await mobile.register();
        const uriTagInResponse = registered.includes('sokrat-wake=' + mobile.uriTag);
        const instanceInResponse = /\+sip\.instance/i.test(registered);
        stage = 'AMI contacts';
        const rows = await ami.contacts();
        const mobileRows = rows.filter(r => (r.uri || '').includes('sokrat-wake=' + mobile.uriTag));
        console.log(JSON.stringify({ registration: 'passed', amiContactCount: rows.length,
            uriTagInRegisterResponse: uriTagInResponse, instanceInRegisterResponse: instanceInResponse,
            uriTagInAmiContact: mobileRows.length === 1, amiCallIdFieldPresent: rows.some(r => !!r.callid) }));
        check(rows.length >= 2, 'same-extension contacts missing');
        stage = 'first simultaneous call';
        const firstId = 'lab-first-' + random();
        await originate(ami, firstId, '701');
        const [d1, m1] = await Promise.all([desktop.invite(), mobile.invite()]);
        desktop.answer(d1, 180); mobile.answer(m1, 180);
        stage = 'second simultaneous call';
        const secondId = 'lab-second-' + random();
        await originate(ami, secondId, '702');
        const [d2, m2] = await Promise.all([desktop.invite(), mobile.invite()]);
        desktop.answer(d2, 180); mobile.answer(m2, 180);
        check(header(m1, 'Call-ID') !== header(m2, 'Call-ID'), 'call IDs not distinct');
        stage = 'independent concurrent cancellation';
        await hangup(ami, firstId);
        await Promise.all([cancelled(desktop, d1), cancelled(mobile, m1)]);
        stage = 'answer and ACK';
        const sdp = 'v=0\r\no=lab 1 1 IN IP4 127.0.0.1\r\ns=lab\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n';
        mobile.answer(m2, 200, sdp);
        await mobile.method('ACK', header(m2, 'Call-ID'));
        stage = 'desktop cancellation'; await cancelled(desktop, d2);
        stage = 'BYE'; await hangup(ami, secondId);
        const bye = await mobile.method('BYE', header(m2, 'Call-ID')); mobile.answer(bye, 200);
        console.log(JSON.stringify({ concurrentDial: 'passed', bothContactsReceivedEachInvite: true, answerAck: 'passed', desktopCancelAck: 'passed', bye: 'passed' }));
        stage = 'reconnect';
        mobile.terminate();
        await sleep(300);
        gateway = await syntheticGateway();
        mobile2 = new Sip('mobile2', true); await mobile2.connect(gateway.url);
        stage = 'guarded registration'; await mobile2.register();
        stage = 'guarded parallel invite';
        const thirdId = 'lab-third-' + random(); await originate(ami, thirdId, '703');
        const [d3, m3] = await Promise.all([desktop.invite(), mobile2.invite()]);
        desktop.answer(d3, 180); mobile2.answer(m3, 180);
        stage = 'guarded cancellation'; await hangup(ami, thirdId);
        await Promise.all([cancelled(desktop, d3), cancelled(mobile2, m3)]);
        console.log(JSON.stringify({ reconnect: 'passed', desktopAndNewMobileReceivedInvite: true, guardedUpstream: !!gateway.state.route, ringingCancelAck: 'passed' }));
        stage = 'targeted route after reconnect';
        const refreshed = await ami.contacts();
        const exact = refreshed.filter(r => (r.uri || '').includes('sokrat-wake=' + mobile2.uriTag));
        check(exact.length === 1, 'target contact ambiguous');
        check(!desktop.queue.entries.some(s => /^INVITE /.test(s)), 'desktop invite queue not empty');
        const fourthId = 'lab-fourth-' + random();
        await originate(ami, fourthId, '704', exact[0].uri);
        const m4 = await mobile2.invite();
        await sleep(300);
        check(!desktop.queue.entries.some(s => /^INVITE /.test(s)), 'targeted route reached desktop');
        mobile2.answer(m4, 180);
        await hangup(ami, fourthId);
        await cancelled(mobile2, m4);
        check(gateway.state.inviteChecks > 1, 'authorization check missing');
        console.log(JSON.stringify({ exactAmiContactDial: 'passed', mobileSocketReceivedInvite: true, desktopSocketReceivedInvite: false, gatewayAuthorizationRechecked: true, targetedCancelAck: 'passed' }));
    } finally {
        desktop.terminate(); mobile.terminate(); if (mobile2) mobile2.terminate();
        if (gateway) gateway.close();
        if (ami.socket) ami.socket.destroy();
    }
}

main().catch(e => { console.error(`BLOCKED at ${stage}: ${['timeout', 'AMI login refused', 'REGISTER rejected', 'unsupported digest challenge', 'AMI contact list unavailable', 'same-extension contacts missing', 'originate refused', 'hangup refused', 'call IDs not distinct', 'target contact ambiguous', 'desktop invite queue not empty', 'targeted route reached desktop', 'authorization check missing'].includes(e.message) ? e.message : 'setup or protocol failure'}`); process.exitCode = 1; });
