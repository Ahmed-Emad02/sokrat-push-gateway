'use strict';

// LAB ONLY: not a SIP proxy, B2BUA, identity service, or deployment component.
// Each instance is bound to exactly one *already authenticated* PBX socket and
// one ticket-authenticated mobile socket. See README for critical assumptions.
const { WebSocket } = require('ws');
const claimed = new WeakSet();
const fields = ['deviceId', 'deviceUuid', 'platform', 'pbxId', 'extension', 'authorizationRevision'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validScope(s) {
    return s && ['ios', 'android'].includes(s.platform) && uuid.test(s.deviceUuid || '') &&
        /^[0-9]{1,32}$/.test(s.extension || '') && typeof s.deviceId === 'string' && s.deviceId.length > 0 &&
        typeof s.pbxId === 'string' && s.pbxId.length > 0 && Number.isSafeInteger(s.authorizationRevision) && s.authorizationRevision >= 0;
}
function equalScope(a, b) { return validScope(b) && fields.every(k => a[k] === b[k]); }
function invalid() { throw new Error('unsupported signaling'); }
function parse(raw) {
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > 65536 || /\r(?!\n)|(?<!\r)\n/.test(raw)) invalid();
    const sep = raw.indexOf('\r\n\r\n');
    if (sep < 0) invalid();
    const lines = raw.slice(0, sep).split('\r\n'), start = lines.shift(), headers = [];
    for (const line of lines) {
        const m = /^([a-z][a-z0-9-]*):[ \t]*(.*)$/i.exec(line);
        if (!m) invalid();
        headers.push([m[1].toLowerCase(), m[2]]);
    }
    function one(...names) {
        const found = headers.filter(h => names.includes(h[0]));
        if (found.length !== 1) invalid();
        return found[0][1];
    }
    const length = one('content-length', 'l');
    if (!/^\d+$/.test(length) || Number(length) !== Buffer.byteLength(raw.slice(sep + 4))) invalid();
    const id = one('call-id', 'i');
    if (!/^[a-z0-9_.@-]{1,128}$/i.test(id)) invalid();
    const cseq = /^(\d{1,9}) (INVITE|ACK|BYE|CANCEL)$/.exec(one('cseq'));
    const branch = /(?:^|;)\s*branch=(z9hG4bK[a-z0-9_.-]+)(?:;|$)/i.exec(one('via', 'v'));
    if (!cseq || !branch) invalid();
    const request = /^(INVITE|ACK|BYE|CANCEL) sip:[^\s]+ SIP\/2\.0$/.exec(start);
    const response = /^SIP\/2\.0 ([1-6]\d\d)(?: .*)?$/.exec(start);
    if ((!request && !response) || (request && request[1] !== cseq[2])) invalid();
    const to = one('to', 't');
    const target = /^<sip:([^@;>]+)@[^>]+>(?:;.*)?$/i.exec(to);
    if (!target) invalid();
    return { raw, id, cseq: Number(cseq[1]), method: cseq[2], branch: branch[1], target: target[1],
        request: !!request, status: response ? Number(response[1]) : null };
}

class GuardedRoute {
    static async open({ ticket, consumeTicket, authorize, pbx, mobile, pbxIdentity }) {
        const scope = await consumeTicket(ticket);
        if (!validScope(scope) || !equalScope(scope, await authorize(scope))) throw new Error('unauthorized');
        // This assertion must be supplied by the trusted PBX connection factory,
        // never by SIP headers or a client. The lab injects it synthetically.
        if (!pbxIdentity || pbxIdentity.authenticated !== true || pbxIdentity.pbxId !== scope.pbxId) throw new Error('untrusted PBX');
        if (!pbx || !mobile || pbx === mobile || pbx.readyState !== WebSocket.OPEN || mobile.readyState !== WebSocket.OPEN) throw new Error('transport unavailable');
        if (claimed.has(pbx) || claimed.has(mobile)) throw new Error('transport already bound');
        claimed.add(pbx); claimed.add(mobile);
        return new GuardedRoute(scope, authorize, pbx, mobile);
    }
    constructor(scope, authorize, pbx, mobile) {
        this.scope = Object.freeze({ ...scope }); this.authorize = authorize;
        this.pbx = pbx; this.mobile = mobile; this.active = true; this.dialogs = new Map();
        this.onPbx = (data, binary) => { this.handle('pbx', data, binary).catch(() => this.close()); };
        this.onMobile = (data, binary) => { this.handle('mobile', data, binary).catch(() => this.close()); };
        this.onClose = () => this.close();
        pbx.on('message', this.onPbx); mobile.on('message', this.onMobile);
        pbx.on('close', this.onClose); mobile.on('close', this.onClose);
        pbx.on('error', this.onClose); mobile.on('error', this.onClose);
    }
    close() {
        if (!this.active) return;
        this.active = false;
        claimed.delete(this.pbx); claimed.delete(this.mobile);
        for (const d of this.dialogs.values()) d.cancelled = true;
        this.dialogs.clear();
        // Closing both transports is deliberate fail-closed lab behavior; it is
        // NOT a standards-compliant replacement for SIP failure/call teardown.
        this.pbx.terminate(); this.mobile.terminate();
    }
    async check() {
        if (!this.active) return false;
        let current, timer;
        try {
            current = await Promise.race([
                this.authorize(this.scope),
                new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('authorization timeout')), 500); })
            ]);
        } catch (_) { this.close(); return false; }
        finally { clearTimeout(timer); }
        if (!this.active) return false;
        if (!equalScope(this.scope, current)) { this.close(); return false; }
        return true;
    }
    forward(socket, raw) {
        if (!this.active || socket.readyState !== WebSocket.OPEN || socket.bufferedAmount > 1024 * 1024) { this.close(); return false; }
        try { socket.send(raw, { binary: false }, err => { if (err) this.close(); }); return true; }
        catch (_) { this.close(); return false; }
    }
    async handle(side, data, binary) {
        if (!this.active) return;
        if (binary) invalid();
        const m = parse(data.toString());
        let d = this.dialogs.get(m.id);
        if (side === 'pbx' && m.request && m.method === 'INVITE') {
            if (d || m.target !== this.scope.extension || this.dialogs.size >= 64) invalid();
            d = { id: m.id, cseq: m.cseq, branch: m.branch, state: 'checking', cancelled: false, bye: null };
            this.dialogs.set(m.id, d);
            if (!await this.check() || d.cancelled || d.state !== 'checking' || this.dialogs.get(m.id) !== d) return;
            // No await between final local validity checks and send().
            if (this.forward(this.mobile, m.raw)) d.state = 'invited';
            return;
        }
        if (!d) invalid();
        if (side === 'pbx' && m.request && m.method === 'CANCEL') {
            if (m.cseq !== d.cseq || m.branch !== d.branch || !['checking', 'invited'].includes(d.state)) invalid();
            d.cancelled = true;
            if (d.state === 'checking') { this.dialogs.delete(m.id); return; }
            d.state = 'cancelling';
            if (await this.check() && this.dialogs.get(m.id) === d && d.state === 'cancelling') this.forward(this.mobile, m.raw);
            return;
        }
        if (side === 'mobile' && !m.request && m.method === 'INVITE') {
            if (m.cseq !== d.cseq || m.branch !== d.branch || !['invited', 'cancelling'].includes(d.state)) invalid();
            if (!await this.check() || this.dialogs.get(m.id) !== d || !['invited', 'cancelling'].includes(d.state)) return;
            if (m.status >= 200) d.state = m.status < 300 ? 'answered' : 'failed';
            this.forward(this.pbx, m.raw);
            return;
        }
        if (side === 'mobile' && !m.request && m.method === 'CANCEL') {
            if (m.cseq !== d.cseq || m.branch !== d.branch || d.state !== 'cancelling') invalid();
            if (await this.check() && this.dialogs.get(m.id) === d && d.state === 'cancelling') this.forward(this.pbx, m.raw);
            return;
        }
        if (side === 'pbx' && m.request && m.method === 'ACK') {
            if (m.cseq !== d.cseq || !['answered', 'failed'].includes(d.state)) invalid();
            if (!await this.check() || this.dialogs.get(m.id) !== d || !['answered', 'failed'].includes(d.state)) return;
            this.forward(this.mobile, m.raw);
            if (d.state === 'failed') this.dialogs.delete(m.id);
            return;
        }
        if (m.request && m.method === 'BYE') {
            if (d.state !== 'answered' || d.bye) invalid();
            d.bye = { side, cseq: m.cseq, branch: m.branch };
            if (await this.check() && this.dialogs.get(m.id) === d) this.forward(side === 'pbx' ? this.mobile : this.pbx, m.raw);
            return;
        }
        if (!m.request && m.method === 'BYE') {
            if (!d.bye || d.bye.side === side || d.bye.cseq !== m.cseq || d.bye.branch !== m.branch) invalid();
            if (!await this.check() || this.dialogs.get(m.id) !== d) return;
            this.forward(side === 'pbx' ? this.mobile : this.pbx, m.raw);
            if (m.status >= 200) this.dialogs.delete(m.id);
            return;
        }
        invalid();
    }
}

module.exports = { GuardedRoute };
