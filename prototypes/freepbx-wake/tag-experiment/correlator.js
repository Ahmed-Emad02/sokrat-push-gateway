'use strict';

// Synthetic-only experiment. It is deliberately NOT a SIP proxy or an AGI
// identity service. The parser accepts only a narrow, tested SIP subset.
const crypto = require('node:crypto');
const TAG = 'sokrat-wake';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const URI = /^sip:[A-Za-z0-9_.!~*+%:@\[\];=\-]+$/;
const SCOPE_FIELDS = ['deviceId', 'deviceUuid', 'platform', 'pbxId', 'extension', 'authorizationRevision'];

function fail() { throw new Error('unsupported or invalid SIP'); }
function parse(message) {
    if (typeof message !== 'string' || Buffer.byteLength(message) > 32768 || /\r(?!\n)|(?<!\r)\n/.test(message)) fail();
    const at = message.indexOf('\r\n\r\n');
    if (at < 0) fail();
    const lines = message.slice(0, at).split('\r\n');
    const start = lines.shift();
    const headers = lines.map(line => {
        const m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$/.exec(line);
        if (!m || /[\r\n]/.test(m[2])) fail();
        return { name: m[1], value: m[2] };
    });
    const lengths = headers.filter(h => /^(?:content-length|l)$/i.test(h.name));
    const body = message.slice(at + 4);
    if (lengths.length !== 1 || !/^\d+$/.test(lengths[0].value) || Number(lengths[0].value) !== Buffer.byteLength(body)) fail();
    return { start, headers, body };
}
function render(m) { return [m.start, ...m.headers.map(h => h.name + ': ' + h.value)].join('\r\n') + '\r\n\r\n' + m.body; }
function values(m, names) { return m.headers.filter(h => names.includes(h.name.toLowerCase())); }
function one(m, names) { const a = values(m, names); if (a.length !== 1) fail(); return a[0].value; }
function splitContacts(value) {
    let angle = false, quote = false, escaped = false, start = 0;
    const out = [];
    for (let i = 0; i < value.length; i++) {
        const c = value[i];
        if (escaped) { escaped = false; continue; }
        if (quote && c === '\\') { escaped = true; continue; }
        if (c === '"') { quote = !quote; continue; }
        if (!quote && c === '<') { if (angle) fail(); angle = true; }
        else if (!quote && c === '>') { if (!angle) fail(); angle = false; }
        else if (!quote && !angle && c === ',') { out.push(value.slice(start, i).trim()); start = i + 1; }
    }
    if (angle || quote || escaped) fail();
    out.push(value.slice(start).trim());
    return out;
}
function contact(value) {
    // No display names or URI headers: unknown syntax fails closed.
    const m = /^<(sip:[^<>\s,]+)>(.*)$/.exec(value);
    if (!m || !URI.test(m[1]) || (m[2] && !/^;[^\r\n]*$/.test(m[2]))) fail();
    return { uri: m[1], params: m[2] };
}
function tagOf(uri) {
    const tags = [...uri.matchAll(/(?:^|;)sokrat-wake=([^;]+)/gi)];
    if (tags.length > 1) fail();
    return tags.length ? tags[0][1] : '';
}
function identity(m) {
    const via = one(m, ['via', 'v']);
    const branch = /(?:^|;)\s*branch=(z9hG4bK[A-Za-z0-9_.-]+)(?:;|$)/i.exec(via);
    const cseq = /^(\d{1,9}) REGISTER$/i.exec(one(m, ['cseq']));
    const callId = one(m, ['call-id', 'i']);
    if (!branch || !cseq || !/^[A-Za-z0-9_.@-]{1,128}$/.test(callId)) fail();
    return { branch: branch[1], cseq: Number(cseq[1]), callId };
}
function sameTxn(a, b) { return a && b && a.branch === b.branch && a.cseq === b.cseq && a.callId === b.callId; }
function scopeValid(a) {
    return a && ['android', 'ios'].includes(a.platform) && UUID.test(a.deviceUuid || '') &&
        /^[0-9]{1,32}$/.test(a.extension || '') && typeof a.deviceId === 'string' && a.deviceId.length > 0 &&
        typeof a.pbxId === 'string' && a.pbxId.length > 0 && Number.isSafeInteger(a.authorizationRevision) && a.authorizationRevision >= 0;
}
function sameScope(a, b) { return scopeValid(b) && SCOPE_FIELDS.every(k => a[k] === b[k]); }
function headerUser(value) { const m = /^\s*<sip:([^@;>]+)@[^>]+>(?:;.*)?$/i.exec(value); return m && m[1]; }

class TagExperiment {
    // consumeTicket is trusted test infrastructure and must consume a single-use
    // ticket and reauthorize its complete immutable scope. No production wiring.
    static async open(ticket, consumeTicket, authorize, now = Date.now) {
        const scope = await consumeTicket(ticket);
        if (!scopeValid(scope) || !sameScope(scope, await authorize(scope))) throw new Error('unauthorized');
        return new TagExperiment(scope, authorize, now);
    }
    constructor(scope, authorize, now) {
        this.scope = Object.freeze({ ...scope }); this.authorize = authorize; this.now = now;
        this.tag = crypto.randomBytes(24).toString('hex'); this.active = true;
        this.pending = null; this.binding = null; this.lastCseq = -1; this.callId = null;
    }
    close() { this.active = false; this.pending = null; this.binding = null; }
    async check() {
        if (!this.active) throw new Error('closed');
        let current;
        try { current = await this.authorize(this.scope); } catch (_) { this.close(); throw new Error('authorization unavailable'); }
        if (!this.active) throw new Error('closed');
        if (!sameScope(this.scope, current)) { this.close(); throw new Error('revoked'); }
    }
    async register(raw) {
        await this.check();
        // Any in-flight change invalidates the old observation immediately.
        this.pending = null; this.binding = null;
        const m = parse(raw);
        if (!/^REGISTER sip:[^\s]+ SIP\/2\.0$/.test(m.start) || m.body) fail();
        if (headerUser(one(m, ['from', 'f'])) !== this.scope.extension || headerUser(one(m, ['to', 't'])) !== this.scope.extension) fail();
        const auth = values(m, ['authorization', 'proxy-authorization']);
        if (auth.some(h => !new RegExp('(?:^|[,\\s])username="' + this.scope.extension + '"(?:,|$)', 'i').test(h.value))) fail();
        const tx = identity(m);
        if ((this.callId && tx.callId !== this.callId) || tx.cseq <= this.lastCseq) fail();
        const h = values(m, ['contact', 'm']);
        if (h.length !== 1 || splitContacts(h[0].value).length !== 1) fail();
        const c = contact(h[0].value);
        if (/(?:^|;)sokrat-wake(?:=|;|$)/i.test(c.uri) || /(?:^|;)\s*sokrat-wake(?:=|;|$)/i.test(c.params)) fail();
        const instance = [...c.params.matchAll(/(?:^|;)\s*\+sip\.instance="<urn:uuid:([^>]+)>"/gi)];
        if (instance.length !== 1 || instance[0][1].toLowerCase() !== this.scope.deviceUuid.toLowerCase()) fail();
        const exp = [...c.params.matchAll(/(?:^|;)\s*expires=(\d+)(?=;|$)/gi)];
        if (exp.length !== 1 || Number(exp[0][1]) > 86400) fail();
        h[0].value = '<' + c.uri + ';' + TAG + '=' + this.tag + '>' + c.params;
        this.callId = tx.callId; this.lastCseq = tx.cseq;
        const sentAt = this.now();
        this.pending = { ...tx, originalUri: c.uri, unregister: Number(exp[0][1]) === 0, sentAt, deadline: sentAt + 10000 };
        return render(m);
    }
    async response(raw) {
        await this.check();
        try { return this.processResponse(raw); }
        catch (err) { this.pending = null; this.binding = null; throw err; }
    }
    processResponse(raw) {
        const m = parse(raw);
        const status = /^SIP\/2\.0 ([1-6]\d\d)(?: .*)?$/.exec(m.start);
        if (!status) fail();
        const tx = identity(m), pending = this.pending;
        if (!sameTxn(tx, pending) || pending.deadline <= this.now()) { this.pending = null; this.binding = null; fail(); }
        const code = Number(status[1]);
        if (code < 200) return raw;
        this.pending = null;
        if (code >= 300 || pending.unregister) return raw;
        const hs = values(m, ['contact', 'm']);
        let matches = 0, ownUri = '', seconds = 0;
        for (const h of hs) {
            const items = splitContacts(h.value).map(item => {
                const c = contact(item), tag = tagOf(c.uri);
                if (tag !== this.tag) return item;
                matches++; ownUri = c.uri;
                const expires = [...c.params.matchAll(/(?:^|;)\s*expires=(\d+)(?=;|$)/gi)];
                if (expires.length !== 1) fail();
                seconds = Number(expires[0][1]);
                // Restore original URI for JsSIP's URI-user matching. Only the
                // exact matching response contact is rewritten; others survive.
                return '<' + pending.originalUri + '>' + c.params;
            });
            h.value = items.join(', ');
        }
        if (matches !== 1 || seconds <= 0 || seconds > 86400) fail();
        this.binding = { uri: ownUri, expiresAt: pending.sentAt + seconds * 1000 };
        return render(m);
    }
    async observe({ pbxId, extension, endpoint, contacts, baseline = [] }) {
        await this.check();
        if (pbxId !== this.scope.pbxId || extension !== this.scope.extension || endpoint !== this.scope.extension ||
            !Array.isArray(contacts) || !Array.isArray(baseline) || !this.binding || this.binding.expiresAt <= this.now()) return { observed: false, dialable: false };
        // Exact URI matches only; never accept substring or partial tag matches.
        try {
            if (contacts.some(c => typeof c !== 'string' || !URI.test(c))) return { observed: false, dialable: false };
            const tagged = contacts.filter(c => tagOf(c) === this.tag);
            return { observed: tagged.length === 1 && tagged[0] === this.binding.uri && !baseline.includes(this.binding.uri), dialable: false };
        } catch (_) { return { observed: false, dialable: false }; }
    }
}

module.exports = { TagExperiment };
