'use strict';

const RINGING_TTL_MS = 2 * 60 * 1000;
const ACTIVE_TTL_MS = 12 * 60 * 60 * 1000;

function readMessage(data) {
    const text = Buffer.isBuffer(data) ? data.toString('utf8') : String(data || '');
    const firstEnd = text.indexOf('\r\n');
    if (firstEnd < 0) return null;
    const first = text.slice(0, firstEnd);
    const headerEnd = text.indexOf('\r\n\r\n');
    const headers = headerEnd >= 0 ? text.slice(0, headerEnd) : text;
    const callId = /^(?:Call-ID|i):[ \t]*([^\r\n]+)$/mi.exec(headers)?.[1]?.trim();
    if (!callId) return null;
    const cseq = /^CSeq:[ \t]*\d+[ \t]+([A-Z]+)\s*$/mi.exec(headers)?.[1]?.toUpperCase();
    const status = /^SIP\/2\.0\s+(\d{3})\b/.exec(first)?.[1];
    const method = !status && /^([A-Z]+)\s+sips?:/i.exec(first)?.[1]?.toUpperCase();
    return { callId, cseq, status: status ? Number(status) : null, method };
}

function createCallTracker({ now = Date.now } = {}) {
    const calls = new Map();
    const sessionCalls = new Map();

    function remove(key) {
        const call = calls.get(key);
        if (!call) return;
        calls.delete(key);
        sessionCalls.get(call.session)?.delete(key);
    }

    function remember(session, key) {
        let keys = sessionCalls.get(session);
        if (!keys) {
            keys = new Set();
            sessionCalls.set(session, keys);
        }
        keys.add(key);
    }

    function observe(data, pbxId, session) {
        const message = readMessage(data);
        if (!message || !pbxId) return;
        const key = `${pbxId}|${message.callId}`;
        const current = calls.get(key);
        if (message.method === 'INVITE') {
            if (!current) {
                calls.set(key, {
                    pbxId,
                    callId: message.callId,
                    state: 'ringing',
                    startedAt: now(),
                    session,
                });
                remember(session, key);
            }
            return;
        }
        if (!current) return;
        if (message.method === 'ACK') {
            if (current.state !== 'active') {
                current.state = 'active';
                current.answeredAt = now();
            }
            return;
        }
        if (message.method === 'BYE' || message.method === 'CANCEL') {
            remove(key);
            return;
        }
        if (message.cseq === 'INVITE' && message.status !== null) {
            if (message.status >= 200 && message.status < 300) {
                current.state = 'active';
                current.answeredAt = current.answeredAt || now();
            } else if (message.status >= 300 && message.status !== 401 && message.status !== 407) {
                remove(key);
            }
        } else if (message.cseq === 'BYE' && message.status >= 200 && message.status < 300) {
            remove(key);
        }
    }

    function removeSession(session) {
        for (const key of sessionCalls.get(session) || []) calls.delete(key);
        sessionCalls.delete(session);
    }

    function prune() {
        const timestamp = now();
        for (const [key, call] of calls) {
            const age = timestamp - call.startedAt;
            if ((call.state === 'ringing' && age > RINGING_TTL_MS) ||
                (call.state === 'active' && age > ACTIVE_TTL_MS)) {
                remove(key);
            }
        }
    }

    function snapshot() {
        const byPbx = new Map();
        for (const call of calls.values()) {
            const entry = byPbx.get(call.pbxId) ||
                { pbxId: call.pbxId, active: 0, ringing: 0, total: 0 };
            entry[call.state] += 1;
            entry.total += 1;
            byPbx.set(call.pbxId, entry);
        }
        return [...byPbx.values()].sort((a, b) => a.pbxId.localeCompare(b.pbxId));
    }

    return { observe, removeSession, prune, snapshot };
}

module.exports = { createCallTracker, readMessage, RINGING_TTL_MS, ACTIVE_TTL_MS };
