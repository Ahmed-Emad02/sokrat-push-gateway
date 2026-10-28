'use strict';
const crypto = require('node:crypto');
// Header secrets only: never put PBX hook credentials in query strings or logs.
function createPbxAuthorizer(control, getCredentialHash) {
    const seen = new Map();
    return async req => {
        const id = req.get('X-Sokrat-Pbx');
        const match = /^Bearer (\S{32,256})$/.exec(req.get('Authorization') || '');
        if (!id || !match || !/^[A-Za-z0-9_-]{1,80}$/.test(id)) return null;
        const pbx = control.store.getPbx(id);
        if (!pbx?.enabled) return null;
        const expected = await getCredentialHash(id);
        if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) return null;
        const actual = crypto.createHash('sha256').update(match[1]).digest();
        if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), actual)) return null;
        const timestamp = req.get('X-Sokrat-Timestamp');
        const nonce = req.get('X-Sokrat-Nonce');
        const now = Date.now();
        if (!timestamp || !/^\d{13}$/.test(timestamp) || Math.abs(now - Number(timestamp)) > 60000 ||
            !nonce || !/^[a-f0-9]{32,64}$/.test(nonce)) return null;
        for (const [key, expires] of seen) if (expires <= now) seen.delete(key);
        const key = `${id}:${nonce}`;
        if (seen.has(key) || seen.size >= 10000) return null;
        seen.set(key, now + 120000);
        return pbx;
    };
}
module.exports = { createPbxAuthorizer };
