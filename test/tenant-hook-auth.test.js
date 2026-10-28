'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createPbxAuthorizer } = require('../src/tenant-hook-auth');
test('PBX hook token is scoped to its server identity and disabled servers fail closed', async () => {
    const token = crypto.randomBytes(32).toString('hex');
    let enabled = true;
    const auth = createPbxAuthorizer({ store: { getPbx: id => ({ id, enabled }) } },
        async id => id === 'A' ? crypto.createHash('sha256').update(token).digest('hex') : null);
    const nonce = crypto.randomBytes(16).toString('hex');
    const req = id => ({ get: name => ({ 'X-Sokrat-Pbx': id, Authorization: `Bearer ${token}`,
        'X-Sokrat-Timestamp': String(Date.now()), 'X-Sokrat-Nonce': nonce })[name] });
    assert.equal((await auth(req('A'))).id, 'A');
    assert.equal(await auth(req('A')), null);
    assert.equal(await auth(req('B')), null);
    enabled = false;
    assert.equal(await auth(req('A')), null);
});
