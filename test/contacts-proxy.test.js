'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { installContactsProxy } = require('../src/contacts-proxy');

async function request({ route, tenant = false, headers = {}, upstream = 200 } = {}) {
    let handler;
    let forwarded;
    installContactsProxy({ get(path, fn) { handler = fn; } }, {
        ...(tenant ? { authorizeDevice: async () => route || null } : {}),
        pbxBase: 'http://pbx.example:8080',
        fetcher: async (url, options) => {
            forwarded = { url, options };
            return { ok: upstream === 200, status: upstream, json: async () => ({ contacts: [{ id: 1, first_name: 'Customer', phone: '204' }] }) };
        }
    });
    const response = { statusCode: 200, set() {}, status(value) { this.statusCode = value; return this; }, json(value) { this.body = value; return this; } };
    await handler({ originalUrl: '/api/gateway/contacts?limit=2000', get: name => headers[name] }, response);
    return { response, forwarded };
}
const headers = { 'X-Sokrat-Extension': '204', 'X-Sokrat-Timestamp': '12345', 'X-Sokrat-Signature': 'fixture-signature' };
test('legacy contacts rejects unsigned requests before any PBX call', async () => {
    const { response, forwarded } = await request();
    assert.equal(response.statusCode, 401);
    assert.equal(forwarded, undefined);
});
test('legacy contacts preserves the exact HMAC path query and no credentials are forwarded elsewhere', async () => {
    const { response, forwarded } = await request({ headers });
    assert.equal(response.statusCode, 200);
    assert.equal(forwarded.url, 'http://pbx.example:8080/api/extension/v1/contacts?limit=2000');
    assert.equal(forwarded.options.headers['X-Sokrat-Signature'], headers['X-Sokrat-Signature']);
    assert.equal(forwarded.options.redirect, 'error');
});
test('unapproved and cross-extension tenant requests cannot access address books', async () => {
    for (const route of [null, { apiUrl: 'http://tenant.example', extension: '205' }]) {
        const { response, forwarded } = await request({ headers, route, tenant: true });
        assert.equal(response.statusCode, 403);
        assert.equal(forwarded, undefined);
    }
});
test('approved tenant uses only its assigned PBX and strips device bearer', async () => {
    const { response, forwarded } = await request({ headers: { ...headers, Authorization: 'Bearer never-forward' }, tenant: true, route: { apiUrl: 'http://tenant.example:8080', extension: '204' } });
    assert.equal(response.statusCode, 200);
    assert.equal(forwarded.url, 'http://tenant.example:8080/api/extension/v1/contacts?limit=2000');
    assert.equal(forwarded.options.headers.Authorization, undefined);
});
test('PBX authentication failures do not expose contacts', async () => {
    const { response } = await request({ headers, upstream: 401 });
    assert.equal(response.statusCode, 401);
    assert.equal(response.body.contacts, undefined);
});
