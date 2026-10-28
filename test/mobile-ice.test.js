'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const install = require('../src/mobile-ice');

test('relay credentials require PBX authentication and expire in one hour', async () => {
    const oldFetch = global.fetch;
    const old = { ...process.env };
    let handler;
    install({ get: (path, fn) => { assert.equal(path, '/api/mobile/ice'); handler = fn; } });
    const values = { 'X-Sokrat-Extension': 'fixture', 'X-Sokrat-Timestamp': '1', 'X-Sokrat-Signature': 'signed' };
    const req = { get: name => values[name] };
    const res = { code: 200, set() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    try {
        process.env.TURN_SHARED_SECRET = crypto.randomBytes(32).toString('hex');
        process.env.TURN_PUBLIC_HOST = 'gateway.example';
        process.env.PBX_AUTH_URL = 'http://pbx.example:8080';
        let calls = 0;
        global.fetch = async (url, opts) => {
            calls++;
            assert.equal(url, 'http://pbx.example:8080/api/extension/v1/whoami');
            assert.equal(opts.headers['X-Sokrat-Signature'], 'signed');
            return { ok: true, json: async () => ({ success: true, extension: 'fixture' }) };
        };
        await handler({ get: () => undefined }, res);
        assert.equal(res.code, 401);
        assert.equal(calls, 0);
        res.code = 200;
        await handler(req, res);
        const server = res.body.iceServers[0];
        assert.equal(server.urls[0], 'turn:gateway.example:3478?transport=udp');
        assert.equal(server.credential, crypto.createHmac('sha1', process.env.TURN_SHARED_SECRET).update(server.username).digest('base64'));
        assert.ok(Math.abs(Number(server.username.split(':')[0]) - Date.now() / 1000 - 3600) < 2);
        global.fetch = async () => ({ ok: false, status: 403 });
        await handler(req, res);
        assert.equal(res.code, 401);
        assert.equal(res.body.iceServers, undefined);
        global.fetch = async () => ({ ok: true, json: async () => ({ success: true, extension: 'other' }) });
        await handler(req, res);
        assert.equal(res.code, 401);
    } finally {
        global.fetch = oldFetch;
        for (const key of ['TURN_SHARED_SECRET', 'TURN_PUBLIC_HOST', 'PBX_AUTH_URL']) {
            if (old[key] === undefined) delete process.env[key]; else process.env[key] = old[key];
        }
    }
});
