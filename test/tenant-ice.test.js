'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { installTenantIce } = require('../src/tenant-ice');
test('tenant media bootstrap uses only the approved PBX relay', async () => {
    let handler, approved = true;
    const secrets = { A: { host: 'gateway.example', port: 3500, secret: 'private-tenant-A-secret' } };
    installTenantIce({ get: (path, fn) => { handler = fn; } }, {
        authorizeDevice: async () => approved ? { deviceId: 'deviceA', pbxId: 'A' } : null,
        getRelay: async id => secrets[id]
    });
    const res = { set() {}, status(code) { this.code = code; return this; }, json(data) { this.body = data; } };
    await handler({}, res);
    assert.deepEqual(res.body.iceServers[0].urls, ['turn:gateway.example:3500?transport=udp', 'turn:gateway.example:3500?transport=tcp']);
    assert.equal(JSON.stringify(res.body).includes(secrets.A.secret), false);
    approved = false;
    await handler({}, res);
    assert.equal(res.code, 403);
});
