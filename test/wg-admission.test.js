'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const { once } = require('node:events');
const { syncVpnPeers } = require('../src/wg-admission');

test('VPN admission refuses non-loopback plaintext before credential or network access', async t => {
    const credentials = t.mock.method(fs, 'readFile', async () => {
        throw new Error('Credential access must not happen');
    });
    const network = t.mock.method(http, 'request', () => {
        throw new Error('Network access must not happen');
    });
    for (const apiURL of ['http://192.0.2.1/', 'http://pbx.example.test/',
        'http://127.0.0.1.example.test/', 'http://localhost/']) {
        await assert.rejects(syncVpnPeers({ id: 'pbx_test', apiURL, vpn: { enabled: true } }, []),
            /requires HTTPS/);
    }
    assert.equal(credentials.mock.callCount(), 0);
    assert.equal(network.mock.callCount(), 0);
});

test('VPN admission retains the literal loopback hop used by the pinned FRP tunnel', async t => {
    const token = 'a'.repeat(64); // Nonsecret fixture, never a deployment credential.
    t.mock.method(fs, 'readFile', async () => JSON.stringify({ token }));
    let received;
    const server = http.createServer(async (req, res) => {
        let data = '';
        for await (const chunk of req) data += chunk;
        received = { path: req.url, pbx: req.headers['x-sokrat-pbx'], body: JSON.parse(data) };
        res.writeHead(req.headers.authorization === `Bearer ${token}` ? 200 : 403,
            { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ applied: 1 }));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => { server.closeAllConnections(); server.close(); });
    const peer = { deviceId: 'device_test', publicKey: Buffer.alloc(32, 1).toString('base64'), address: '10.66.0.2/32' };
    const result = await syncVpnPeers({ id: 'pbx_test',
        apiURL: `http://127.0.0.1:${server.address().port}/pbx/`, vpn: { enabled: true } }, [peer]);
    assert.deepEqual(result, { applied: 1 });
    assert.deepEqual(received, { path: '/pbx/api/gateway/wg/apply', pbx: 'pbx_test', body: { peers: [peer] } });
});
