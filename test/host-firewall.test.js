'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { readHostFirewall } = require('../src/control/host-firewall');

test('reads only the sanitized installer-managed firewall summary', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-firewall-'));
    const file = path.join(dir, 'host-firewall.json');
    fs.writeFileSync(file, JSON.stringify({
        configured: true,
        manager: 'ufw',
        sshPort: 2222,
        tls: true,
        ports: ['2222/tcp', '443/tcp', '3500:3654/udp', 'not-a-port'],
        updatedAt: '2026-11-04T12:00:00.000Z',
        token: 'must-not-leak'
    }));
    const result = readHostFirewall(file);
    assert.deepEqual(result, {
        configured: true,
        manager: 'ufw',
        sshPort: 2222,
        tls: true,
        ports: ['2222/tcp', '443/tcp', '3500:3654/udp'],
        updatedAt: '2026-11-04T12:00:00.000Z'
    });
    assert.equal('token' in result, false);
    fs.rmSync(dir, { recursive: true, force: true });
});

test('missing or invalid firewall records fail closed', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-firewall-'));
    const missing = path.join(dir, 'missing.json');
    const invalid = path.join(dir, 'invalid.json');
    fs.writeFileSync(invalid, JSON.stringify({ configured: true, manager: 'provider' }));
    assert.equal(readHostFirewall(missing), null);
    assert.equal(readHostFirewall(invalid), null);
    fs.rmSync(dir, { recursive: true, force: true });
});
