'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { readHostFirewall } = require('../src/control/host-firewall');

const script = path.resolve(__dirname, '../scripts/media-udp-ports.py');

function parse(value) {
    return spawnSync('python3', ['-B', script, value], { encoding: 'utf8', timeout: 15000 });
}

test('an empty media port list opens nothing', () => {
    const result = parse('');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), '');
});

test('media UDP ports and inclusive ranges are canonicalized for the firewall', () => {
    const result = parse(' 26154, 26000:26154 ,26154/udp,26003:26003 ');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), '26154/udp,26000:26154/udp,26003/udp');
});

test('malformed, privileged, oversized, reversed and non-UDP entries are refused', () => {
    for (const value of ['80', '0', '65536', '26000:', ':26154', '26154:26000',
                         '26154/tcp', '1.2.3.4', 'abc', '26000,,26154']) {
        const result = parse(value);
        assert.equal(result.status, 2, value);
        assert.match(result.stderr, /media-udp-ports:/);
        assert.equal(result.stdout.trim(), '');
    }
});

test('the bounded entry count is enforced before firewall materialization', () => {
    assert.equal(parse('20000,20001,20002,20003,20004,20005,20006,20007').status, 0);
    const result = parse('20000,20001,20002,20003,20004,20005,20006,20007,20008');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /too many/);
});

test('operator media ports remain visible in the sanitized host firewall summary', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-media-ports-'));
    const file = path.join(directory, 'host-firewall.json');
    const parsed = parse('26154,26000:26154');
    assert.equal(parsed.status, 0, parsed.stderr);
    fs.writeFileSync(file, JSON.stringify({
        configured: true,
        manager: 'ufw',
        sshPort: 22,
        tls: true,
        ports: ['22/tcp', ...parsed.stdout.trim().split(','), 'not-a-port'],
        updatedAt: '2026-11-14T00:00:00.000Z'
    }));
    assert.deepEqual(readHostFirewall(file).ports,
        ['22/tcp', '26154/udp', '26000:26154/udp']);
    fs.rmSync(directory, { recursive: true, force: true });
});
