'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fsp = require('node:fs').promises;

const { createMediaTransportReader, parseRegistry } = require('../src/control/media-transport');

async function registry(t, body) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'media-transport-'));
    t.after(() => fsp.rm(dir, { recursive: true, force: true }));
    const file = path.join(dir, 'installations.json');
    await fsp.writeFile(file, JSON.stringify(body));
    return file;
}

test('plain and direct UDP rows are UDP; rows without a transport are legacy TCP', () => {
    const byPbx = parseRegistry(JSON.stringify({
        a: { pbxId: 'pbx_a', mediaTransport: { mode: 'plain-udp', port: 26002 } },
        b: { pbxId: 'pbx_b', mediaTransport: { mode: 'direct-udp', port: 26154 } },
        c: { pbxId: 'pbx_c' },
        d: { notARow: true }
    }));
    assert.deepEqual(byPbx.get('pbx_a'), { media: 'udp', port: 26002, mode: 'plain-udp' });
    assert.deepEqual(byPbx.get('pbx_b'), { media: 'udp', port: 26154, mode: 'direct-udp' });
    assert.deepEqual(byPbx.get('pbx_c'), { media: 'tcp', port: null, mode: 'legacy-tcp' });
    assert.equal(byPbx.size, 3);
});

test('the reader caches by mtime and reports unknown for missing entries', async (t) => {
    const file = await registry(t, { a: { pbxId: 'pbx_a', mediaTransport: { mode: 'plain-udp', port: 26002 } } });
    let stats = 0;
    let reads = 0;
    const reader = createMediaTransportReader({
        file,
        statSync: (target) => { stats += 1; return require('node:fs').statSync(target); },
        readFileSync: (target, encoding) => { reads += 1; return require('node:fs').readFileSync(target, encoding); }
    });
    assert.equal(reader.lookup('pbx_a').media, 'udp');
    assert.equal(reader.lookup('pbx_a').media, 'udp');
    assert.equal(reads, 1, 'the registry is parsed once per mtime');
    assert.equal(stats, 2, 'each lookup stats the file to notice a change');
    assert.deepEqual(reader.lookup('pbx_missing'), { media: 'unknown', port: null, mode: null });
});

test('an unreadable or corrupt registry never breaks the caller', async (t) => {
    const file = await registry(t, { a: { pbxId: 'pbx_a' } });
    const reader = createMediaTransportReader({
        file: path.join(path.dirname(file), 'missing.json')
    });
    assert.equal(reader.lookup('pbx_a').media, 'unknown');

    await fsp.writeFile(file, '{not json');
    const corrupt = createMediaTransportReader({ file });
    assert.equal(corrupt.lookup('pbx_a').media, 'unknown');
});
