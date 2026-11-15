'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fsp = require('node:fs').promises;

const { createMediaTransportReader, parseProjection, parseRegistry } = require('../src/control/media-transport');

async function write(t, name, body) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'media-transport-'));
    t.after(() => fsp.rm(dir, { recursive: true, force: true }));
    const file = path.join(dir, name);
    await fsp.writeFile(file, JSON.stringify(body));
    return file;
}

test('the projection maps plain and direct UDP to udp with its port', () => {
    const byPbx = parseProjection(JSON.stringify({
        pbx_a: { mode: 'plain-udp', port: 26002 },
        pbx_b: { mode: 'direct-udp', port: 26154 },
        pbx_c: { mode: null, port: null }
    }));
    assert.deepEqual(byPbx.get('pbx_a'), { media: 'udp', port: 26002, mode: 'plain-udp' });
    assert.deepEqual(byPbx.get('pbx_b'), { media: 'udp', port: 26154, mode: 'direct-udp' });
    assert.deepEqual(byPbx.get('pbx_c'), { media: 'tcp', port: null, mode: null });
});

test('the registry fallback still classifies rows without a transport as TCP', () => {
    const byPbx = parseRegistry(JSON.stringify({
        a: { pbxId: 'pbx_a', mediaTransport: { mode: 'plain-udp', port: 26002 } },
        b: { pbxId: 'pbx_b' },
        c: { notARow: true }
    }));
    assert.deepEqual(byPbx.get('pbx_a'), { media: 'udp', port: 26002, mode: 'plain-udp' });
    assert.deepEqual(byPbx.get('pbx_b'), { media: 'tcp', port: null, mode: 'legacy-tcp' });
    assert.equal(byPbx.size, 2);
});

test('the projection wins, is cached by mtime, and falls back to the registry', async (t) => {
    const projection = await write(t, 'media-transport.json', { pbx_a: { mode: 'plain-udp', port: 26002 } });
    const registry = await write(t, 'installations.json', { a: { pbxId: 'pbx_b', mediaTransport: { mode: 'plain-udp', port: 26154 } } });
    let reads = 0;
    const reader = createMediaTransportReader({
        file: projection,
        fallbackFile: registry,
        statSync: (target) => require('node:fs').statSync(target),
        readFileSync: (target, encoding) => { reads += 1; return require('node:fs').readFileSync(target, encoding); }
    });
    assert.equal(reader.lookup('pbx_a').media, 'udp');
    assert.equal(reader.lookup('pbx_a').media, 'udp');
    assert.equal(reads, 1, 'the projection is parsed once per mtime');
    assert.equal(reader.lookup('pbx_b').media, 'udp', 'registry fallback still answers');
    assert.deepEqual(reader.lookup('pbx_missing'), { media: 'unknown', port: null, mode: null });
});

test('an unreadable or corrupt projection never breaks the caller', async (t) => {
    const missing = createMediaTransportReader({
        file: path.join(os.tmpdir(), 'does-not-exist-media.json'),
        fallbackFile: path.join(os.tmpdir(), 'does-not-exist-registry.json')
    });
    assert.equal(missing.lookup('pbx_a').media, 'unknown');

    const corruptFile = await write(t, 'media-transport.json', {});
    await fsp.writeFile(corruptFile, '{not json');
    const corrupt = createMediaTransportReader({ file: corruptFile, fallbackFile: corruptFile });
    assert.equal(corrupt.lookup('pbx_a').media, 'unknown');
});
