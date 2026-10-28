'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { readPrivateRuntimeManifest } = require('../src/tenant-runtime');
test('runtime manifest refuses public permissions, malformed relays and symlinks', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-manifest-'));
    const file = path.join(dir, 'runtime.json');
    const data = { relays: { pbx_A: { host: 'gateway.example', port: 3500, secretFile: '/etc/sokrat/turn/A/secret', peerIps: ['10.0.0.2'] } } };
    try {
        await fs.writeFile(file, JSON.stringify(data), { mode: 0o600 });
        assert.equal((await readPrivateRuntimeManifest(file)).relays.pbx_A.port, 3500);
        await fs.chmod(file, 0o644);
        await assert.rejects(readPrivateRuntimeManifest(file), /private/);
        await fs.chmod(file, 0o600);
        data.relays.pbx_A.host = 'bad;command';
        await fs.writeFile(file, JSON.stringify(data));
        await assert.rejects(readPrivateRuntimeManifest(file), /Invalid/);
        await fs.symlink(file, path.join(dir, 'link'));
        await assert.rejects(readPrivateRuntimeManifest(path.join(dir, 'link')));
    } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
