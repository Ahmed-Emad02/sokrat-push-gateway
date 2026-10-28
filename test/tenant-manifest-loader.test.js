'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { readPrivateRuntimeManifest } = require('../src/tenant-runtime');
const { createTenantManifestLoader } = require('../src/tenant-manifest-loader');
const { createRelayResolver, startTenantServer } = require('../src/tenant-server');

const hookHash = () => crypto.randomBytes(32).toString('hex');
const relay = (host, port, extra = {}) => ({ host, port,
    secretFile: '/etc/sokrat/turn/fixture/secret', peerIps: ['10.0.0.2'], ...extra });

let sequence = 0;
async function writeManifest(file, data) {
    const tmp = path.join(path.dirname(file), `.runtime-${process.pid}-${++sequence}.tmp`);
    await fs.writeFile(tmp, typeof data === 'string' ? data : JSON.stringify(data), { mode: 0o600 });
    await fs.rename(tmp, file);
}

async function manifestDir(t) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-manifest-loader-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    return dir;
}

test('hot reloads relay and hook hash after an atomic manifest replacement', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    const firstHash = hookHash();
    const secondHash = hookHash();
    await writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) }, hookHashes: { pbx_A: firstHash } });

    const loader = createTenantManifestLoader(file);
    const initial = await loader.load();
    assert.equal(initial.relays.pbx_A.port, 3500);
    assert.equal((await loader.getRelay('pbx_A')).host, 'turn-a.example');
    assert.equal(await loader.getHookHash('pbx_A'), firstHash);

    // The provisioner replaces the file by rename; no restart or reload call.
    await writeManifest(file, { relays: { pbx_A: relay('turn-b.example', 3501) }, hookHashes: { pbx_A: secondHash } });
    assert.equal((await loader.getRelay('pbx_A')).host, 'turn-b.example');
    assert.equal((await loader.getRelay('pbx_A')).port, 3501);
    assert.equal(await loader.getHookHash('pbx_A'), secondHash);
    assert.notEqual(await loader.getHookHash('pbx_A'), firstHash);

    // Removing a PBX from the manifest revokes new relay/hook authorization.
    await writeManifest(file, { relays: {}, hookHashes: {} });
    assert.equal(await loader.getRelay('pbx_A'), null);
    assert.equal(await loader.getHookHash('pbx_A'), undefined);
    assert.equal(loader.getStats().failures, 0);
});

test('invalid or missing replacement fails closed without serving stale authorization', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    const goodHash = hookHash();
    await writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) }, hookHashes: { pbx_A: goodHash } });

    const loader = createTenantManifestLoader(file);
    await loader.load();
    assert.equal((await loader.getRelay('pbx_A')).host, 'turn-a.example');

    const cases = [
        ['malformed JSON', async () => writeManifest(file, '{"relays": {')],
        ['invalid relay host', async () => writeManifest(file, { relays: { pbx_A: relay('bad;host', 3500) } })],
        ['invalid hook hash', async () => writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) },
            hookHashes: { pbx_A: 'not-a-hash' } })],
        ['non-private permissions', async () => {
            await writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) } });
            await fs.chmod(file, 0o644);
        }],
        ['symlinked manifest', async () => {
            const target = path.join(dir, 'target.json');
            await fs.writeFile(target, JSON.stringify({ relays: { pbx_A: relay('turn-a.example', 3500) } }), { mode: 0o600 });
            const link = path.join(dir, 'link.json');
            await fs.symlink(target, link);
            await fs.rename(link, file);
        }],
        ['missing file', async () => fs.rm(file, { force: true })]
    ];
    for (const [name, replace] of cases) {
        await replace();
        await assert.rejects(loader.getManifest(), Error, name);
        assert.equal(await loader.getRelay('pbx_A'), null, `${name}: relay must fail closed`);
        assert.equal(await loader.getHookHash('pbx_A'), undefined, `${name}: hook hash must fail closed`);
        // The last good copy exists only as a diagnostic snapshot.
        assert.equal(loader.peek().relays.pbx_A.host, 'turn-a.example', name);
    }
    assert.ok(loader.getStats().failures >= cases.length);

    // Recovery is automatic once the provisioner writes a valid file again.
    const recoveredHash = hookHash();
    await writeManifest(file, { relays: { pbx_A: relay('turn-c.example', 3502) }, hookHashes: { pbx_A: recoveredHash } });
    assert.equal((await loader.getRelay('pbx_A')).host, 'turn-c.example');
    assert.equal(await loader.getHookHash('pbx_A'), recoveredHash);
});

test('concurrent lookups bound file reads', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    await writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) } });

    let reads = 0;
    const loader = createTenantManifestLoader(file, { readManifest: async pathname => {
        reads += 1;
        return readPrivateRuntimeManifest(pathname);
    } });
    const results = await Promise.all(Array.from({ length: 32 }, () => loader.getRelay('pbx_A')));
    assert.ok(results.every(result => result && result.port === 3500));
    // One shared read plus at most one re-read that every joiner shares.
    assert.ok(reads <= 2, `expected bounded reads, saw ${reads}`);
    assert.ok(loader.getStats().coalesced >= 30);
});

test('a replacement landing mid-read is observed by lookups issued afterwards', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    const goodHash = hookHash();
    await writeManifest(file, { relays: { pbx_A: relay('turn-a.example', 3500) }, hookHashes: { pbx_A: goodHash } });

    let reads = 0;
    let release;
    let blocked = true;
    let signalBlocked;
    const blockedRead = new Promise(resolve => { signalBlocked = resolve; });
    const loader = createTenantManifestLoader(file, { readManifest: async pathname => {
        reads += 1;
        const manifest = await readPrivateRuntimeManifest(pathname);
        if (blocked) {
            blocked = false;
            signalBlocked();
            await new Promise(resolve => { release = resolve; });
        }
        return manifest;
    } });

    const beforeReplacement = loader.getRelay('pbx_A');
    await blockedRead;
    assert.equal(reads, 1);

    // Break the manifest while the first read is still open, then issue new
    // lookups: they must not be answered from the read that predates the swap.
    await writeManifest(file, '{broken');
    const afterReplacement = Array.from({ length: 24 }, () => loader.getRelay('pbx_A'));
    release();

    assert.equal((await beforeReplacement).host, 'turn-a.example');
    const results = await Promise.all(afterReplacement);
    assert.ok(results.every(result => result === null), 'new lookups must fail closed');
    assert.ok(reads <= 2, `expected bounded reads, saw ${reads}`);
    assert.equal(await loader.getHookHash('pbx_A'), undefined);
});

test('relay resolver reloads the manifest and keeps its existing checks', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    const secretFile = path.join(dir, 'secret');
    const secret = hookHash();
    await fs.writeFile(secretFile, `${secret}\n`, { mode: 0o600 });
    const control = { store: { getPbx: id => id === 'pbx_A' ? { id, enabled: true, mediaIps: ['10.0.0.2'] } : null } };
    const withSecret = (host, port, peers = ['10.0.0.2']) => ({
        relays: { pbx_A: { host, port, secretFile, peerIps: peers } } });

    await writeManifest(file, withSecret('turn-a.example', 3500));
    const loader = createTenantManifestLoader(file);
    await loader.load();
    const resolveRelay = createRelayResolver(control, loader);

    const initial = await resolveRelay('pbx_A');
    assert.equal(initial.host, 'turn-a.example');
    assert.equal(initial.secret, secret);

    // Same process, no restart: the next lookup sees the replacement.
    await writeManifest(file, withSecret('turn-b.example', 3501));
    const replaced = await resolveRelay('pbx_A');
    assert.equal(replaced.host, 'turn-b.example');
    assert.equal(replaced.port, 3501);

    // Unchanged existing behavior: media peer mismatch requires re-provisioning.
    await writeManifest(file, withSecret('turn-b.example', 3501, ['10.0.0.3']));
    assert.equal(await resolveRelay('pbx_A'), null);

    // Invalid replacement: no relay at all, even though the last copy was valid.
    await writeManifest(file, '{broken');
    assert.equal(await resolveRelay('pbx_A'), null);
    assert.ok(loader.peek());

    // Missing file, unknown PBX and non-private relay secret stay fail-closed.
    await fs.rm(file, { force: true });
    assert.equal(await resolveRelay('pbx_A'), null);
    assert.equal(await resolveRelay('pbx_B'), null);
    await writeManifest(file, withSecret('turn-b.example', 3501));
    await fs.chmod(secretFile, 0o644);
    await assert.rejects(resolveRelay('pbx_A'), /not private/);
    await fs.chmod(secretFile, 0o600);
    assert.equal((await resolveRelay('pbx_A')).host, 'turn-b.example');
    await fs.writeFile(secretFile, 'a'.repeat(129));
    await assert.rejects(resolveRelay('pbx_A'), /too large/);
});

test('bounds manifest size before parsing', async t => {
    const dir = await manifestDir(t);
    const file = path.join(dir, 'tenant-runtime.json');
    const limit = 1024 * 1024;
    const prefix = '{"relays":{},"padding":"';
    const suffix = '"}';
    const atLimit = prefix + 'a'.repeat(limit - Buffer.byteLength(prefix) - Buffer.byteLength(suffix)) + suffix;
    assert.equal(Buffer.byteLength(atLimit), limit);

    const loader = createTenantManifestLoader(file);
    await writeManifest(file, atLimit);
    assert.deepEqual((await loader.getManifest()).relays, {});

    // One byte over the limit must be rejected before JSON parsing, even though
    // trailing whitespace alone would be valid JSON.
    await writeManifest(file, `${atLimit} `);
    await assert.rejects(loader.getManifest(), /too large/);
    assert.equal(await loader.getRelay('pbx_A'), null);
    assert.equal(await loader.getHookHash('pbx_A'), undefined);
});

test('missing TENANT_RUNTIME_FILE keeps startup failure and fail-closed semantics', async () => {
    for (const file of [undefined, '']) {
        const loader = createTenantManifestLoader(file);
        await assert.rejects(loader.load(), /not configured/);
        assert.equal(await loader.getRelay('pbx_A'), null);
        assert.equal(await loader.getHookHash('pbx_A'), undefined);
        assert.equal(loader.peek(), null);
        assert.ok(loader.getStats().failures >= 1);
    }
    // The tenant listener is only started when TENANT_RUNTIME_FILE is configured;
    // a blank value must still abort startup before any provider is initialized.
    await assert.rejects(startTenantServer({ store: {} }, {}), /not configured/);
});
