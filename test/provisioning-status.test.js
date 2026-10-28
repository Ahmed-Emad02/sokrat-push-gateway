'use strict';

/**
 * Sanitized provisioning status API + dashboard wiring.
 *
 * The worker snapshot is untrusted input: these tests cover file hardening
 * (symlink, hardlink, ownership, mode, size), strict enum sanitization, secret
 * redaction, prototype-key rejection, staleness/reconciliation, and the
 * session-protected read-only HTTP route.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const express = require('express');
const { execFileSync } = require('node:child_process');

const { ControlStore } = require('../src/control/store');
const { createControlRouter } = require('../src/control/router');
const {
    getProvisioningStatus,
    resolveStatusFile,
    DEFAULT_STATUS_FILE,
    MAX_BYTES,
    STALE_AFTER_MS
} = require('../src/control/provisioning');

const PUBLIC_DIR = path.join(__dirname, '..', 'src', 'control', 'public');
const CURRENT_UID = typeof process.getuid === 'function' ? process.getuid() : 0;

async function workspace(t) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gateway-provisioning-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    return dir;
}

async function writeStatus(dir, payload, options = {}) {
    const filePath = path.join(dir, options.name || 'provisioning-status.json');
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    await fs.writeFile(filePath, body, { mode: options.mode === undefined ? 0o600 : options.mode });
    if (options.mode !== undefined) await fs.chmod(filePath, options.mode);
    return filePath;
}

async function newStore(t, dir) {
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    t.after(() => store.close && store.close());
    return store;
}

async function addPbx(store, name = 'Head office PBX') {
    return store.addPbx({
        name,
        wsURL: 'wss://pbx.example.com:8089/ws',
        apiURL: 'https://pbx.example.com:8080',
        mediaIps: '203.0.113.10',
        enabled: true
    }, { actor: 'admin@127.0.0.1' });
}

function documentFor(pbxId, entry, updatedAt) {
    return {
        schemaVersion: 1,
        updatedAt: updatedAt || new Date().toISOString(),
        pbx: { [pbxId]: entry }
    };
}

function readyEntry(pbxUpdatedAt, overrides = {}) {
    return {
        state: 'ready',
        stages: { relay: 'ready', firewall: 'ready', hook: 'ready' },
        reason: 'ready',
        fingerprint: 'a'.repeat(64),
        capturedUpdatedAt: pbxUpdatedAt,
        ...overrides
    };
}

test('default status path is the root-owned worker directory and env wins', () => {
    assert.equal(DEFAULT_STATUS_FILE, '/var/lib/sokrat-tenant-provisioning/status.json');
    assert.equal(resolveStatusFile({}), DEFAULT_STATUS_FILE);
    assert.equal(
        resolveStatusFile({ CONTROL_PROVISIONING_STATUS_FILE: ' /run/sokrat/status.json ' }),
        '/run/sokrat/status.json'
    );
    assert.equal(resolveStatusFile({ CONTROL_PROVISIONING_STATUS_FILE: '   ' }), DEFAULT_STATUS_FILE);
});

test('missing status file reports not_configured without failing', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const result = await getProvisioningStatus({
        filePath: path.join(dir, 'absent.json'),
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.status, 'not_configured');
    assert.equal(result.code, 'missing');
    assert.equal(result.updatedAt, null);
    assert.equal(result.pbx.length, 1);
    assert.equal(result.pbx[0].id, pbx.id);
    assert.equal(result.pbx[0].state, 'not_configured');
    assert.equal(result.pbx[0].effectiveState, 'not_configured');
    assert.equal(result.pbx[0].reason, 'not_configured');
    assert.equal(result.pbx[0].reconciliation, 'unknown');
    assert.deepEqual(result.pbx[0].stages, {
        relay: 'unknown',
        firewall: 'unknown',
        hook: 'unknown'
    });
});

test('valid 0600 snapshot returns only sanitized enumerated fields', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const updatedAt = new Date(Date.now() + 1000).toISOString();
    const filePath = await writeStatus(dir, documentFor(pbx.id, readyEntry(pbx.updatedAt, {
        // Untrusted extras must never be echoed.
        stdout: 'SUPER-SECRET-TOKEN stdout',
        stderr: 'SUPER-SECRET-TOKEN stderr',
        command: 'curl -H "Authorization: SUPER-SECRET-TOKEN"',
        detail: 'SUPER-SECRET-TOKEN detail',
        apiKey: 'SUPER-SECRET-TOKEN key',
        nested: { token: 'SUPER-SECRET-TOKEN nested' }
    }), updatedAt));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });

    assert.equal(result.status, 'ok');
    assert.equal(result.code, 'ok');
    assert.equal(result.schemaVersion, 1);
    assert.equal(result.updatedAt, updatedAt);
    assert.equal(result.staleAfterMs, STALE_AFTER_MS);
    assert.equal(result.pbx.length, 1);
    const entry = result.pbx[0];
    assert.deepEqual(Object.keys(entry).sort(), [
        'effectiveState', 'fingerprint', 'id', 'reason', 'reconciliation', 'stages', 'state'
    ]);
    assert.equal(entry.state, 'ready');
    assert.equal(entry.effectiveState, 'ready');
    assert.equal(entry.reconciliation, 'current');
    assert.equal(entry.reason, 'ready');
    assert.equal(entry.fingerprint, 'a'.repeat(64));
    assert.deepEqual(entry.stages, { relay: 'ready', firewall: 'ready', hook: 'ready' });

    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes('SUPER-SECRET-TOKEN'), 'worker strings must never be echoed');
    for (const key of ['stdout', 'stderr', 'command', 'detail', 'apiKey', 'nested']) {
        assert.ok(!serialized.includes(`"${key}"`), `${key} must not be forwarded`);
    }
});

test('unknown enum values degrade to safe enumerated values', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const updatedAt = new Date(Date.now() + 1000).toISOString();
    const filePath = await writeStatus(dir, documentFor(pbx.id, {
        state: 'totally-ready',
        stages: {
            relay: 'ready',
            firewall: 'firewall is open, trust me',
            hook: 42
        },
        reason: 'leaked /etc/shadow contents',
        fingerprint: 'not-a-hash',
        capturedUpdatedAt: pbx.updatedAt
    }, updatedAt));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    const entry = result.pbx[0];
    assert.equal(entry.state, 'error');
    assert.equal(entry.effectiveState, 'error');
    assert.equal(entry.reason, 'unknown');
    assert.deepEqual(entry.stages, { relay: 'ready', firewall: 'unknown', hook: 'unknown' });
    assert.equal(entry.fingerprint, null);
    assert.ok(!JSON.stringify(result).includes('/etc/shadow'));
});

test('the agreed worker stage vocabulary is accepted verbatim', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const filePath = await writeStatus(dir, documentFor(pbx.id, {
        state: 'blocked',
        stages: { relay: 'pending', firewall: 'skipped', hook: 'blocked' },
        reason: 'hook_required',
        capturedUpdatedAt: pbx.updatedAt
    }, new Date(Date.now() + 1000).toISOString()));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.deepEqual(result.pbx[0].stages, {
        relay: 'pending',
        firewall: 'skipped',
        hook: 'blocked'
    });
    assert.equal(result.pbx[0].effectiveState, 'blocked');
});

test('a non-object PBX entry is reported as configuration_invalid', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const filePath = await writeStatus(dir, {
        schemaVersion: 1,
        updatedAt: new Date(Date.now() + 1000).toISOString(),
        pbx: { [pbx.id]: 'ready' }
    });
    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.pbx[0].state, 'error');
    assert.equal(result.pbx[0].reason, 'configuration_invalid');
});

test('prototype-ish PBX keys are ignored and cannot pollute objects', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const raw = {
        schemaVersion: 1,
        updatedAt: new Date(Date.now() + 1000).toISOString(),
        pbx: JSON.parse(`{
            "__proto__": {"state": "ready", "reason": "ready", "polluted": "yes"},
            "constructor": {"state": "ready", "reason": "ready"},
            "prototype": {"state": "ready", "reason": "ready"}
        }`)
    };
    const filePath = await writeStatus(dir, raw);

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });

    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);
    assert.equal(result.pbx.length, 1);
    assert.equal(result.pbx[0].id, pbx.id, 'only control-store ids are returned');
    assert.equal(result.pbx[0].state, 'not_configured');
    assert.ok(!JSON.stringify(result).includes('polluted'));
});

test('a snapshot older than two minutes is stale and never reports ready', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const updatedAt = new Date(Date.now() - STALE_AFTER_MS - 30_000).toISOString();
    const filePath = await writeStatus(dir, documentFor(pbx.id, readyEntry(pbx.updatedAt), updatedAt));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.status, 'stale');
    assert.equal(result.code, 'stale');
    assert.ok(result.ageMs > STALE_AFTER_MS);
    assert.equal(result.pbx[0].state, 'ready', 'the reported value is preserved for context');
    assert.equal(result.pbx[0].reconciliation, 'stale');
    assert.equal(result.pbx[0].effectiveState, 'stale', 'ready must not be claimed when stale');
});

test('capturedUpdatedAt must match the current record exactly', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    // Snapshot is recent (not stale), but the worker reconciled an older revision.
    const updatedAt = new Date(Date.now() + 1000).toISOString();
    const staleRevision = new Date(Date.parse(pbx.updatedAt) - 120_000).toISOString();
    const filePath = await writeStatus(dir, documentFor(
        pbx.id,
        readyEntry(staleRevision),
        updatedAt
    ));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.status, 'ok');
    assert.equal(result.pbx[0].reconciliation, 'pending');
    assert.equal(result.pbx[0].effectiveState, 'pending');
});

test('a ready entry without capturedUpdatedAt is downgraded to pending', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const entry = readyEntry(pbx.updatedAt);
    delete entry.capturedUpdatedAt;
    const filePath = await writeStatus(dir, documentFor(
        pbx.id,
        entry,
        new Date(Date.now() + 1000).toISOString()
    ));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.pbx[0].state, 'ready', 'reported value is preserved for context');
    assert.equal(result.pbx[0].reconciliation, 'pending');
    assert.equal(result.pbx[0].effectiveState, 'pending', 'old-schema ready must not be claimed');
});

test('legacy non-ready entries fall back to the completion timestamp', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const updatedAt = new Date(Date.now() - 60_000).toISOString();
    const filePath = await writeStatus(dir, documentFor(pbx.id, {
        state: 'blocked',
        stages: { relay: 'blocked', firewall: 'pending', hook: 'pending' },
        reason: 'relay_failed'
    }, updatedAt));

    const result = await getProvisioningStatus({
        filePath,
        ownerUids: [CURRENT_UID],
        pbx: [{ id: pbx.id, updatedAt: pbx.updatedAt }]
    });
    assert.equal(result.pbx[0].reconciliation, 'pending');
    assert.equal(result.pbx[0].effectiveState, 'pending');
});

test('file hardening: permissions, ownership, symlinks, hardlinks and size', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const records = [{ id: pbx.id, updatedAt: pbx.updatedAt }];
    const payload = documentFor(pbx.id, readyEntry(pbx.updatedAt), new Date(Date.now() + 1000).toISOString());

    const worldReadable = await writeStatus(dir, payload, { name: 'world.json', mode: 0o644 });
    let result = await getProvisioningStatus({
        filePath: worldReadable, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'permissions_invalid');

    const groupReadable = await writeStatus(dir, payload, { name: 'group.json', mode: 0o640 });
    result = await getProvisioningStatus({
        filePath: groupReadable, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'ok', '0640 root/service-readable is accepted');

    const privateFile = await writeStatus(dir, payload, { name: 'private.json', mode: 0o600 });
    const wrongOwner = CURRENT_UID === 0 ? 424242 : 0;
    result = await getProvisioningStatus({
        filePath: privateFile, ownerUids: [wrongOwner], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'owner_invalid');

    const link = path.join(dir, 'link.json');
    await fs.symlink(privateFile, link);
    result = await getProvisioningStatus({
        filePath: link, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'symlink');

    const hard = path.join(dir, 'hard.json');
    await fs.link(privateFile, hard);
    result = await getProvisioningStatus({
        filePath: hard, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'hardlink');

    const huge = await writeStatus(dir, ' '.repeat(MAX_BYTES + 1024), { name: 'huge.json' });
    result = await getProvisioningStatus({
        filePath: huge, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'too_large');

    const directory = path.join(dir, 'as-directory');
    await fs.mkdir(directory);
    result = await getProvisioningStatus({
        filePath: directory, ownerUids: [CURRENT_UID], pbx: records
    });
    assert.equal(result.status, 'unavailable');
    assert.ok(['not_regular', 'unreadable'].includes(result.code), result.code);
});

test('a FIFO cannot block the status read before rejection', async (t) => {
    const dir = await workspace(t);
    const fifo = path.join(dir, 'fifo.json');
    try {
        execFileSync('mkfifo', [fifo]);
    } catch {
        t.skip('mkfifo is unavailable on this platform');
        return;
    }
    const started = Date.now();
    const result = await getProvisioningStatus({
        filePath: fifo,
        ownerUids: [CURRENT_UID],
        pbx: []
    });
    assert.ok(Date.now() - started < 2000, 'open must not block on a FIFO');
    assert.equal(result.status, 'unavailable');
    assert.equal(result.code, 'not_regular');
});

test('malformed documents are unavailable, never partially trusted', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const records = [{ id: pbx.id, updatedAt: pbx.updatedAt }];

    const cases = [
        ['not json at all', 'invalid_json'],
        ['[]', 'invalid_schema'],
        [JSON.stringify({ schemaVersion: 2, updatedAt: new Date().toISOString(), pbx: {} }), 'invalid_schema'],
        [JSON.stringify({ schemaVersion: 1, updatedAt: new Date().toISOString(), pbx: [] }), 'invalid_schema'],
        [JSON.stringify({ schemaVersion: 1, updatedAt: 'not-a-date', pbx: {} }), 'invalid_timestamp'],
        [JSON.stringify({
            schemaVersion: 1,
            updatedAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            pbx: {}
        }), 'invalid_timestamp']
    ];

    let index = 0;
    for (const [body, code] of cases) {
        const filePath = await writeStatus(dir, body, { name: `bad-${index++}.json` });
        const result = await getProvisioningStatus({
            filePath, ownerUids: [CURRENT_UID], pbx: records
        });
        assert.equal(result.status, 'unavailable', body);
        assert.equal(result.code, code, body);
        assert.equal(result.updatedAt, null);
        assert.equal(result.pbx[0].effectiveState, 'unavailable');
    }
});

test('GET /api/provisioning is session protected, read-only and sanitized', async (t) => {
    const dir = await workspace(t);
    const store = await newStore(t, dir);
    const pbx = await addPbx(store);
    const updatedAt = new Date(Date.now() + 1000).toISOString();
    const filePath = await writeStatus(dir, documentFor(pbx.id, readyEntry(pbx.updatedAt, {
        stdout: 'SUPER-SECRET-TOKEN'
    }), updatedAt));

    const password = crypto.randomBytes(32).toString('hex');
    const app = express();
    app.use('/control', createControlRouter({
        store,
        loginFailureDelayMs: 0,
        provisioning: { filePath, ownerUids: [CURRENT_UID] },
        credential: {
            configured: true,
            source: 'test',
            verify: async (value) => value === password
        }
    }));
    const server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    t.after(async () => {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
    });

    const origin = `http://127.0.0.1:${server.address().port}/control/api`;
    const storeBefore = await fs.readFile(path.join(dir, 'control.json'), 'utf8');

    const anonymous = await fetch(`${origin}/provisioning`);
    assert.equal(anonymous.status, 401);

    const session = await fetch(`${origin}/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    });
    assert.equal(session.status, 200);
    const cookie = session.headers.getSetCookie().map((value) => value.split(';')[0]).join('; ');
    const { csrfToken } = await session.json();

    const response = await fetch(`${origin}/provisioning?file=${encodeURIComponent('/etc/passwd')}`, {
        headers: { Cookie: cookie }
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.success, true);
    assert.equal(body.provisioning.status, 'ok');
    assert.equal(body.provisioning.pbx.length, 1);
    assert.equal(body.provisioning.pbx[0].id, pbx.id);
    assert.equal(body.provisioning.pbx[0].effectiveState, 'ready');
    assert.ok(!JSON.stringify(body).includes('SUPER-SECRET-TOKEN'));
    assert.ok(!JSON.stringify(body).includes('root:x:'));

    const mutation = await fetch(`${origin}/provisioning`, {
        method: 'POST',
        headers: { Cookie: cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ state: 'ready' })
    });
    assert.equal(mutation.status, 404, 'provisioning has no mutation route');

    const storeAfter = await fs.readFile(path.join(dir, 'control.json'), 'utf8');
    assert.equal(storeAfter, storeBefore, 'reading provisioning must not touch the control store');
});

test('dashboard renders provisioning with textContent and an explicit timestamp', async () => {
    const [html, script] = await Promise.all([
        fs.readFile(path.join(PUBLIC_DIR, 'index.html'), 'utf8'),
        fs.readFile(path.join(PUBLIC_DIR, 'app.js'), 'utf8')
    ]);

    assert.match(html, /id="pbx-provisioning-summary"[^>]*role="status"[^>]*aria-live="polite"/);
    assert.match(html, /<th scope="col">Provisioning<\/th>/);
    assert.match(script, /\/api\/provisioning/);
    assert.match(script, /provisioningCell/);
    assert.match(script, /Last reconciliation/);
    assert.ok(!script.includes('.innerHTML'), 'provisioning values must be written as text');
    for (const state of ['ready', 'blocked', 'error', 'planned', 'not_configured', 'pending', 'stale', 'unavailable']) {
        assert.ok(script.includes(`${state}:`), `UI should label the ${state} state`);
    }
    for (const stage of ['pending', 'ready', 'blocked', 'error', 'planned', 'skipped', 'unknown']) {
        assert.ok(script.includes(`${stage}:`), `UI should label the ${stage} stage`);
    }
    assert.ok(!script.includes("required: 'Required'"), 'stage vocabulary must match the worker');
});
