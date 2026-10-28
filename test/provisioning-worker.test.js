'use strict';

/**
 * Tests for scripts/reconcile-tenant-provisioning.py.
 *
 * Every case runs the real worker against a throwaway directory with a fake
 * sync script, fake systemctl and fake adapters. No root, no network, no live
 * gateway state is touched. The worker runs with --allow-unprivileged, which is
 * the documented staging/test escape hatch.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const WORKER = path.join(ROOT, 'scripts', 'reconcile-tenant-provisioning.py');
const PYTHON = process.env.PYTHON || 'python3';

const FAKE_SYNC = String.raw`#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
opts = {}
index = 0
while index < len(args):
    if args[index].startswith('--'):
        key = args[index][2:]
        if index + 1 >= len(args) or args[index + 1].startswith('--'):
            opts[key] = True
            index += 1
        else:
            opts[key] = args[index + 1]
            index += 2
    else:
        index += 1

count_path = os.path.join(here, 'sync-count')
count = int(open(count_path).read().strip()) + 1 if os.path.exists(count_path) else 1
open(count_path, 'w').write(str(count))

control_path = opts['control']
control = json.load(open(control_path))
with open(os.path.join(here, 'snapshot-%d.json' % count), 'w') as handle:
    json.dump(control, handle, indent=2, sort_keys=True)

if os.path.exists(os.path.join(here, 'sync-mutate-control')):
    target = open(os.path.join(here, 'sync-mutate-control')).read().strip()
    with open(target, 'a') as handle:
        handle.write(' \n')

if os.path.exists(os.path.join(here, 'sync-sleep')):
    time.sleep(float(open(os.path.join(here, 'sync-sleep')).read().strip() or '1'))

if os.path.exists(os.path.join(here, 'sync-fail')):
    sys.stderr.write('SYNC-SECRET-LEAK should never reach the operator\n')
    sys.exit(2)

state_dir = opts['state-dir']
os.makedirs(state_dir, exist_ok=True)
plan_path = os.path.join(state_dir, 'tenant-plan.json')
plan = json.load(open(plan_path)) if os.path.exists(plan_path) else {'schemaVersion': 1, 'allocations': {}}
used = set(entry['slot'] for entry in plan['allocations'].values())
slugs = set(entry['slug'] for entry in plan['allocations'].values())

for record in control['pbx']:
    if record['id'] in plan['allocations']:
        if record['enabled']:
            plan['allocations'][record['id']]['peerIps'] = list(record['mediaIps'])
        continue
    slot = 0
    while slot in used:
        slot += 1
    used.add(slot)
    base = ''.join(ch if ch.isalnum() else '-' for ch in record['id'].lower()).strip('-')[:19].strip('-')
    slug = base or 'tenant'
    if slug in slugs:
        slug = base[:10] + '-' + hashlib.sha256(record['id'].encode()).hexdigest()[:8]
    slugs.add(slug)
    plan['allocations'][record['id']] = {
        'slug': slug,
        'slot': slot,
        'listenerPort': 3500 + slot,
        'relayMinPort': 50000 + slot * 100,
        'relayMaxPort': 50000 + slot * 100 + 99,
        'peerIps': list(record['mediaIps']) if record['enabled'] else [],
    }

with open(plan_path, 'w') as handle:
    json.dump(plan, handle, indent=2, sort_keys=True)
os.chmod(plan_path, 0o600)

public_host = 'gw.example.test'
env_path = opts.get('env-file')
if env_path and os.path.exists(env_path):
    for line in open(env_path):
        if line.strip().startswith('GATEWAY_PUBLIC_HOST='):
            public_host = line.split('=', 1)[1].strip().strip('"\'')

secrets_dir = os.path.join(state_dir, 'secrets')
os.makedirs(secrets_dir, mode=0o700, exist_ok=True)
tokens_path = os.path.join(state_dir, 'hook-tokens.json')
tokens = json.load(open(tokens_path)) if os.path.exists(tokens_path) else {}
manifest = {'relays': {}, 'hookHashes': {}}
for record in control['pbx']:
    if not record['enabled']:
        continue
    allocation = plan['allocations'][record['id']]
    secret_path = os.path.join(secrets_dir, allocation['slug'] + '.secret')
    with open(secret_path, 'w') as handle:
        handle.write('a' * 64 + '\n')
    os.chmod(secret_path, 0o600)
    token = tokens.setdefault(record['id'], 'tok_' + record['id'] + '_' + 'Q' * 40)
    manifest['relays'][record['id']] = {
        'host': public_host,
        'port': allocation['listenerPort'],
        'secretFile': secret_path,
        'peerIps': list(record['mediaIps']),
    }
    manifest['hookHashes'][record['id']] = hashlib.sha256(token.encode()).hexdigest()

with open(tokens_path, 'w') as handle:
    json.dump(tokens, handle, indent=2, sort_keys=True)
os.chmod(tokens_path, 0o600)
manifest_path = os.path.join(state_dir, 'tenant-runtime.json')
with open(manifest_path, 'w') as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
os.chmod(manifest_path, 0o600)

warnings = []
if os.path.exists(os.path.join(here, 'sync-warn')):
    warnings.append('fake warning')
print(json.dumps({'ok': not warnings, 'warnings': warnings}))
sys.exit(1 if warnings else 0)
`;

const FAKE_ADAPTER = String.raw`#!/usr/bin/env python3
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
name = os.path.basename(__file__).rsplit('.', 1)[0]
payload = sys.stdin.read()
with open(os.path.join(here, name + '-requests.jsonl'), 'a') as handle:
    handle.write(payload + '\n')
# Adapter noise, including any token in the request: the worker must discard it.
sys.stderr.write('adapter noise ' + payload + '\n')
exit_file = os.path.join(here, name + '-exit')
code = int(open(exit_file).read().strip() or '0') if os.path.exists(exit_file) else 0
sys.exit(code)
`;

const FAKE_SYSTEMCTL = String.raw`#!/usr/bin/env python3
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
state_file = os.path.join(here, 'unit-state')
value = open(state_file).read().strip() if os.path.exists(state_file) else 'active'
print(value)
sys.exit(0 if value == 'active' else 3)
`;

function writeFile(file, text, mode = 0o600) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 });
    fs.writeFileSync(file, text, { mode });
    fs.chmodSync(file, mode);
    return file;
}

function writeJson(file, value, mode = 0o600) {
    return writeFile(file, JSON.stringify(value, null, 2) + '\n', mode);
}

function fingerprint({ wsURL, apiURL, mediaIps, approval }) {
    const document = { apiURL, approval, mediaIps: [...mediaIps].sort(), wsURL };
    return crypto.createHash('sha256').update(JSON.stringify(document)).digest('hex');
}

function slugFor(pbxId) {
    return pbxId.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 19).replace(/-+$/g, '');
}

function allocationFor(pbxId, slot, peerIps = []) {
    return {
        slug: slugFor(pbxId),
        slot,
        listenerPort: 3500 + slot,
        relayMinPort: 50000 + slot * 100,
        relayMaxPort: 50000 + slot * 100 + 99,
        peerIps,
    };
}

function makePin(record, options = {}) {
    const approval = options.approval || (record.management ? 'approved' : 'unmanaged');
    const pin = {
        wsURL: options.wsURL || record.wsURL,
        apiURL: options.apiURL || record.apiURL,
        mediaIps: options.mediaIps || [...record.mediaIps],
        approval,
    };
    pin.fingerprint = options.fingerprint || fingerprint(pin);
    if (options.hookAdapter) pin.hookAdapter = options.hookAdapter;
    return pin;
}

function defaultRecord(overrides = {}) {
    return {
        id: 'pbx_alpha',
        name: 'Alpha',
        wsURL: 'wss://alpha.example.test:8089/ws',
        apiURL: 'https://alpha.example.test:8080/',
        mediaIps: ['100.64.0.10'],
        enabled: true,
        createdAt: '2026-10-01T00:00:00Z',
        updatedAt: '2026-10-28T10:00:00Z',
        ...overrides,
    };
}

function makeFixture(t, options = {}) {
    const dir = fs.mkdtempSync(path.join(__dirname, '.tmp-provisioning-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin, { mode: 0o755 });
    const state = path.join(dir, 'state');
    fs.mkdirSync(state, { mode: 0o700 });
    const lockDir = path.join(dir, 'run');
    const statusFile = path.join(dir, 'status', 'status.json');
    const controlFile = path.join(state, 'control.json');
    const envFile = path.join(dir, 'runtime.env');
    const configFile = path.join(dir, 'gateway-provisioning.json');

    const syncScript = writeFile(path.join(bin, 'sync-tenant-runtime.py'), FAKE_SYNC, 0o755);
    const firewallAdapter = writeFile(path.join(bin, 'firewall-adapter.py'), FAKE_ADAPTER, 0o755);
    const hookAdapter = writeFile(path.join(bin, 'hook-adapter.py'), FAKE_ADAPTER, 0o755);
    const systemctl = writeFile(path.join(bin, 'systemctl.py'), FAKE_SYSTEMCTL, 0o755);
    writeFile(path.join(bin, 'unit-state'), 'active\n', 0o644);

    writeFile(envFile, 'GATEWAY_PUBLIC_HOST=gw.example.test\nGATEWAY_LISTEN_IP=10.0.0.5\nGATEWAY_PRIVATE_IP=10.8.0.2\n');

    const records = options.records || [defaultRecord()];
    writeJson(controlFile, {
        schemaVersion: 2,
        pbx: records,
        extensions: [],
        enrollmentTokens: [],
        devices: [],
        audit: [],
    });

    if (options.plan) {
        writeJson(path.join(state, 'tenant-plan.json'), { schemaVersion: 1, allocations: options.plan });
    }

    const pins = {};
    for (const record of records) {
        if (options.omitPins && options.omitPins.includes(record.id)) continue;
        pins[record.id] = makePin(record, {
            approval: options.approval,
            wsURL: options.pinWsURL,
            fingerprint: options.pinFingerprint,
            hookAdapter,
            ...(options.pinOverrides && options.pinOverrides[record.id]),
        });
    }
    for (const [id, pin] of Object.entries(options.extraPins || {})) pins[id] = pin;

    const config = {
        schemaVersion: 1,
        lockDir,
        statusFile,
        controlFile,
        runtime: {
            syncScript,
            envFile,
            gatewayUrl: 'https://gw.example.test',
            stateDir: state,
            turnRoot: path.join(dir, 'turn'),
            unitDir: path.join(dir, 'units'),
            iface: 'tailscale0',
            serviceUser: 'sokrat-push',
        },
        pbx: pins,
    };
    if (options.firewall !== false) config.firewallAdapter = firewallAdapter;
    writeJson(configFile, config);

    if (options.previousStatus) writeJson(statusFile, options.previousStatus, 0o640);

    const fixture = {
        dir, bin, state, lockDir, statusFile, controlFile, envFile, configFile,
        syncScript, firewallAdapter, hookAdapter, systemctl,
        readStatus() {
            return JSON.parse(fs.readFileSync(statusFile, 'utf8'));
        },
        readControl() {
            return JSON.parse(fs.readFileSync(controlFile, 'utf8'));
        },
        syncCount() {
            const file = path.join(bin, 'sync-count');
            return fs.existsSync(file) ? Number(fs.readFileSync(file, 'utf8')) : 0;
        },
        snapshot(n) {
            return JSON.parse(fs.readFileSync(path.join(bin, `snapshot-${n}.json`), 'utf8'));
        },
        requests(name) {
            const file = path.join(bin, `${name}-requests.jsonl`);
            if (!fs.existsSync(file)) return [];
            return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
        },
        flag(name, value = '1') {
            writeFile(path.join(bin, name), String(value), 0o644);
        },
        unflag(name) {
            try { fs.unlinkSync(path.join(bin, name)); } catch {}
        },
        unitState(value) {
            writeFile(path.join(bin, 'unit-state'), value + '\n', 0o644);
        },
        run(extra = []) {
            return spawnSync(PYTHON, [WORKER, '--config', configFile, '--allow-unprivileged', ...extra], {
                encoding: 'utf8',
                timeout: 60000,
                env: { ...process.env, PROVISIONING_TEST_SYSTEMCTL: systemctl },
            });
        },
    };
    return fixture;
}

function parseStatus(result) {
    return JSON.parse(result.stdout);
}

// ---------------------------------------------------------------------------
// Dry-run and happy path
// ---------------------------------------------------------------------------

test('dry-run writes nothing and runs no command', (t) => {
    const fixture = makeFixture(t);
    const result = fixture.run(['--dry-run']);

    assert.ok(result.status === 0, result.stderr + result.stdout);
    const status = parseStatus(result);
    assert.equal(status.schemaVersion, 1);
    assert.equal(status.pbx.pbx_alpha.state, 'planned');
    assert.equal(status.pbx.pbx_alpha.reason, 'planned');
    assert.equal(status.pbx.pbx_alpha.stages.relay, 'planned');
    assert.equal(status.pbx.pbx_alpha.capturedUpdatedAt, '2026-10-28T10:00:00Z');

    assert.equal(fs.existsSync(fixture.statusFile), false);
    assert.equal(fs.existsSync(fixture.lockDir), false);
    assert.equal(fixture.syncCount(), 0);
    assert.deepEqual(fixture.requests('firewall-adapter'), []);
    assert.deepEqual(fixture.requests('hook-adapter'), []);
});

test('apply reaches ready with 0640 status, pinned manifest and both adapters', (t) => {
    const fixture = makeFixture(t);
    const result = fixture.run(['--apply']);

    assert.ok(result.status === 0, result.stderr + result.stdout);
    const mode = fs.statSync(fixture.statusFile).mode & 0o777;
    assert.equal(mode, 0o640);

    const status = fixture.readStatus();
    const entry = status.pbx.pbx_alpha;
    assert.equal(entry.state, 'ready');
    assert.equal(entry.reason, 'ready');
    assert.deepEqual(entry.stages, { relay: 'ready', firewall: 'ready', hook: 'ready' });
    assert.equal(entry.capturedUpdatedAt, '2026-10-28T10:00:00Z');
    assert.match(entry.fingerprint, /^[a-f0-9]{64}$/);

    const firewall = fixture.requests('firewall-adapter');
    assert.equal(firewall.length, 1);
    assert.deepEqual(firewall[0], {
        pbxId: 'pbx_alpha',
        gatewayUrl: 'https://gw.example.test',
        listenerPort: 3500,
        peerIps: ['100.64.0.10'],
        enabled: true,
    });
    assert.equal('token' in firewall[0], false);

    const hook = fixture.requests('hook-adapter');
    assert.equal(hook.length, 1);
    assert.equal(hook[0].pbxId, 'pbx_alpha');
    assert.equal(hook[0].enabled, true);
    assert.match(hook[0].token, /^[A-Za-z0-9_-]{32,200}$/);

    const statusText = fs.readFileSync(fixture.statusFile, 'utf8');
    assert.equal(statusText.includes(hook[0].token), false);
    assert.equal(result.stdout.includes(hook[0].token), false);
    assert.equal(result.stderr.includes(hook[0].token), false);
});

test('second run is idempotent: no sync, no adapters, fresh updatedAt', async (t) => {
    const fixture = makeFixture(t);
    assert.equal(fixture.run(['--apply']).status, 0);
    const first = fixture.readStatus();
    const firewallCount = fixture.requests('firewall-adapter').length;
    const hookCount = fixture.requests('hook-adapter').length;

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const result = fixture.run(['--apply']);
    assert.ok(result.status === 0, result.stderr + result.stdout);

    assert.equal(fixture.syncCount(), 1);
    assert.equal(fixture.requests('firewall-adapter').length, firewallCount);
    assert.equal(fixture.requests('hook-adapter').length, hookCount);

    const second = fixture.readStatus();
    assert.equal(second.pbx.pbx_alpha.state, 'ready');
    assert.equal(second.pbx.pbx_alpha.stages.relay, 'ready');
    assert.notEqual(second.updatedAt, first.updatedAt);
});

test('failed firewall adapter is retried and never reports ready early', (t) => {
    const fixture = makeFixture(t);
    fixture.flag('firewall-adapter-exit', '1');

    const failed = fixture.run(['--apply']);
    assert.equal(failed.status, 1);
    const failedStatus = fixture.readStatus();
    assert.equal(failedStatus.pbx.pbx_alpha.state, 'error');
    assert.equal(failedStatus.pbx.pbx_alpha.reason, 'firewall_failed');
    assert.equal(failedStatus.pbx.pbx_alpha.stages.firewall, 'error');
    assert.deepEqual(fixture.requests('hook-adapter'), []);

    fixture.unflag('firewall-adapter-exit');
    const retried = fixture.run(['--apply']);
    assert.equal(retried.status, 0, retried.stderr);
    assert.equal(fixture.syncCount(), 2);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.state, 'ready');
});

test('hook adapter failure is an error state, not ready', (t) => {
    const fixture = makeFixture(t);
    fixture.flag('hook-adapter-exit', '1');

    const result = fixture.run(['--apply']);
    assert.equal(result.status, 1);
    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.state, 'error');
    assert.equal(entry.reason, 'hook_failed');
    assert.deepEqual(entry.stages, { relay: 'ready', firewall: 'ready', hook: 'error' });
    assert.equal(Object.values(fixture.readStatus().pbx).some((item) => item.state === 'ready'), false);
});

test('sync failure aborts adapters and redacts subprocess output', (t) => {
    const fixture = makeFixture(t);
    fixture.flag('sync-fail');

    const result = fixture.run(['--apply']);
    assert.equal(result.status, 1);
    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.reason, 'relay_failed');
    assert.equal(result.stderr.includes('SYNC-SECRET-LEAK'), false);
    assert.equal(fs.readFileSync(fixture.statusFile, 'utf8').includes('SYNC-SECRET-LEAK'), false);
    assert.deepEqual(fixture.requests('firewall-adapter'), []);
});

// ---------------------------------------------------------------------------
// Authorization gates
// ---------------------------------------------------------------------------

test('pin mismatch (dashboard record changed) refuses without sync', (t) => {
    const fixture = makeFixture(t, {
        pinWsURL: 'wss://old.example.test:8089/ws',
    });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 0, result.stderr);
    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.state, 'blocked');
    assert.equal(entry.reason, 'identity_mismatch');
    assert.equal(fixture.syncCount(), 0);
    assert.deepEqual(fixture.requests('firewall-adapter'), []);
});

test('managed record pending approval is refused (approval_required)', (t) => {
    const record = defaultRecord({
        management: { approvalStatus: 'pending', extensionPolicyRequired: false },
    });
    const fixture = makeFixture(t, {
        records: [record],
        pinOverrides: { pbx_alpha: { approval: 'approved' } },
    });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 0, result.stderr);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.reason, 'approval_required');
    assert.equal(fixture.syncCount(), 0);
});

test('managed approved record is provisioned', (t) => {
    const record = defaultRecord({
        management: { approvalStatus: 'approved', extensionPolicyRequired: false },
    });
    const fixture = makeFixture(t, { records: [record] });
    const result = fixture.run(['--apply']);
    assert.ok(result.status === 0, result.stderr + result.stdout);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.state, 'ready');
});

test('config fingerprint that does not match its pins is configuration_invalid', (t) => {
    const fixture = makeFixture(t, { pinFingerprint: 'a'.repeat(64) });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /configuration_invalid/);
    assert.equal(fs.existsSync(fixture.statusFile), false);
    assert.equal(fixture.syncCount(), 0);
});

test('unlisted existing allocation blocks the whole run without writes', (t) => {
    const legacy = defaultRecord({
        id: 'pbx_legacy',
        name: 'Legacy',
        wsURL: 'wss://legacy.example.test:8089/ws',
        apiURL: 'https://legacy.example.test:8080/',
        mediaIps: ['100.64.0.99'],
    });
    const plan = {
        pbx_legacy: allocationFor('pbx_legacy', 3, ['100.64.0.99']),
    };
    const fixture = makeFixture(t, { records: [defaultRecord(), legacy], plan, omitPins: ['pbx_legacy'] });
    const planBefore = fs.readFileSync(path.join(fixture.state, 'tenant-plan.json'));

    const result = fixture.run(['--apply']);
    assert.equal(result.status, 2);
    const status = fixture.readStatus();
    assert.equal(status.pbx.pbx_legacy.state, 'blocked');
    assert.equal(status.pbx.pbx_legacy.reason, 'not_configured');
    assert.equal(status.pbx.pbx_alpha.state, 'blocked');
    assert.equal(fixture.syncCount(), 0);
    assert.deepEqual(fixture.requests('firewall-adapter'), []);
    assert.deepEqual(fs.readFileSync(path.join(fixture.state, 'tenant-plan.json')), planBefore);
});

test('allocation without a dashboard record blocks the run', (t) => {
    const fixture = makeFixture(t, {
        records: [],
        extraPins: { pbx_alpha: makePin(defaultRecord()) },
        plan: { pbx_alpha: allocationFor('pbx_alpha', 0, ['100.64.0.10']) },
    });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 2);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.reason, 'not_configured');
    assert.equal(fixture.syncCount(), 0);
});

test('configured PBX missing from the dashboard is blocked, others still run', (t) => {
    const ghost = makePin(defaultRecord({ id: 'pbx_ghost' }));
    const fixture = makeFixture(t, { extraPins: { pbx_ghost: ghost } });
    const result = fixture.run(['--apply']);

    assert.ok(result.status === 0, result.stderr + result.stdout);
    const status = fixture.readStatus();
    assert.equal(status.pbx.pbx_ghost.state, 'blocked');
    assert.equal(status.pbx.pbx_ghost.reason, 'not_configured');
    assert.equal(status.pbx.pbx_alpha.state, 'ready');
});

test('missing firewall adapter blocks the run (cloud firewall required)', (t) => {
    const fixture = makeFixture(t, {
        firewall: false,
        plan: { pbx_alpha: allocationFor('pbx_alpha', 0, ['100.64.0.10']) },
    });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 2);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.reason, 'firewall_required');
    assert.equal(fixture.syncCount(), 0);
});

test('disabled known record is deprovisioned without hook install or cloud deallocation', (t) => {
    const record = defaultRecord({ enabled: false, mediaIps: [] });
    const fixture = makeFixture(t, {
        records: [record],
        pinOverrides: { pbx_alpha: { mediaIps: [] } },
        plan: { pbx_alpha: allocationFor('pbx_alpha', 0, ['100.64.0.10']) },
    });
    const result = fixture.run(['--apply']);

    assert.ok(result.status === 0, result.stderr + result.stdout);
    assert.equal(fixture.syncCount(), 1);
    const snapshot = fixture.snapshot(1);
    assert.equal(snapshot.pbx[0].enabled, false);
    assert.deepEqual(fixture.requests('hook-adapter'), []);
    assert.deepEqual(fixture.requests('firewall-adapter'), []);

    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.state, 'blocked');
    assert.equal(entry.reason, 'not_configured');
    assert.deepEqual(entry.stages, { relay: 'skipped', firewall: 'skipped', hook: 'skipped' });
});

test('invalid allocation arithmetic is refused before any command', (t) => {
    const broken = allocationFor('pbx_alpha', 0, ['100.64.0.10']);
    broken.listenerPort = 3999;
    const fixture = makeFixture(t, { plan: { pbx_alpha: broken } });
    const result = fixture.run(['--apply']);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /configuration_invalid/);
    assert.equal(fixture.syncCount(), 0);
    assert.equal(fs.existsSync(fixture.statusFile), false);
});

// ---------------------------------------------------------------------------
// Concurrency, locking and freshness
// ---------------------------------------------------------------------------

test('dashboard edit during the run aborts before adapters and clears ready', (t) => {
    const fixture = makeFixture(t);
    fixture.flag('sync-mutate-control', fixture.controlFile);

    const result = fixture.run(['--apply']);
    assert.equal(result.status, 1);
    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.state, 'error');
    assert.equal(entry.reason, 'worker_failed');
    assert.equal(entry.stages.relay, 'pending');
    assert.equal(entry.capturedUpdatedAt, '2026-10-28T10:00:00Z');
    assert.deepEqual(fixture.requests('firewall-adapter'), []);
    assert.deepEqual(fixture.requests('hook-adapter'), []);
});

test('flock lock: a held lock refuses, a SIGKILLed holder releases it', async (t) => {
    const fixture = makeFixture(t);
    fs.mkdirSync(fixture.lockDir, { recursive: true, mode: 0o700 });
    const lockPath = path.join(fixture.lockDir, 'lock');
    writeFile(lockPath, '', 0o600);

    const holder = spawn(PYTHON, ['-c', [
        'import fcntl, os, sys, time',
        `fd = os.open(${JSON.stringify(lockPath)}, os.O_RDWR)`,
        'fcntl.flock(fd, fcntl.LOCK_EX)',
        'print("locked", flush=True)',
        'time.sleep(60)',
    ].join('\n')], { stdio: ['ignore', 'pipe', 'ignore'] });
    t.after(() => holder.kill('SIGKILL'));
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('lock holder did not start')), 10000);
        holder.stdout.once('data', (chunk) => {
            clearTimeout(timer);
            if (String(chunk).includes('locked')) resolve();
            else reject(new Error('unexpected holder output'));
        });
    });

    const refused = fixture.run(['--apply']);
    assert.equal(refused.status, 2);
    assert.match(refused.stderr, /worker_failed/);
    assert.equal(fixture.syncCount(), 0);

    holder.kill('SIGKILL');
    await new Promise((resolve) => holder.once('exit', resolve));

    const afterKill = fixture.run(['--apply']);
    assert.equal(afterKill.status, 0, afterKill.stderr);
    assert.equal(fixture.syncCount(), 1);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.state, 'ready');
});

test('previous status that is not private is not trusted for skip', (t) => {
    const fixture = makeFixture(t);
    assert.equal(fixture.run(['--apply']).status, 0);
    assert.equal(fixture.syncCount(), 1);

    // A world-readable status file is not immutable root evidence.
    fs.chmodSync(fixture.statusFile, 0o644);

    const result = fixture.run(['--apply']);
    assert.ok(result.status === 0, result.stderr + result.stdout);
    assert.equal(fixture.syncCount(), 2);
    assert.equal(fixture.readStatus().pbx.pbx_alpha.state, 'ready');
});

test('service-writable status parent is rejected before any work', (t) => {
    const fixture = makeFixture(t);
    const shared = path.join(fixture.dir, 'service-shared');
    fs.mkdirSync(shared, { recursive: true, mode: 0o777 });
    fs.chmodSync(shared, 0o777);
    const config = JSON.parse(fs.readFileSync(fixture.configFile, 'utf8'));
    config.statusFile = path.join(shared, 'status.json');
    writeJson(fixture.configFile, config);

    const result = fixture.run(['--apply']);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /configuration_invalid/);
    assert.equal(fixture.syncCount(), 0);
    assert.equal(fs.existsSync(path.join(shared, 'status.json')), false);
});

test('status file is root-owned private and capturedUpdatedAt tracks the record', (t) => {
    const record = defaultRecord({ updatedAt: '2026-10-28T11:22:33Z' });
    const fixture = makeFixture(t, { records: [record] });
    assert.equal(fixture.run(['--apply']).status, 0);

    const info = fs.statSync(fixture.statusFile);
    assert.equal(info.mode & 0o007, 0);
    const entry = fixture.readStatus().pbx.pbx_alpha;
    assert.equal(entry.capturedUpdatedAt, '2026-10-28T11:22:33Z');
});

test('the hook token file trusts the service account like the other state files', () => {
    // The plan, the runtime manifest and the control store are read with the
    // service account in the owner set, because the control service owns the
    // state directory and must keep writing there. The hook token file lives
    // in the same directory; refusing it would make the whole run fail with
    // `configuration_invalid` before any stage is evaluated.
    const source = fs.readFileSync(WORKER, 'utf8');
    const loader = source.slice(
        source.indexOf('def load_tokens('),
        source.indexOf('def read_control_digest(')
    );
    assert.match(loader, /owners\.add\(config\["serviceUid"\]\)/);
});
