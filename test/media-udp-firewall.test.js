'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const script = path.resolve(__dirname, '../scripts/media-udp-firewall.py');

function plan(slot) {
    const base = [0, 4, 12][slot] || slot * 4;
    return {
        pbxId: `pbx_${String(slot).padStart(16, '0')}`,
        slot,
        interface: `skm${slot}`,
        gatewayIp: `10.253.0.${base + 1}`,
        pbxIp: `10.253.0.${base + 2}`,
        remoteMediaPort: 22000 + slot,
        localMediaPort: 17001
    };
}

function entry(slot, transport) {
    const value = {
        installationId: String(slot + 1).repeat(32).slice(0, 32),
        pbxId: `pbx_${String(slot).padStart(16, '0')}`,
        secretHash: 'not-used',
        plan: plan(slot),
        ports: { ws: 23000 + slot * 2, api: 23001 + slot * 2, media: 22000 + slot }
    };
    if (transport !== undefined) value.mediaTransport = transport;
    return value;
}

function setup(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-media-firewall-'));
    const bin = path.join(root, 'bin');
    fs.mkdirSync(bin);
    const runner = path.join(root, 'manager-runner.py');
    fs.writeFileSync(runner, `import os, runpy\nos.geteuid = lambda: 0\nrunpy.run_path(${JSON.stringify(script)}, run_name='__main__')\n`);
    const log = path.join(root, 'commands.log');
    const allowed = path.join(root, 'allowed');
    const status = path.join(root, 'ufw-status');
    const firewalldPorts = path.join(root, 'firewalld-ports');
    const firewalldRuntimePorts = path.join(root, 'firewalld-runtime-ports');
    fs.writeFileSync(log, '');
    fs.writeFileSync(allowed, '');
    fs.writeFileSync(firewalldPorts, '');
    fs.writeFileSync(firewalldRuntimePorts, '');
    fs.writeFileSync(status, [
        'Status: active', '', 'To                         Action      From',
        '--                         ------      ----', '22/tcp                     ALLOW       Anywhere',
        '3500:3654/udp              ALLOW       Anywhere', ''
    ].join('\n'));
    const ufw = `#!/bin/sh
set -eu
echo "ufw $*" >> "$SOKRAT_TEST_LOG"
if [ "$1" = status ]; then cat "$SOKRAT_TEST_STATUS"; exit 0; fi
if [ "$1" = allow ]; then echo "$2 ALLOW Anywhere" >> "$SOKRAT_TEST_STATUS"; echo "$2" >> "$SOKRAT_TEST_ALLOWED"; exit 0; fi
exit 0
`;
    const firewall = `#!/bin/sh
set -eu
echo "firewall-cmd $*" >> "$SOKRAT_TEST_LOG"
ports="$SOKRAT_TEST_FIREWALLD_RUNTIME_PORTS"
if [ "$1" = --permanent ]; then ports="$SOKRAT_TEST_FIREWALLD_PORTS"; shift; fi
case "$1" in
  --query-port=*) grep -qx "\${1#--query-port=}" "$ports" 2>/dev/null; exit $? ;;
  --add-port=*) echo "\${1#--add-port=}" >> "$ports" ;;
  --reload) cp "$SOKRAT_TEST_FIREWALLD_PORTS" "$SOKRAT_TEST_FIREWALLD_RUNTIME_PORTS" ;;
esac
exit 0
`;
    fs.writeFileSync(path.join(bin, 'ufw'), ufw, { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'firewall-cmd'), firewall, { mode: 0o755 });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return {
        root,
        manifest: path.join(root, 'host-firewall.json'),
        registry: path.join(root, 'installations.json'),
        log,
        allowed,
        firewalldPorts,
        firewalldRuntimePorts,
        runner,
        env: {
            ...process.env,
            PATH: `${bin}:${process.env.PATH}`,
            SOKRAT_TEST_LOG: log,
            SOKRAT_TEST_ALLOWED: allowed,
            SOKRAT_TEST_STATUS: status,
            SOKRAT_TEST_FIREWALLD_PORTS: firewalldPorts,
            SOKRAT_TEST_FIREWALLD_RUNTIME_PORTS: firewalldRuntimePorts
        }
    };
}

function writeRegistry(file, rows) {
    fs.writeFileSync(file, JSON.stringify(Object.fromEntries(rows.map((row, index) => [`i${index}`, row]))));
}

function writeManifest(file, manager = 'ufw') {
    fs.writeFileSync(file, JSON.stringify({
        configured: true,
        manager,
        sshPort: 22,
        tls: true,
        ports: ['22/tcp', '3500:3654/udp'],
        updatedAt: '2026-01-01T00:00:00+00:00'
    }));
}

function run(fx, value) {
    return spawnSync('python3', ['-B', fx.runner, '--apply', '--manifest', fx.manifest,
        '--registry', fx.registry, ...(value ? ['--operator-ports', value] : [])],
    { env: fx.env, encoding: 'utf8', timeout: 20000 });
}

test('registry-selected direct ports are materialized without converting legacy tenants', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 }),
        entry(1, { mode: 'direct-udp', host: 'gateway.example.test', port: 26003 }),
        entry(3, null)]);
    writeManifest(fx.manifest);
    const result = run(fx, '26004');
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(new Set(manifest.ports), new Set(['22/tcp', '3500:3654/udp', '26004/udp', '26154/udp', '26003/udp']));
    assert.deepEqual(new Set(manifest.mediaUdpPorts), new Set(['26154/udp', '26003/udp']));
    assert.deepEqual(manifest.operatorMediaUdpPorts, ['26004/udp']);
    assert.equal(manifest.manager, 'ufw');
    assert.equal(manifest.sshPort, 22);
    assert.equal(manifest.tls, true);
    assert.deepEqual(new Set(fs.readFileSync(fx.allowed, 'utf8').trim().split('\n').filter(Boolean)),
        new Set(['26004/udp', '26154/udp', '26003/udp']));
});

test('repeated reconcile is idempotent and does not duplicate rules or rewrite the manifest', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 })]);
    writeManifest(fx.manifest);
    assert.equal(run(fx).status, 0);
    const first = fs.readFileSync(fx.manifest, 'utf8');
    const afterFirst = fs.readFileSync(fx.log, 'utf8');
    assert.match(afterFirst, /ufw allow 26154\/udp/);
    assert.equal(run(fx).status, 0);
    assert.equal(fs.readFileSync(fx.manifest, 'utf8'), first);
    const allows = value => value.split('\n').filter(line => line.includes('ufw allow '));
    assert.deepEqual(allows(fs.readFileSync(fx.log, 'utf8')), allows(afterFirst));
});

test('existing operator ports and unrelated firewall entries survive an upgrade reconcile', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(1, { mode: 'direct-udp', host: 'gateway.example.test', port: 26003 })]);
    fs.writeFileSync(fx.manifest, JSON.stringify({
        configured: true,
        manager: 'ufw',
        sshPort: 2222,
        tls: true,
        ports: ['2222/tcp', '3500:3654/udp', '26004/udp', '26154/udp'],
        mediaUdpPorts: ['26154/udp'],
        operatorMediaUdpPorts: ['26004/udp'],
        updatedAt: '2026-01-01T00:00:00+00:00',
        futureField: { keep: true }
    }));
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(new Set(manifest.ports), new Set(['2222/tcp', '3500:3654/udp', '26004/udp', '26003/udp']));
    assert.deepEqual(manifest.mediaUdpPorts, ['26003/udp']);
    assert.deepEqual(manifest.operatorMediaUdpPorts, ['26004/udp']);
    assert.deepEqual(manifest.futureField, { keep: true });
    assert.equal(manifest.sshPort, 2222);
});

test('a legacy-only registry removes the recorded media entry but never deletes firewall rules', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, null)]);
    fs.writeFileSync(fx.manifest, JSON.stringify({
        configured: true, manager: 'ufw', sshPort: 22, tls: true,
        ports: ['22/tcp', '26154/udp'], mediaUdpPorts: ['26154/udp'],
        updatedAt: '2026-01-01T00:00:00+00:00'
    }));
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(manifest.ports, ['22/tcp']);
    assert.deepEqual(manifest.mediaUdpPorts, []);
    assert.doesNotMatch(fs.readFileSync(fx.log, 'utf8'), /ufw delete|ufw --force delete/);
});

test('firewalld persists a runtime-only media port without removing unrelated runtime rules', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 })]);
    writeManifest(fx.manifest, 'firewalld');
    fs.writeFileSync(fx.firewalldRuntimePorts, '26154/udp\n39000/udp\n');
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(fx.firewalldPorts, 'utf8').trim().split('\n'), ['26154/udp']);
    assert.deepEqual(new Set(fs.readFileSync(fx.firewalldRuntimePorts, 'utf8').trim().split('\n')),
        new Set(['26154/udp', '39000/udp']));
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(manifest.mediaUdpPorts, ['26154/udp']);
});

test('firewalld restores a permanent-only media port to runtime without removing unrelated rules', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 })]);
    writeManifest(fx.manifest, 'firewalld');
    fs.writeFileSync(fx.firewalldPorts, '26154/udp\n');
    fs.writeFileSync(fx.firewalldRuntimePorts, '39000/udp\n');
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(fs.readFileSync(fx.firewalldPorts, 'utf8').trim().split('\n'), ['26154/udp']);
    assert.deepEqual(new Set(fs.readFileSync(fx.firewalldRuntimePorts, 'utf8').trim().split('\n')),
        new Set(['26154/udp', '39000/udp']));
});

test('an unconfigured host firewall records no rule and invokes no firewall command', t => {
    const fx = setup(t);
    writeRegistry(fx.registry, [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 })]);
    fs.writeFileSync(fx.manifest, JSON.stringify({ configured: false, manager: '', ports: [] }));
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(fx.log, 'utf8'), '');
    assert.deepEqual(JSON.parse(fs.readFileSync(fx.manifest, 'utf8')).ports, []);
});

test('malformed or conflicting selected transports fail before any firewall change', t => {
    const fx = setup(t);
    writeManifest(fx.manifest);
    const before = fs.readFileSync(fx.manifest, 'utf8');
    const invalid = [
        [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26154 }),
            entry(1, { mode: 'direct-udp', host: 'gateway.example.test', port: 26154 })],
        [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 80 })],
        [entry(0, { mode: 'plain-udp', host: 'gateway.example.test', port: 26003, extra: true })],
        [entry(0, { mode: 'plain-udp', host: 'gateway.example.test\\nremote evil 1', port: 26003 })]
    ];
    for (const rows of invalid) {
        writeRegistry(fx.registry, rows);
        const result = run(fx);
        assert.notEqual(result.status, 0, JSON.stringify(rows));
        assert.equal(fs.readFileSync(fx.manifest, 'utf8'), before);
        assert.equal(fs.readFileSync(fx.log, 'utf8'), '');
    }
});

test('fresh installer operator ports are recorded and opened before enrollment exists', t => {
    const fx = setup(t);
    writeManifest(fx.manifest);
    const result = run(fx, '26004');
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(manifest.operatorMediaUdpPorts, ['26004/udp']);
    assert.deepEqual(manifest.mediaUdpPorts, []);
    assert.ok(manifest.ports.includes('26004/udp'));
    assert.deepEqual(fs.readFileSync(fx.allowed, 'utf8').trim().split('\n').filter(Boolean), ['26004/udp']);
});

test('a missing registry without operator input never clears recorded media state', t => {
    const fx = setup(t);
    fs.writeFileSync(fx.manifest, JSON.stringify({
        configured: true, manager: 'ufw', sshPort: 22, tls: true,
        ports: ['22/tcp', '26154/udp'], mediaUdpPorts: ['26154/udp']
    }));
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.ok(manifest.ports.includes('26154/udp'));
    assert.deepEqual(manifest.mediaUdpPorts, ['26154/udp']);
    assert.doesNotMatch(fs.readFileSync(fx.log, 'utf8'), /ufw delete/);
});

test('a previously opened media port remains after legacy selection while the manifest updates', t => {
    const fx = setup(t);
    fs.appendFileSync(fx.env.SOKRAT_TEST_STATUS, '26154/udp ALLOW Anywhere\n');
    writeRegistry(fx.registry, [entry(0, null)]);
    fs.writeFileSync(fx.manifest, JSON.stringify({
        configured: true, manager: 'ufw', sshPort: 22, tls: true,
        ports: ['22/tcp', '26154/udp'], mediaUdpPorts: ['26154/udp'],
        operatorMediaUdpPorts: [],
        updatedAt: '2026-01-01T00:00:00+00:00'
    }));
    const result = run(fx);
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(fs.readFileSync(fx.log, 'utf8'), /ufw delete|--remove-port/);
    assert.match(fs.readFileSync(fx.env.SOKRAT_TEST_STATUS, 'utf8'), /26154\/udp ALLOW/);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(manifest.ports, ['22/tcp']);
    assert.deepEqual(manifest.mediaUdpPorts, []);
});

test('a manually added rule survives rollback reconcile unchanged', t => {
    const fx = setup(t);
    fs.appendFileSync(fx.env.SOKRAT_TEST_STATUS, '26154/udp ALLOW Anywhere # manual\n');
    writeRegistry(fx.registry, [entry(0, null)]);
    fs.writeFileSync(fx.manifest, JSON.stringify({
        configured: true, manager: 'ufw', sshPort: 22, tls: true,
        ports: ['22/tcp', '26154/udp'], mediaUdpPorts: ['26154/udp'],
        operatorMediaUdpPorts: [],
        updatedAt: '2026-01-01T00:00:00+00:00'
    }));
    assert.equal(run(fx).status, 0);
    assert.match(fs.readFileSync(fx.env.SOKRAT_TEST_STATUS, 'utf8'), /26154\/udp ALLOW Anywhere # manual/);
});

test('operator port ranges stay one canonical UFW range', t => {
    const fx = setup(t);
    writeManifest(fx.manifest);
    const result = run(fx, '26004:26005');
    assert.equal(result.status, 0, result.stderr);
    const manifest = JSON.parse(fs.readFileSync(fx.manifest, 'utf8'));
    assert.deepEqual(manifest.operatorMediaUdpPorts, ['26004:26005/udp']);
    assert.deepEqual(fs.readFileSync(fx.allowed, 'utf8').trim().split('\n').filter(Boolean),
        ['26004:26005/udp']);
});
