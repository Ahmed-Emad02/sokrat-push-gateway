'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function fixture(t) {
    const root = fs.mkdtempSync('/tmp/opencode/public-cert-test-');
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const managed = path.join(root, 'managed');
    const tls = path.join(managed, 'tls');
    const lineage = path.join(root, 'renewed');
    const prior = path.join(root, 'prior');
    const bin = path.join(root, 'bin');
    for (const dir of [managed, tls, lineage, prior, bin]) fs.mkdirSync(dir, { mode: 0o700 });
    for (const [dir, serial] of [[lineage, '2'], [prior, '1']]) {
        const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-days', '2', '-subj', '/CN=fixture.invalid', '-set_serial', serial,
            '-keyout', path.join(dir, 'privkey.pem'), '-out', path.join(dir, 'fullchain.pem')], { encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
    }
    const log = path.join(root, 'docker.log');
    const script = path.join(root, 'deploy.sh');
    const source = fs.readFileSync(path.resolve(__dirname, '../scripts/deploy-public-certificate.sh'), 'utf8');
    assert.match(source, /destination=\/etc\/sokrat\/tls/);
    // Redirect fixed managed paths only in this test copy. The shipped hook
    // deliberately has no environment override for privileged destinations.
    fs.writeFileSync(script, source.replaceAll('/etc/sokrat', managed));
    const executable = (name, content) => fs.writeFileSync(path.join(bin, name), '#!/bin/bash\nset -eu\n' + content, { mode: 0o755 });
    executable('id', 'echo "${FIXTURE_UID:-0}"\n');
    executable('stat', 'if [ "$2" = "%u" ]; then echo 0; else exec /usr/bin/stat "$@"; fi\n');
    executable('docker', `printf '%s\\n' "$*" >> "$FIXTURE_DOCKER_LOG"
if [ "$1" = inspect ]; then
    [ "\${FIXTURE_FAIL:-}" != inspect ] || exit 1
    echo "\${FIXTURE_RUNNING:-true}"
elif [ "$3" = /bin/bash ]; then
    [ "\${FIXTURE_FAIL:-}" != check ] || exit 1
elif [ "$3" = nginx ]; then
    [ "\${FIXTURE_FAIL:-}" != reload ] || exit 1
else exit 1
fi
`);
    const run = (env = {}) => spawnSync('bash', [script], {
        env: { ...process.env, PATH: bin + ':' + process.env.PATH, RENEWED_LINEAGE: lineage,
            FIXTURE_DOCKER_LOG: log, FIXTURE_FAIL: '', FIXTURE_RUNNING: 'true', FIXTURE_UID: '0', ...env },
        encoding: 'utf8', timeout: 10000
    });
    const seed = () => {
        for (const name of ['fullchain.pem', 'privkey.pem']) fs.copyFileSync(path.join(prior, name), path.join(tls, name));
    };
    const matches = dir => {
        for (const name of ['fullchain.pem', 'privkey.pem']) {
            assert.deepEqual(fs.readFileSync(path.join(tls, name)), fs.readFileSync(path.join(dir, name)), name);
        }
    };
    const calls = () => fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [];
    return { root, managed, tls, lineage, prior, run, seed, matches, calls };
}

test('renewal installs a matching real certificate pair and tests nginx before graceful reload', t => {
    const f = fixture(t); f.seed();
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    f.matches(f.lineage);
    assert.equal(fs.statSync(path.join(f.tls, 'privkey.pem')).mode & 0o777, 0o600);
    assert.equal(fs.statSync(f.tls).mode & 0o777, 0o700);
    const calls = f.calls();
    assert.match(calls[1], /configure-gateway-tls.sh; nginx -t/);
    assert.match(calls[2], /nginx -s reload/);
    assert.equal(calls.length, 3);
    assert.deepEqual(fs.readdirSync(f.tls).sort(), ['.deploy.lock', 'fullchain.pem', 'privkey.pem']);
});

for (const failure of ['check', 'reload']) {
    test(`failed nginx ${failure} restores the prior pair and exits nonzero`, t => {
        const f = fixture(t); f.seed();
        const result = f.run({ FIXTURE_FAIL: failure });
        assert.notEqual(result.status, 0);
        f.matches(f.prior);
        assert.match(result.stderr, /previous certificate files restored/);
        assert.match(f.calls().at(-1), /configure-gateway-tls.sh; nginx -t/);
        assert.equal(f.calls().filter(call => call.includes('nginx -s reload')).length, failure === 'check' ? 0 : 1);
    });
}

test('failed first deployment removes the new pair rather than leaving partial TLS enabled', t => {
    const f = fixture(t);
    assert.notEqual(f.run({ FIXTURE_FAIL: 'check' }).status, 0);
    assert.equal(fs.existsSync(path.join(f.tls, 'fullchain.pem')), false);
    assert.equal(fs.existsSync(path.join(f.tls, 'privkey.pem')), false);
});

test('wrong private key is rejected before managed certificates or Docker are touched', t => {
    const f = fixture(t); f.seed();
    fs.copyFileSync(path.join(f.prior, 'privkey.pem'), path.join(f.lineage, 'privkey.pem'));
    assert.notEqual(f.run().status, 0);
    f.matches(f.prior);
    assert.deepEqual(f.calls(), []);
});

test('certificate with less than one day remaining is rejected before deployment', t => {
    const f = fixture(t); f.seed();
    const result = spawnSync('openssl', ['req', '-x509', '-key', path.join(f.lineage, 'privkey.pem'),
        '-days', '1', '-subj', '/CN=fixture.invalid', '-out', path.join(f.lineage, 'fullchain.pem')]);
    assert.equal(result.status, 0);
    assert.notEqual(f.run().status, 0);
    f.matches(f.prior);
    assert.deepEqual(f.calls(), []);
});

test('Docker inspection errors never report successful renewal or replace the prior pair', t => {
    const f = fixture(t); f.seed();
    assert.notEqual(f.run({ FIXTURE_FAIL: 'inspect' }).status, 0);
    f.matches(f.prior);
    assert.equal(f.calls().length, 1);
});

test('stopped container stages the pair and explicitly reports pending live reload', t => {
    const f = fixture(t);
    const result = f.run({ FIXTURE_RUNNING: 'false' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /live reload remains pending/);
    f.matches(f.lineage);
    assert.equal(f.calls().length, 1);
});

for (const target of ['tls', 'fullchain.pem', '.deploy.lock']) {
    test(`unsafe symlink at ${target} is rejected without modifying its target`, t => {
        const f = fixture(t);
        const outside = path.join(f.root, 'outside');
        fs.writeFileSync(outside, 'untouched');
        if (target === 'tls') fs.rmdirSync(f.tls);
        fs.symlinkSync(outside, target === 'tls' ? f.tls : path.join(f.tls, target));
        assert.notEqual(f.run().status, 0);
        assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
    });
}

test('non-root execution, missing lineage and writable managed parent all refuse', t => {
    const f = fixture(t); f.seed();
    assert.notEqual(f.run({ FIXTURE_UID: '1000' }).status, 0);
    assert.notEqual(f.run({ RENEWED_LINEAGE: '' }).status, 0);
    fs.chmodSync(f.managed, 0o777);
    assert.notEqual(f.run().status, 0);
    f.matches(f.prior);
    assert.deepEqual(f.calls(), []);
});
