'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { verifyPasswordHash } = require('../src/control/auth');

const installer = fs.readFileSync(path.resolve(__dirname, '../install.sh'), 'utf8');
test('installer hashes supplied passwords as data, not executable Python/shell source', async () => {
    const start = installer.indexOf('ADMIN_HASH=$(');
    const end = installer.indexOf('echo -e "${GREEN}[4/8]', start);
    assert.ok(start > 0 && end > start);
    const password = crypto.randomUUID() + '\"\'"""$dollar`echo unsafe`$(echo unsafe)\\';
    const result = spawnSync('bash', ['-c', 'set -eu\n' + installer.slice(start, end) + '\nprintf "%s" "$ADMIN_HASH"'], {
        env: { ...process.env, ADMIN_PASS: password }, encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await verifyPasswordHash(password, result.stdout), true);
    assert.equal(result.stdout.includes(password), false);
});
test('installer carries TLS options and activates host enrollment for pairing', () => {
    assert.equal(spawnSync('bash', ['-n', path.resolve(__dirname, '../install.sh')]).status, 0);
    assert.match(installer, /GATEWAY_TLS_ENABLED=\$\{TLS_ENABLED\}/);
    assert.match(installer, /GATEWAY_HTTPS_PORT=\$\{HTTPS_PORT\}/);
    assert.match(installer, /GATEWAY_WSS_PORT=\$\{WSS_PORT\}/);
    assert.match(installer, /python3 scripts\/install-tunnel-enrollment\.py --apply/);
    assert.match(installer, /bash scripts\/install-reverse-tls-deps\.sh/);
    assert.match(installer, /tunnel-enrollment\.py --init/);
    assert.match(installer, /install -m 0644 systemd\/frps\.service/);
    assert.match(installer, /systemctl enable sokrat-tunnel-enrollment\.service frps\.service/);
    assert.match(installer, /trustedStateDir.*\/runtime-state/);
    assert.match(installer, /lockDir.*\/locks/);
    assert.match(installer, /Employee public onboarding NOT READY/);
    assert.doesNotMatch(installer, /Generated random admin password:.*ADMIN_PASS/);
});
test('renewal hook is shipped and private build credentials stay out of Docker context', () => {
    const hook = path.resolve(__dirname, '../scripts/deploy-public-certificate.sh');
    assert.equal(spawnSync('bash', ['-n', hook]).status, 0);
    const text = fs.readFileSync(hook, 'utf8');
    assert.match(text, /RENEWED_LINEAGE/);
    assert.match(text, /nginx -t/);
    assert.match(text, /nginx -s reload/);
    assert.doesNotMatch(text, /control\.json|installationSecret|pairingSecret/);
    assert.match(installer, /install -m 0755 scripts\/deploy-public-certificate\.sh/);
    const ignore = fs.readFileSync(path.resolve(__dirname, '../.dockerignore'), 'utf8');
    for (const line of ['config/firebase-service-account.json', 'config/firebase-service-account.b64', '**/*.p8', '**/*.key', '**/*.pem']) {
        assert.ok(ignore.split('\n').includes(line), line);
    }
});
