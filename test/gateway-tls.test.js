'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-tls-test-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const tls = path.join(root, 'tls');
    const conf = path.join(root, 'conf');
    fs.mkdirSync(tls); fs.mkdirSync(conf);
    const output = path.join(conf, 'sokrat-public-tls.conf');
    const run = (env = {}) => spawnSync('bash', [path.resolve(__dirname, '../docker/configure-gateway-tls.sh')], {
        env: { ...process.env, GATEWAY_TLS_ENABLED: 'auto', GATEWAY_TLS_DIR: tls,
            GATEWAY_HTTPS_PORT: '443', GATEWAY_WSS_PORT: '8089',
            GATEWAY_NGINX_CONF_DIR: conf,
            GATEWAY_TLS_TEMPLATE: path.resolve(__dirname, '../docker/nginx-wss.conf'), ...env }, encoding: 'utf8'
    });
    const certificates = () => {
        fs.writeFileSync(path.join(tls, 'fullchain.pem'), 'fixture-cert');
        fs.writeFileSync(path.join(tls, 'privkey.pem'), 'fixture-key');
    };
    return { tls, output, run, certificates };
}

test('fresh legacy install without certificates starts without TLS config', t => {
    const f = fixture(t);
    assert.equal(f.run().status, 0);
    assert.equal(fs.existsSync(f.output), false);
});
test('explicit or incomplete TLS refuses plaintext-only startup', t => {
    const f = fixture(t);
    assert.notEqual(f.run({ GATEWAY_TLS_ENABLED: 'true' }).status, 0);
    fs.writeFileSync(path.join(f.tls, 'fullchain.pem'), 'fixture-cert');
    assert.notEqual(f.run().status, 0);
    assert.equal(fs.existsSync(f.output), false);
});
test('TLS rendering retains nginx variables and limits public API exposure', t => {
    const f = fixture(t); f.certificates();
    assert.equal(f.run().status, 0);
    const rendered = fs.readFileSync(f.output, 'utf8');
    assert.match(rendered, /listen 443 ssl/);
    assert.match(rendered, /listen 8089 ssl/);
    assert.match(rendered, /ssl_certificate .*\/fullchain\.pem;/);
    assert.match(rendered, /location \/api\/gateway\//);
    assert.match(rendered, /location = \/ws/);
    assert.match(rendered, /\$sokrat_ws_upstream\$request_uri/);
    assert.match(rendered, /X-Forwarded-For \$remote_addr/);
    assert.doesNotMatch(rendered, /8002|9096|8095|\/control|\/api\/push/);
    assert.doesNotMatch(rendered, /\$\{GATEWAY_/);
    assert.equal(f.run().status, 0);
});
test('TLS config validates options and never overwrites an operator config', t => {
    const f = fixture(t); f.certificates();
    for (const env of [{ GATEWAY_HTTPS_PORT: '0' }, { GATEWAY_WSS_PORT: '65536' },
        { GATEWAY_WSS_PORT: '443' }, { GATEWAY_TLS_ENABLED: 'maybe' }]) {
        assert.notEqual(f.run(env).status, 0);
    }
    fs.writeFileSync(f.output, '# operator config');
    assert.notEqual(f.run().status, 0);
    assert.equal(fs.readFileSync(f.output, 'utf8'), '# operator config');
});
test('explicit TLS disable removes only the generated config', t => {
    const f = fixture(t); f.certificates();
    assert.equal(f.run().status, 0);
    assert.equal(fs.existsSync(f.output), true);
    assert.equal(f.run({ GATEWAY_TLS_ENABLED: 'false' }).status, 0);
    assert.equal(fs.existsSync(f.output), false);
    fs.writeFileSync(f.output, '# operator config');
    assert.notEqual(f.run({ GATEWAY_TLS_ENABLED: 'false' }).status, 0);
    assert.equal(fs.readFileSync(f.output, 'utf8'), '# operator config');
});
