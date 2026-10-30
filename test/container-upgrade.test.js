'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const source = path.resolve(__dirname, '../scripts/upgrade-container-gateway.py');
const fakeDocker = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const root = process.env.HOME;
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'fixture.json')));
const args = process.argv.slice(2);
fs.appendFileSync(path.join(root, 'docker.log'), JSON.stringify({args, injectedPort: process.env.GATEWAY_HTTP_PORT}) + '\\n');
if (args[0] === 'context') console.log(JSON.stringify([{Endpoints:{docker:{Host:fixture.context}}}]));
else if (args[0] === 'inspect') {
  const count = fs.readFileSync(path.join(root, 'docker.log'), 'utf8').split('\\n').filter(line => line && JSON.parse(line).args[0] === 'inspect').length;
  if (fixture.replaceDuringBuild && count > 1) fixture.container.Id = 'c'.repeat(64);
  console.log(JSON.stringify([fixture.container]));
}
else if (args[0] === 'image') console.log(JSON.stringify([fixture.image]));
else if (args[0] === 'exec') console.log(args.includes('-u') ? '1234' : '2345');
else if (args[0] === 'compose' && args.includes('config')) {
  const count = fs.readFileSync(path.join(root, 'docker.log'), 'utf8').split('\\n').filter(line => line && JSON.parse(line).args.includes('config')).length;
  if (fixture.configChangesDuringBuild && count > 1) fixture.service.environment.GATEWAY_HTTP_PORT = '9999';
  console.log(JSON.stringify({services:{'sokrat-gateway':fixture.service}}));
}
else if (args[0] === 'compose' && args.includes('build')) { if (fixture.buildFails) process.exit(1); }
else if (args[0] === 'compose' && args.includes('up')) { if (fixture.upFails) process.exit(1); }
else process.exit(2);
`;

function setup(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-container-upgrade-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    fs.mkdirSync(path.join(root, 'scripts'));
    fs.mkdirSync(path.join(root, 'bin'));
    fs.copyFileSync(source, path.join(root, 'scripts/upgrade-container-gateway.py'));
    fs.writeFileSync(path.join(root, 'bin/docker'), fakeDocker, { mode: 0o755 });
    fs.writeFileSync(path.join(root, 'docker-compose.yml'), 'fixture\n');
    fs.writeFileSync(path.join(root, '.env'), 'SOKRAT_UID=1234\nSOKRAT_GID=2345\n', { mode: 0o600 });
    const dirs = ['etc-sokrat', 'state', 'provisioning', 'log'];
    for (const dir of dirs) fs.mkdirSync(path.join(root, dir), { mode: 0o750 });
    const secret = path.join(root, 'etc-sokrat', 'firebase-service-account.json');
    fs.writeFileSync(secret, 'fixture credential', { mode: 0o640 });
    const mounts = dirs.map((dir, i) => ({ type: 'bind', source: path.join(root, dir), target: ['/etc/sokrat', '/var/lib/sokrat-gateway', '/var/lib/sokrat-tenant-provisioning', '/var/log/sokrat'][i], bind: { create_host_path: true } }));
    const env = ['PATH=/usr/bin:/bin', 'NODE_ENV=production', 'GATEWAY_HTTP_PORT=8080'];
    const base = { Env: ['PATH=/usr/bin:/bin'], User: '', Entrypoint: ['/entrypoint.sh'], Cmd: ['supervisord'], WorkingDir: '/opt/sokrat-push-gateway' };
    const fixture = {
        context: 'unix:///var/run/docker.sock',
        image: { Config: base },
        container: { Id: 'b'.repeat(64), Image: 'sha256:' + 'a'.repeat(64), State: { Running: true },
            Config: { ...base, Env: env, Labels: { 'com.docker.compose.project': 'gateway', 'com.docker.compose.service': 'sokrat-gateway', 'com.docker.compose.project.working_dir': root, 'com.docker.compose.project.config_files': path.join(root, 'docker-compose.yml') } },
            HostConfig: { NetworkMode: 'host', RestartPolicy: { Name: 'unless-stopped' }, LogConfig: { Type: 'json-file', Config: { 'max-size': '50m', 'max-file': '5' } } },
            Mounts: mounts.map(m => ({ Type: 'bind', Source: m.source, Destination: m.target, RW: true, Propagation: 'rprivate' })) },
        service: { container_name: 'sokrat-gateway', command: null, entrypoint: null, image: 'sokrat/push-gateway:latest', network_mode: 'host', restart: 'unless-stopped', build: { args: { SOKRAT_UID: '1234', SOKRAT_GID: '2345' } }, environment: { NODE_ENV: 'production', GATEWAY_HTTP_PORT: '8080' }, volumes: mounts, logging: { driver: 'json-file', options: { 'max-size': '50m', 'max-file': '5' } } },
    };
    return { root, fixture, secret };
}

function upgrade(root, fixture, apply = false) {
    fs.writeFileSync(path.join(root, 'fixture.json'), JSON.stringify(fixture));
    const result = spawnSync('python3', [path.join(root, 'scripts/upgrade-container-gateway.py'), ...(apply ? ['--apply'] : [])], {
        encoding: 'utf8', env: { PATH: path.join(root, 'bin') + path.delimiter + process.env.PATH, HOME: root, GATEWAY_HTTP_PORT: '9999', COMPOSE_FILE: 'unexpected.yml' },
    });
    const log = fs.readFileSync(path.join(root, 'docker.log'), 'utf8').trim().split('\n').map(JSON.parse);
    return { ...result, log };
}

test('container upgrade dry-run is read-only and ignores caller Compose overrides', t => {
    const { root, fixture, secret } = setup(t);
    const before = fs.statSync(secret);
    const result = upgrade(root, fixture);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Dry run only/);
    assert.ok(result.log.every(row => !row.args.includes('build') && !row.args.includes('up') && row.injectedPort === undefined));
    assert.equal(fs.readFileSync(secret, 'utf8'), 'fixture credential');
    assert.equal(fs.statSync(secret).mode, before.mode);
    assert.equal(fs.statSync(secret).uid, before.uid);
    assert.equal(fs.statSync(secret).gid, before.gid);
});

test('apply builds then recreates only gateway without dependencies or host file changes', t => {
    const { root, fixture, secret } = setup(t);
    const before = fs.statSync(secret);
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 0, result.stderr);
    const actions = result.log.filter(row => row.args.includes('build') || row.args.includes('up'));
    assert.equal(actions.length, 2);
    assert.deepEqual(actions[0].args.slice(-2), ['build', 'sokrat-gateway']);
    assert.deepEqual(actions[1].args.slice(-5), ['up', '-d', '--no-deps', '--no-build', 'sokrat-gateway']);
    assert.equal(fs.readFileSync(secret, 'utf8'), 'fixture credential');
    assert.equal(fs.statSync(secret).mode, before.mode);
    assert.equal(fs.statSync(secret).uid, before.uid);
    assert.equal(fs.statSync(secret).gid, before.gid);
    assert.match(fs.readFileSync(path.join(root, '.env'), 'utf8'), /SOKRAT_UID=1234/);
});

test('unsafe or mismatched deployments refuse before build or recreation without disclosing values', async t => {
    const cases = {
        environment: f => { f.container.Config.Env.push('SECRET=do-not-print'); },
        mount: f => { f.container.Mounts.pop(); },
        privileged: f => { f.container.HostConfig.Privileged = true; },
        network: f => { f.container.HostConfig.NetworkMode = 'bridge'; },
        account: f => { f.service.build.args.SOKRAT_UID = '9999'; },
        remote: f => { f.context = 'tcp://remote.invalid:2375'; },
        stopped: f => { f.container.State.Running = false; },
        compose: f => { f.container.Config.Labels['com.docker.compose.project.config_files'] += ',override.yml'; },
    };
    for (const [name, mutate] of Object.entries(cases)) await t.test(name, t => {
        const { root, fixture } = setup(t);
        mutate(fixture);
        const result = upgrade(root, fixture, true);
        assert.equal(result.status, 2);
        assert.ok(result.log.every(row => !row.args.includes('build') && !row.args.includes('up')));
        assert.doesNotMatch(result.stderr, /do-not-print/);
    });
});

test('failed image build never recreates the running gateway', t => {
    const { root, fixture } = setup(t);
    fixture.buildFails = true;
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 2);
    assert.ok(result.log.some(row => row.args.includes('build')));
    assert.ok(result.log.every(row => !row.args.includes('up')));
});

test('older deployments accept only newly introduced TLS defaults', t => {
    const { root, fixture } = setup(t);
    Object.assign(fixture.service.environment, { GATEWAY_TLS_ENABLED: 'auto', GATEWAY_HTTPS_PORT: '443', GATEWAY_WSS_PORT: '8089' });
    const result = upgrade(root, fixture);
    assert.equal(result.status, 0, result.stderr);
});

test('new non-default TLS settings still require reviewed configuration changes', t => {
    const { root, fixture } = setup(t);
    fixture.service.environment.GATEWAY_HTTPS_PORT = '9443';
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 2);
    assert.ok(result.log.every(row => !row.args.includes('build') && !row.args.includes('up')));
});

test('recreation re-runs authority-aware tenant reconciliation', t => {
    const { root, fixture } = setup(t);
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 0, result.stderr);
    const up = result.log.findIndex(row => row.args.includes('up'));
    const reconcile = result.log.findIndex(row => row.args.some(arg => arg.includes('reconcile-tenant-provisioning.py')));
    assert.ok(reconcile > up);
});

test('container replaced during build is not recreated', t => {
    const { root, fixture } = setup(t);
    fixture.replaceDuringBuild = true;
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 2);
    assert.ok(result.log.some(row => row.args.includes('build')));
    assert.ok(result.log.every(row => !row.args.includes('up')));
});

test('Compose configuration changed during build is not applied', t => {
    const { root, fixture } = setup(t);
    fixture.configChangesDuringBuild = true;
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 2);
    assert.ok(result.log.some(row => row.args.includes('build')));
    assert.ok(result.log.every(row => !row.args.includes('up')));
});

test('accepts the actual Compose JSON shape for the shipped configuration', t => {
    const { root, fixture } = setup(t);
    fs.copyFileSync(path.resolve(__dirname, '../docker-compose.yml'), path.join(root, 'docker-compose.yml'));
    const rendered = spawnSync('docker', ['compose', '-f', path.join(root, 'docker-compose.yml'), 'config', '--format', 'json'], {
        cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: root },
    });
    if (rendered.error && rendered.error.code === 'ENOENT') return t.skip('Docker Compose CLI unavailable');
    if (rendered.status !== 0) return t.skip('Docker Compose config unavailable');
    const service = JSON.parse(rendered.stdout).services['sokrat-gateway'];
    service.volumes = fixture.service.volumes;
    fixture.service = service;
    fixture.container.Config.Env = [...fixture.image.Config.Env, ...Object.entries(service.environment).map(([key, value]) => key + '=' + value)];
    const result = upgrade(root, fixture);
    assert.equal(result.status, 0, result.stderr);
});

test('first-install guard precedes writes and container startup does not recursively chown bind mounts', () => {
    const install = fs.readFileSync(path.resolve(__dirname, '../install.sh'), 'utf8');
    const entrypoint = fs.readFileSync(path.resolve(__dirname, '../docker/entrypoint.sh'), 'utf8');
    assert.ok(install.indexOf('Existing gateway configuration found') < install.indexOf('mkdir -p /etc/sokrat/ssh'));
    assert.doesNotMatch(install, /chown -R root:root \/etc\/sokrat/);
    assert.doesNotMatch(entrypoint, /chown -R .*\/(?:etc\/sokrat|var\/lib\/sokrat-gateway|var\/log\/sokrat)/);
});
