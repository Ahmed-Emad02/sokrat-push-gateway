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
    fs.writeFileSync(path.join(root, '.env'), 'SOKRAT_UID=1234\nSOKRAT_GID=2345\nDB_ROOT_PASSWORD=fixture-db-root\nDB_PASS=fixture-db-pass\n', { mode: 0o600 });
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
    if (rendered.status !== 0) {
        assert.fail(`Docker Compose config failed: ${rendered.stderr || rendered.stdout}`);
    }
    const service = JSON.parse(rendered.stdout).services['sokrat-gateway'];
    service.volumes = fixture.service.volumes;
    fixture.service = service;
    fixture.container.Config.Env = [...fixture.image.Config.Env, ...Object.entries(service.environment).map(([key, value]) => key + '=' + value)];
    const result = upgrade(root, fixture);
    assert.equal(result.status, 0, result.stderr);
});

test('host bundle promotion refuses an incomplete or failed bundle', () => {
    const upgrade = path.resolve(__dirname, '../scripts/upgrade-container-gateway.py');
    const result = spawnSync('python3', ['-B', '-c', `
import importlib.util, subprocess, sys, tempfile
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('upgrade', ${JSON.stringify(upgrade)})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as root:
    bundle = Path(root) / 'bundle'; bundle.mkdir()
    (bundle / 'tunnel-enrollment.py').write_text('fixture')
    with patch.object(m, 'BUNDLE', Path(root) / 'missing'):
        try:
            m.promote_host_bundle({})
        except m.Refusal:
            pass
        else:
            raise AssertionError('incomplete bundle promoted')
    with patch.object(m, 'BUNDLE', bundle), \\
         patch.object(m.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'installer')):
        try:
            m.promote_host_bundle({})
        except m.Refusal:
            pass
        else:
            raise AssertionError('failed promotion hidden')
print('ok')
`], { encoding: 'utf8', timeout: 15000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'ok');
});

test('host enrollment without a promotable bundle refuses before build', t => {
    if (fs.existsSync('/usr/local/lib/sokrat-tenant-provisioning/tunnel-enrollment.py')) {
        t.skip('host bundle present on this test machine');
        return;
    }
    const { root, fixture } = setup(t);
    fs.mkdirSync(path.join(root, 'etc-sokrat', 'tunnel-enrollment'));
    fs.writeFileSync(path.join(root, 'etc-sokrat', 'tunnel-enrollment', 'config.json'), '{}');
    const result = upgrade(root, fixture, true);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /host provisioning bundle is incomplete/);
    assert.ok(result.log.every(row => !row.args.includes('build') && !row.args.includes('up')));
});

// --- Enrolled media convergence after host-bundle promotion ------------------
// These drive the real promoted installer and renderer against a filesystem
// fixture; only systemd (recorded by a fake on PATH) and root ownership (the
// test process runs unprivileged) are simulated.

const mediaSystemctl = `#!/usr/bin/env node
const fs = require('node:fs');
const control = JSON.parse(fs.readFileSync(process.env.MEDIA_CONTROL, 'utf8'));
const args = process.argv.slice(2);
const unit = args[args.length - 1];
fs.appendFileSync(control.log, args.join(' ') + '\\n');
const save = () => fs.writeFileSync(process.env.MEDIA_CONTROL, JSON.stringify(control));
if (args[0] === 'daemon-reload' && control.unitPath) {
  const definition = fs.readFileSync(control.unitPath, 'utf8');
  if (definition === control.refuseUnit) process.exit(1);
  control.loadedUnit = definition;
  save();
}
if (args[0] === 'is-active') process.exit(control.active.includes(unit) ? 0 : 3);
if (args[0] === 'restart') {
  if (control.conflict && control.conflict.unit === unit) {
    fs.writeFileSync(control.conflict.path, control.conflict.content);
    fs.chmodSync(control.conflict.path, control.conflict.mode);
  }
  let fail = control.failRestart.includes(unit);
  if (control.failOnce.includes(unit)) {
    control.failOnce = control.failOnce.filter(item => item !== unit);
    fail = true;
    save();
  }
  if (fail) {
    control.runningUnit = null;
    save();
    process.exit(1);
  }
  control.succeeded.push(unit);
  control.runningUnit = control.loadedUnit || null;
  save();
}
if (args[0] === 'restart' && control.lockPath) {
  const probe = require('node:child_process').spawnSync('python3', [control.lockProbe, control.lockPath], { encoding: 'utf8' });
  control.lockSeen.push(probe.stdout.trim());
  save();
}
process.exit(0);
`;

const mediaDriver = `
import contextlib, hashlib, importlib.util, io, json, os, stat, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

root = Path(sys.argv[1]); case = sys.argv[2]; repo = Path(sys.argv[3])
bundle = root / 'bundle'; bin_dir = root / 'bin'
control_path = root / 'control.json'
control = json.loads(control_path.read_text())
log = Path(control['log'])

sys.path.insert(0, str(bundle))
import tunnel_media
import tunnel_media_material

spec = importlib.util.spec_from_file_location('upgrade_under_test', repo / 'upgrade-container-gateway.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
upgrade.BUNDLE = bundle
real_loader = upgrade.load_media_installer

def loader(media_root, unit_root):
    installer, material = real_loader(media_root, unit_root)
    installer.version = lambda: (2, 6)
    installer.openvpn_binary = lambda: '/usr/sbin/openvpn'
    installer.link_daemon = lambda: bundle / 'udp-media-link.py'
    installer.os.geteuid = lambda: 0
    return installer, material

upgrade.load_media_installer = loader
etc_root = root / 'etc'
media_root = etc_root / 'media'
unit_root = root / 'units'
enrollment = etc_root / 'tunnel-enrollment'

worker_config = etc_root / 'gateway-provisioning.json'
worker_config.write_text(json.dumps({'schemaVersion': 1, 'lockDir': str(root / 'provisioning-lock'),
    'statusFile': str(root / 'status.json'), 'controlFile': str(root / 'control-store.json'),
    'runtime': {'syncScript': str(root / 'sync.py'), 'envFile': str(root / '.env'),
                'gatewayUrl': 'https://gateway.example.test'}}, sort_keys=True) + '\\n')
os.chmod(worker_config, 0o600)

real_lstat = Path.lstat
def owned(self):
    info = real_lstat(self)
    if stat.S_ISDIR(info.st_mode):
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0,
                               st_size=info.st_size, st_nlink=info.st_nlink)
    return SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IMODE(info.st_mode), st_uid=0,
                           st_size=info.st_size, st_nlink=info.st_nlink)

real_fstat = os.fstat
def owned_fstat(fd):
    info = real_fstat(fd)
    try:
        target = os.readlink('/proc/self/fd/' + str(fd))
    except OSError:
        return info
    if not target.startswith(str(root)):
        return info
    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                           st_size=info.st_size, st_nlink=info.st_nlink)

state = {'installer': None}
def media_installer():
    if state['installer'] is None:
        state['installer'], _unused = loader(media_root, unit_root)
    return state['installer']

def unit_name(pbx_id):
    return 'sokrat-media-' + pbx_id + '.service'

def provision(pbx_id, slot, transport=None):
    plan = tunnel_media.allocation(pbx_id, slot, '10.253.0.0/22')
    material = tunnel_media_material.new_material(plan, transport)
    media_installer().install({'plan': plan, 'transport': transport,
        'material': tunnel_media_material.for_role(material, 'gateway')}, 'gateway', False)
    directory = enrollment / pbx_id
    directory.mkdir()
    (directory / 'material.json').write_text(json.dumps(material, sort_keys=True) + '\\n')
    os.chmod(directory / 'material.json', 0o600)
    os.chmod(directory, 0o700)
    return plan, material, {'pbxId': pbx_id, 'installationId': 'a' * 32, 'secretHash': 'h',
                            'plan': plan, 'ports': {}, 'mediaTransport': transport}

def save_registry(records):
    path = enrollment / 'installations.json'
    path.write_text(json.dumps({'%02d' % index + record['installationId']: record
                                for index, record in enumerate(records)}, sort_keys=True) + '\\n')
    os.chmod(path, 0o600)

def activate(*units, fail=(), fail_once=(), conflict=None):
    control['active'] = list(units)
    control['failRestart'] = list(fail)
    control['failOnce'] = list(fail_once)
    control['conflict'] = conflict
    control['succeeded'] = []
    control['lockSeen'] = []
    control_path.write_text(json.dumps(control))

def recovered():
    return json.loads(control_path.read_text())['succeeded']

def digest(pbx_id):
    directory = media_root / pbx_id
    unit = unit_root / unit_name(pbx_id)
    files = {entry.name: [hashlib.sha256(entry.read_bytes()).hexdigest(),
                          stat.S_IMODE(entry.stat().st_mode)] for entry in sorted(directory.iterdir())}
    files[unit.name] = [hashlib.sha256(unit.read_bytes()).hexdigest(),
                        stat.S_IMODE(unit.stat().st_mode)]
    return files

def media_conf(pbx_id):
    return (media_root / pbx_id / 'media.conf').read_text()

def write_stale(pbx_id):
    path = media_root / pbx_id / 'media.conf'
    path.write_text(path.read_text().replace('proto tcp-client', 'proto udp'))

def write_stale_generated(pbx_id):
    path = media_root / pbx_id / 'media.conf'
    path.write_text(path.read_text() + '# stale renderer\\n')

def calls():
    return log.read_text().splitlines() if log.exists() else []

def refresh():
    return refresh_details()[0]

def refresh_details():
    env = {'PATH': str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
           'MEDIA_CONTROL': str(control_path)}
    with contextlib.redirect_stdout(sys.stderr), contextlib.redirect_stderr(sys.stderr):
        try:
            return None, upgrade.refresh_enrolled_media(env, etc_root=etc_root, unit_root=unit_root)
        except upgrade.Refusal as error:
            return str(error), None

def stale_legacy():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    _other_plan, _other_material, other = provision('pbx_fedcba9876543210', 4)
    save_registry([record, other])
    activate(unit_name(record['pbxId']), unit_name(other['pbxId']))
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    stale = media_conf(record['pbxId'])
    other_before = digest(other['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'stale': stale, 'current': media_conf(record['pbxId']),
            'before': before, 'after': digest(record['pbxId']),
            'other_before': other_before, 'other_after': digest(other['pbxId']),
            'lock_seen': json.loads(control_path.read_text())['lockSeen'],
            'succeeded': recovered(), 'calls': calls()}

def plain_unchanged():
    _plan, _material, record = provision('pbx_0011223344556677', 5,
        {'mode': 'plain-udp', 'host': 'gateway.example.test', 'port': 26155})
    save_registry([record])
    activate(unit_name(record['pbxId']))
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def stopped():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    activate()
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def active_legacy():
    _plan, _material, legacy_row = provision('pbx_0123456789abcdef', 3)
    _udp_plan, _udp_material, udp_row = provision('pbx_fedcba9876543210', 4,
        {'mode': 'plain-udp', 'host': 'gateway.example.test', 'port': 26154})
    save_registry([legacy_row, udp_row])
    activate(unit_name(legacy_row['pbxId']), unit_name(udp_row['pbxId']))
    write_stale(legacy_row['pbxId'])
    write_stale_generated(udp_row['pbxId'])
    registry_path = enrollment / 'installations.json'
    registry_before = registry_path.read_bytes()
    legacy_before = digest(legacy_row['pbxId'])
    udp_before = digest(udp_row['pbxId'])
    refusal, reported = refresh_details()
    return {'refusal': refusal, 'reported': reported,
            'legacy_before': legacy_before, 'legacy_after': digest(legacy_row['pbxId']),
            'udp_before': udp_before, 'udp_after': digest(udp_row['pbxId']),
            'registry_unchanged': registry_before == registry_path.read_bytes(),
            'current': media_conf(legacy_row['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def retired_legacy():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    # A stopped link is the operator's choice (retired tenant), not a finding.
    activate()
    before = digest(record['pbxId'])
    refusal, reported = refresh_details()
    return {'refusal': refusal, 'reported': reported,
            'before': before, 'after': digest(record['pbxId']), 'calls': calls()}

def legacy_message():
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        upgrade.report_legacy_media(['pbx_0123456789abcdef'])
    empty = io.StringIO()
    with contextlib.redirect_stderr(empty):
        upgrade.report_legacy_media([])
    return {'message': buffer.getvalue(), 'empty': empty.getvalue()}

def unmanaged_active():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    activate(unit_name(record['pbxId']))
    write_stale(record['pbxId'])
    (unit_root / unit_name(record['pbxId'])).write_text('custom unit\\n')
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def drift(mutate):
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    _other_plan, _other_material, other = provision('pbx_fedcba9876543210', 4)
    save_registry([record, other])
    activate(unit_name(record['pbxId']), unit_name(other['pbxId']))
    write_stale(record['pbxId'])
    mutate(other)
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def drift_plan(other):
    path = media_root / other['pbxId'] / 'plan.json'
    path.write_text(json.dumps(tunnel_media.allocation(other['pbxId'], 6, '10.253.0.0/22'),
                               sort_keys=True) + '\\n')

def drift_transport(other):
    path = media_root / other['pbxId'] / 'transport.json'
    path.write_text(json.dumps({'mode': 'plain-udp', 'host': 'gateway.example.test',
                                'port': 26160}, sort_keys=True) + '\\n')

def drift_credentials(other):
    path = enrollment / other['pbxId'] / 'material.json'
    path.write_text(json.dumps(tunnel_media_material.new_material(other['plan']),
                               sort_keys=True) + '\\n')
    os.chmod(path, 0o600)

def drift_missing_material(other):
    (enrollment / other['pbxId'] / 'material.json').unlink()

def cross_identity():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    foreign_plan = tunnel_media.allocation('pbx_9988776655443322', 6, '10.253.0.0/22')
    save_registry([dict(record, plan=foreign_plan)])
    activate(unit_name(record['pbxId']))
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'foreign_exists': (media_root / foreign_plan['pbxId']).exists(),
            'succeeded': recovered(), 'calls': calls()}

def boundary_untrusted():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    _other_plan, _other_material, other = provision('pbx_fedcba9876543210', 4)
    save_registry([record, other])
    activate(unit_name(record['pbxId']), unit_name(other['pbxId']))
    write_stale(record['pbxId'])
    os.chmod(media_root / other['pbxId'] / 'media.conf', 0o666)
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def concurrent_edit():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    unit = unit_name(record['pbxId'])
    activate(unit, fail=[unit], conflict={'unit': unit,
             'path': str(media_root / record['pbxId'] / 'media.conf'),
             'content': 'concurrent operator edit\\n', 'mode': 0o600})
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'current': media_conf(record['pbxId']), 'succeeded': recovered(), 'calls': calls()}

def rollback_recover():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    unit = unit_name(record['pbxId'])
    activate(unit, fail_once=[unit])
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

def rollback_unit(recovery_reload_fails=False):
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    unit = unit_name(record['pbxId'])
    unit_path = unit_root / unit
    previous = unit_path.read_text().replace(
        'ExecStart=/usr/sbin/openvpn ', 'ExecStart=/usr/local/sbin/openvpn ')
    unit_path.write_text(previous)
    activate(unit, fail_once=[unit])
    control.update({'unitPath': str(unit_path), 'loadedUnit': previous,
                    'runningUnit': previous,
                    'refuseUnit': previous if recovery_reload_fails else None})
    control_path.write_text(json.dumps(control))
    before = digest(record['pbxId'])
    refusal = refresh()
    current = json.loads(control_path.read_text())
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'previous_unit': previous, 'running_unit': current.get('runningUnit'),
            'succeeded': recovered()}

def lock_contention():
    installer = media_installer()
    held = upgrade.provisioning_lock(installer, etc_root, timeout=0)
    try:
        try:
            upgrade.provisioning_lock(installer, etc_root, timeout=0)
            busy = None
        except upgrade.Refusal as error:
            busy = str(error)
    finally:
        held.close()
    released = upgrade.provisioning_lock(installer, etc_root, timeout=0)
    released.close()
    return {'busy_refused': busy is not None, 'released': True}

def rollback_persistent():
    _plan, _material, record = provision('pbx_0123456789abcdef', 3)
    save_registry([record])
    unit = unit_name(record['pbxId'])
    activate(unit, fail=[unit])
    write_stale(record['pbxId'])
    before = digest(record['pbxId'])
    refusal = refresh()
    return {'refusal': refusal, 'before': before, 'after': digest(record['pbxId']),
            'succeeded': recovered(), 'calls': calls()}

cases = {
    'stale-legacy': stale_legacy,
    'active-legacy': active_legacy,
    'retired-legacy': retired_legacy,
    'legacy-message': legacy_message,
    'plain-unchanged': plain_unchanged,
    'stopped': stopped,
    'unmanaged-active': unmanaged_active,
    'drift-plan': lambda: drift(drift_plan),
    'drift-transport': lambda: drift(drift_transport),
    'drift-credentials': lambda: drift(drift_credentials),
    'drift-missing-material': lambda: drift(drift_missing_material),
    'cross-identity': cross_identity,
    'boundary-untrusted': boundary_untrusted,
    'concurrent-edit': concurrent_edit,
    'lock-contention': lock_contention,
    'rollback-recover': rollback_recover,
    'rollback-persistent': rollback_persistent,
    'rollback-unit': rollback_unit,
    'rollback-unit-reload-failure': lambda: rollback_unit(True),
}

with patch.object(Path, 'lstat', owned), patch.object(os, 'fstat', owned_fstat):
    print(json.dumps(cases[case]()))
`;

const mediaScripts = path.resolve(__dirname, '../scripts');

function mediaSetup(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-media-refresh-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    fs.mkdirSync(path.join(root, 'bundle'));
    for (const name of ['install-media-link.py', 'tunnel_media.py', 'tunnel_media_material.py', 'udp-media-link.py']) {
        fs.copyFileSync(path.join(mediaScripts, name), path.join(root, 'bundle', name));
    }
    fs.mkdirSync(path.join(root, 'bin'));
    fs.writeFileSync(path.join(root, 'bin/systemctl'), mediaSystemctl, { mode: 0o755 });
    fs.writeFileSync(path.join(root, 'bin/lockprobe.py'), `import fcntl, os, sys
descriptor = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print('free')
except OSError:
    print('held')
`);
    fs.mkdirSync(path.join(root, 'etc/media'), { recursive: true });
    fs.mkdirSync(path.join(root, 'etc/tunnel-enrollment'));
    fs.mkdirSync(path.join(root, 'units'));
    fs.writeFileSync(path.join(root, 'control.json'), JSON.stringify({
        active: [], failRestart: [], failOnce: [], succeeded: [], conflict: null, lockSeen: [],
        lockPath: path.join(root, 'provisioning-lock/lock'),
        lockProbe: path.join(root, 'bin/lockprobe.py'),
        log: path.join(root, 'systemctl.log'),
    }));
    return root;
}

function mediaRefresh(root, name) {
    const result = spawnSync('python3', ['-B', '-c', mediaDriver, root, name, mediaScripts],
        { encoding: 'utf8', timeout: 60000 });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
}

function changedFiles(before, after) {
    return Object.keys(before).filter(name => JSON.stringify(before[name]) !== JSON.stringify(after[name])).sort();
}

function restarts(out) {
    return out.calls.filter(line => line.startsWith('restart '));
}

function unitActions(out, prefix) {
    return out.calls.filter(line => line === prefix || line.startsWith(prefix + ' '));
}

test('upgrade refresh converges a stale legacy media renderer to TCP with identical credentials', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'stale-legacy');
    assert.equal(out.refusal, null);
    assert.match(out.stale, /proto udp/);
    assert.match(out.current, /proto tcp-client/);
    assert.match(out.current, /remote 127\.0\.0\.1 22003/);
    // Only the generated renderer output changes; keys, unit and plan do not.
    assert.deepEqual(changedFiles(out.before, out.after), ['media.conf']);
    assert.deepEqual(restarts(out), ['restart sokrat-media-pbx_0123456789abcdef.service']);
    assert.deepEqual(unitActions(out, 'enable'), []);
    assert.deepEqual(unitActions(out, 'start'), []);
    // The already-correct tenant link is neither rewritten nor restarted.
    assert.deepEqual(out.other_before, out.other_after);
    // The shared provisioning lock is held while the link is changed.
    assert.deepEqual(out.lock_seen, ['held']);
});

test('upgrade reports active legacy TCP media rows without aborting UDP tenants', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'active-legacy');
    assert.equal(out.refusal, null);
    // The active registry row without an explicit transport is reported.
    assert.deepEqual(out.reported, ['pbx_0123456789abcdef']);
    // Legacy tenant keeps working on the promoted renderer (TCP unchanged).
    assert.match(out.current, /proto tcp-client/);
    assert.deepEqual(changedFiles(out.legacy_before, out.legacy_after), ['media.conf']);
    // The stale plain-UDP tenant still converges: the finding never aborts it.
    assert.deepEqual(changedFiles(out.udp_before, out.udp_after), ['media.conf']);
    assert.deepEqual(restarts(out).sort(), [
        'restart sokrat-media-pbx_0123456789abcdef.service',
        'restart sokrat-media-pbx_fedcba9876543210.service',
    ]);
    // Nothing is stopped, deleted or rewritten besides generated renderers.
    assert.deepEqual(unitActions(out, 'stop'), []);
    assert.deepEqual(unitActions(out, 'disable'), []);
    assert.equal(out.registry_unchanged, true);
});

test('upgrade ignores a retired legacy row and never starts it', t => {
    const out = mediaRefresh(mediaSetup(t), 'retired-legacy');
    assert.equal(out.refusal, null);
    assert.deepEqual(out.reported, []);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(restarts(out), []);
});

test('legacy media report names the tenant and the exact conversion action', t => {
    const out = mediaRefresh(mediaSetup(t), 'legacy-message');
    assert.match(out.message, /pbx_0123456789abcdef/);
    assert.match(out.message, /media-transport-transaction\.py/);
    assert.match(out.message, /gateway role/);
    assert.match(out.message, /PBX role/);
    assert.match(out.message, /verify/);
    assert.equal(out.empty, '');
});

test('upgrade media phase refuses a busy provisioning lock and releases its own', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'lock-contention');
    assert.equal(out.busy_refused, true);
    assert.equal(out.released, true);
});

test('upgrade refresh leaves an unchanged active plain-UDP link untouched and unrestarted', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'plain-unchanged');
    assert.equal(out.refusal, null);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(restarts(out), []);
    assert.deepEqual(unitActions(out, 'daemon-reload'), []);
    assert.deepEqual(unitActions(out, 'enable'), []);
    assert.deepEqual(unitActions(out, 'start'), []);
});

test('upgrade refresh never starts or rewrites a stopped media link', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'stopped');
    assert.equal(out.refusal, null);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(restarts(out), []);
    assert.deepEqual(unitActions(out, 'enable'), []);
    assert.deepEqual(unitActions(out, 'start'), []);
});

test('upgrade refresh refuses an active media unit it does not manage', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'unmanaged-active');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(restarts(out), []);
});

test('upgrade refresh refuses plan, transport or credential drift before changing any link', async t => {
    for (const name of ['drift-plan', 'drift-transport', 'drift-credentials', 'drift-missing-material']) {
        await t.test(name, t => {
            const root = mediaSetup(t);
            const out = mediaRefresh(root, name);
            assert.ok(out.refusal);
            // Preflight precedes every write, including for the healthy first link.
            assert.deepEqual(out.before, out.after);
            assert.deepEqual(restarts(out), []);
        });
    }
});

test('upgrade refresh refuses a registry plan that belongs to another PBX before writing', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'cross-identity');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.equal(out.foreign_exists, false);
    assert.deepEqual(restarts(out), []);
});

test('upgrade refresh proves every selected link safe before changing any of them', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'boundary-untrusted');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(restarts(out), []);
});

test('upgrade refresh never overwrites a concurrent edit during rollback', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'concurrent-edit');
    assert.ok(out.refusal);
    assert.equal(out.current, 'concurrent operator edit\n');
    assert.deepEqual(out.succeeded, []);
});

test('upgrade refresh restores the previous media service after a failed restart', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'rollback-recover');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(out.succeeded, ['sokrat-media-pbx_0123456789abcdef.service']);
});

test('upgrade refresh fails closed when the previous media service cannot recover', t => {
    const root = mediaSetup(t);
    const out = mediaRefresh(root, 'rollback-persistent');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.deepEqual(out.succeeded, []);
});

test('upgrade rollback recovers the previously loaded service definition', t => {
    const out = mediaRefresh(mediaSetup(t), 'rollback-unit');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.equal(out.running_unit, out.previous_unit);
});

test('upgrade rollback refuses a recovery restart when the restored unit cannot reload', t => {
    const out = mediaRefresh(mediaSetup(t), 'rollback-unit-reload-failure');
    assert.ok(out.refusal);
    assert.deepEqual(out.before, out.after);
    assert.equal(out.running_unit, null);
    assert.deepEqual(out.succeeded, []);
});
