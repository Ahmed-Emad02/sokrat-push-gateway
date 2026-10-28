'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SCRIPTS = path.join(ROOT, 'scripts');
const HOOK_ADAPTER = path.join(SCRIPTS, 'provisioning-hook-ssh.py');
const FIREWALL_ADAPTER = path.join(SCRIPTS, 'provisioning-firewall-aws.py');
const INSTALLER = path.join(SCRIPTS, 'install-tenant-push-hook.py');
const HOOK_RUNNER = path.join(SCRIPTS, 'pbx-tenant-push-hook.py');
const PYTHON = process.env.PYTHON || 'python3';
const TOKEN = 't'.repeat(64);
const GATEWAY = 'https://gateway.example.com';
const HOST = '192.0.2.10';
const SG = 'sg-0123456789abcdef0';

function tempDir(prefix = 'sokrat-provisioning-') {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(file, content, mode = 0o600) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    fs.chmodSync(file, mode);
    return file;
}

function readJson(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function fakeSshScript() {
    return String.raw`#!/usr/bin/env python3
import json, os, sys
base = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(base, 'fake-ssh.argv.json'), 'w') as handle:
    json.dump(sys.argv[1:], handle)
with open(os.path.join(base, 'fake-ssh.stdin'), 'wb') as handle:
    handle.write(sys.stdin.buffer.read())
exit_file = os.path.join(base, 'fake-ssh.exit')
if os.path.exists(exit_file):
    sys.stderr.write('RAW-SECRET-SSH-OUTPUT\n')
    raise SystemExit(int(open(exit_file).read().strip() or '255'))
result_file = os.path.join(base, 'fake-ssh.result.json')
if os.path.exists(result_file):
    result = open(result_file).read()
else:
    result = '{"ok":true,"action":"installed"}'
sys.stdout.write(result.strip() + '\n')
`;
}

function fakeAwsScript() {
    return String.raw`#!/usr/bin/env python3
import json, os, sys
base = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
with open(os.path.join(base, 'fake-aws.log'), 'a') as handle:
    handle.write(json.dumps(args) + '\n')
state_file = os.path.join(base, 'fake-aws.state.json')
state = json.load(open(state_file)) if os.path.exists(state_file) else {'rules': []}
mode_file = os.path.join(base, 'fake-aws.mode')
mode = open(mode_file).read().strip() if os.path.exists(mode_file) else ''
if mode == 'error':
    sys.stderr.write('An error occurred (AccessDenied) when calling the DescribeSecurityGroups operation: raw detail\n')
    raise SystemExit(254)
if 'describe-security-groups' in args:
    group = args[args.index('--group-ids') + 1]
    if state.get('missing'):
        print(json.dumps({'SecurityGroups': []}))
        raise SystemExit(0)
    permissions = {}
    for rule in state.get('rules', []):
        key = (rule['protocol'], rule['port'])
        permissions.setdefault(key, {
            'IpProtocol': rule['protocol'],
            'FromPort': rule['port'],
            'ToPort': rule['port'],
            'IpRanges': [],
        })
        permissions[key]['IpRanges'].append({'CidrIp': rule.get('cidr', '0.0.0.0/0')})
    print(json.dumps({'SecurityGroups': [{'GroupId': group, 'IpPermissions': list(permissions.values())}]}))
elif 'authorize-security-group-ingress' in args:
    permissions = json.loads(args[args.index('--ip-permissions') + 1])
    for permission in permissions:
        for entry in permission.get('IpRanges', []):
            state.setdefault('rules', []).append({
                'protocol': permission['IpProtocol'],
                'port': permission['FromPort'],
                'cidr': entry['CidrIp'],
            })
    with open(state_file, 'w') as handle:
        json.dump(state, handle)
    print(json.dumps({'Return': True}))
else:
    print('{}')
`;
}

function sandbox() {
    const dir = tempDir();
    const identity = write(path.join(dir, 'id_ed25519'), 'FAKE-PRIVATE-KEY\n', 0o600);
    const knownHosts = write(path.join(dir, 'known_hosts'),
        HOST + ' ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKey\n', 0o600);
    const fakeSsh = write(path.join(dir, 'fake-ssh.py'), fakeSshScript(), 0o755);
    const fakeAws = write(path.join(dir, 'fake-aws.py'), fakeAwsScript(), 0o755);
    const config = path.join(dir, 'adapters.json');
    const box = {
        dir,
        identity,
        knownHosts,
        fakeSsh,
        fakeAws,
        config,
        writeConfig(mutator) {
            const data = {
                pbx: {
                    pbx_test: {
                        ssh: {
                            sshHost: HOST,
                            sshUser: 'root',
                            identityFile: identity,
                            knownHostsFile: knownHosts,
                            calleeVar: 'CALLEE',
                            callerVar: 'CALLER',
                            nameVar: 'CALLER_NAME',
                            dialplanFile: '/etc/asterisk/extensions_custom.conf',
                            hookPath: '/usr/local/sbin/pbx-tenant-push-hook.py',
                            hookConfigPath: '/etc/sokrat/gateway-hook.json',
                            gatewayUrl: GATEWAY,
                            hookConfigMode: '0640',
                            hookConfigGroup: 'asterisk',
                            hookRunnerUser: 'asterisk',
                            reloadDialplan: true,
                            port: 22,
                            connectTimeout: 10,
                            timeoutSeconds: 30,
                        },
                        firewall: { region: 'us-east-1', securityGroupId: SG },
                    },
                },
            };
            if (mutator) mutator(data);
            write(config, JSON.stringify(data), 0o600);
            return data;
        },
    };
    box.writeConfig();
    return box;
}

function baseRequest(overrides = {}) {
    return {
        pbxId: 'pbx_test',
        gatewayUrl: GATEWAY,
        listenerPort: 3500,
        peerIps: [],
        enabled: true,
        token: TOKEN,
        ...overrides,
    };
}

function runHookArgv(box, argvPbxId, request, extraEnv = {}) {
    return spawnSync(PYTHON, [HOOK_ADAPTER, argvPbxId], {
        input: JSON.stringify(request),
        encoding: 'utf8',
        timeout: 20000,
        env: {
            ...process.env,
            SOKRAT_PROVISIONING_ADAPTERS_CONFIG: box.config,
            SOKRAT_PROVISIONING_BUNDLE: SCRIPTS,
            SOKRAT_PROVISIONING_SSH: box.fakeSsh,
            ...extraEnv,
        },
    });
}

function runHook(box, request, extraEnv = {}) {
    return runHookArgv(box, request.pbxId || 'pbx_test', request, extraEnv);
}

function runFirewall(box, request, extraEnv = {}) {
    return spawnSync(PYTHON, [FIREWALL_ADAPTER, request.pbxId || 'pbx_test'], {
        input: JSON.stringify(request),
        encoding: 'utf8',
        timeout: 20000,
        env: {
            ...process.env,
            SOKRAT_PROVISIONING_ADAPTERS_CONFIG: box.config,
            SOKRAT_PROVISIONING_BUNDLE: SCRIPTS,
            SOKRAT_PROVISIONING_AWS: box.fakeAws,
            ...extraEnv,
        },
    });
}

function output(result) {
    return JSON.parse(result.stdout.trim());
}

function assertNoToken(result) {
    assert.ok(!result.stdout.includes(TOKEN), 'stdout must not contain the token');
    assert.ok(!result.stderr.includes(TOKEN), 'stderr must not contain the token');
}

function assertRefused(result, code) {
    assert.equal(result.status, 2, result.stdout + result.stderr);
    const data = output(result);
    assert.equal(data.ok, false);
    assert.equal(data.error.code, code);
}

function resetFakeSsh(box) {
    for (const name of ['fake-ssh.argv.json', 'fake-ssh.stdin', 'fake-ssh.exit', 'fake-ssh.result.json']) {
        fs.rmSync(path.join(box.dir, name), { force: true });
    }
}

function fakeSshResult(box, value) {
    write(path.join(box.dir, 'fake-ssh.result.json'), JSON.stringify(value), 0o600);
}

function fakeAwsState(box, value) {
    write(path.join(box.dir, 'fake-aws.state.json'), JSON.stringify(value), 0o600);
}

function fakeAwsLog(box) {
    const file = path.join(box.dir, 'fake-aws.log');
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}

function resetFakeAws(box, state = { rules: [] }) {
    fs.rmSync(path.join(box.dir, 'fake-aws.log'), { force: true });
    fs.rmSync(path.join(box.dir, 'fake-aws.mode'), { force: true });
    fakeAwsState(box, state);
}

test('hook adapter sends strict SSH options and keeps the token off argv', () => {
    const box = sandbox();
    resetFakeSsh(box);
    fakeSshResult(box, { ok: true, action: 'installed', hookBackup: false, configBackup: false });
    const result = runHook(box, baseRequest());
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(output(result).action, 'installed');
    assertNoToken(result);

    const argv = readJson(path.join(box.dir, 'fake-ssh.argv.json'));
    const joined = argv.join(' ');
    for (const expected of ['-F', '/dev/null', 'BatchMode=yes', 'StrictHostKeyChecking=yes',
        'ProxyCommand=none', 'ProxyJump=none', 'IdentitiesOnly=yes',
        'UserKnownHostsFile=' + box.knownHosts, '-l', 'root', HOST]) {
        assert.ok(joined.includes(expected), 'missing SSH option ' + expected);
    }
    assert.ok(argv[argv.length - 1].startsWith('/usr/bin/python3 -c '));
    assert.ok(!joined.includes(TOKEN), 'token must not appear in argv');
    assert.ok(!joined.includes(GATEWAY), 'gateway URL must not appear in argv');

    const stdinText = fs.readFileSync(path.join(box.dir, 'fake-ssh.stdin'), 'utf8');
    const payload = JSON.parse(stdinText);
    assert.equal(payload.pbxId, 'pbx_test');
    assert.equal(payload.gatewayUrl, GATEWAY);
    assert.equal(payload.hookConfigMode, 0o640);
    assert.equal(payload.hookConfigGroup, 'asterisk');
    assert.equal(payload.hookRunnerUser, 'asterisk');
    assert.equal(payload.reloadDialplan, true);
    assert.ok(!stdinText.includes(TOKEN), 'token is only inside the base64 hook config');
    const hookConfig = JSON.parse(Buffer.from(payload.hookConfigB64, 'base64').toString('utf8'));
    assert.deepEqual(hookConfig, { gatewayUrl: GATEWAY, pbxId: 'pbx_test', token: TOKEN });
});

test('hook adapter skips disabled PBXs without invoking SSH', () => {
    const box = sandbox();
    resetFakeSsh(box);
    const result = runHook(box, baseRequest({ enabled: false }));
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(output(result).action, 'skipped');
    assert.ok(!fs.existsSync(path.join(box.dir, 'fake-ssh.argv.json')));
});

test('hook adapter refuses a gateway URL that is not pinned by root config', () => {
    const box = sandbox();
    resetFakeSsh(box);
    const result = runHook(box, baseRequest({ gatewayUrl: 'https://evil.example.com' }));
    assertRefused(result, 'gateway_pin_mismatch');
    assertNoToken(result);
    assert.ok(!fs.existsSync(path.join(box.dir, 'fake-ssh.argv.json')));
});

test('hook adapter requires an explicit readable hook group', () => {
    const box = sandbox();
    box.writeConfig(data => { delete data.pbx.pbx_test.ssh.hookConfigGroup; });
    resetFakeSsh(box);
    const result = runHook(box, baseRequest());
    assertRefused(result, 'pbx_unconfigured');
    assert.match(output(result).error.message, /hookConfigGroup/);
});

test('hook adapter rejects malformed tokens before invoking SSH', () => {
    const box = sandbox();
    resetFakeSsh(box);
    const result = runHook(box, baseRequest({ token: 'short token' }));
    assertRefused(result, 'request_invalid');
    assert.ok(!result.stdout.includes('short token'));
    assert.ok(!fs.existsSync(path.join(box.dir, 'fake-ssh.argv.json')));
});

test('hook adapter refuses a worker pbxId that differs from argv', () => {
    const box = sandbox();
    resetFakeSsh(box);
    const result = runHookArgv(box, 'pbx_test', baseRequest({ pbxId: 'pbx_other' }));
    assertRefused(result, 'pbx_mismatch');
});

test('hook adapter refuses public root config permissions and symlink ancestors', () => {
    const box = sandbox();
    fs.chmodSync(box.config, 0o644);
    resetFakeSsh(box);
    assertRefused(runHook(box, baseRequest()), 'unsafe_permissions');

    box.writeConfig();
    const real = path.join(box.dir, 'real');
    fs.mkdirSync(real);
    box.writeConfig(data => {
        data.pbx.pbx_test.ssh.identityFile = path.join(real, 'id_ed25519');
    });
    fs.renameSync(box.identity, path.join(real, 'id_ed25519'));
    const link = path.join(box.dir, 'linked');
    fs.symlinkSync(real, link);
    box.writeConfig(data => {
        data.pbx.pbx_test.ssh.identityFile = path.join(link, 'id_ed25519');
    });
    assertRefused(runHook(box, baseRequest()), 'path_symlink');
});

test('hook adapter maps remote refusal and transport failure without raw output', () => {
    const box = sandbox();
    resetFakeSsh(box);
    fakeSshResult(box, { ok: false, error: { code: 'reload_required', detail: 'raw remote detail' } });
    const refused = runHook(box, baseRequest());
    assert.equal(refused.status, 1, refused.stdout + refused.stderr);
    assert.equal(output(refused).error.code, 'reload_required');
    assert.ok(!refused.stdout.includes('raw remote detail'));
    assertNoToken(refused);

    resetFakeSsh(box);
    write(path.join(box.dir, 'fake-ssh.exit'), '255', 0o600);
    const failed = runHook(box, baseRequest());
    assert.equal(failed.status, 1, failed.stdout + failed.stderr);
    assert.equal(output(failed).error.code, 'ssh_failed');
    assert.ok(!failed.stdout.includes('RAW-SECRET-SSH-OUTPUT'));
    assert.ok(!failed.stderr.includes('RAW-SECRET-SSH-OUTPUT'));
});

test('hook adapter accepts reloadDialplan false but forwards the pin honestly', () => {
    const box = sandbox();
    box.writeConfig(data => { data.pbx.pbx_test.ssh.reloadDialplan = false; });
    resetFakeSsh(box);
    fakeSshResult(box, { ok: true, action: 'unchanged' });
    const result = runHook(box, baseRequest());
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const payload = JSON.parse(fs.readFileSync(path.join(box.dir, 'fake-ssh.stdin'), 'utf8'));
    assert.equal(payload.reloadDialplan, false);
});

test('firewall adapter authorizes only exact TCP and UDP listener rules', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [] });
    const result = runFirewall(box, baseRequest());
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const data = output(result);
    assert.equal(data.action, 'authorized');
    assert.deepEqual(data.present.sort(), ['tcp', 'udp']);
    assert.deepEqual(data.authorized.sort(), ['tcp', 'udp']);
    assertNoToken(result);

    const log = fakeAwsLog(box);
    assert.equal(log.length, 3, 'describe, authorize, verify describe');
    assert.ok(log[0].includes('describe-security-groups'));
    assert.ok(log[1].includes('authorize-security-group-ingress'));
    assert.ok(log[2].includes('describe-security-groups'));
    const authorize = log[1];
    const permissions = JSON.parse(authorize[authorize.indexOf('--ip-permissions') + 1]);
    assert.equal(permissions.length, 2);
    for (const permission of permissions) {
        assert.ok(['tcp', 'udp'].includes(permission.IpProtocol));
        assert.equal(permission.FromPort, 3500);
        assert.equal(permission.ToPort, 3500);
        assert.deepEqual(permission.IpRanges.map(entry => entry.CidrIp), ['0.0.0.0/0']);
    }
    for (const argv of log) {
        const joined = argv.join(' ');
        assert.ok(!/delete|revoke/i.test(joined), 'adapter must never delete or revoke rules');
        assert.ok(!joined.includes('0-65535'), 'adapter must not open the whole port range');
        assert.ok(!joined.includes('50000'), 'adapter must not open the private relay range');
    }
});

test('firewall adapter authorizes only the absent protocol when one exact rule exists', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [{ protocol: 'tcp', port: 3500, cidr: '0.0.0.0/0' }] });
    const result = runFirewall(box, baseRequest());
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const data = output(result);
    assert.equal(data.action, 'authorized');
    assert.deepEqual(data.present.sort(), ['tcp', 'udp']);
    assert.deepEqual(data.authorized, ['udp']);
    const authorize = fakeAwsLog(box).find(argv => argv.includes('authorize-security-group-ingress'));
    const permissions = JSON.parse(authorize[authorize.indexOf('--ip-permissions') + 1]);
    assert.equal(permissions.length, 1);
    assert.equal(permissions[0].IpProtocol, 'udp');
});

test('firewall adapter is idempotent when both exact rules already exist', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [
        { protocol: 'tcp', port: 3500, cidr: '0.0.0.0/0' },
        { protocol: 'udp', port: 3500, cidr: '0.0.0.0/0' },
    ] });
    const result = runFirewall(box, baseRequest());
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(output(result).action, 'unchanged');
    assert.ok(!fakeAwsLog(box).some(argv => argv.includes('authorize-security-group-ingress')));
});

test('firewall adapter accepts allocation.listenerPort and refuses out-of-scope ports', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [] });
    const nested = baseRequest({ listenerPort: undefined, allocation: { listenerPort: 3501 } });
    const result = runFirewall(box, nested);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(output(result).listenerPort, 3501);

    for (const port of [3478, 3499, 3655, 0, 65535]) {
        const refused = runFirewall(box, baseRequest({ listenerPort: port }));
        assertRefused(refused, 'listener_port_out_of_scope');
    }
});

test('firewall adapter skips disabled PBXs and refuses scope overrides', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [] });
    const skipped = runFirewall(box, baseRequest({ enabled: false }));
    assert.equal(skipped.status, 0, skipped.stdout + skipped.stderr);
    assert.equal(output(skipped).action, 'skipped');
    assert.equal(fakeAwsLog(box).length, 0);

    assertRefused(runFirewall(box, baseRequest({ securityGroupId: 'sg-fffffffffffffffff' })),
        'request_scope_override');
    assertRefused(runFirewall(box, baseRequest({ region: 'eu-west-1' })), 'request_scope_override');
});

test('firewall adapter fails closed when AWS CLI is unavailable and resolves symlinked binaries', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [] });
    const missing = runFirewall(box, baseRequest(), {
        SOKRAT_PROVISIONING_AWS: path.join(box.dir, 'does-not-exist-aws'),
    });
    assert.equal(missing.status, 1, missing.stdout + missing.stderr);
    assert.equal(output(missing).error.code, 'cloud_unavailable');

    const link = path.join(box.dir, 'aws-link');
    fs.symlinkSync(box.fakeAws, link);
    const linked = runFirewall(box, baseRequest(), { SOKRAT_PROVISIONING_AWS: link });
    assert.equal(linked.status, 0, linked.stdout + linked.stderr);
    assert.equal(output(linked).action, 'authorized');
});

test('firewall adapter returns only the sanitized AWS error code', () => {
    const box = sandbox();
    resetFakeAws(box, { rules: [] });
    write(path.join(box.dir, 'fake-aws.mode'), 'error', 0o600);
    const result = runFirewall(box, baseRequest());
    assert.equal(result.status, 1, result.stdout + result.stderr);
    const data = output(result);
    assert.equal(data.error.code, 'aws_error');
    assert.equal(data.error.message, 'AccessDenied');
    assert.ok(!result.stdout.includes('raw detail'));
});

test('ancestor ownership test seam enforces root ownership and non-writable ancestors', () => {
    const script = String.raw`
import importlib.util, json, stat, types
def check(path):
    spec = importlib.util.spec_from_file_location('adapter', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    good = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    not_root = types.SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o755)
    writable = types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777)
    return [
        module.ancestor_allowed(good, euid=0),
        module.ancestor_allowed(not_root, euid=0),
        module.ancestor_allowed(writable, euid=0),
        module.ancestor_allowed(not_root, euid=1000),
    ]
print(json.dumps({'hook': check(${JSON.stringify(HOOK_ADAPTER)}), 'firewall': check(${JSON.stringify(FIREWALL_ADAPTER)})}))
`;
    const result = spawnSync(PYTHON, ['-c', script], { encoding: 'utf8', timeout: 20000 });
    assert.equal(result.status, 0, result.stderr);
    const data = JSON.parse(result.stdout.trim());
    assert.deepEqual(data.hook, [true, false, false, true]);
    assert.deepEqual(data.firewall, [true, false, false, true]);
});

const REMOTE_HARNESS = String.raw`
import grp
import importlib.util
import io
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import types

spec = json.load(open(sys.argv[1], 'r'))
adapter_spec = importlib.util.spec_from_file_location('sokrat_adapter', spec['adapter'])
adapter = importlib.util.module_from_spec(adapter_spec)
adapter_spec.loader.exec_module(adapter)
remote_code = adapter.REMOTE_CODE

for target, content in spec.get('files', {}).items():
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'wb') as handle:
        handle.write(content.encode('utf-8'))
    os.chmod(target, spec.get('modes', {}).get(target, 0o600))

ancestor_dirs = set()
for target in spec['targets'].values():
    current = '/'
    for part in [part for part in target.split('/') if part][:-1]:
        current = os.path.join(current, part)
        ancestor_dirs.add(current)

real_lstat = os.lstat

def fake_lstat(path, *args, **kwargs):
    if path in ancestor_dirs:
        return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
    return real_lstat(path, *args, **kwargs)

uid = os.getuid()
gid = os.getgid()
os.lstat = fake_lstat
os.geteuid = lambda: 0
os.chown = lambda *args, **kwargs: None
pwd.getpwnam = lambda name: types.SimpleNamespace(pw_uid=uid, pw_gid=gid)
grp.getgrnam = lambda name: types.SimpleNamespace(gr_gid=gid)
os.getgrouplist = lambda name, default: list(spec.get('runnerGroups', [gid]))
shutil.which = lambda name: '/fake/asterisk' if name == 'asterisk' else None

calls = []
scenario = spec.get('scenario', 'success')

def fake_run(argv, **kwargs):
    calls.append(argv)
    if argv and argv[0] == '/usr/bin/python3':
        if '--apply' not in argv:
            if scenario == 'dry_refuse':
                return subprocess.CompletedProcess(argv, 2, b'', b'raw dry-run error')
            if scenario in ('dry_unchanged', 'not_effective'):
                return subprocess.CompletedProcess(argv, 0, b'Tenant push hook: already installed\n', b'')
            return subprocess.CompletedProcess(
                argv, 0, b'Tenant push hook: inserted one System() action before line 9\n', b'')
        if scenario == 'apply_refuse':
            return subprocess.CompletedProcess(argv, 2, b'', b'raw apply error')
        if scenario == 'apply_timeout':
            raise subprocess.TimeoutExpired(argv, 120)
        if scenario in ('dry_unchanged', 'not_effective'):
            return subprocess.CompletedProcess(argv, 0, b'Tenant push hook: already installed\n', b'')
        return subprocess.CompletedProcess(argv, 0, b'Applied. Backup written\n', b'')
    if argv and argv[0] == '/fake/asterisk':
        if argv[-1] == 'dialplan reload':
            if scenario == 'reload_fail':
                return subprocess.CompletedProcess(argv, 1, b'', b'raw reload error')
            return subprocess.CompletedProcess(argv, 0, b'Dialplan reloaded.\n', b'')
        if scenario == 'not_effective':
            return subprocess.CompletedProcess(argv, 0, b'[sub-sokrat-push-send]\n', b'')
        return subprocess.CompletedProcess(
            argv, 0, b'[sub-sokrat-push-send] System(... pbx-tenant-push-hook.py ...)\n', b'')
    return subprocess.CompletedProcess(argv, 0, b'', b'')

subprocess.run = fake_run
payload = spec['payload']
sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode('utf-8')))
try:
    exec(compile(remote_code, '<remote>', 'exec'), {'__name__': '__main__'})
except SystemExit:
    pass
with open(spec['callsFile'], 'w') as handle:
    json.dump(calls, handle)
`;

test('remote body refuses to overwrite a hook config belonging to another PBX', () => {
    const oldConfig = '{"gatewayUrl":"https://old.example.com","pbxId":"pbx_other","token":"' + 'o'.repeat(64) + '"}\n';
    const oldHook = '#!/usr/bin/env python3\nprint("old")\n';
    const harnessDir = tempDir('sokrat-remote-conflict-');
    const targets = {
        dialplanFile: path.join(harnessDir, 'etc/asterisk/extensions_custom.conf'),
        hookPath: path.join(harnessDir, 'usr/local/sbin/pbx-tenant-push-hook.py'),
        hookConfigPath: path.join(harnessDir, 'etc/sokrat/gateway-hook.json'),
    };
    for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(targets.hookPath, oldHook);
    fs.chmodSync(targets.hookPath, 0o600);
    fs.writeFileSync(targets.hookConfigPath, oldConfig);
    fs.chmodSync(targets.hookConfigPath, 0o600);
    const payload = {
        pbxId: 'pbx_test', gatewayUrl: GATEWAY,
        dialplanFile: targets.dialplanFile, hookPath: targets.hookPath,
        hookConfigPath: targets.hookConfigPath,
        calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
        callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
        hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk', reloadDialplan: true,
        installerB64: fs.readFileSync(INSTALLER).toString('base64'),
        hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
        hookConfigB64: Buffer.from('{"gatewayUrl":"' + GATEWAY + '","pbxId":"pbx_test","token":"' + TOKEN + '"}\n').toString('base64'),
    };
    const callsFile = path.join(harnessDir, 'calls.json');
    const specFile = path.join(harnessDir, 'spec.json');
    const harness = path.join(harnessDir, 'harness.py');
    write(harness, REMOTE_HARNESS, 0o700);
    write(specFile, JSON.stringify({
        adapter: HOOK_ADAPTER, payload, targets, callsFile, scenario: 'success',
        files: {}, modes: {},
    }), 0o600);
    const result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
    const data = JSON.parse(result.stdout.trim().split('\n').pop());
    assert.equal(data.ok, false);
    assert.equal(data.error.code, 'hook_config_conflict');
    assert.equal(fs.readFileSync(targets.hookConfigPath, 'utf8'), oldConfig);
    assert.equal(fs.readFileSync(targets.hookPath, 'utf8'), oldHook);
    assert.deepEqual(readJson(callsFile), []);
});

test('remote body migrates only a retired hook owned by this gateway and verifies a custom hook name', () => {
    for (const sameGateway of [true, false]) {
        const dir = tempDir('sokrat-retired-hook-');
        const targets = {
            dialplanFile: path.join(dir, 'etc/asterisk/extensions_custom.conf'),
            hookPath: path.join(dir, 'usr/local/bin/sokrat-tenant-push-hook.py'),
            hookConfigPath: path.join(dir, 'etc/sokrat/gateway-hook.json'),
        };
        const oldConfig = JSON.stringify({ gatewayUrl: sameGateway ? GATEWAY : 'https://other.example.com',
            pbxId: 'pbx_retired', token: 'o'.repeat(64) });
        for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
        const payload = {
            pbxId: 'pbx_test', gatewayUrl: GATEWAY, ...targets,
            calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
            callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
            hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk', reloadDialplan: true,
            installerB64: fs.readFileSync(INSTALLER).toString('base64'),
            hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
            hookConfigB64: Buffer.from(JSON.stringify({ gatewayUrl: GATEWAY, pbxId: 'pbx_test', token: TOKEN })).toString('base64'),
            retiredPbxIds: ['pbx_retired'],
        };
        const callsFile = path.join(dir, 'calls.json');
        const specFile = path.join(dir, 'spec.json');
        const harness = path.join(dir, 'harness.py');
        write(harness, REMOTE_HARNESS.replace('System(... pbx-tenant-push-hook.py ...)', 'System(... sokrat-tenant-push-hook.py ...)'), 0o700);
        write(specFile, JSON.stringify({ adapter: HOOK_ADAPTER, payload, targets, callsFile,
            files: { [targets.hookConfigPath]: oldConfig }, modes: {} }), 0o600);
        const result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
        assert.equal(result.status, 0, result.stderr);
        const data = JSON.parse(result.stdout.trim().split('\n').pop());
        if (sameGateway) {
            assert.equal(data.ok, true, result.stdout);
            assert.equal(data.configBackup, true);
            assert.equal(readJson(targets.hookConfigPath).pbxId, 'pbx_test');
        } else {
            assert.equal(data.ok, false);
            assert.equal(data.error.code, 'hook_config_conflict');
            assert.equal(fs.readFileSync(targets.hookConfigPath, 'utf8'), oldConfig);
            assert.deepEqual(readJson(callsFile), []);
        }
    }
});

test('remote body restores hook and config after dry-run refusal, timeout, and reload-required', () => {
    for (const scenario of ['dry_refuse', 'apply_timeout', 'reload_required']) {
        const dir = tempDir('sokrat-remote-rollback-');
        const targets = {
            dialplanFile: path.join(dir, 'etc/asterisk/extensions_custom.conf'),
            hookPath: path.join(dir, 'usr/local/sbin/pbx-tenant-push-hook.py'),
            hookConfigPath: path.join(dir, 'etc/sokrat/gateway-hook.json'),
        };
        for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
        const oldHook = '#!/usr/bin/env python3\nprint("old")\n';
        const oldConfig = '{"gatewayUrl":"https://old.example.com","pbxId":"pbx_test","token":"' + 'o'.repeat(64) + '"}\n';
        fs.writeFileSync(targets.hookPath, oldHook);
        fs.chmodSync(targets.hookPath, 0o600);
        fs.writeFileSync(targets.hookConfigPath, oldConfig);
        fs.chmodSync(targets.hookConfigPath, 0o600);
        const payload = {
            pbxId: 'pbx_test', gatewayUrl: GATEWAY,
            dialplanFile: targets.dialplanFile, hookPath: targets.hookPath,
            hookConfigPath: targets.hookConfigPath,
            calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
            callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
            hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk',
            reloadDialplan: scenario !== 'reload_required',
            installerB64: fs.readFileSync(INSTALLER).toString('base64'),
            hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
            hookConfigB64: Buffer.from('{"gatewayUrl":"' + GATEWAY + '","pbxId":"pbx_test","token":"' + TOKEN + '"}\n').toString('base64'),
        };
        const callsFile = path.join(dir, 'calls.json');
        const specFile = path.join(dir, 'spec.json');
        const harness = path.join(dir, 'harness.py');
        write(harness, REMOTE_HARNESS, 0o700);
        write(specFile, JSON.stringify({
            adapter: HOOK_ADAPTER, payload, targets, callsFile,
            scenario: scenario === 'reload_required' ? 'success' : scenario,
            files: {}, modes: {},
        }), 0o600);
        const result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
        const data = JSON.parse(result.stdout.trim().split('\n').pop());
        assert.equal(data.ok, false, scenario);
        const expected = { dry_refuse: 'installer_refused', apply_timeout: 'installer_timeout', reload_required: 'reload_required' }[scenario];
        assert.equal(data.error.code, expected, scenario + ' ' + JSON.stringify(data));
        assert.equal(fs.readFileSync(targets.hookPath, 'utf8'), oldHook, scenario);
        assert.equal(fs.readFileSync(targets.hookConfigPath, 'utf8'), oldConfig, scenario);
        assert.equal(fs.statSync(targets.hookPath).mode & 0o777, 0o600, scenario);
        assert.equal(fs.statSync(targets.hookConfigPath).mode & 0o777, 0o600, scenario);
    }
});

test('remote body forces hook 0755 and reloads only changed dialplans', () => {
    const dir = tempDir('sokrat-remote-success-');
    const targets = {
        dialplanFile: path.join(dir, 'etc/asterisk/extensions_custom.conf'),
        hookPath: path.join(dir, 'usr/local/sbin/pbx-tenant-push-hook.py'),
        hookConfigPath: path.join(dir, 'etc/sokrat/gateway-hook.json'),
    };
    for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(targets.hookPath, '#!/usr/bin/env python3\nprint("old")\n');
    fs.chmodSync(targets.hookPath, 0o600);
    const payload = {
        pbxId: 'pbx_test', gatewayUrl: GATEWAY,
        dialplanFile: targets.dialplanFile, hookPath: targets.hookPath,
        hookConfigPath: targets.hookConfigPath,
        calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
        callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
        hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk', reloadDialplan: true,
        installerB64: fs.readFileSync(INSTALLER).toString('base64'),
        hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
        hookConfigB64: Buffer.from('{"gatewayUrl":"' + GATEWAY + '","pbxId":"pbx_test","token":"' + TOKEN + '"}\n').toString('base64'),
    };
    const callsFile = path.join(dir, 'calls.json');
    const specFile = path.join(dir, 'spec.json');
    const harness = path.join(dir, 'harness.py');
    write(harness, REMOTE_HARNESS, 0o700);
    write(specFile, JSON.stringify({
        adapter: HOOK_ADAPTER, payload, targets, callsFile, scenario: 'success',
        files: {}, modes: {},
    }), 0o600);
    const result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
    const data = JSON.parse(result.stdout.trim().split('\n').pop());
    assert.equal(data.ok, true);
    assert.equal(data.action, 'installed');
    assert.equal(data.reload, 'reloaded');
    assert.equal(fs.statSync(targets.hookPath).mode & 0o777, 0o755);
    assert.equal(fs.statSync(targets.hookConfigPath).mode & 0o777, 0o640);
    const calls = readJson(callsFile);
    assert.equal(calls.filter(argv => argv[0] === '/usr/bin/python3' && argv.includes('--apply')).length, 1);
    assert.ok(calls.some(argv => argv[0] === '/fake/asterisk' && argv.includes('dialplan reload')));
    assert.ok(calls.some(argv => argv[0] === '/fake/asterisk' && argv.includes('dialplan show sub-sokrat-push-send')));
    assert.ok(!calls.some(argv => argv.join(' ').includes('restart')), 'never restart Asterisk');
});

test('remote body verifies the running dialplan and blocks when it is not effective', () => {
    const dir = tempDir('sokrat-remote-effective-');
    const targets = {
        dialplanFile: path.join(dir, 'etc/asterisk/extensions_custom.conf'),
        hookPath: path.join(dir, 'usr/local/sbin/pbx-tenant-push-hook.py'),
        hookConfigPath: path.join(dir, 'etc/sokrat/gateway-hook.json'),
    };
    for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
    const payload = {
        pbxId: 'pbx_test', gatewayUrl: GATEWAY,
        dialplanFile: targets.dialplanFile, hookPath: targets.hookPath,
        hookConfigPath: targets.hookConfigPath,
        calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
        callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
        hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk', reloadDialplan: false,
        installerB64: fs.readFileSync(INSTALLER).toString('base64'),
        hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
        hookConfigB64: Buffer.from('{"gatewayUrl":"' + GATEWAY + '","pbxId":"pbx_test","token":"' + TOKEN + '"}\n').toString('base64'),
    };
    const callsFile = path.join(dir, 'calls.json');
    const specFile = path.join(dir, 'spec.json');
    const harness = path.join(dir, 'harness.py');
    write(harness, REMOTE_HARNESS, 0o700);
    write(specFile, JSON.stringify({
        adapter: HOOK_ADAPTER, payload, targets, callsFile,
        scenario: 'dry_unchanged', files: {}, modes: {},
    }), 0o600);
    let result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
    let data = JSON.parse(result.stdout.trim().split('\n').pop());
    assert.equal(data.ok, true);
    assert.equal(data.action, 'unchanged');
    assert.equal(data.reload, 'unchanged');

    write(specFile, JSON.stringify({
        adapter: HOOK_ADAPTER, payload, targets, callsFile,
        scenario: 'not_effective', files: {}, modes: {},
    }), 0o600);
    result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
    data = JSON.parse(result.stdout.trim().split('\n').pop());
    assert.equal(data.ok, false);
    assert.equal(data.error.code, 'dialplan_not_effective');
});

test('remote body refuses a runner that cannot read the hook config', () => {
    const dir = tempDir('sokrat-remote-runner-');
    const targets = {
        dialplanFile: path.join(dir, 'etc/asterisk/extensions_custom.conf'),
        hookPath: path.join(dir, 'usr/local/sbin/pbx-tenant-push-hook.py'),
        hookConfigPath: path.join(dir, 'etc/sokrat/gateway-hook.json'),
    };
    for (const target of Object.values(targets)) fs.mkdirSync(path.dirname(target), { recursive: true });
    const payload = {
        pbxId: 'pbx_test', gatewayUrl: GATEWAY,
        dialplanFile: targets.dialplanFile, hookPath: targets.hookPath,
        hookConfigPath: targets.hookConfigPath,
        calleeVar: 'CALLEE', callerVar: 'CALLER', nameVar: 'CALLER_NAME',
        callIdVar: 'SOKRAT_CALL_ID', hookConfigMode: 0o640,
        hookConfigGroup: 'asterisk', hookRunnerUser: 'asterisk', reloadDialplan: true,
        installerB64: fs.readFileSync(INSTALLER).toString('base64'),
        hookB64: fs.readFileSync(HOOK_RUNNER).toString('base64'),
        hookConfigB64: Buffer.from('{"gatewayUrl":"' + GATEWAY + '","pbxId":"pbx_test","token":"' + TOKEN + '"}\n').toString('base64'),
    };
    const callsFile = path.join(dir, 'calls.json');
    const specFile = path.join(dir, 'spec.json');
    const harness = path.join(dir, 'harness.py');
    write(harness, REMOTE_HARNESS, 0o700);
    write(specFile, JSON.stringify({
        adapter: HOOK_ADAPTER, payload, targets, callsFile, scenario: 'success',
        files: {}, modes: {}, runnerGroups: [],
    }), 0o600);
    const result = spawnSync(PYTHON, [harness, specFile], { encoding: 'utf8', timeout: 20000 });
    const data = JSON.parse(result.stdout.trim().split('\n').pop());
    assert.equal(data.ok, false);
    assert.equal(data.error.code, 'hook_group_unreadable');
    assert.deepEqual(readJson(callsFile), []);
});
