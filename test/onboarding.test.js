'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const express = require('express');
const crypto = require('node:crypto');
const { requestOnboarding, resolvePbxAddress } = require('../src/control/onboarding');

test('one PBX address derives standard settings and pins hostnames to one Tailscale IPv4', async () => {
    const direct = await resolvePbxAddress('100.64.0.12');
    assert.deepEqual(direct, { host: '100.64.0.12', wsURL: 'ws://100.64.0.12:8088/ws', apiURL: 'http://100.64.0.12:8080', mediaIps: '100.64.0.12' });
    assert.deepEqual(await resolvePbxAddress('PBX.example.', async host => {
        assert.equal(host, 'pbx.example'); return [{ address: '100.64.0.12', family: 4 }];
    }), direct);
    for (const address of ['127.0.0.1', '169.254.169.254', '192.0.2.1', '100.63.0.1', '100.128.0.1', 'http://pbx.example', 'pbx.example:22', '-option', 'x;id', '::1']) {
        await assert.rejects(resolvePbxAddress(address, async () => []));
    }
    for (const answers of [[], [{ address: '192.0.2.1' }], [{ address: '100.64.0.12' }, { address: '100.64.0.13' }], [{ address: '100.64.0.12' }, { address: '::1' }]]) {
        await assert.rejects(resolvePbxAddress('pbx.example', async () => answers));
    }
});
const { createControlRouter } = require('../src/control/router');
const { ControlStore } = require('../src/control/store');

test('broker rejects non-Tailscale hosts, SSH options, unconfirmed keys and arbitrary payloads', () => {
    const file = path.resolve(__dirname, '../scripts/provisioning-onboarding.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util,types
spec=importlib.util.spec_from_file_location('broker',${JSON.stringify(file)})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
valid={'action':'probe','host':'100.64.0.12','username':'root'}
assert m.validate_request(valid)=='100.64.0.12'
for patch in [{'host':'127.0.0.1'},{'host':'192.0.2.1'},{'host':'example.com'},{'host':'100.64.0.12;id'}, {'username':'-oProxyCommand=id'},{'command':'id'},{'password':'should-not-be-probed'}]:
 try:m.validate_request({**valid,**patch})
 except ValueError:pass
 else:raise AssertionError(patch)
worker=types.SimpleNamespace(record_approval=lambda r:r.get('management',{}).get('approvalStatus','unmanaged'))
record={'wsURL':'ws://100.64.0.12:8088/ws','apiURL':'http://100.64.0.12:8080/','mediaIps':['100.64.0.12']}
assert m.record_identity(record,'100.64.0.12',worker)['approval']=='unmanaged'
for approval in ['pending','approved']:
 assert m.record_identity({**record,'management':{'approvalStatus':approval}},'100.64.0.12',worker)['approval']==approval
for patch in [{'mediaIps':['100.64.0.13']},{'apiURL':'http://127.0.0.1/'},{'wsURL':'ws://100.64.0.13:8088/ws'},{'management':{'approvalStatus':'suspended'}},{'management':{'approvalStatus':'retired'}},{'management':{'approvalStatus':''}}]:
 try:m.record_identity({**record,**patch},'100.64.0.12',worker)
 except ValueError:pass
 else:raise AssertionError(patch)
compile(m.BOOTSTRAP,'remote-bootstrap','exec')
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('bootstrap is additive and idempotent, and host key mismatch never sends password', () => {
    const file = path.resolve(__dirname, '../scripts/provisioning-onboarding.py');
    const result = spawnSync('python3', ['-c', `
import importlib.util, tempfile, pathlib, types, sys, io, json
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('broker',${JSON.stringify(file)})
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
 root=pathlib.Path(directory)
 dp=root/'extensions_sokrat.conf'; dp.write_text('[sub-sokrat-push-send]\\n; \\x24{TARGET_EXT}')
 ssh=root/'ssh';ssh.mkdir();auth=ssh/'authorized_keys';auth.write_text('existing-customer-key\\n')
 code=m.BOOTSTRAP.replace('/root/.ssh',str(ssh)).replace('/etc/asterisk/extensions_sokrat.conf',str(dp))
 payload=json.dumps({'key':'ssh-ed25519 AAAA sokrat-gateway-pbx_test','pbxId':'pbx_test'})
 for attempt in range(2):
  with patch('os.geteuid',return_value=0), patch('os.fstat',side_effect=lambda fd:types.SimpleNamespace(st_mode=0o100600,st_uid=0)), patch('sys.stdin',io.StringIO(payload)), patch('sys.stdout',io.StringIO()):exec(compile(code,'remote','exec'),{})
 assert auth.read_text()=='existing-customer-key\\nrestrict ssh-ed25519 AAAA sokrat-gateway-pbx_test\\n'
 before=auth.read_text();dp.write_text('unsupported PBX')
 with patch('os.geteuid',return_value=0),patch('sys.stdin',io.StringIO(payload)):
  try:exec(compile(code,'remote','exec'),{})
  except SystemExit as e:assert e.code==3
  else:raise AssertionError('unsupported PBX accepted')
 assert auth.read_text()==before
key=types.SimpleNamespace(asbytes=lambda:b'actual-key')
class FakeTransport:
 def __init__(self,*args):pass
 def start_client(self,**kwargs):pass
 def get_remote_server_key(self):return key
 def close(self):pass
with patch.dict(sys.modules,{'paramiko':types.SimpleNamespace(Transport=FakeTransport)}),patch.object(m.socket,'create_connection'):
 req={'action':'enroll','host':'100.64.0.12','username':'root','pbxId':'pbx_test','fingerprint':'SHA256:'+'a'*43,'password':'never-sent'}
 try:m.handle(req,None)
 except ValueError as e:assert str(e)=='host key changed'
 else:raise AssertionError('changed host accepted')
`], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
});

test('local client transports password only on socket and never echoes broker errors', async t => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-onboard-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const socketPath = path.join(dir, 'broker.sock');
    let received;
    const server = net.createServer({ allowHalfOpen: true }, connection => {
        let body = '';
        connection.on('data', part => body += part);
        connection.on('end', () => {
            received = JSON.parse(body);
            connection.end(JSON.stringify({ ok: false, password: 'NEVER-ECHO' }));
        });
    });
    await new Promise(resolve => server.listen(socketPath, resolve));
    t.after(() => server.close());
    await assert.rejects(requestOnboarding({ action: 'enroll', password: 'one-time' }, { socketPath }), error => !error.message.includes('NEVER-ECHO'));
    assert.equal(received.password, 'one-time');
});

test('SSH API requires session and CSRF and returns no credentials', async t => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-onboard-api-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const session = { id: 'test-session', csrfToken: 'test-csrf' };
    let called = false;
    const app = express();
    app.use('/control', createControlRouter({ store,
        credential: { configured: true },
        sessions: { get: id => id === session.id ? session : null },
        onboardingRequest: async payload => { called = true; return { fingerprint: 'SHA256:' + 'a'.repeat(43) }; }
    }));
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => server.close());
    const origin = `http://127.0.0.1:${server.address().port}`;
    const url = origin + '/control/api/pbx-ssh/probe';
    let r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 401);
    r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: 'sokrat_control_sid=test-session', Origin: origin }, body: '{}' });
    assert.equal(r.status, 403);
    assert.equal(called, false);
    const resolved = await fetch(origin + '/control/api/pbx-ssh/resolve', { method: 'POST', headers: {
        'Content-Type': 'application/json', Cookie: 'sokrat_control_sid=test-session', Origin: origin, 'X-CSRF-Token': session.csrfToken
    }, body: JSON.stringify({ address: '100.64.0.12' }) });
    assert.equal(resolved.status, 200);
    assert.equal((await resolved.json()).host, '100.64.0.12');
    assert.equal(called, false, 'resolution never invokes the SSH broker');
    r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: 'sokrat_control_sid=test-session', Origin: origin, 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify({ host: '100.64.0.12', username: 'root' }) });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).fingerprint, 'SHA256:' + 'a'.repeat(43));
    assert.equal(called, true);
});

test('SSH enrollment approves pending PBXs only after success and rejects concurrent record changes', async t => {
    for (const scenario of ['success', 'auth failure', 'suspended', 'edited', 'deleted', 'queued edit']) {
        await t.test(scenario, async t => {
            const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-onboard-approval-'));
            t.after(() => fs.rm(dir, { recursive: true, force: true }));
            const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
            await store.init();
            const pbx = await store.addPbx({ name: 'Pending fixture', wsURL: 'ws://100.64.0.12:8088/ws',
                apiURL: 'http://100.64.0.12:8080/', mediaIps: ['100.64.0.12'], enabled: true,
                management: { approvalStatus: 'pending', extensionPolicyRequired: true } });
            let called = false;
            const app = express();
            app.use('/control', createControlRouter({ store, credential: { configured: true },
                sessions: { get: id => id === 'fixture' ? { id, csrfToken: 'csrf' } : null },
                onboardingRequest: async payload => {
                    called = true;
                    assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'pending');
                    assert.equal(payload.password, 'transient-fixture-password');
                    if (scenario === 'auth failure') throw Object.assign(new Error('not exposed'), { code: 'password_auth_failed' });
                    if (scenario === 'suspended') await store.updatePbx(pbx.id, { management: { approvalStatus: 'suspended' } });
                    if (scenario === 'edited') await store.updatePbx(pbx.id, { apiURL: 'http://100.64.0.13:8080/' });
                    if (scenario === 'deleted') await store.removePbx(pbx.id);
                    if (scenario === 'queued edit') {
                        const update = store.updatePbx.bind(store);
                        store.updatePbx = async (id, patch, meta) => {
                            await update(id, { management: { approvalStatus: 'suspended' } });
                            return update(id, patch, meta);
                        };
                    }
                    return { configured: true };
                } }));
            const server = app.listen(0, '127.0.0.1');
            await new Promise(resolve => server.once('listening', resolve));
            t.after(() => server.close());
            const origin = `http://127.0.0.1:${server.address().port}`;
            const response = await fetch(origin + '/control/api/pbx-ssh/enroll', { method: 'POST',
                headers: { 'Content-Type': 'application/json', Cookie: 'sokrat_control_sid=fixture', Origin: origin, 'X-CSRF-Token': 'csrf' },
                body: JSON.stringify({ pbxId: pbx.id, host: '100.64.0.12', username: 'root',
                    fingerprint: 'SHA256:' + 'a'.repeat(43), password: 'transient-fixture-password' }) });
            assert.equal(called, true);
            const body = await response.json();
            assert.ok(!JSON.stringify(body).includes('transient-fixture-password'));
            if (scenario === 'success') {
                assert.equal(response.status, 200);
                assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'approved');
                assert.equal(store.getPbx(pbx.id).management.extensionPolicyRequired, true);
            } else if (scenario === 'auth failure') {
                assert.equal(response.status, 503);
                assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'pending');
            } else {
                assert.equal(response.status, 409);
                assert.equal(body.code || body.error, 'pbx_changed_during_setup');
                assert.notEqual(store.getPbx(pbx.id)?.management.approvalStatus, 'approved');
            }
        });
    }
});

test('multiple PBXs keep identical extension numbers and policies isolated', async t => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-multi-pbx-'));
    t.after(() => fs.rm(dir, { recursive: true, force: true }));
    const store = new ControlStore({ filePath: path.join(dir, 'control.json') });
    await store.init();
    const records = [];
    for (const [index, host] of ['100.64.0.12', '100.64.0.13'].entries()) {
        const pbx = await store.addPbx({ name: `PBX ${index}`, wsURL: `ws://${host}:8088/ws`, apiURL: `http://${host}:8080/`, mediaIps: [host], enabled: true,
            management: { approvalStatus: 'pending', extensionPolicyRequired: true } });
        await store.updatePbx(pbx.id, { management: { ...pbx.management, approvalStatus: 'approved' } });
        const extension = await store.addExtension({ pbxId: pbx.id, extension: '001', name: `Desk ${index}`, status: 'enabled', maxDevices: 5, allowedPlatforms: ['android', 'desktop'] });
        const { token } = await store.createEnrollmentToken({ label: 'test', maxUses: 1 });
        const { device } = await store.enrollDevice({ token, deviceUuid: crypto.randomUUID(), platform: 'android' });
        const approved = await store.approveDevice(device.id, { pbxId: pbx.id, extension: '001' });
        records.push({ pbx, extension, approved });
    }
    assert.notEqual(records[0].extension.id, records[1].extension.id);
    assert.equal(store.listExtensions(records[0].pbx.id).length, 1);
    assert.equal(store.listExtensions(records[1].pbx.id).length, 1);
    await store.updateExtension(records[0].extension.id, { status: 'suspended' });
    assert.equal(store.verifyDeviceSecret(records[0].approved.device.id, records[0].approved.secret).ok, false);
    assert.equal(store.verifyDeviceSecret(records[1].approved.device.id, records[1].approved.secret).ok, true);
});
