'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { ControlStore } = require('../src/control/store');
const fs = require('node:fs/promises');
const os = require('node:os');
const crypto = require('node:crypto');

test('FRP plugin fails closed for cross-tenant proxies, ports and invalid installation credentials', () => {
    const result = execFileSync('python3', ['-B', '-c', `
import importlib.util
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
secret='a'*43;pbx='pbx_0123456789abcdef'
record={'pbxId':pbx,'secretHash':m.hash_secret(secret),'ports':m.proxy_ports(3)}
rows={'b'*32:record};user={'user':pbx,'metas':{'installationSecret':secret}}
assert m.authorize_plugin('Login',user,rows)
for kind,port in record['ports'].items():
 c={'user':user,'proxy_name':pbx+'.'+kind,'proxy_type':'tcp','remote_port':port}
 assert m.authorize_plugin('NewProxy',c,rows)
 for field,value in [('remote_port',80),('proxy_name','other.ws'),('proxy_type','udp'),('group','shared')]:
  d=dict(c);d[field]=value
  assert not m.authorize_plugin('NewProxy',d,rows)
assert not m.authorize_plugin('Login',{'user':pbx,'metas':{'installationSecret':'wrong'}},rows)
assert not m.authorize_plugin('Login',{'user':'other','metas':{'installationSecret':secret}},rows)
assert not m.authorize_plugin('CloseProxy',{},rows)
record['migrationExpected']='c'*64
assert not m.authorize_plugin('Login',user,rows)
assert m.plugin_operation({'op':'Login'},'/handler')=='Login'
assert m.plugin_operation({'op':'Login'},'/handler?op=Login')=='Login'
for url in ['/handler?op=NewProxy','/handler?op=','/handler?op=Login&op=NewProxy']:
 try:m.plugin_operation({'op':'Login'},url);raise AssertionError('conflicting operation accepted')
 except ValueError:pass
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8' });
    assert.equal(result.trim(), 'ok');
});

test('explicit migration preserves the PBX id and cannot reapprove a changed or disabled record', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tunnel-migration-'));
    try {
        const store = new ControlStore({ filePath: path.join(root, 'control.json') });
        await store.init();
        const old = await store.addPbx({ name: 'Legacy test', wsURL: 'ws://127.0.0.1:18088/ws',
            apiURL: 'http://127.0.0.1:18080', mediaIps: ['10.0.0.2'],
            management: { approvalStatus: 'approved', extensionPolicyRequired: false } });
        const migration = { pbxId: old.id, installationId: 'c'.repeat(32), name: old.name,
            wsURL: 'ws://127.0.0.1:23006/ws', apiURL: 'http://127.0.0.1:23007', mediaIps: ['10.253.0.14'],
            migrationExpected: crypto.createHash('sha256').update(JSON.stringify(old)).digest('hex') };
        await assert.rejects(store.registerTunnel({ ...migration, migrationExpected: '0'.repeat(64) }), /changed or is not approved/);
        const migrated = await store.registerTunnel(migration);
        assert.equal(migrated.id, old.id);
        assert.equal(migrated.management.approvalStatus, 'approved');
        assert.equal(migrated.management.reviewedInstallationId, migration.installationId);
        assert.equal(store.listPbx().length, 1);
        assert.deepEqual(await store.registerTunnel(migration), migrated, 'lost bridge response can safely retry');
        await store.updatePbx(old.id, { enabled: false });
        assert.equal((await store.registerTunnel(migration)).enabled, false);
    } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('a stalled TLS handshake does not block a second HTTPS client', () => {
    const result = execFileSync('python3', ['-B', '-c', `
import importlib.util,ssl,socket,threading,tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
material=m.new_material(m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22'))
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  self.send_response(204);self.end_headers()
with tempfile.TemporaryDirectory() as root:
 p=Path(root);(p/'cert').write_text(material['pbx.crt']);(p/'key').write_text(material['pbx.key'])
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(p/'cert'),str(p/'key'))
 server=m.BoundedServer(('127.0.0.1',0),Handler,tls_context=context)
 thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 stalled=socket.create_connection(server.server_address,timeout=2)
 client=ssl.create_default_context(cadata=material['ca.crt']);client.check_hostname=False
 try:
  with client.wrap_socket(socket.create_connection(server.server_address,timeout=2),server_hostname='fixture') as conn:
   conn.settimeout(2);conn.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n');assert b'204' in conn.recv(1024)
 finally:
  stalled.close();server.shutdown();server.server_close()
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(result.trim(), 'ok');
});

test('stable tunnel retry never captures a display name or restores disabled/revoked approval', async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'tunnel-enrollment-'));
    try {
        const store = new ControlStore({ filePath: path.join(root, 'control.json') });
        await store.init();
        const input = { pbxId: 'pbx_0123456789abcdef', installationId: 'a'.repeat(32),
            name: 'Test installation', wsURL: 'ws://127.0.0.1:23006/ws', apiURL: 'http://127.0.0.1:23007',
            mediaIps: ['10.253.0.14'], enabled: true };
        const pbx = await store.registerTunnel(input);
        assert.equal(pbx.management.approvalStatus, 'approved');
        assert.deepEqual(await store.registerTunnel(input), pbx);
        await assert.rejects(store.registerTunnel({ ...input, installationId: 'b'.repeat(32) }), /Installation or route changed/);
        await assert.rejects(store.registerTunnel({ ...input, pbxId: 'pbx_fedcba9876543210' }), /already exists/);
        await store.updatePbx(pbx.id, { enabled: false, management: { approvalStatus: 'retired' } });
        const retry = await store.registerTunnel(input);
        assert.equal(retry.enabled, false);
        assert.equal(retry.management.approvalStatus, 'retired');
        await assert.rejects(store.registerTunnel({ ...input, pbxId: 'pbx_1111111111111111',
            existingRequired: true }), /Previously enrolled PBX was removed/);
        await assert.rejects(store.registerTunnel({ ...input, pbxId: 'pbx_2222222222222222',
            migrationExpected: 'a'.repeat(64) }), /Previously enrolled PBX was removed/);
    } finally {
        await fs.rm(root, { recursive: true, force: true });
    }
});

test('root broker rejects service-owned ancestors and symlinks before opening privileged state', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util,stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for mode,owner in [(stat.S_IFDIR|0o700,999),(stat.S_IFDIR|0o777,0),(stat.S_IFLNK|0o700,0)]:
 with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=owner)),patch.object(m.os,'open') as opened:
  try:m.read_json(Path('/var/lib/reviewed/state.json'));raise AssertionError('untrusted parent accepted')
  except ValueError:pass
  assert not opened.called
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});

test('legacy short FRP token fails preflight before reserving or migrating a tenant', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util
from pathlib import Path
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
body={'installationId':'a'*32,'installationSecret':'b'*43,'name':'Preflight fixture'}
for token in ['x'*30,'invalid token','x'*201]:
 with patch.object(Path,'read_text',return_value=token),patch.object(m,'reserve') as reserve,patch.object(m,'bridge') as bridge:
  try:m.register({'frpTokenFile':'/etc/frp/fixture'},body);raise AssertionError('invalid FRP credential accepted')
  except ValueError:pass
  assert not reserve.called and not bridge.called
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});
