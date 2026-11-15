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
 for field,value in [('remote_port',80),('proxy_name','other.ws'),('group','shared')]:
  d=dict(c);d[field]=value
  assert not m.authorize_plugin('NewProxy',d,rows)
 d=dict(c);d['proxy_type']='udp'
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

test('FRP media proxy authorization requires legacy TCP and forbids explicit UDP transports', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
secret='d'*43
def record(slot,transport='absent'):
 plan=m.allocation('pbx_0123456789abcdef',slot,'10.253.0.0/22')
 row={'pbxId':plan['pbxId'],'plan':plan,'ports':m.proxy_ports(slot),'secretHash':m.hash_secret(secret)}
 if transport!='absent':row['mediaTransport']=transport
 return row
def check(row,kind,scope,port):
 content={'user':{'user':row['pbxId'],'metas':{'installationSecret':secret}},
          'proxy_type':kind,'proxy_name':row['pbxId']+'.'+scope,'remote_port':port}
 return m.authorize_plugin('NewProxy',content,{row['pbxId']:row})
def login(row):
 return m.authorize_plugin('Login',{'user':row['pbxId'],'metas':{'installationSecret':secret}},
                           {row['pbxId']:row})
# A legacy record has no mediaTransport: its media proxy carries TCP only.
for transport in ('absent',None):
 row=record(0,transport); media=row['ports']['media']
 assert login(row),transport
 assert check(row,'tcp','media',media),transport
 assert not check(row,'udp','media',media),transport
 assert check(row,'tcp','ws',row['ports']['ws']) and check(row,'tcp','api',row['ports']['api'])
 assert not check(row,'udp','ws',row['ports']['ws'])
 assert not check(row,'udp','api',row['ports']['api'])
# An explicit plain/direct UDP tenant owns its media path: no FRP media proxy.
for slot,mode in ((1,'direct-udp'),(2,'plain-udp')):
 row=record(slot)
 transport=m.validate_transport({'mode':mode,'host':'gateway.example.test','port':26000+slot},row['plan'])
 row['mediaTransport']=transport
 media=row['ports']['media']
 assert login(row),mode
 assert not check(row,'tcp','media',media),mode
 assert not check(row,'udp','media',media),mode
 assert not check(row,'udp','media',transport['port']),mode
 assert check(row,'tcp','ws',row['ports']['ws']) and check(row,'tcp','api',row['ports']['api'])
 assert not check(row,'udp','ws',row['ports']['ws'])
 assert not check(row,'udp','api',row['ports']['api'])
# Unknown persisted transport values fail closed for every media protocol.
row=record(3,'udp')
assert not check(row,'tcp','media',row['ports']['media'])
assert not check(row,'udp','media',row['ports']['media'])
assert check(row,'tcp','ws',row['ports']['ws'])
# WireGuard stays canonical UDP-only.
row=record(4)
assert check(row,'udp','wireguard',24004)
assert not check(row,'tcp','wireguard',24004)
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
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

test('enrollment takes media transport from the registry only, never from the request or a downgrade', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util,stat,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
plan=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
material=m.new_material(plan);material['readinessKey']='r'*43
entry={'pbxId':plan['pbxId'],'installationId':'a'*32,'secretHash':'x','plan':plan,
       'ports':m.proxy_ports(3),'controlRegistered':True}
body={'installationId':'a'*32,'installationSecret':'b'*43,'name':'Fixture'}
direct={'mode':'direct-udp','host':'gateway.example.test','port':26003}
calls=[];bridges=[]
fake=SimpleNamespace(private_directory=lambda p:None,write=lambda *a:True,
    install=lambda document,role,start:calls.append((document,role,start)))
def fake_bridge(config,row,name):
    bridges.append(name);return {'enabled':True,'approvalStatus':'approved'}
info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)
with tempfile.TemporaryDirectory() as root:
    root=Path(root);(root/'server.crt').write_text('ca');(root/'frp.token').write_text('x'*43)
    hooks={plan['pbxId']:'h'*43}
    def read_json(path,default=None):
        name=str(path)
        if name.endswith('gateway-provisioning.json'):return {'lockDir':str(root)}
        if name.endswith('installations.json'):return {'a'*32:entry}
        if name.endswith('hook-tokens.json'):return hooks
        if name.endswith('material.json'):return material
        raise AssertionError(name)
    config={'frpTokenFile':str(root/'frp.token'),'controlPort':1,'publicHost':'gateway.example.test',
            'gatewayUrl':'https://gateway.example.test:7443','tunnelPort':7000,'trustedStateDir':str(root)}
    with patch.object(m,'ROOT',root),patch.object(m,'read_json',read_json), \
         patch.object(m,'save_json',lambda *a:None),patch.object(m,'pin',lambda row:None), \
         patch.object(m,'bridge',fake_bridge),patch.object(m,'load_installer',lambda:fake), \
         patch.object(m,'reserve',lambda c,i,b:entry),patch.object(m.os,'fstat',lambda fd:info), \
         patch.object(m,'reconcile_media_firewall',return_value=None):
        # An installed direct tenant is reenrolled with the exact same endpoint,
        # including when the request tries to carry its own transport fields.
        for smuggled in ({},direct):
            entry['mediaTransport']=direct;calls.clear();bridges.clear()
            response=m.register(config,dict(body,**smuggled))
            assert response['mediaTransport']==direct,response
            assert len(calls)==1 and calls[0][1]=='gateway' and calls[0][2] is True
            assert calls[0][0]['transport']==direct
            assert calls[0][0]['plan']==plan and calls[0][0]['material']['ca.crt']==material['ca.crt']
            assert response['pbxId']==plan['pbxId'] and response['serverHost']=='gateway.example.test'
        # A legacy registry row stays legacy and the request cannot opt in.
        del entry['mediaTransport'];calls.clear();bridges.clear()
        response=m.register(config,dict(body,mediaTransport=direct,transport=direct))
        assert 'mediaTransport' not in response
        assert calls[0][0]['transport'] is None
        assert calls[0][0]['plan']==plan
        # A malformed stored endpoint fails closed before bridge or service work.
        for bad in [{'mode':'direct-tcp','host':'gateway.example.test','port':26003},
                    {'mode':'direct-udp','host':'gateway.example.test','port':True},
                    {'mode':'direct-udp','host':'gateway.example.test','port':'26003'},
                    {'mode':'direct-udp','host':'gateway.example.test','port':26003,'extra':1},
                    {'mode':'direct-udp','host':'gw;reboot','port':26003},
                    {'mode':'direct-udp','host':'','port':26003},'direct-udp',[]]:
            entry['mediaTransport']=bad;calls.clear();bridges.clear()
            try:m.register(config,body);raise AssertionError('accepted '+repr(bad))
            except ValueError:pass
            assert not calls and not bridges,bad
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});

test('WireGuard proxy authorization is canonical UDP-only and media/control scope is unchanged', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
secret='b'*43
def record(slot):
 plan=m.allocation('pbx_0123456789abcdef',slot,'10.253.0.0/22')
 return {'pbxId':plan['pbxId'],'plan':plan,'ports':m.proxy_ports(slot),'secretHash':m.hash_secret(secret)}
def check(row,kind,name,port,extra=None):
 content={'user':{'user':row['pbxId'],'metas':{'installationSecret':secret}},
          'proxy_type':kind,'proxy_name':name,'remote_port':port}
 content.update(extra or {})
 return m.authorize_plugin('NewProxy',content,{row['pbxId']:row})
row=record(0); pbx=row['pbxId']
assert check(row,'udp',pbx+'.wireguard',24000)
assert not check(row,'tcp',pbx+'.wireguard',24000)
assert not check(row,'udp',pbx+'.wireguard',24001)
assert not check(row,'udp',pbx+'.wireguardx',24000)
assert not check(row,'udp',pbx+'.wireguard',24000,{'group':'x'})
assert not check(row,'udp',pbx+'.wireguard',24000,{'group_key':'x'})
assert not check(row,'udp','pbx_fedcba9876543210.wireguard',24000)
assert check(dict(row,ports=dict(row['ports'],wireguard=25000)),'udp',pbx+'.wireguard',24000)
assert not check(dict(row,ports=dict(row['ports'],wireguard=25000)),'udp',pbx+'.wireguard',25000)
assert not check(row,'udp',pbx+'.wireguard',25000)
assert not check(row,'udp',pbx+'.media',row['ports']['media'])
assert check(row,'tcp',pbx+'.media',row['ports']['media'])
assert check(row,'tcp',pbx+'.ws',row['ports']['ws'])
assert not check(row,'udp',pbx+'.ws',row['ports']['ws'])
assert check(row,'tcp',pbx+'.api',row['ports']['api'])
assert not check(dict(row,plan=dict(row['plan'],slot=155)),'udp',pbx+'.wireguard',24155)
last=record(154);assert check(last,'udp',last['pbxId']+'.wireguard',24154)
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});

test('fresh enrollment reserves a canonical plain-udp profile and reconciles firewall before media start', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import copy,importlib.util,json,os,shutil,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
source=Path.cwd()
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
body={'installationId':'a'*32,'installationSecret':'b'*43,'name':'Fresh plain',
      'pairingSecret':'p'*43,'mediaTransport':{'mode':'direct-udp','host':'evil.example','port':26004},
      'transport':{'mode':'plain-udp','host':'evil.example','port':26004}}
config={'pairingSecret':'p'*43,'mediaPool':'10.253.0.0/22','publicHost':'gateway.example.test',
        'frpTokenFile':'/fixture/frp-token','controlPort':1,
        'gatewayUrl':'https://gateway.example.test:7443','tunnelPort':7000,
        'trustedStateDir':'/fixture/trusted'}
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);scripts=root/'scripts';scripts.mkdir()
 for name in ('tunnel-enrollment.py','sync-tenant-runtime.py','tunnel_media.py','tunnel_media_material.py','media-udp-ports.py'):
  shutil.copyfile(source/name,scripts/name)
 shutil.copyfile(source/'media-udp-firewall.py',scripts/'media-udp-firewall-actual.py')
 (scripts/'media-udp-firewall.py').write_text('''#!/usr/bin/env python3
import os,runpy,sys
from pathlib import Path
os.geteuid=lambda:0
here=Path(__file__).resolve().parent
sys.argv=[str(here/'media-udp-firewall-actual.py')]+sys.argv[1:]+[
 '--manifest',os.environ['SOKRAT_TEST_MANIFEST'],
 '--registry',os.environ['SOKRAT_TEST_REGISTRY']]
runpy.run_path(str(here/'media-udp-firewall-actual.py'),run_name='__main__')
''')
 m.__file__=str(scripts/'tunnel-enrollment.py')
 plan_path=root/'tenant-plan.json'
 plan_path.write_text(json.dumps({'schemaVersion':1,'allocations':{}}));plan_path.chmod(0o600)
 manifest=root/'host-firewall.json'
 manifest.write_text(json.dumps({'configured':True,'manager':'ufw','sshPort':22,'tls':True,
                                 'ports':['22/tcp','3500:3654/udp'],'updatedAt':'2026-01-01T00:00:00+00:00'}))
 hooks_path=root/'hook-tokens.json';files={};log_path=root/'events.log';log_path.write_text('')
 m.REGISTRY=root/'installations.json'
 os.environ['SOKRAT_TEST_MANIFEST']=str(manifest)
 os.environ['SOKRAT_TEST_REGISTRY']=str(m.REGISTRY)
 bin_dir=root/'bin';bin_dir.mkdir()
 status=root/'ufw.status'
 status.write_text(chr(10).join(['Status: active','','To Action From','-- ------ ----','22/tcp ALLOW Anywhere','']))
 os.environ['SOKRAT_TEST_LOG']=str(log_path)
 os.environ['SOKRAT_TEST_STATUS']=str(status)
 (bin_dir/'ufw').write_text('''#!/bin/sh
set -eu
echo "ufw $*" >> "$SOKRAT_TEST_LOG"
if [ "$1" = status ]; then cat "$SOKRAT_TEST_STATUS"; exit 0; fi
if [ "$1" = allow ]; then echo "$2 ALLOW Anywhere" >> "$SOKRAT_TEST_STATUS"; exit 0; fi
exit 0
''')
 (bin_dir/'systemctl').write_text('''#!/bin/sh
exit 0
''')
 os.chmod(bin_dir/'ufw',0o755);os.chmod(bin_dir/'systemctl',0o755)
 os.environ['PATH']=str(bin_dir)+os.pathsep+os.environ['PATH']
 def read(file,default=None):
  file=Path(file)
  if file==Path('/etc/sokrat/gateway-provisioning.json'):return {'lockDir':str(root/'locks')}
  if file==hooks_path:return copy.deepcopy(files.get(file,{}))
  return copy.deepcopy(files.get(file,default))
 def save(file,value):
  file=Path(file);files[file]=copy.deepcopy(value)
  if file==m.REGISTRY:
   file.write_text(json.dumps(value,sort_keys=True)+chr(10))
   with log_path.open('a') as stream:stream.write('registry'+chr(10))
 def trusted(c):return plan_path,hooks_path
 real_read_text=Path.read_text
 installs=[];fail=[True]
 def install(document,role,start):
  selected=document['transport'];port=str(selected['port'])+'/udp'
  assert port+' ALLOW Anywhere' in real_read_text(status)
  assert port in json.loads(real_read_text(manifest))['mediaUdpPorts']
  assert json.loads(real_read_text(m.REGISTRY))[body['installationId']]['mediaTransport']==selected
  with log_path.open('a') as stream:stream.write('install'+chr(10))
  installs.append((document,role,start))
  if fail[0]:fail[0]=False;raise RuntimeError('injected media failure')
 installer=SimpleNamespace(private_directory=lambda p:p.mkdir(parents=True,exist_ok=True),install=install)
 def bridge(c,e,n):return {'enabled':True,'approvalStatus':'approved'}
 def read_text(path,*args):
  if str(path).endswith('frp-token'):return 'f'*43
  if Path(path).name=='server.crt':return 'fixture certificate'
  return real_read_text(path,*args)
 real_fstat=m.os.fstat
 def fixture_owner(fd):
  fields=list(real_fstat(fd));fields[4]=0
  return m.os.stat_result(fields)
 with patch.object(m,'ROOT',root),patch.object(m,'read_json',side_effect=read), \\
      patch.object(m,'save_json',side_effect=save),patch.object(m,'trusted_state',side_effect=trusted), \\
      patch.object(m,'load_installer',return_value=installer),patch.object(m,'bridge',side_effect=bridge), \\
      patch.object(m,'pin'),patch.object(m.os,'fstat',side_effect=fixture_owner), \\
      patch.object(Path,'read_text',new=read_text):
  entry=m.reserve(config,{},body)
  selected=entry['mediaTransport']
  assert selected['mode']=='plain-udp' and selected['host']==config['publicHost']
  assert type(selected['port']) is int and 1024<=selected['port']<=65535
  expected=copy.deepcopy(selected)
  material_file=m.ROOT/entry['pbxId']/'material.json'
  material=files[material_file]
  assert set(material)=={'udp.key','readinessKey'},sorted(material)
  assert len(bytes.fromhex(material['udp.key'].strip()))==32
  assert files[m.REGISTRY][body['installationId']]['mediaTransport']==expected
  first=copy.deepcopy(entry);first_material=copy.deepcopy(material)
  retry=m.reserve(config,{body['installationId']:entry},body)
  assert retry==first and files[material_file]==first_material
  log_path.write_text('');installs.clear()
  try:m.register(config,body);raise AssertionError('media failure hidden')
  except RuntimeError:pass
  assert len(installs)==1
  assert files[m.REGISTRY][body['installationId']]['mediaTransport']==expected
  assert files[material_file]==first_material
  log_path.write_text('');installs.clear()
  response=m.register(config,body)
  assert response['mediaTransport']==expected
  assert response['material']=={'udp.key':first_material['udp.key']}
  assert response['readinessKey']==first_material['readinessKey']
  assert len(installs)==1
  document,role,start=installs[0]
  assert role=='gateway' and start is True
  assert document['transport']==expected
  assert document['material']=={'udp.key':first_material['udp.key']}
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 30000 });
    assert.equal(output.trim(), 'ok');
});

test('fresh enrollment ignores request-selected media and fails closed on a canonical port collision', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import copy,importlib.util,json,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
body={'installationId':'c'*32,'installationSecret':'d'*43,'name':'Fresh collision',
      'pairingSecret':'p'*43,'mediaTransport':{'mode':'plain-udp','host':'evil.example','port':26000}}
config={'pairingSecret':'p'*43,'mediaPool':'10.253.0.0/22','publicHost':'gateway.example.test',
        'trustedStateDir':'/fixture/trusted'}
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary); plan_path=root/'tenant-plan.json'
 plan_path.write_text(json.dumps({'schemaVersion':1,'allocations':{}}));plan_path.chmod(0o600)
 other_plan=m.allocation('pbx_fedcba9876543210',1,'10.253.0.0/22')
 other={'pbxId':other_plan['pbxId'],'plan':other_plan,'ports':m.proxy_ports(1),
        'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':26000}}
 files={m.REGISTRY:{'other':other}};writes=[]
 def read(file,default=None):return copy.deepcopy(files.get(Path(file),default))
 def save(file,value):writes.append(Path(file));files[Path(file)]=copy.deepcopy(value)
 installer=SimpleNamespace(private_directory=lambda p:None)
 before=copy.deepcopy(files[m.REGISTRY])
 with patch.object(m,'ROOT',root),patch.object(m,'read_json',side_effect=read), \
      patch.object(m,'save_json',side_effect=save),patch.object(m,'trusted_state',return_value=(plan_path,root/'hook-tokens.json')), \
      patch.object(m,'load_installer',return_value=installer):
  try:m.reserve(config,files[m.REGISTRY],body);raise AssertionError('collision accepted')
  except ValueError:pass
  assert files[m.REGISTRY]==before,writes
  assert writes==[],writes
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 20000 });
    assert.equal(output.trim(), 'ok');
});

test('existing legacy and explicit plain enrollments remain unchanged on retry', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import copy,importlib.util
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
config={'pairingSecret':'p'*43,'mediaPool':'10.253.0.0/22','publicHost':'gateway.example.test'}
writes=[]
with __import__('tempfile').TemporaryDirectory() as temporary:
 from pathlib import Path
 root=Path(temporary); plan_path=root/'plan.json'
 legacy_plan=m.allocation('pbx_0123456789abcdef',1,'10.253.0.0/22')
 plain_plan=m.allocation('pbx_fedcba9876543210',2,'10.253.0.0/22')
 legacy_secret='e'*43;plain_secret='f'*43
 legacy={'pbxId':legacy_plan['pbxId'],'installationId':'1'*32,
         'secretHash':m.hash_secret(legacy_secret),'plan':legacy_plan,'ports':m.proxy_ports(1)}
 plain={'pbxId':plain_plan['pbxId'],'installationId':'2'*32,
        'secretHash':m.hash_secret(plain_secret),'plan':plain_plan,'ports':m.proxy_ports(2),
        'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':26002}}
 rows={legacy['installationId']:legacy,plain['installationId']:plain};before=copy.deepcopy(rows)
 def read(file,default=None):return copy.deepcopy(rows.get(Path(file),default))
 def save(file,value):writes.append(Path(file));rows[Path(file)]=copy.deepcopy(value)
 with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=save):
  got_legacy=m.reserve(config,rows,{'installationId':legacy['installationId'],
      'installationSecret':legacy_secret,'name':'Legacy','pairingSecret':'x'})
  got_plain=m.reserve(config,rows,{'installationId':plain['installationId'],
      'installationSecret':plain_secret,'name':'Plain','pairingSecret':'x'})
  assert got_legacy==legacy and got_plain==plain
  assert m.validate_transport(got_legacy.get('mediaTransport'),got_legacy['plan']) is None
  assert m.validate_transport(got_plain['mediaTransport'],got_plain['plan'])==plain['mediaTransport']
 assert writes==[] and rows==before,writes
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 15000 });
    assert.equal(output.trim(), 'ok');
});
