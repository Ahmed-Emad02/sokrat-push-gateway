'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('bootstrap commits its activation marker last and can retry an interrupted credential install', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util,pwd
from contextlib import ExitStack,redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
args=SimpleNamespace(host='gateway.example.test',pool='10.253.0.0/22',
 gateway_url='https://gateway.example.test:7443',port=7443,control_port=8002,
 plugin_port=7450,tunnel_port=7000,runtime_port=9097,service_user='fixture',
 trusted_state_dir='/fixture/trusted')
for failure in ('account','server.key','pairing','bridge','metadata','trusted'):
 files={};writes=[];injected=[False]
 def fail_once(stage):
  if stage==failure and not injected[0]:
   injected[0]=True;raise RuntimeError('interrupted '+stage)
 def account(name):fail_once('account');return SimpleNamespace(pw_gid=123)
 def write(file,value,mode):
  stage='pairing' if file==m.PAIRING_FILE else 'bridge' if file==m.BRIDGE_FILE else file.name
  fail_once(stage);files[file]=value;writes.append(file)
 def save(file,value):files[file]=value;writes.append(file)
 def metadata(*a):fail_once('metadata')
 def trusted(*a):fail_once('trusted')
 installer=SimpleNamespace(private_directory=lambda p:None,write=write)
 with ExitStack() as stack:
  stack.enter_context(patch.object(pwd,'getpwnam',side_effect=account))
  stack.enter_context(patch.object(m.subprocess,'check_output',return_value=b'[]'))
  stack.enter_context(patch.object(m,'load_installer',return_value=installer))
  stack.enter_context(patch.object(m,'trusted_state',side_effect=trusted))
  stack.enter_context(patch.object(m,'save_json',side_effect=save))
  stack.enter_context(patch.object(m.os,'chown',side_effect=metadata))
  stack.enter_context(patch.object(m.os,'chmod',side_effect=metadata))
  stack.enter_context(patch.object(m.CONFIG.__class__,'exists',autospec=True,side_effect=lambda p:p in files))
  stack.enter_context(redirect_stdout(StringIO()))
  try:m.initialize(args);raise AssertionError('interruption hidden')
  except RuntimeError:pass
  assert m.CONFIG not in files
  if failure=='account':assert not writes
  m.initialize(args)
  assert injected[0] and writes[-1]==m.CONFIG
  assert m.PAIRING_FILE in files and m.BRIDGE_FILE in files
  before=dict(files)
  try:m.initialize(args);raise AssertionError('existing credentials overwritten')
  except ValueError:pass
  assert files==before
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 20000 });
    assert.equal(output.trim(), 'ok');
});

test('broker retries bridge, pin and media failures with the same reserved identity and keys', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import copy,importlib.util,io,stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('enrollment','tunnel-enrollment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
body={'installationId':'a'*32,'installationSecret':'b'*43,'name':'Recovery fixture'}
config={'frpTokenFile':'/fixture/frp-token','trustedStateDir':'/fixture/trusted',
 'tunnelPort':7000,'publicHost':'gateway.example.test','gatewayUrl':'https://gateway.example.test:7443'}
pbx='pbx_0123456789abcdef'
class FakeLock(io.BytesIO):
 def fileno(self):return 42
for failure in ('bridge','pin','media'):
 entry={'pbxId':pbx,'installationId':body['installationId'],
  'secretHash':m.hash_secret(body['installationSecret']),
  'plan':m.allocation(pbx,3,'10.253.0.0/22'),'ports':m.proxy_ports(3)}
 rows={body['installationId']:entry}
 material=m.new_material(entry['plan']);material['readinessKey']='r'*43
 files={m.REGISTRY:copy.deepcopy(rows),
  Path('/etc/sokrat/gateway-provisioning.json'):{'lockDir':'/fixture/lock'},
  Path('/fixture/trusted/hook-tokens.json'):{pbx:'h'*43},
  m.ROOT/pbx/'material.json':copy.deepcopy(material)}
 def read(file,default=None):return copy.deepcopy(files.get(file,default))
 def save(file,value):files[file]=copy.deepcopy(value)
 calls=[];injected=[False]
 def fail_once(stage):
  calls.append(stage)
  if stage==failure and not injected[0]:
   injected[0]=True;raise RuntimeError('injected '+stage)
 def bridge(c,e,name):
  fail_once('bridge');return {'enabled':True,'approvalStatus':'approved'}
 def pin(e):fail_once('pin')
 def install(document,role,start):
  assert role=='gateway' and start is True
  assert document['material']==m.for_role(material,'gateway')
  fail_once('media')
 installer=SimpleNamespace(private_directory=lambda p:None,install=install)
 def reserve(c,installations,b):
  assert b==body;return installations[b['installationId']]
 with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=save),patch.object(m,'trusted_state',return_value=(Path('/fixture/trusted/tenant-plan.json'),Path('/fixture/trusted/hook-tokens.json'))),patch.object(m,'load_installer',return_value=installer),patch.object(m,'reserve',side_effect=reserve),patch.object(m,'bridge',side_effect=bridge),patch.object(m,'pin',side_effect=pin),patch.object(m.os,'open',return_value=42),patch.object(m.os,'fdopen',side_effect=lambda *a:FakeLock()),patch.object(m.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)),patch.object(m.fcntl,'flock'),patch.object(Path,'read_text',side_effect=lambda *a: 'f'*43 if a[0]==Path('/fixture/frp-token') else 'fixture certificate',autospec=True):
  try:m.register(config,body);raise AssertionError('failure was hidden')
  except RuntimeError:pass
  result=m.register(config,body)
  assert result['pbxId']==pbx and result['installationId']==body['installationId']
  assert result['material']==m.for_role(material,'pbx')
  assert result['readinessKey']==material['readinessKey'] and result['hookToken']=='h'*43
  assert files[m.REGISTRY][body['installationId']]['controlRegistered'] is True
  assert len(files[m.REGISTRY])==1
  assert files[m.ROOT/pbx/'material.json']==material
  assert files[Path('/fixture/trusted/hook-tokens.json')]=={pbx:'h'*43}
  assert injected[0] and calls[-1]=='media'
 # A later revocation must stop recovery before privileged pin/start actions.
 with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=save),patch.object(m,'trusted_state',return_value=(Path('/fixture/trusted/tenant-plan.json'),Path('/fixture/trusted/hook-tokens.json'))),patch.object(m,'load_installer',return_value=installer),patch.object(m,'reserve',side_effect=reserve),patch.object(m,'bridge',return_value={'enabled':False,'approvalStatus':'retired'}),patch.object(m,'pin') as pin_mock,patch.object(m.os,'open',return_value=42),patch.object(m.os,'fdopen',side_effect=lambda *a:FakeLock()),patch.object(m.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)),patch.object(m.fcntl,'flock'),patch.object(Path,'read_text',return_value='f'*43):
  before=len(calls)
  try:m.register(config,body);raise AssertionError('retired tenant recovered')
  except ValueError:pass
  assert not pin_mock.called and len(calls)==before
print('ok')`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 20000 });
    assert.equal(output.trim(), 'ok');
});
