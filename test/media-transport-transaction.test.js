'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function python(body) {
    return execFileSync('python3', ['-B', '-c', `import importlib.util
s=importlib.util.spec_from_file_location('transaction','media-transport-transaction.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
${body}`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8' });
}

test('media cutover and rollback preserve other tenants and reject stale installation authority', () => {
    assert.equal(python(`
pbx='pbx_0123456789abcdef'
old={'pbxId':pbx,'secretHash':'old-hash','controlRegistered':True}
other={'pbxId':'pbx_fedcba9876543210','secretHash':'other-hash','controlRegistered':False}
registry={'installation-a':old,'installation-b':other}
direct=dict(old,mediaTransport={'mode':'direct-udp','host':'gateway.example.test','port':26003})
changed=m.replace_entry(registry,pbx,old,direct)
assert changed['installation-a']==direct and changed['installation-b']==other
restored=m.replace_entry(changed,pbx,direct,old)
assert restored==registry
for current in [dict(old,secretHash='rotated-hash'),dict(old,controlRegistered=False)]:
 try:m.replace_entry({'installation-a':current},pbx,old,direct);raise AssertionError('stale authority overwritten')
 except ValueError:pass
for rows in [{},dict(registry,duplicate=dict(old))]:
 try:m.replace_entry(rows,pbx,old,direct);raise AssertionError('ambiguous/missing installation accepted')
 except ValueError:pass
print('ok')`).trim(), 'ok');
});

test('transaction identities cannot escape the per-PBX private backup directory', () => {
    assert.equal(python(`
pbx='pbx_0123456789abcdef'
assert str(m.transaction_path(pbx,'test-20261112')).endswith('/'+pbx+'/test-20261112')
for identity in ['../other','a/b','x\\ny','',None,'x'*65]:
 try:m.transaction_path(pbx,identity);raise AssertionError('unsafe transaction identity accepted')
 except ValueError:pass
for identity in ['pbx_other','../etc','pbx_0123456789abcdef\\n',None]:
 try:m.transaction_path(identity,'valid');raise AssertionError('unsafe PBX identity accepted')
 except ValueError:pass
print('ok')`).trim(), 'ok');
});

test('interrupted installer staging files are recoverable without deleting unrelated or unsafe files', () => {
    assert.equal(python(`
import stat
from types import SimpleNamespace
safe=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
assert m.recoverable_temporary('.media-abcd1234',safe)
for name in ['operator-note','.media-short','.media-abcd1234.backup','transport.json']:
 assert not m.recoverable_temporary(name,safe)
for mode,uid,links in [(stat.S_IFREG|0o644,0,1),(stat.S_IFREG|0o600,1000,1),(stat.S_IFLNK|0o600,0,1),(stat.S_IFREG|0o600,0,2)]:
 assert not m.recoverable_temporary('.media-abcd1234',SimpleNamespace(st_mode=mode,st_uid=uid,st_nlink=links))
print('ok')`).trim(), 'ok');
});

test('a media cutover cannot steal another registered tenant UDP endpoint', () => {
    assert.equal(python(`
import tempfile
from pathlib import Path
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,0,'10.253.0.0/22'))
entry={'pbxId':pbx,'plan':plan}
other={'pbxId':'pbx_fedcba9876543210',
       'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':26154}}
def read(file):
 if file.name=='plan.json':return plan
 if file.name=='config.json':return {'publicHost':'gateway.example.test'}
 if file.name=='installations.json':return {'selected':entry,'other':other}
 raise AssertionError('Read private material before rejecting the collision')
with tempfile.TemporaryDirectory() as root:
 m.BACKUPS=Path(root)
 with patch.object(m,'read_json',side_effect=read):
  try:
   m.prepare('gateway',pbx,'collision',transport_mode='plain-udp',transport_port=26154)
   raise AssertionError('Accepted another tenant endpoint')
  except ValueError:pass
print('ok')`).trim(), 'ok');
});

test('apply refuses an endpoint acquired by another tenant after prepare without stopping media', () => {
    assert.equal(python(`
from pathlib import Path
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
transport={'mode':'plain-udp','host':'gateway.example.test','port':26154}
old={'pbxId':pbx}
registry={'selected':old,'other':{'pbxId':'pbx_fedcba9876543210','mediaTransport':transport}}
state={'state':'prepared','role':'gateway','pbxId':pbx,'fingerprint':'unchanged',
       'oldEntry':old,'document':{'transport':transport}}
def read(file):
 if file.name=='installations.json':return registry
 raise AssertionError('Read beyond endpoint ownership guard')
with patch.object(m,'fingerprint',return_value='unchanged'), patch.object(m,'read_json',side_effect=read):
 try:
  m.apply(state,Path('/unused'))
  raise AssertionError('Applied a conflicting prepared endpoint')
 except ValueError:pass
assert state['state']=='prepared' and registry['selected']==old
print('ok')`).trim(), 'ok');
});

test('prepare switches a valid plain tenant to direct UDP on its own occupied port without rekeying', () => {
    assert.equal(python(`
import importlib.util,socket,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tunnel_media
pbx='pbx_0123456789abcdef'; other_pbx='pbx_fedcba9876543210'
plan=m.validate_plan(tunnel_media.allocation(pbx,3,'10.253.0.0/22'))
other_plan=m.validate_plan(tunnel_media.allocation(other_pbx,4,'10.253.0.0/22'))
holder=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);holder.bind(('0.0.0.0',0));port=holder.getsockname()[1]
other_holder=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);other_holder.bind(('0.0.0.0',0));other_port=other_holder.getsockname()[1]
old={'pbxId':pbx,'plan':plan,'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':port},'secretHash':'x','controlRegistered':True}
other={'pbxId':other_pbx,'plan':other_plan,
       'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':other_port}}
old_material={'udp.key':'a'*64+chr(10),'readinessKey':'r'*43}
spec=importlib.util.spec_from_file_location('media_installer','install-media-link.py')
real=importlib.util.module_from_spec(spec);spec.loader.exec_module(real)
try:
 with tempfile.TemporaryDirectory() as root:
  root=Path(root);m.BACKUPS=root;files={}
  reads={'plan.json':plan,'config.json':{'publicHost':'gateway.example.test'},
         'installations.json':{'selected':old,'other':other},'material.json':old_material}
  def read(path,default=None):return reads[path.name]
  def save(path,value):files[path]=value
  install=SimpleNamespace(validate_material=real.validate_material,
                          media_config=real.media_config,version=lambda:(2,6))
  with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=save), \
       patch.object(m,'snapshot',return_value='fingerprint'),patch.object(m,'installer',return_value=install):
   state=m.prepare('gateway',pbx,'plain-to-direct',transport_mode='direct-udp',transport_port=port)
  assert state['oldEntry']==old and state['oldMaterial']==old_material
  assert state['newMaterial']['readinessKey']==old_material['readinessKey']
  assert state['document']['plan']==plan
  assert state['document']['transport']=={'mode':'direct-udp','host':'gateway.example.test','port':port}
  assert 'udp.key' not in state['document']['material']
  assert files and {path.name for path in files}=={'peer-bundle.json','state.json'}
finally:
 holder.close();other_holder.close()
print('ok')`).trim(), 'ok');
});

test('apply revalidates the freed port after stopping its own unit before saving or starting', () => {
    assert.equal(python(`
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
pbx='pbx_0123456789abcdef'; other_pbx='pbx_fedcba9876543210'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
other_plan=m.validate_plan(__import__('tunnel_media').allocation(other_pbx,4,'10.253.0.0/22'))
holder=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);holder.bind(('0.0.0.0',0));port=holder.getsockname()[1]
other_holder=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);other_holder.bind(('0.0.0.0',0));other_port=other_holder.getsockname()[1]
transport={'mode':'direct-udp','host':'gateway.example.test','port':port}
old={'pbxId':pbx,'plan':plan,'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':port},'secretHash':'x'}
other={'pbxId':other_pbx,'plan':other_plan,
       'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':other_port}}
old_material={'udp.key':'a'*64+chr(10),'readinessKey':'r'*43}
new_material={'ca.crt':'ca','gateway.crt':'cert','gateway.key':'key','tls-crypt.key':'tc','readinessKey':'r'*43}
registry={'selected':old,'other':other}
unit_name='sokrat-media-'+pbx+'.service'
events=[]
def run(argv,check=True):
 events.append(tuple(argv))
 if argv[:3]==['systemctl','stop',unit_name]:holder.close()
 return SimpleNamespace(returncode=0)
def read(path,default=None):return registry if path.name=='installations.json' else old_material
def save(path,value):events.append(('save',path.name))
def install(document,role,start):events.append(('install',role,start))
fake=SimpleNamespace(install=install)
state={'role':'gateway','pbxId':pbx,'state':'prepared','fingerprint':'fingerprint',
       'document':{'plan':plan,'transport':transport},'oldEntry':old,
       'oldMaterial':old_material,'newMaterial':new_material}
try:
 with patch.object(m,'media_paths',return_value=(Path('/media'),Path('/units')/unit_name)), \
      patch.object(m,'fingerprint',return_value='fingerprint'),patch.object(m,'read_json',side_effect=read), \
      patch.object(m,'save_json',side_effect=save),patch.object(m,'installer',return_value=fake), \
      patch.object(m,'reconcile_media_firewall') as fw,patch.object(m,'run',side_effect=run):
  m.apply(state,Path('/transaction'))
 assert not fw.called
 assert state['state']=='applied',state
 stop=next(i for i,x in enumerate(events) if x[:3]==('systemctl','stop',unit_name))
 commits=[i for i,x in enumerate(events) if x[0]=='save' and x[1] in ('installations.json','material.json')]
 start=next(i for i,x in enumerate(events) if x[0]=='install')
 assert commits and stop<min(commits)<start,events
 assert registry['other']==other
finally:holder.close();other_holder.close()
print('ok')`).trim(), 'ok');
});

test('a newly occupied different target port leaves the existing media service and profile untouched', () => {
    assert.equal(python(`
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
own=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);own.bind(('0.0.0.0',0))
foreign=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);foreign.bind(('0.0.0.0',0))
old_transport={'mode':'plain-udp','host':'gateway.example.test','port':own.getsockname()[1]}
transport=dict(old_transport,mode='direct-udp',port=foreign.getsockname()[1])
old={'pbxId':pbx,'plan':plan,'mediaTransport':old_transport}
state={'role':'gateway','pbxId':pbx,'state':'prepared','fingerprint':'fingerprint',
       'oldEntry':old,'document':{'plan':plan,'transport':transport}}
def forbidden(*args,**kwargs):raise AssertionError('occupied different port must not interrupt or mutate the existing link')
try:
 with patch.object(m,'media_paths',return_value=(Path('/media'),Path('/units/media.service'))), \
      patch.object(m,'fingerprint',return_value='fingerprint'), \
      patch.object(m,'read_json',return_value={'selected':old}), \
      patch.object(m,'save_json',side_effect=forbidden),patch.object(m,'run',side_effect=forbidden), \
      patch.object(m,'installer',return_value=SimpleNamespace(install=forbidden)):
  try:m.apply(state,Path('/transaction'))
  except OSError:pass
  else:raise AssertionError('occupied foreign target was accepted')
 assert state['state']=='prepared'
 assert own.getsockname()[1]==old_transport['port']
 assert old['mediaTransport']==old_transport
finally:own.close();foreign.close()
print('ok')`).trim(), 'ok');
});

test('apply rolls back before media start when a foreign socket still holds the port after its own stop', () => {
    assert.equal(python(`
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
own=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);own.bind(('0.0.0.0',0));old_port=own.getsockname()[1]
foreign=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);port=old_port
transport={'mode':'direct-udp','host':'gateway.example.test','port':port}
old={'pbxId':pbx,'plan':plan,'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':old_port},'secretHash':'x'}
old_material={'udp.key':'a'*64+chr(10),'readinessKey':'r'*43}
new_material={'ca.crt':'ca','gateway.crt':'cert','gateway.key':'key','tls-crypt.key':'tc','readinessKey':'r'*43}
registry={'selected':old};saved={};events=[]
unit_name='sokrat-media-'+pbx+'.service'
def run(argv,check=True):
 events.append(tuple(argv))
 if argv[:3]==['systemctl','stop',unit_name] and not own._closed:
  own.close();foreign.bind(('0.0.0.0',port))
 return SimpleNamespace(returncode=0)
def read(path,default=None):return registry if path.name=='installations.json' else old_material
def save(path,value):saved[path.name]=value
def install(document,role,start):raise AssertionError('media started despite occupied target port')
fake=SimpleNamespace(install=install)
state={'role':'gateway','pbxId':pbx,'state':'prepared','fingerprint':'fingerprint',
       'document':{'plan':plan,'transport':transport},'oldEntry':old,
       'oldMaterial':old_material,'newMaterial':new_material}
try:
 with patch.object(m,'media_paths',return_value=(Path('/media'),Path('/units')/unit_name)), \
      patch.object(m,'fingerprint',return_value='fingerprint'),patch.object(m,'read_json',side_effect=read), \
      patch.object(m,'save_json',side_effect=save),patch.object(m,'installer',return_value=fake), \
      patch.object(m,'restore_files'),patch.object(m,'reconcile_media_firewall'), \
      patch.object(m,'run',side_effect=run):
  try:m.apply(state,Path('/transaction'))
  except OSError:pass
  else:raise AssertionError('foreign UDP port accepted')
 assert state['state']=='rolled-back',state
 assert saved.get('installations.json')=={'selected':old},saved
 assert saved.get('material.json')==old_material
finally:foreign.close();own.close()
print('ok')`).trim(), 'ok');
});

test('rollback restores the exact previous plain profile files and removes generated TLS', () => {
    assert.equal(python(`
import os,socket,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
pbx='pbx_0123456789abcdef'; other_pbx='pbx_fedcba9876543210'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
other_plan=m.validate_plan(__import__('tunnel_media').allocation(other_pbx,4,'10.253.0.0/22'))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',0));port=s.getsockname()[1];s.close()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',0));other_port=s.getsockname()[1];s.close()
transport={'mode':'direct-udp','host':'gateway.example.test','port':port}
old={'pbxId':pbx,'plan':plan,'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':port},'secretHash':'x'}
other={'pbxId':other_pbx,'plan':other_plan,
       'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test','port':other_port}}
old_material={'udp.key':'a'*64+chr(10),'readinessKey':'r'*43}
new_material={'ca.crt':'ca','gateway.crt':'cert','gateway.key':'key','tls-crypt.key':'tc','readinessKey':'r'*43}
registry={'selected':dict(old,mediaTransport=transport),'other':other}
saved={};events=[]
state={'role':'gateway','pbxId':pbx,'state':'applied','transactionId':'tx','oldEntry':old,
       'oldMaterial':old_material,'newMaterial':new_material,
       'document':{'plan':plan,'transport':transport,'material':new_material}}
with tempfile.TemporaryDirectory() as root:
 root=Path(root);directory=root/'media'/pbx;destination=root/'transaction';original=destination/'old-media'
 directory.mkdir(parents=True);original.mkdir(parents=True)
 old_files={'udp.key':old_material['udp.key'],'link-up':'old-up','link-down':'old-down',
            'media.conf':'old-conf','plan.json':'old-plan','transport.json':'old-transport'}
 for name,value in old_files.items():
  (original/name).write_text(value);(directory/name).write_text(value)
 for name in ('ca.crt','gateway.crt','gateway.key','tls-crypt.key'):
  (directory/name).write_text('generated-'+name)
 (destination/'old-unit').write_text('old-unit')
 (root/'units').mkdir();(root/'units'/('sokrat-media-'+pbx+'.service')).write_text('generated-unit')
 def read(path,default=None):return registry if path.name=='installations.json' else new_material
 def save(path,value):saved[path.name]=value
 def run(argv,check=True):events.append(tuple(argv));return SimpleNamespace(returncode=0)
 def write(path,data,mode):
  Path(path).write_text(data);os.chmod(path,mode)
 installer=SimpleNamespace(write=write)
 with patch.object(m,'media_paths',return_value=(directory,root/'units'/('sokrat-media-'+pbx+'.service'))), \
      patch.object(m,'private_read',side_effect=lambda path:path.read_text()), \
      patch.object(m,'installer',return_value=installer),patch.object(m,'read_json',side_effect=read), \
      patch.object(m,'save_json',side_effect=save),patch.object(m,'run',side_effect=run), \
      patch.object(m,'reconcile_media_firewall') as fw:
  m.rollback(state,destination)
 assert not fw.called
 assert state['state']=='rolled-back'
 assert (directory/'udp.key').read_text()==old_files['udp.key']
 assert (directory/'media.conf').read_text()=='old-conf'
 assert (directory/'transport.json').read_text()=='old-transport'
 for name in ('ca.crt','gateway.crt','gateway.key','tls-crypt.key'):
  assert not (directory/name).exists(),name
 assert (root/'units'/('sokrat-media-'+pbx+'.service')).read_text()=='old-unit'
 assert saved['installations.json']=={'selected':old,'other':other}
 assert saved['material.json']==old_material
print('ok')`).trim(), 'ok');
});

test('prepare rejects a malformed old profile before writes or media stop', () => {
    assert.equal(python(`
import socket,tempfile
from pathlib import Path
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',0));port=s.getsockname()[1];s.close()
old={'pbxId':pbx,'plan':plan,'mediaTransport':{'mode':'plain-udp','host':'gateway.example.test'},'secretHash':'x'}
writes=[]
with tempfile.TemporaryDirectory() as root:
 m.BACKUPS=Path(root)
 def read(path,default=None):
  if path.name=='plan.json':return plan
  if path.name=='config.json':return {'publicHost':'gateway.example.test'}
  if path.name=='installations.json':return {'selected':old}
  raise AssertionError('read material before validating old profile')
 with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=lambda *a:writes.append(a)), \
      patch.object(m,'snapshot') as snapshot,patch.object(m,'run') as command:
  try:m.prepare('gateway',pbx,'malformed-old',transport_mode='direct-udp',transport_port=port)
  except ValueError:pass
  else:raise AssertionError('malformed old profile accepted')
  assert writes==[] and not snapshot.called and not command.called
print('ok')`).trim(), 'ok');
});

test('prepare refuses an already selected exact direct endpoint without rekeying', () => {
    assert.equal(python(`
import socket,tempfile
from pathlib import Path
from unittest.mock import patch
pbx='pbx_0123456789abcdef'
plan=m.validate_plan(__import__('tunnel_media').allocation(pbx,3,'10.253.0.0/22'))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',0));port=s.getsockname()[1];s.close()
transport={'mode':'direct-udp','host':'gateway.example.test','port':port}
old={'pbxId':pbx,'plan':plan,'mediaTransport':transport,'secretHash':'x'}
writes=[]
with tempfile.TemporaryDirectory() as root:
 m.BACKUPS=Path(root)
 def read(path,default=None):
  if path.name=='plan.json':return plan
  if path.name=='config.json':return {'publicHost':'gateway.example.test'}
  if path.name=='installations.json':return {'selected':old}
  raise AssertionError('read beyond selected-row validation')
 with patch.object(m,'read_json',side_effect=read),patch.object(m,'save_json',side_effect=lambda *a:writes.append(a)):
  try:m.prepare('gateway',pbx,'already-direct',transport_mode='direct-udp',transport_port=port)
  except ValueError:pass
  else:raise AssertionError('rekeyed an already selected endpoint')
assert writes==[],writes
print('ok')`).trim(), 'ok');
});
