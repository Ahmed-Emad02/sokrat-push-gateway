'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function python(body) {
    return execFileSync('python3', ['-B', '-c', body], {
        cwd: path.join(__dirname, '../scripts'), encoding: 'utf8',
    });
}

test('TLS media slots have disjoint interfaces, IP pairs and reverse loopback ports', () => {
    const rows = JSON.parse(python(`import json,tunnel_media as m
print(json.dumps([m.allocation('pbx_0123456789abcdef', n, '10.253.0.0/22') for n in range(155)]))`));
    for (const key of ['gatewayIp', 'pbxIp', 'interface', 'remoteMediaPort']) {
        assert.equal(new Set(rows.map(row => row[key])).size, 155);
    }
    assert.equal(new Set(rows.flatMap(row => [row.gatewayIp, row.pbxIp])).size, 310);
});

test('TLS media config uses mutual certificate verification and no office/default routes', () => {
    const configs = JSON.parse(python(`import json,tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
print(json.dumps({r:m.media_config(p,r,'/etc/sokrat/media/pbx_0123456789abcdef') for r in ('gateway','pbx')}))`));
    assert.match(configs.gateway, /remote 127\.0\.0\.1 22003/);
    assert.match(configs.pbx, /local 127\.0\.0\.1/);
    assert.match(configs.gateway, /^proto tcp-client$/m);
    assert.match(configs.pbx, /^proto tcp-server$/m);
    assert.match(configs.gateway, /remote-cert-tls server/);
    assert.match(configs.pbx, /remote-cert-tls client/);
    assert.match(configs.pbx, /^server-poll-timeout 0$/m);
    assert.doesNotMatch(configs.gateway, /server-poll-timeout/);
    for (const config of Object.values(configs)) {
        assert.match(config, /verify-x509-name pbx_0123456789abcdef-/);
        assert.match(config, /tls-version-min 1\.2/);
        assert.doesNotMatch(config, /redirect-gateway|^push |^route /m);
        assert.match(config, /route-noexec/);
    }
});

test('TLS media allocator rejects unbounded slots, public networks and injected identities', () => {
    assert.equal(python(`import tunnel_media as m
bad=[('pbx_0123456789abcdef',155,'10.253.0.0/22'),('pbx_0123456789abcdef',-1,'10.253.0.0/22'),('pbx_0123456789abcdef',0,'8.8.0.0/16'),('pbx_0123456789abcdef',0,'127.0.0.0/8'),('pbx_0123456789abcdef',0,'169.254.0.0/16'),('bad;id',0,'10.253.0.0/22')]
for args in bad:
 try: m.allocation(*args); raise AssertionError('accepted unsafe input')
 except ValueError: pass
print('ok')`).trim(), 'ok');
});

test('media config supports vendor OpenVPN 2.4 without unrecognized 2.5/2.6 options', () => {
    const config = python(`import tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
print(m.media_config(p,'pbx','/etc/sokrat/media/pbx_0123456789abcdef',(2,4)))`);
    assert.match(config, /cipher AES-256-GCM/);
    assert.match(config, /ncp-ciphers AES-256-GCM:AES-128-GCM/);
    assert.doesNotMatch(config, /data-ciphers|disable-dco/);
});

test('config and privileged helper reject altered plans before interpolating input', () => {
    assert.equal(python(`import tunnel_media as m
for field,value in [('interface','skm0;id'),('pbxIp','8.8.8.8'),('remoteMediaPort',80),('slot',True)]:
 p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22'); p[field]=value
 for call in [lambda:m.media_config(p,'pbx','/etc/sokrat/media'),lambda:m.link_script(p,'pbx',True)]:
  try: call(); raise AssertionError('accepted unsafe plan')
  except ValueError: pass
print('ok')`).trim(), 'ok');
});

test('media certificates are tenant-specific, role-scoped and exclude CA private key', () => {
    assert.equal(python(`import tunnel_media as m,tunnel_media_material as k
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
a=k.new_material(p); b=k.new_material(p)
assert a['ca.crt']!=b['ca.crt'] and a['pbx.key']!=b['pbx.key']
assert 'ca.key' not in a
assert 'gateway.key' not in k.for_role(a,'pbx')
for role,usage in [('pbx',ExtendedKeyUsageOID.SERVER_AUTH),('gateway',ExtendedKeyUsageOID.CLIENT_AUTH)]:
 c=x509.load_pem_x509_certificate(a[role+'.crt'].encode())
 assert c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value==p['pbxId']+'-'+role
 assert list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[usage]
print('ok')`).trim(), 'ok');
});

test('media helper permits only tenant UDP media and drops host/forwarded traffic', () => {
    const script = python(`import tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
print(m.link_script(p,'gateway',True))`);
    assert.match(script, /-s 10\.253\.0\.14 -d 10\.253\.0\.13 -p udp --sport 10000:20000 --dport 50300:50399 -j ACCEPT/);
    assert.match(script, /-A SKM3 -j DROP/);
    assert.match(script, /FORWARD -i skm3 -j DROP/);
    assert.match(script, /FORWARD -o skm3 -j DROP/);
    assert.doesNotMatch(script, /MASQUERADE|ip_forward|default|flush|iptables -F/);
    assert.match(script, /ip link set dev skm3 mtu 1400 up/);
});

test('tenant TURN config can bind its own media link without changing other tenants', () => {
    assert.equal(python(`import importlib.util
s=importlib.util.spec_from_file_location('sync','sync-tenant-runtime.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t={'pbxId':'fixture','listenerPort':3503,'relayMinPort':50300,'relayMaxPort':50399,'slug':'fixture','peerIps':['10.253.0.14']}
c={'listen_ip':'0.0.0.0','relay_ip':'100.64.0.1'}
assert 'relay-ip=100.64.0.1\\n' in m.build_conf(t,'fixture',c)
t['relayIp']='10.253.0.13'
assert 'relay-ip=10.253.0.13\\n' in m.build_conf(t,'fixture',c)
assert 'allowed-peer-ip=10.253.0.14\\n' in m.build_conf(t,'fixture',c)
print('ok')`).trim(), 'ok');
});

test('media installer verifies certificate signatures, not only matching issuer names', () => {
    assert.equal(python(`import importlib.util,tunnel_media as m,tunnel_media_material as k
s=importlib.util.spec_from_file_location('installer','install-media-link.py')
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
a=k.new_material(p);b=k.new_material(p)
material=k.for_role(a,'pbx');i.validate_material(material,p,'pbx')
material['ca.crt']=b['ca.crt']
try:i.validate_material(material,p,'pbx');raise AssertionError('accepted foreign CA with same subject')
except Exception as e:
 assert not isinstance(e,AssertionError)
print('ok')`).trim(), 'ok');
});

test('TURN migration removes old peer rules on their original address and interface', () => {
    assert.equal(python(`import importlib.util
from unittest.mock import patch
from types import SimpleNamespace
s=importlib.util.spec_from_file_location('sync','sync-tenant-runtime.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
from pathlib import Path
t={'user':'fixture','secretDir':Path('/etc/turn/fixture'),'secret':'a'*64,
 'secretFile':Path('/etc/turn/fixture/secret'),'confFile':Path('/etc/turn/fixture/turnserver.conf'),
 'previousPeers':['100.64.0.2'],'peerIps':['10.253.0.14'],'relayIp':'10.253.0.13','mediaIface':'skm3',
 'pbxId':'fixture','listenerPort':3503,'relayMinPort':50300,'relayMaxPort':50399,'slug':'fixture'}
c={'turn_root':Path('/etc/turn'),'service_uid':None,'service_user':'fixture','firewall':True,
 'iface':'tailscale0','relay_ip':'100.64.0.1','listen_ip':'0.0.0.0'}
state={'config':c,'previousRelayIp':'100.64.0.1','allocations':{'fixture':{}}}
with patch.object(m,'ensure_service_user'),patch.object(m.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=1)),patch.object(m,'ensure_dir'),patch.object(m,'ensure_file_metadata'),patch.object(m,'check_regular_or_absent',return_value=None),patch.object(m,'atomic_write'),patch.object(m,'listener_firewall'),patch.object(m,'peer_firewall') as rules:
 m.provision_tenant(t,state,[])
 assert rules.call_args_list[0].args[1:3]==('10.253.0.14',True)
 assert rules.call_args_list[1].args[1:3]==('100.64.0.2',False)
 assert rules.call_args_list[1].kwargs=={'relay_ip':'100.64.0.1','iface':'tailscale0'}
print('ok')`).trim(), 'ok');
});

test('VPN-free TURN unit has no Tailscale ordering dependency', () => {
    assert.equal(python(`import importlib.util
s=importlib.util.spec_from_file_location('sync','sync-tenant-runtime.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
from pathlib import Path
unit=m.build_unit({'turn_root':Path('/etc/sokrat/turn'),'transport':'openvpn-frp'})
assert 'After=network-online.target' in unit
assert 'tailscaled.service' not in unit
print('ok')`).trim(), 'ok');
});

test('legacy TURN unit retains the legacy Tailscale ordering dependency', () => {
    assert.equal(python(`import importlib.util
s=importlib.util.spec_from_file_location('sync','sync-tenant-runtime.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
from pathlib import Path
unit=m.build_unit({'turn_root':Path('/etc/sokrat/turn'),'transport':'legacy'})
assert 'After=network-online.target tailscaled.service' in unit
print('ok')`).trim(), 'ok');
});

test('direct UDP media swaps TLS roles and endpoints between gateway and PBX', () => {
    const configs = JSON.parse(python(`import json,tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
t={'mode':'direct-udp','host':'media.example.net','port':26003}
print(json.dumps({r:m.media_config(p,r,'/etc/sokrat/media/pbx_0123456789abcdef',(2,6),t) for r in ('gateway','pbx')}))`));
    assert.match(configs.gateway, /^tls-server$/m);
    assert.match(configs.gateway, /^local 0\.0\.0\.0$/m);
    assert.match(configs.gateway, /^port 26003$/m);
    assert.match(configs.gateway, /^remote-cert-tls client$/m);
    assert.match(configs.gateway, /verify-x509-name pbx_0123456789abcdef-pbx name/);
    assert.match(configs.gateway, /^server-poll-timeout 0$/m);
    assert.match(configs.pbx, /^tls-client$/m);
    assert.match(configs.pbx, /^nobind$/m);
    assert.match(configs.pbx, /^remote media\.example\.net 26003$/m);
    assert.match(configs.pbx, /^remote-cert-tls server$/m);
    assert.match(configs.pbx, /verify-x509-name pbx_0123456789abcdef-gateway name/);
    assert.doesNotMatch(configs.pbx, /server-poll-timeout/);
    assert.doesNotMatch(configs.gateway, /127\.0\.0\.1|17001|22003/);
    assert.doesNotMatch(configs.pbx, /127\.0\.0\.1|17001|22003/);
    assert.match(configs.gateway, /^ifconfig 10\.253\.0\.13 10\.253\.0\.14$/m);
    assert.match(configs.pbx, /^ifconfig 10\.253\.0\.14 10\.253\.0\.13$/m);
    for (const config of Object.values(configs)) {
        assert.match(config, /^dev skm3$/m);
        assert.match(config, /^ca \/etc\/sokrat\/media\/pbx_0123456789abcdef\/ca\.crt$/m);
        assert.match(config, /tls-crypt \/etc\/sokrat\/media\/pbx_0123456789abcdef\/tls-crypt\.key/);
        assert.match(config, /cipher AES-256-GCM/);
        assert.doesNotMatch(config, /redirect-gateway|^push |^route /m);
    }
});

test('direct UDP media keeps vendor OpenVPN 2.4 without 2.5-only options', () => {
    const config = python(`import tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',0,'10.253.0.0/22')
t={'mode':'direct-udp','host':'203.0.113.7','port':26000}
print(m.media_config(p,'gateway','/etc/sokrat/media/pbx_0123456789abcdef',(2,4),t))`);
    assert.match(config, /^port 26000$/m);
    assert.match(config, /^tls-server$/m);
    assert.match(config, /ncp-ciphers AES-256-GCM:AES-128-GCM/);
    assert.doesNotMatch(config, /data-ciphers|disable-dco|^remote /m);
});

test('media transport accepts a bounded explicit UDP endpoint', () => {
    assert.equal(python(`import tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
ok=[{'mode':'direct-udp','host':'203.0.113.7','port':26003},
    {'mode':'direct-udp','host':'media.example.net','port':26154},
    {'mode':'direct-udp','host':'a','port':65535}]
bad=[{'mode':'direct-udp','host':'media.example.net','port':1023},
     {'mode':'direct-udp','host':'media.example.net','port':65536},
     {'mode':'direct-udp','host':'media.example.net','port':True},
     {'mode':'direct-udp','host':'media.example.net','port':'26003'},
     {'mode':'direct-udp','host':'media.example.net','port':26003.0},
     {'mode':'direct-upd','host':'media.example.net','port':26003},
     {'mode':True,'host':'media.example.net','port':26003},
     {'mode':'direct-udp','host':'media.example.net','port':26003,'extra':1},
     {'mode':'direct-udp','host':'media.example.net'},
     {'host':'media.example.net','port':26003},
     {'mode':'direct-udp','host':'media.example.net\\nremote evil 1','port':26003},
     {'mode':'direct-udp','host':'media example.net','port':26003},
     {'mode':'direct-udp','host':'media.example.net\\n','port':26003},
     {'mode':'direct-udp','host':'media.example.net;id','port':26003},
     {'mode':'direct-udp','host':'media.example.net#x','port':26003},
     {'mode':'direct-udp','host':'media.example.net,udp4','port':26003},
     {'mode':'direct-udp','host':'-bad.example.net','port':26003},
     {'mode':'direct-udp','host':'bad-.example.net','port':26003},
     {'mode':'direct-udp','host':'media..example.net','port':26003},
     {'mode':'direct-udp','host':'999.1.1.1','port':26003},
     {'mode':'direct-udp','host':'','port':26003},
     {'mode':'direct-udp','host':26003,'port':26003}]
for t in ok:
 assert m.validate_transport(t,p)==t
for t in bad:
 try: m.validate_transport(t,p); raise AssertionError('accepted bad transport: %r' % (t,))
 except ValueError: pass
for t in ([], 'direct-udp', 1):
 try: m.validate_transport(t,p); raise AssertionError('accepted non-dict transport')
 except ValueError: pass
assert m.validate_transport(None,p) is None
q=m.allocation('pbx_0123456789abcdef',0,'10.253.0.0/22')
assert m.validate_transport({'mode':'direct-udp','host':'h.example','port':26000},q)['port']==26000
r=m.allocation('pbx_0123456789abcdef',154,'10.253.0.0/22')
assert m.validate_transport({'mode':'direct-udp','host':'h.example','port':26154},r)['port']==26154
print('ok')`).trim(), 'ok');
});

test('installer refuses an injected transport before querying openvpn or writing files', () => {
    assert.equal(python(`import importlib.util
from unittest.mock import patch
import tunnel_media as m
s=importlib.util.spec_from_file_location('installer','install-media-link.py')
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
calls=[]
def fail(*args,**kwargs):
 calls.append(args)
 raise AssertionError('side effect before transport validation')
for bad in [{'mode':'direct-udp','host':'media.example.net\\nremote 1.2.3.4 1','port':26003},
            {'mode':'direct-udp','host':'media.example.net','port':26004},
            {'mode':'frp','host':'media.example.net','port':26003}]:
 with patch.object(i.os,'geteuid',lambda:0),patch.object(i,'version',fail),patch.object(i,'private_directory',fail),patch.object(i,'write',fail):
  try: i.install({'plan':p,'transport':bad,'material':{}},'gateway')
  except ValueError: pass
  else: raise AssertionError('accepted invalid transport')
assert calls==[]
print('ok')`).trim(), 'ok');
});

test('direct and legacy media certificates are not interchangeable', () => {
    assert.equal(python(`import importlib.util
import tunnel_media as m,tunnel_media_material as k
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
s=importlib.util.spec_from_file_location('installer','install-media-link.py')
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
t={'mode':'direct-udp','host':'media.example.net','port':26003}
direct=k.new_material(p,t); legacy=k.new_material(p)
for role,usage in [('gateway',ExtendedKeyUsageOID.SERVER_AUTH),('pbx',ExtendedKeyUsageOID.CLIENT_AUTH)]:
 c=x509.load_pem_x509_certificate(direct[role+'.crt'].encode())
 assert list(c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)==[usage]
i.validate_material(k.for_role(direct,'gateway'),p,'gateway',t)
i.validate_material(k.for_role(direct,'pbx'),p,'pbx',t)
i.validate_material(k.for_role(legacy,'gateway'),p,'gateway')
i.validate_material(k.for_role(legacy,'pbx'),p,'pbx')
def refused(material,role,transport=None):
 try: i.validate_material(material,p,role,transport)
 except ValueError: return
 raise AssertionError('accepted mismatched media material')
refused(k.for_role(legacy,'gateway'),'gateway',t)
refused(k.for_role(direct,'gateway'),'gateway')
refused(k.for_role(direct,'pbx'),'pbx')
refused(k.for_role(legacy,'pbx'),'pbx',t)
refused(k.for_role(direct,'pbx'),'gateway',t)
refused(k.for_role(direct,'gateway'),'pbx',t)
foreign=m.allocation('pbx_fedcba9876543210',3,'10.253.0.0/22')
refused(k.for_role(k.new_material(foreign,t),'gateway'),'gateway',t)
print('ok')`).trim(), 'ok');
});

test('plain UDP transport keeps host validation and unprivileged port boundaries', () => {
    assert.equal(python(`import tunnel_media as m
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
ok=[{'mode':'plain-udp','host':'203.0.113.7','port':26003},
    {'mode':'plain-udp','host':'media.example.net','port':26154}]
bad=[{'mode':'plain-upd','host':'media.example.net','port':26003},
     {'mode':{},'host':'media.example.net','port':26003},
     {'mode':[],'host':'media.example.net','port':26003},
     {'mode':'plain-udp','host':'media.example.net','port':1023},
     {'mode':'plain-udp','host':'media.example.net','port':True},
     {'mode':'plain-udp','host':'media.example.net\\nremote 1.2.3.4 1','port':26003},
     {'mode':'plain-udp','host':'media.example.net','port':26003,'extra':1},
     {'mode':'plain-udp','host':'media.example.net'}]
for t in ok:
 assert m.validate_transport(t,p)==t
for t in bad:
 try: m.validate_transport(t,p); raise AssertionError('accepted bad plain transport: %r' % (t,))
 except ValueError: pass
print('ok')`).trim(), 'ok');
});

test('plain material is one role-independent key and its config is JSON with derived paths', () => {
    const out = JSON.parse(python(`import json,tunnel_media as m,tunnel_media_material as k
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
t={'mode':'plain-udp','host':'media.example.net','port':26003}
a=k.new_material(p,t)
assert set(a)=={'udp.key'}
assert len(a['udp.key'])==65 and a['udp.key'].endswith('\\n')
assert all(c in '0123456789abcdef' for c in a['udp.key'][:-1])
full=dict(a,readinessKey='r'*43)
assert k.for_role(full,'gateway')==a and k.for_role(full,'pbx')==a
legacy=k.new_material(p)
legacy['readinessKey']='r'*43
assert set(k.for_role(legacy,'gateway'))=={'ca.crt','gateway.crt','gateway.key','tls-crypt.key'}
assert set(k.for_role(legacy,'pbx'))=={'ca.crt','pbx.crt','pbx.key','tls-crypt.key'}
d='/etc/sokrat/media/'+p['pbxId']
c={r:json.loads(m.media_config(p,r,d,transport=t)) for r in ('gateway','pbx')}
for r in c:
 assert set(c[r])=={'role','plan','transport','keyFile','up','down'},c[r]
 assert c[r]['role']==r and c[r]['plan']==p and c[r]['transport']==t
 assert c[r]['keyFile']==d+'/udp.key'
 assert c[r]['up']==d+'/link-up' and c[r]['down']==d+'/link-down'
try: m.media_config(p,'root',d,transport=t); raise AssertionError('accepted unknown plain role')
except ValueError: pass
assert __import__('re').fullmatch(r'[a-f0-9]{64}\\n',a['udp.key'])
print(json.dumps({'config':c}))`));
    assert.doesNotMatch(JSON.stringify(out.config), /BEGIN|tls-crypt|openvpn|remote /i);
    for (const role of ['gateway', 'pbx']) {
        assert.deepEqual(Object.keys(out.config[role]).sort(),
            ['down', 'keyFile', 'plan', 'role', 'transport', 'up']);
        assert.equal(out.config[role].role, role);
        assert.equal(out.config[role].plan.pbxId, 'pbx_0123456789abcdef');
        assert.equal(out.config[role].keyFile, '/etc/sokrat/media/pbx_0123456789abcdef/udp.key');
        assert.equal(out.config[role].up, '/etc/sokrat/media/pbx_0123456789abcdef/link-up');
    }
});

test('plain installer rejects malformed or mixed material before privileged writes', () => {
    assert.equal(python(`import importlib.util
from unittest.mock import patch
import tunnel_media as m,tunnel_media_material as k
s=importlib.util.spec_from_file_location('installer','install-media-link.py')
i=importlib.util.module_from_spec(s);s.loader.exec_module(i)
p=m.allocation('pbx_0123456789abcdef',3,'10.253.0.0/22')
t={'mode':'plain-udp','host':'media.example.net','port':26003}
good=k.new_material(p,t)
i.validate_material(good,p,'gateway',t);i.validate_material(good,p,'pbx',t)
def refused(material):
 try:i.validate_material(material,p,'gateway',t)
 except ValueError:return
 raise AssertionError('accepted malformed plain material')
for bad in [{},{'udp.key':'a'*64},
            {'udp.key':'A'*64+'\\n'},{'udp.key':'g'*64+'\\n'},
            {'udp.key':good['udp.key']+'\\n'},
            {'udp.key':good['udp.key'],'readinessKey':'r'*43},
            {'udp.key':good['udp.key'],'ca.crt':'x'}]:
 refused(bad)
refused(k.new_material(p))
refused(k.for_role(k.new_material(p),'gateway'))
calls=[]
def fail(*args,**kwargs):
 calls.append(args);raise AssertionError('side effect before material validation')
with patch.object(i.os,'geteuid',lambda:0),patch.object(i,'version',fail),patch.object(i,'private_directory',fail),patch.object(i,'write',fail):
 try:i.install({'plan':p,'transport':t,'material':{'udp.key':'a'*63+'\\n'}},'gateway')
 except ValueError:pass
 else:raise AssertionError('accepted malformed plain key')
assert calls==[]
print('ok')`).trim(), 'ok');
});

