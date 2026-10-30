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
    assert.match(configs.gateway, /remote-cert-tls server/);
    assert.match(configs.pbx, /remote-cert-tls client/);
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
