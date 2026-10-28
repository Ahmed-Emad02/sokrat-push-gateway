'use strict';
const { test } = require('node:test');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// Loads the cutover script as a module (main() is never called) and runs one
// assertion program in python3. Keeps every check on the real implementation.
const LOAD = `
import importlib.util
import json
spec = importlib.util.spec_from_file_location('cutover', 'scripts/enable-tenant-routing.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
`;

const SIP = `server {
    listen 8088;
    server_name gw.example;
    location = /ws {
        access_log off;
        limit_conn sokrat_ws 10;
        if ($http_upgrade !~* "^websocket$") { return 426; }
        proxy_pass http://10.0.0.5:8088/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $proxy_host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
    location / { return 404; }
}
`;

const PUSH = `server {
    location = /api/push/register-device {
        proxy_pass http://127.0.0.1:8095;
    }
    location = /api/push/remove-device {
        proxy_pass http://127.0.0.1:8095;
    }
    location = /api/mobile/ice {
        limit_req zone=push_reg burst=10 nodelay;
        proxy_pass http://127.0.0.1:8095;
    }
    location / { return 404; }
}`;

const STATE = `{
  "schemaVersion": 2,
  "pbx": [{"id": "pbx_a", "enabled": true, "mediaIps": ["10.0.0.2"],
           "management": {"approvalStatus": "approved", "extensionPolicyRequired": false}}],
  "devices": [{"id": "dev_1", "status": "approved", "pbxId": "pbx_a", "extension": "160",
               "enrollmentMode": "claim", "claimRedeemedAt": "2026-10-28T10:00:00.000Z",
               "secretHash": "${'a'.repeat(64)}"}]
}`;

const MANIFEST = `{
  "relays": {"pbx_a": {"host": "turn.example", "port": 3500,
                        "secretFile": "/var/lib/sokrat-gateway/secrets/pbx_a.secret",
                        "peerIps": ["10.0.0.2"]}},
  "hookHashes": {"pbx_a": "${'b'.repeat(64)}"}
}`;

function run(script) {
    execFileSync('python3', ['-c', LOAD + script], { cwd: ROOT, stdio: 'pipe' });
}

test('tenant nginx cutover is idempotent and refuses missing legacy routes', () => {
    run(`
sip = ${JSON.stringify('location = /ws { proxy_pass http://pbx.example:8088/ws; }')}
push = 'server {\\n' + ''.join('    location = ' + p + ' {\\n        proxy_pass http://127.0.0.1:8095;\\n    }\\n' for p in ('/api/push/register-device', '/api/push/remove-device', '/api/mobile/ice')) + '    location / { return 404; }\\n}'
a, b = m.render(sip, push)
assert '9097/ws' in a and b.count('return 410') == 3
assert m.render(a, b) == (a, b)
for invalid in ('server {}', push.replace('/api/mobile/ice', '/wrong')):
    try:
        m.render(sip, invalid)
    except ValueError:
        pass
    else:
        raise AssertionError('Unsafe configuration accepted')
`);
});

test('prepare stages the tenant API and leaves legacy routes alone', () => {
    run(`
push = ${JSON.stringify(PUSH)}
out = m.prepare(push)
assert out.count('location /api/gateway/') == 1
assert 'proxy_pass http://127.0.0.1:9097;' in out
assert 'return 410' not in out
assert out.count('location = /api/mobile/ice') == 1
assert m.prepare(out) == out
try:
    m.prepare('server {}')
except ValueError:
    pass
else:
    raise AssertionError('Unknown HTTP site accepted')
`);
});

test('coexist routes only ticketed /ws to the tenant runtime', () => {
    run(`
out, push = m.render_coexist(${JSON.stringify(SIP)}, ${JSON.stringify(PUSH)})
block = out[out.index('location = /ws'):]
assert 'set $sokrat_ws_upstream http://10.0.0.5:8088;' in block
assert 'set $sokrat_ws_upstream http://127.0.0.1:9097;' in block
assert 'proxy_pass $sokrat_ws_upstream$request_uri;' in block
# exactly one proxy_pass, and the bare legacy upgrade keeps the PBX upstream
assert block.count('proxy_pass') == 1
assert 'proxy_pass http://127.0.0.1:9097' not in block
assert 'proxy_next_upstream' not in out
# the tenant upstream is selected only after the ticket test
ticket_if = block.index('if ($arg_ticket != "")')
assert ticket_if < block.index('http://127.0.0.1:9097')
assert 'http://127.0.0.1:9097' not in block[:ticket_if]
# variable proxy_pass loses $proxy_host; the legacy Host is preserved explicitly
assert 'set $sokrat_ws_host 10.0.0.5:8088;' in block
assert 'proxy_set_header Host $sokrat_ws_host;' in block
assert 'proxy_set_header Upgrade $http_upgrade;' in block
assert 'limit_conn sokrat_ws 10;' in block
assert m.render_coexist(out, push) == (out, push)
`);
});

test('coexist never falls back on an invalid ticket and keeps legacy ICE/register', () => {
    run(`
out, push = m.render_coexist(${JSON.stringify(SIP)}, ${JSON.stringify(PUSH)})
block = out[out.index('location = /ws'):]
# an invalid ticket is answered by 9097 (403); there is no second upstream
assert block.count('set $sokrat_ws_upstream') == 2
assert 'proxy_pass $sokrat_ws_upstream$request_uri;' in block
assert 'error_page' not in block and 'proxy_intercept_errors' not in block
assert 'proxy_next_upstream' not in out
assert 'return 410' not in push
assert push.count('location = /api/mobile/ice') == 1
assert 'proxy_pass http://127.0.0.1:8095;' in push
assert 'location /api/gateway/' in push
`);
});

test('coexist refuses an unrecognized or already cut-over /ws site', () => {
    run(`
sip = ${JSON.stringify(SIP)}
for invalid in (
    sip.replace('proxy_http_version 1.1;', ''),
    sip.replace('http://10.0.0.5:8088/ws', 'http://127.0.0.1:9097/ws'),
    sip.replace('http://10.0.0.5:8088/ws', 'http://pbx.example:8088/ws'),
    sip + sip,
):
    try:
        m.render_coexist(invalid, ${JSON.stringify(PUSH)})
    except ValueError:
        pass
    else:
        raise AssertionError('Unsafe SIP site accepted')
out, _ = m.render_coexist(sip, ${JSON.stringify(PUSH)})
try:
    m.render(out, ${JSON.stringify(PUSH)})
except ValueError:
    pass
else:
    raise AssertionError('Full activation accepted a coexist site')
`);
});

test('readiness gate accepts an approved, provisioned deployment', () => {
    run(`
state = json.loads(${JSON.stringify(STATE)})
manifest = json.loads(${JSON.stringify(MANIFEST)})
assert m.validate_readiness(state, manifest) == []
# a disabled PBX needs no relay and is not gated
state['pbx'].append({'id': 'pbx_off', 'enabled': False, 'mediaIps': ['10.0.0.9']})
assert m.validate_readiness(state, manifest) == []
# invite enrollment holds its credential from approval, with no claim to redeem
state['devices'][0]['enrollmentMode'] = 'invite'
state['devices'][0]['claimRedeemedAt'] = None
assert m.validate_readiness(state, manifest) == []
`);
});

test('readiness gate blocks a missing approved claimed device', () => {
    run(`
state = json.loads(${JSON.stringify(STATE)})
manifest = json.loads(${JSON.stringify(MANIFEST)})
for devices in ([], [{**state['devices'][0], 'status': 'pending'}],
                [{**state['devices'][0], 'claimRedeemedAt': None}],
                [{**state['devices'][0], 'secretHash': None}],
                [{**state['devices'][0], 'pbxId': 'pbx_off'}]):
    state['devices'] = devices
    problems = m.validate_readiness(state, manifest)
    assert any('device' in p for p in problems), problems
`);
});

test('readiness gate blocks missing relays, bad hashes and media mismatches', () => {
    run(`
state = json.loads(${JSON.stringify(STATE)})
manifest = json.loads(${JSON.stringify(MANIFEST)})

missing = json.loads(json.dumps(manifest)); missing['relays'] = {}
assert any('relay' in p for p in m.validate_readiness(state, missing))

wrong_peers = json.loads(json.dumps(manifest)); wrong_peers['relays']['pbx_a']['peerIps'] = ['10.0.0.3']
assert any('mediaIps' in p for p in m.validate_readiness(state, wrong_peers))

no_peers = json.loads(json.dumps(manifest)); no_peers['relays']['pbx_a']['peerIps'] = []
assert any('peer' in p for p in m.validate_readiness(state, no_peers))

for hook in ({}, {'pbx_a': 'B' * 64}, {'pbx_a': 'b' * 63}, {'pbx_a': 7}):
    broken = json.loads(json.dumps(manifest)); broken['hookHashes'] = hook
    assert any('hook hash' in p for p in m.validate_readiness(state, broken)), hook

pending = json.loads(${JSON.stringify(STATE)})
pending['pbx'][0]['management']['approvalStatus'] = 'pending'
assert any('management approval' in p for p in m.validate_readiness(pending, manifest))

assert m.validate_readiness({}, manifest)
assert m.validate_readiness(state, {})
`);
});

test('env file parsing never sources or expands values', () => {
    run(`
values = m.parse_env_text('''CONTROL_DATA_FILE=/var/lib/sokrat-gateway/control.json
TENANT_RUNTIME_FILE="/var/lib/sokrat-gateway/tenant-runtime.json"
export EVIL=$(touch /tmp/sokrat-pwned)
INJECTED=ok; rm -rf /tmp/sokrat-pwned
NOT A LINE
# comment=1
''')
assert values['CONTROL_DATA_FILE'] == '/var/lib/sokrat-gateway/control.json'
assert values['TENANT_RUNTIME_FILE'] == '/var/lib/sokrat-gateway/tenant-runtime.json'
assert values['INJECTED'] == 'ok; rm -rf /tmp/sokrat-pwned'
assert 'EVIL' not in values
assert len(values) == 3, values
`);
});
