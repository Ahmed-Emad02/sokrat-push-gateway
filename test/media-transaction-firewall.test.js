'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('gateway apply opens and persists the UDP endpoint before starting the media link', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util, json, os, shutil, stat, tempfile
from pathlib import Path
from types import SimpleNamespace

source = Path.cwd()
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    scripts = root / 'scripts'; scripts.mkdir()
    for name in ('media-transport-transaction.py', 'media-udp-ports.py', 'tunnel_media.py'):
        shutil.copyfile(source / name, scripts / name)
    shutil.copyfile(source / 'media-udp-firewall.py', scripts / 'media-udp-firewall-actual.py')
    (scripts / 'media-udp-firewall.py').write_text('''#!/usr/bin/env python3
import os, runpy, sys
from pathlib import Path
os.geteuid = lambda: 0
here = Path(__file__).resolve().parent
sys.argv = [str(here / 'media-udp-firewall-actual.py')] + sys.argv[1:] + [
    '--manifest', os.environ['SOKRAT_TEST_MANIFEST'],
    '--registry', os.environ['SOKRAT_TEST_REGISTRY'],
]
runpy.run_path(str(here / 'media-udp-firewall-actual.py'), run_name='__main__')
''')
    spec = importlib.util.spec_from_file_location('transaction', scripts / 'media-transport-transaction.py')
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

    bin_dir = root / 'bin'; bin_dir.mkdir()
    events = root / 'events.log'; events.write_text('')
    status = root / 'ufw.status'; status.write_text(
        'Status: active\\n\\nTo Action From\\n-- ------ ----\\n22/tcp ALLOW Anywhere\\n')
    allowed = root / 'allowed'; allowed.write_text('')
    os.environ['SOKRAT_TEST_LOG'] = str(events)
    os.environ['SOKRAT_TEST_STATUS'] = str(status)
    os.environ['SOKRAT_TEST_ALLOWED'] = str(allowed)
    (bin_dir / 'ufw').write_text('''#!/bin/sh
set -eu
echo "ufw $*" >> "$SOKRAT_TEST_LOG"
if [ "$1" = status ]; then cat "$SOKRAT_TEST_STATUS"; exit 0; fi
if [ "$1" = allow ]; then echo "$2 ALLOW Anywhere" >> "$SOKRAT_TEST_STATUS"; echo "$2" >> "$SOKRAT_TEST_ALLOWED"; exit 0; fi
exit 0
''')
    (bin_dir / 'systemctl').write_text('''#!/bin/sh
echo "systemctl $*" >> "$SOKRAT_TEST_LOG"
exit 0
''')
    os.chmod(bin_dir / 'ufw', 0o755)
    os.chmod(bin_dir / 'systemctl', 0o755)
    os.environ['PATH'] = str(bin_dir) + os.pathsep + os.environ['PATH']

    plan = {'pbxId': 'pbx_0123456789abcdef', 'slot': 3, 'interface': 'skm3',
            'gatewayIp': '10.253.0.13', 'pbxIp': '10.253.0.14',
            'remoteMediaPort': 22003, 'localMediaPort': 17001}
    transport = {'mode': 'plain-udp', 'host': 'gateway.example.test', 'port': 26154}
    old = {'pbxId': plan['pbxId'], 'plan': plan, 'mediaTransport': None}
    enrollment = root / 'enrollment'; enrollment.mkdir()
    (enrollment / 'installations.json').write_text(json.dumps({'fixture': old}))
    material_dir = enrollment / plan['pbxId']; material_dir.mkdir()
    (material_dir / 'material.json').write_text(json.dumps({'m': 1}))
    manifest = root / 'host-firewall.json'
    manifest.write_text(json.dumps({'configured': True, 'manager': 'ufw', 'sshPort': 22,
                                    'tls': True, 'ports': ['22/tcp', '3500:3654/udp'],
                                    'updatedAt': '2026-01-01T00:00:00+00:00'}))
    media_root = root / 'media'; units = root / 'units'

    def read_json(file, default=None):
        return json.loads(Path(file).read_text())

    def save_json(file, value):
        Path(file).write_text(json.dumps(value, sort_keys=True) + '\\n')

    def install(document, role, start):
        current = json.loads(manifest.read_text()).get('mediaUdpPorts')
        with events.open('a') as stream:
            stream.write('install %s %s media=%s\\n' % (role, start, current))

    m.ENROLLMENT = enrollment
    m.SETTINGS = root / 'settings.json'
    m.BACKUPS = root / 'backups'
    m.read_json = read_json
    m.save_json = save_json
    m.media_paths = lambda pbx: (media_root / pbx, units / (pbx + '.service'))
    m.fingerprint = lambda directory, unit: 'fixture'
    m.check_gateway_endpoint = lambda *args, **kwargs: None
    m.installer = lambda: SimpleNamespace(install=install)
    os.environ['SOKRAT_TEST_MANIFEST'] = str(manifest)
    os.environ['SOKRAT_TEST_REGISTRY'] = str(enrollment / 'installations.json')

    state = {'role': 'gateway', 'pbxId': plan['pbxId'], 'state': 'prepared',
             'fingerprint': 'fixture', 'document': {'plan': plan, 'transport': transport},
             'oldEntry': old, 'oldMaterial': {'m': 1}, 'newMaterial': {'m': 2}}
    transaction = root / 'transaction'; transaction.mkdir()
    m.apply(state, transaction)

    lines = events.read_text().splitlines()
    stop = next(index for index, line in enumerate(lines) if line.startswith('systemctl stop'))
    allow = next(index for index, line in enumerate(lines) if line == 'ufw allow 26154/udp')
    started = next(index for index, line in enumerate(lines) if line.startswith('install gateway True'))
    assert stop < allow < started, lines
    assert lines[started].endswith("media=['26154/udp']"), lines[started]
    assert json.loads(manifest.read_text())['mediaUdpPorts'] == ['26154/udp']
    assert '26154/udp' in status.read_text()

    before = events.read_text()
    m.reconcile_media_firewall('pbx')
    assert events.read_text() == before, 'PBX role invoked the gateway firewall manager'
print('ok')
`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 30000 });
    assert.equal(output.trim(), 'ok');
});
