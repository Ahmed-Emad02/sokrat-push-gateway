'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

test('media installer materializes fresh legacy, existing managed, plain and refuses unmanaged state', () => {
    const output = execFileSync('python3', ['-B', '-c', `
import importlib.util, json, os, stat, sys, tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tunnel_media as media
import tunnel_media_material as material
spec = importlib.util.spec_from_file_location('installer', 'install-media-link.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
real_lstat = Path.lstat
def owned(self):
    info = real_lstat(self)
    if stat.S_ISDIR(info.st_mode):
        mode = stat.S_IFDIR | 0o755
    else:
        mode = stat.S_IFREG | (stat.S_IMODE(info.st_mode) & ~0o022)
    return SimpleNamespace(st_mode=mode, st_uid=0, st_size=info.st_size,
                           st_nlink=info.st_nlink)
def command(argv, **kwargs):
    commands.append(list(argv))
    return SimpleNamespace(returncode=0)
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); media_root = root / 'media'; unit_root = root / 'units'
    daemon = root / 'udp-media-link.py'; daemon.write_text('#!/usr/bin/python3\\n'); os.chmod(daemon, 0o755)
    commands = []
    plan = media.allocation('pbx_0123456789abcdef', 3, '10.253.0.0/22')
    legacy = material.new_material(plan)
    with patch.object(Path, 'lstat', owned), patch.object(installer, 'ROOT', media_root), \\
         patch.object(installer, 'UNIT_ROOT', unit_root), patch.object(installer.os, 'geteuid', lambda: 0), \\
         patch.object(installer, 'version', lambda: (2, 6)), patch.object(installer, 'link_daemon', lambda: daemon), \\
         patch.object(installer, 'openvpn_binary', lambda: '/usr/sbin/openvpn'), \\
         patch.object(installer.subprocess, 'run', side_effect=command):
        result = installer.install({'plan': plan, 'material': material.for_role(legacy, 'gateway')},
                                   'gateway', True)
        directory = media_root / plan['pbxId']
        unit = unit_root / ('sokrat-media-' + plan['pbxId'] + '.service')
        names = {entry.name for entry in directory.iterdir()}
        assert result['transport'] is None and result['started'] is True
        assert names == {'ca.crt', 'gateway.crt', 'gateway.key', 'tls-crypt.key',
                         'link-up', 'link-down', 'media.conf', 'plan.json', 'transport.json'}
        assert json.loads((directory / 'transport.json').read_text()) is None
        assert json.loads((directory / 'plan.json').read_text()) == plan
        assert 'ExecStart=/usr/sbin/openvpn --config ' + str(directory / 'media.conf') in unit.read_text()
        assert commands[-1] == ['systemctl', 'restart', unit.name]
        before = {entry.name: entry.read_text() for entry in directory.iterdir()}
        commands.clear()
        installer.install({'plan': plan, 'material': material.for_role(legacy, 'gateway')},
                          'gateway', True)
        assert {entry.name: entry.read_text() for entry in directory.iterdir()} == before
        assert commands[-1] == ['systemctl', 'start', unit.name]
        assert not any(item[:2] == ['systemctl', 'restart'] for item in commands)

        unmanaged_plan = media.allocation('pbx_fedcba9876543210', 4, '10.253.0.0/22')
        unmanaged = unit_root / ('sokrat-media-' + unmanaged_plan['pbxId'] + '.service')
        unmanaged.write_text('custom unit')
        try:
            installer.install({'plan': unmanaged_plan,
                               'material': material.for_role(material.new_material(unmanaged_plan), 'gateway')},
                              'gateway')
        except ValueError:
            pass
        else:
            raise AssertionError('accepted an unmanaged media unit')
        assert not any(entry.is_file() for entry in (media_root / unmanaged_plan['pbxId']).iterdir())

        plain_plan = media.allocation('pbx_0011223344556677', 5, '10.253.0.0/22')
        transport = {'mode': 'plain-udp', 'host': 'gateway.example.test', 'port': 26154}
        plain = material.new_material(plain_plan, transport)
        result = installer.install({'plan': plain_plan, 'transport': transport,
                                    'material': material.for_role(plain, 'gateway')}, 'gateway', True)
        plain_directory = media_root / plain_plan['pbxId']
        plain_unit = unit_root / ('sokrat-media-' + plain_plan['pbxId'] + '.service')
        assert result['transport'] == transport
        assert {entry.name for entry in plain_directory.iterdir()} == {
            'udp.key', 'link-up', 'link-down', 'media.conf', 'plan.json', 'transport.json'}
        assert json.loads((plain_directory / 'transport.json').read_text()) == transport
        configuration = json.loads((plain_directory / 'media.conf').read_text())
        assert configuration['transport'] == transport and configuration['role'] == 'gateway'
        assert configuration['keyFile'] == str(plain_directory / 'udp.key')
        assert (plain_directory / 'udp.key').read_text() == plain['udp.key']
        unit_text = plain_unit.read_text()
        assert 'ExecStart=' + sys.executable + ' ' + str(daemon) + ' --config ' + \\
               str(plain_directory / 'media.conf') in unit_text
        assert 'openvpn' not in unit_text
        import hashlib
        assert '# renderer-sha256=' + hashlib.sha256(daemon.read_bytes()).hexdigest() in unit_text
        # An unchanged renderer keeps the link untouched.
        commands.clear()
        installer.install({'plan': plain_plan, 'transport': transport,
                           'material': material.for_role(plain, 'gateway')}, 'gateway', True)
        assert commands[-1] == ['systemctl', 'start', plain_unit.name]
        assert not any(item[:2] == ['systemctl', 'restart'] for item in commands)
        # Replacing only the renderer changes generated state, so the running
        # link is restarted instead of keeping stale code.
        daemon.write_text('#!/usr/bin/python3\\n# upgraded renderer\\n'); os.chmod(daemon, 0o755)
        commands.clear()
        installer.install({'plan': plain_plan, 'transport': transport,
                           'material': material.for_role(plain, 'gateway')}, 'gateway', True)
        assert commands[-1] == ['systemctl', 'restart', plain_unit.name]
        assert '# renderer-sha256=' + hashlib.sha256(daemon.read_bytes()).hexdigest() in plain_unit.read_text()
print('ok')
`], { cwd: path.join(__dirname, '../scripts'), encoding: 'utf8', timeout: 30000 });
    assert.equal(output.trim(), 'ok');
});
