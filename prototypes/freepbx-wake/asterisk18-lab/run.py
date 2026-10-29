#!/usr/bin/env python3
"""Run only disposable, network-isolated synthetic Asterisk tests."""
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PBX_IMAGE = 'andrius/asterisk:18'
CLIENT_IMAGE = 'sokrat/push-gateway:latest'


def docker(*args, timeout=30, check=True):
    return subprocess.run(['docker', *args], text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=check)


def main():
    container = None
    with tempfile.TemporaryDirectory(prefix='asterisk-lab-', dir='/tmp/opencode') as tmp:
        path = Path(tmp)
        password = secrets.token_hex(24)
        ami_pass = secrets.token_hex(24)
        configs = {
            'http.conf': '[general]\nenabled=yes\nbindaddr=127.0.0.1\nbindport=8088\n',
            'manager.conf': '[general]\nenabled=yes\nbindaddr=127.0.0.1\nport=5038\n[lab]\nsecret=' + ami_pass + '\nread=all\nwrite=all\n',
            'modules.conf': '[modules]\nautoload=yes\nnoload => chan_sip.so\nnoload => chan_oss.so\n',
            'extensions.conf': '[lab]\nexten => 321,1,Dial(${PJSIP_DIAL_CONTACTS(321)},30)\n same => n,Hangup()\n'
                               'exten => 322,1,Dial(PJSIP/321/${LAB_URI},30)\n same => n,Hangup()\n',
            'pjsip.conf': '''[transport-ws]
type=transport
protocol=ws
bind=127.0.0.1
[321]
type=aor
max_contacts=8
remove_existing=no
qualify_frequency=0
[321]
type=auth
auth_type=userpass
username=321
password={password}
[321]
type=endpoint
transport=transport-ws
context=lab
disallow=all
allow=ulaw
aors=321
auth=321
rewrite_contact=yes
direct_media=no
'''.format(password=password),
        }
        for name, content in configs.items():
            (path / name).write_text(content, encoding='utf-8')
        (path / 'test-secrets.json').write_text(json.dumps({'password': password, 'ami': ami_pass}), encoding='utf-8')
        os.chmod(path / 'test-secrets.json', 0o600)
        mounts = []
        for name in configs:
            mounts.extend(['--mount', f'type=bind,src={path / name},dst=/etc/asterisk/{name},readonly'])
        try:
            result = docker('run', '-d', '--network', 'none', '--entrypoint', '/usr/sbin/asterisk',
                            *mounts, PBX_IMAGE, '-f', '-vvv', timeout=30)
            container = result.stdout.strip()
            ready = False
            for _ in range(80):
                time.sleep(.25)
                result = docker('exec', container, 'asterisk', '-rx', 'core show version', check=False)
                if result.returncode == 0 and 'Asterisk 18.' in result.stdout:
                    ready = True
                    print('Disposable Asterisk 18 process ready', flush=True)
                    aor = docker('exec', container, 'asterisk', '-rx', 'pjsip show aor 321', check=False).stdout.lower()
                    print(json.dumps({'aor_loaded': 'max_contacts' in aor, 'aor_max_eight': any('max_contacts' in line and ': 8' in line for line in aor.splitlines())}), flush=True)
                    break
            if not ready:
                print('BLOCKED: disposable Asterisk did not start', file=sys.stderr)
                return 1
            result = docker('run', '--rm', '--network', 'container:' + container,
                            '--mount', f'type=bind,src={HERE},dst=/lab,readonly',
                            '--mount', f'type=bind,src={HERE.parent / "route-experiment"},dst=/route,readonly',
                            '--mount', f'type=bind,src={path / "test-secrets.json"},dst=/run/lab-secrets.json,readonly',
                            '-e', 'NODE_PATH=/opt/sokrat-push-gateway/node_modules',
                            '--entrypoint', 'node', CLIENT_IMAGE, '/lab/integration.js', timeout=60, check=False)
            print(result.stdout, end='')
            if result.returncode:
                # Test output is deliberately sanitized; never print container logs.
                print(result.stderr, end='', file=sys.stderr)
                logs = docker('logs', container, check=False).stdout.lower()
                print(json.dumps({key: phrase in logs for key, phrase in {
                    'no_aors': 'has no aors', 'max_contacts': 'exceed max contacts',
                    'auth_failed': 'failed to authenticate', 'no_endpoint': 'no matching endpoint',
                    'aor_not_found': 'aor' + " '" + '321' + "' not found", 'registration_denied': 'unable to register',
                    'zero_max_contacts': 'no configured max_contacts', 'registrar_contact_failed': 'failed to validate contacts',
                    'transport_failed': 'unable to create transport', 'contact_bind_failed': 'unable to bind contact'
                }.items()}))
                for line in logs.splitlines():
                    if 'res_pjsip_registrar.c' in line or 'res_pjsip_authenticator_digest.c' in line:
                        line = re.sub(r"'[^']*'", "'[redacted]'", line)
                        line = re.sub(r'\b\d+(?:\.\d+){3}(?::\d+)?\b', '[address]', line)
                        print('Asterisk diagnostic:', line)
                return result.returncode
            return 0
        finally:
            if container:
                docker('rm', '-f', container, timeout=20, check=False)


if __name__ == '__main__':
    sys.exit(main())
