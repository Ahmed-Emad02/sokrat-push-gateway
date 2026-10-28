#!/usr/bin/env python3
"""Explicitly enabled root broker: verified Tailscale SSH bootstrap, no password persistence.

Only the configured dashboard uid can connect. Root operator opts in via
/etc/sokrat/gateway-onboarding.json {"enabled":true,"serviceUser":"sokrat-push"}.
UI requests can authorize ONLY matching Tailscale endpoint/media identities;
arbitrary commands, paths, public hosts, and SSH users are not accepted.
"""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import urllib.parse

BUNDLE = Path('/usr/local/lib/sokrat-tenant-provisioning')
CONFIG = Path('/etc/sokrat/gateway-onboarding.json')
SOCKET = Path('/run/sokrat-tenant-onboarding/broker.sock')


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def validate_request(req):
    if not isinstance(req, dict) or set(req) - {'action', 'host', 'username', 'password', 'fingerprint', 'pbxId'}:
        raise ValueError('request')
    host = req.get('host')
    if not isinstance(host, str) or str(ipaddress.ip_address(host)) != host or ipaddress.ip_address(host) not in ipaddress.ip_network('100.64.0.0/10'):
        raise ValueError('Tailscale IPv4 required')
    if req.get('username') != 'root' or req.get('action') not in ('probe', 'enroll'):
        raise ValueError('root SSH required')
    if req['action'] == 'enroll':
        if not re.fullmatch(r'pbx_[A-Za-z0-9_-]{1,76}', req.get('pbxId', '')):
            raise ValueError('id')
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', req.get('fingerprint', '')):
            raise ValueError('fingerprint')
        if not isinstance(req.get('password'), str) or not 1 <= len(req['password']) <= 1024:
            raise ValueError('password')
    elif 'password' in req:
        raise ValueError('probe must not receive password')
    return host


def record_identity(record, host, worker):
    if sorted(record.get('mediaIps', [])) != [host]:
        raise ValueError('media pin')
    for field in ('wsURL', 'apiURL'):
        if urllib.parse.urlsplit(record[field]).hostname != host:
            raise ValueError('endpoint pin')
    approval = worker.record_approval(record)
    if approval not in ('approved', 'unmanaged'):
        raise ValueError('approval required')
    return { 'wsURL': record['wsURL'], 'apiURL': record['apiURL'],
             'mediaIps': [host], 'approval': approval }


BOOTSTRAP = r'''
import json,os,stat,pathlib,sys,re
if os.geteuid()!=0:raise SystemExit(2)
p=json.load(sys.stdin);key=p['key'];pbx=p['pbxId']
if not re.fullmatch(r'pbx_[A-Za-z0-9_-]+',pbx):raise SystemExit(2)
if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+ sokrat-gateway-'+re.escape(pbx),key):raise SystemExit(2)
dp=pathlib.Path('/etc/asterisk/extensions_sokrat.conf')
if not dp.exists():dp=pathlib.Path('/etc/asterisk/extensions_custom.conf')
text=dp.read_text()
if '[sub-sokrat-push-send]' not in text:raise SystemExit(3)
root=pathlib.Path('/root/.ssh')
if root.is_symlink():raise SystemExit(2)
root.mkdir(mode=0o700,exist_ok=True)
f=root/'authorized_keys'
fd=os.open(f,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'r+') as s:
 st=os.fstat(s.fileno())
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise SystemExit(2)
 old=s.read()
 if not any(line.endswith(key) for line in old.splitlines()):s.write(('\n' if old and not old.endswith('\n') else '')+'restrict '+key+'\n')
 os.fchmod(s.fileno(),0o600)
print(json.dumps({'dialplanFile':str(dp),'calleeVar':'TARGET_EXT' if '${TARGET_EXT}' in text else 'CALLEE','callerVar':'SOKRAT_CALLER_NUM' if '${SOKRAT_CALLER_NUM}' in text else 'CALLER','nameVar':'SOKRAT_CALLER_NAME' if '${SOKRAT_CALLER_NAME}' in text else 'CALLER_NAME'}))
'''


def load_worker():
    spec = importlib.util.spec_from_file_location('worker', BUNDLE / 'reconcile-tenant-provisioning.py')
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    return worker


def stage_error(stage, error):
    """Tag a failure with the step it happened in.

    The message never carries the password: only the step name and the
    exception type reach the journal.
    """
    return ValueError('%s:%s' % (stage, type(error).__name__))


# Safe, operator-facing reason codes. The raw exception text never leaves the
# broker: only these codes are returned to the dashboard.
STAGE_CODES = {
    'ssh_handshake': 'ssh_unreachable',
    'pbx_pin': 'pbx_not_approved_or_mismatched',
    'password_auth': 'password_auth_failed',
    'pbx_bootstrap': 'pbx_bootstrap_failed',
    'verify_key': 'key_login_failed',
    'config_write': 'config_write_failed',
    'host key changed': 'host_key_changed',
}


def refusal_code(error):
    text = str(error)
    if text in STAGE_CODES:
        return STAGE_CODES[text]
    stage = text.split(':', 1)[0]
    return STAGE_CODES.get(stage, 'onboarding_refused')


def handle(req, worker):
    import paramiko
    host = validate_request(req)
    # Handshake without authentication: show fingerprint before sending password.
    try:
        with socket.create_connection((host, 22), timeout=10) as raw:
            transport = paramiko.Transport(raw)
            try:
                transport.start_client(timeout=10)
                key = transport.get_remote_server_key()
                actual = fingerprint(key)
            finally:
                transport.close()
    except Exception as error:
        raise stage_error('ssh_handshake', error)
    if req['action'] == 'probe':
        return {'ok': True, 'fingerprint': actual}
    if req['fingerprint'] != actual:
        raise ValueError('host key changed')
    config = worker.load_config('/etc/sokrat/gateway-provisioning.json', False)
    control = worker.read_regular(config['controlFile'], 'control')
    records = json.loads(control)['pbx']
    record = next(p for p in records if p['id'] == req['pbxId'])
    try:
        pin = record_identity(record, host, worker)
    except Exception as error:
        raise stage_error('pbx_pin', error)
    pbx = record['id']
    worker.ensure_dir('/etc/sokrat/ssh', 0o700)
    identity = Path('/etc/sokrat/ssh') / (pbx + '.key')
    known = Path('/etc/sokrat/ssh') / (pbx + '.known_hosts')
    if not identity.exists():
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'sokrat-gateway-' + pbx, '-f', str(identity)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    worker.check_file(identity, 'identity', {0}, private=True)
    public_path = identity.with_suffix('.key.pub')
    worker.check_file(public_path, 'public key', {0})
    public = public_path.read_text().strip()
    client = paramiko.SSHClient()
    client.get_host_keys().add(host, key.get_name(), key)
    try:
        try:
            client.connect(host, username='root', password=req['password'], allow_agent=False, look_for_keys=False, timeout=10, auth_timeout=15, banner_timeout=10)
        except Exception as error:
            raise stage_error('password_auth', error)
        import shlex
        try:
            stdin, stdout, stderr = client.exec_command('/usr/bin/python3 -c ' + shlex.quote(BOOTSTRAP), timeout=20)
            stdin.write(json.dumps({'key': public, 'pbxId': pbx}));stdin.flush();stdin.channel.shutdown_write()
            result = stdout.read(8193)
            if len(result)>8192 or stdout.channel.recv_exit_status()!=0:
                raise stage_error('pbx_bootstrap', RuntimeError('the PBX refused the gateway key'))
            remote = json.loads(result)
        except Exception as error:
            if isinstance(error, ValueError) and str(error).startswith('pbx_bootstrap:'):
                raise
            raise stage_error('pbx_bootstrap', error)
    finally:
        client.close()
        req.pop('password', None)
    if remote.get('dialplanFile') not in ('/etc/asterisk/extensions_sokrat.conf', '/etc/asterisk/extensions_custom.conf'):
        raise ValueError('unsupported PBX')
    if set(remote) != {'dialplanFile', 'calleeVar', 'callerVar', 'nameVar'}:
        raise ValueError('unexpected discovery fields')
    for field in ('calleeVar','callerVar','nameVar'):
        if not isinstance(remote[field],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',remote[field]):
            raise ValueError('invalid dialplan variable')
    # Verify key-only access before promoting the access profile.
    verify = paramiko.SSHClient();verify.get_host_keys().add(host,key.get_name(),key)
    try:
        verify.connect(host, username='root', key_filename=str(identity), allow_agent=False, look_for_keys=False, timeout=10, auth_timeout=10)
    finally:
        verify.close()
    lock = worker.acquire_lock(config)
    if lock is None:raise ValueError('worker busy; retry')
    try:
        if worker.read_regular(config['controlFile'], 'control') != control:raise ValueError('record changed')
        worker.atomic_write(known, host + ' ' + key.get_name() + ' ' + key.get_base64() + '\n', 0o600)
        adapters_path = Path('/etc/sokrat/gateway-provisioning-adapters.json')
        worker.check_file(adapters_path, 'adapters', {0}, private=True)
        adapters = json.loads(worker.read_regular(adapters_path, 'adapters'))
        ssh = {'sshHost':host,'sshUser':'root','identityFile':str(identity),'knownHostsFile':str(known),
               'gatewayUrl':config['gatewayUrl'],'hookConfigGroup':'asterisk','hookRunnerUser':'asterisk','reloadDialplan':True,
               'hookPath':'/usr/local/bin/sokrat-tenant-push-hook.py','hookConfigPath':'/etc/sokrat/gateway-hook.json',**remote}
        adapters.setdefault('pbx', {}).setdefault(pbx, {})['ssh'] = ssh
        worker.atomic_write(adapters_path, json.dumps(adapters,indent=2)+'\n', 0o600)
        config_path = Path('/etc/sokrat/gateway-provisioning.json')
        config_doc = json.loads(worker.read_regular(config_path, 'config'))
        pin['fingerprint'] = hashlib.sha256(json.dumps(pin,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        pin['hookAdapter'] = str(BUNDLE / 'provisioning-hook-ssh.py')
        config_doc['pbx'][pbx] = pin
        worker.atomic_write(config_path,json.dumps(config_doc,indent=2)+'\n',0o600)
    finally:
        worker.release_lock(lock)
    return {'ok':True}


def main():
    worker = load_worker()
    worker.validate_helper(Path(__file__), 'onboarding', False)
    worker.check_file(CONFIG,'onboarding config',{0},private=True)
    config = json.loads(CONFIG.read_text())
    if config.get('enabled') is not True:raise ValueError('disabled')
    account = pwd.getpwnam(config.get('serviceUser','sokrat-push'))
    worker.ensure_dir(SOCKET.parent,0o750,gid=account.pw_gid)
    if SOCKET.exists():
        import stat
        if not stat.S_ISSOCK(SOCKET.lstat().st_mode):raise ValueError('socket target')
        SOCKET.unlink()
    server = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(SOCKET))
    os.chown(SOCKET,0,account.pw_gid);os.chmod(SOCKET,0o660);server.listen(4)
    while True:
        connection,_ = server.accept()
        request = None
        with connection:
            try:
                _,uid,_ = struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid != account.pw_uid:raise ValueError('peer')
                connection.settimeout(5);data=b''
                while True:
                    part=connection.recv(4096)
                    if not part:break
                    data+=part
                    if len(data)>8192:raise ValueError('size')
                request=json.loads(data)
                data=b''
                result=handle(request,worker)
            except Exception as error:
                # The reason is logged for the operator; the request itself is
                # dropped and the password never reaches the journal. Only a
                # safe code is returned to the dashboard.
                result={'ok': False, 'code': refusal_code(error)}
                print('onboarding refused: %s' % (str(error)[:120] or type(error).__name__), file=sys.stderr, flush=True)
            finally:
                if isinstance(request,dict):request.pop('password',None)
            try:connection.sendall(json.dumps(result).encode())
            except OSError:pass


if __name__ == '__main__':main()
