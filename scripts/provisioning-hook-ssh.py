#!/usr/bin/env python3
"""Optional root provisioning adapter: install the additive PBX push hook over SSH.

Contract (worker -> adapter):

    provisioning-hook-ssh.py <pbxId>   (exactly one argv element, never a secret)

The worker writes one bounded JSON object to stdin:

    {pbxId, gatewayUrl, listenerPort, peerIps, enabled, token}

``token`` is accepted only from stdin and is forwarded to the remote installer
inside a base64-encoded private hook config on the SSH stdin channel. It is
never placed in argv, environment, logs, or stdout. When ``enabled`` is false
the adapter returns ``{"action": "skipped"}`` without contacting the PBX.

The adapter itself must live in the immutable root bundle
``/usr/local/lib/sokrat-tenant-provisioning`` (override only for tests with
``SOKRAT_PROVISIONING_BUNDLE``); the installer and hook runner are read from the
same directory as this file, never from the service-writable application tree.

Root config (default ``/etc/sokrat/gateway-provisioning-adapters.json``, mode
0600, root-owned, no symlink ancestors; override for tests with
``SOKRAT_PROVISIONING_ADAPTERS_CONFIG``)::

    {
      "pbx": {
        "pbx_example": {
          "ssh": {
            "sshHost": "192.0.2.10",
            "sshUser": "root",
            "identityFile": "/etc/sokrat/ssh/id_ed25519",
            "knownHostsFile": "/etc/sokrat/ssh/known_hosts",
            "calleeVar": "CALLEE",
            "callerVar": "CALLER",
            "nameVar": "CALLER_NAME",
            "dialplanFile": "/etc/asterisk/extensions_custom.conf",
            "hookPath": "/usr/local/sbin/pbx-tenant-push-hook.py",
            "hookConfigPath": "/etc/sokrat/gateway-hook.json",
            "gatewayUrl": "https://gateway.example.com",
            "callIdVar": "SOKRAT_CALL_ID",
            "hookConfigMode": "0640",
            "hookConfigGroup": "asterisk",
            "hookRunnerUser": "asterisk",
            "reloadDialplan": false,
            "port": 22,
            "connectTimeout": 10,
            "timeoutSeconds": 120
          }
        }
      }
    }

The seven SSH identity/routing fields are required per PBX; nothing is
inherited from a global block. ``sshUser`` must be ``root`` because the remote
installer uses ``--apply``. ``gatewayUrl`` is also a required root-config pin:
the worker's dashboard value must match it exactly, so a compromised worker
cannot redirect the PBX hook to another endpoint. OpenSSH runs with
``-F /dev/null``, batch mode, strict host-key checking against the pinned file,
public-key authentication only, and ProxyCommand/ProxyJump disabled.
``hookConfigGroup`` is required (normally ``asterisk``) and the remote adapter
checks that ``hookRunnerUser`` (default ``asterisk``) is in that group and can
read the installed hook config. ``reloadDialplan`` must be true before a
changed dialplan is applied; when true the adapter runs only the scoped
``asterisk -rx "dialplan reload"`` after an actual change and then verifies the
hook is visible in the running ``[sub-sokrat-push-send]`` context. It never
restarts Asterisk. An already-installed dialplan is accepted only after that
effective-context check.

Output is one JSON object on stdout (no secrets), exit 0 on success/unchanged/
skipped, 2 on a safe refusal, 1 on an operational failure. The remote installer
never reloads Asterisk and only adds the additive System() action inside the
existing ``[sub-sokrat-push-send]`` context; no global dialplan pattern is
created.
"""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ADAPTER = 'hook-ssh'
DEFAULT_CONFIG = '/etc/sokrat/gateway-provisioning-adapters.json'
DEFAULT_BUNDLE = '/usr/local/lib/sokrat-tenant-provisioning'
INSTALLER_NAME = 'install-tenant-push-hook.py'
HOOK_NAME = 'pbx-tenant-push-hook.py'

MAX_STDIN = 64 * 1024
MAX_CONFIG = 64 * 1024
MAX_INSTALLER = 512 * 1024
MAX_HOOK = 256 * 1024
MAX_IDENTITY = 64 * 1024
MAX_KNOWN_HOSTS = 1024 * 1024
MAX_PAYLOAD = 2 * 1024 * 1024
MAX_REMOTE_OUTPUT = 128 * 1024

PBX_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
VAR_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PATH_RE = re.compile(r'^/[A-Za-z0-9._+/-]+$')
HOSTNAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
GROUP_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9._~+/=-]{16,512}$')
LISTENER_MIN = 3500
LISTENER_MAX = 3654
SECRETS = []


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def refuse(code, message):
    raise Refusal(code, message)


def fail(code, message):
    raise Failure(code, message)


def sanitize(value):
    text = str(value).replace('\r', ' ').replace('\n', ' ')
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, '[redacted]')
    text = re.sub(r'(?i)(token|secret|bearer|authorization|password)\s*[=:]\s*\S+',
                  r'\1=[redacted]', text)
    return text[:300]


def emit(payload):
    sys.stdout.write(json.dumps(payload, sort_keys=True) + '\n')
    sys.stdout.flush()


def success(pbx_id, **fields):
    result = {'ok': True, 'adapter': ADAPTER, 'pbxId': pbx_id}
    result.update(fields)
    emit(result)
    return 0


def refusal(pbx_id, code, message):
    emit({'ok': False, 'adapter': ADAPTER, 'pbxId': pbx_id, 'action': 'failed',
          'error': {'code': code, 'message': sanitize(message)}})
    return 2


def failure(pbx_id, code, message):
    emit({'ok': False, 'adapter': ADAPTER, 'pbxId': pbx_id, 'action': 'failed',
          'error': {'code': code, 'message': sanitize(message)}})
    return 1


def ancestor_allowed(info, euid=None):
    """Root runs require every ancestor to be root-owned and not group/other writable.

    ``euid`` is an explicit test seam; runtime callers leave it as None.
    """
    effective = os.geteuid() if euid is None else euid
    if effective != 0:
        return True
    return info.st_uid == 0 and not (info.st_mode & 0o022)


def check_path_ancestry(path, label):
    raw = str(path)
    if not raw.startswith('/') or len(raw) > 4096:
        refuse('path_unsafe', '%s must be an absolute path' % label)
    if any(character in raw for character in ('\x00', '\n', '\r')):
        refuse('path_unsafe', '%s contains control characters' % label)
    current = Path('/')
    for part in [item for item in raw.split('/') if item][:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            refuse('path_missing', '%s has a missing ancestor: %s' % (label, current))
        except OSError as error:
            refuse('path_unsafe', '%s cannot be inspected: %s' % (label, error))
        if stat.S_ISLNK(info.st_mode):
            refuse('path_symlink', '%s has a symlink ancestor: %s' % (label, current))
        if not stat.S_ISDIR(info.st_mode):
            refuse('path_unsafe', '%s has a non-directory ancestor: %s' % (label, current))
        if not ancestor_allowed(info):
            refuse('path_unsafe',
                   '%s has an ancestor that is not root-owned or is group/other writable: %s'
                   % (label, current))


def stat_regular(path, label):
    check_path_ancestry(path, label)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        refuse('path_missing', '%s not found: %s' % (label, path))
    except OSError as error:
        refuse('path_unsafe', '%s cannot be inspected: %s' % (label, error))
    if stat.S_ISLNK(info.st_mode):
        refuse('path_symlink', '%s must not be a symlink: %s' % (label, path))
    if not stat.S_ISREG(info.st_mode):
        refuse('path_unsafe', '%s is not a regular file: %s' % (label, path))
    return info


def read_regular(path, label, limit):
    info = stat_regular(path, label)
    if info.st_size > limit:
        refuse('path_unsafe', '%s is unexpectedly large: %s' % (label, path))
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        refuse('path_unsafe', '%s cannot be opened: %s' % (label, error))
    with os.fdopen(descriptor, 'rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        refuse('path_unsafe', '%s is unexpectedly large: %s' % (label, path))
    return data


def owner_allowed(info, euid=None):
    effective = os.geteuid() if euid is None else euid
    if effective == 0:
        return info.st_uid == 0
    return info.st_uid in (0, effective)


def check_bundle():
    bundle = Path(os.environ.get('SOKRAT_PROVISIONING_BUNDLE', DEFAULT_BUNDLE))
    if not bundle.is_absolute():
        refuse('bundle_unsafe', 'provisioning bundle must be an absolute path')
    check_path_ancestry(bundle, 'provisioning bundle')
    try:
        info = os.lstat(bundle)
    except FileNotFoundError:
        refuse('bundle_missing', 'provisioning bundle not found: %s' % bundle)
    except OSError as error:
        refuse('bundle_unsafe', 'provisioning bundle cannot be inspected: %s' % error)
    if stat.S_ISLNK(info.st_mode):
        refuse('bundle_symlink', 'provisioning bundle must not be a symlink: %s' % bundle)
    if not stat.S_ISDIR(info.st_mode):
        refuse('bundle_unsafe', 'provisioning bundle is not a directory: %s' % bundle)
    if info.st_mode & 0o022:
        refuse('bundle_not_immutable', 'provisioning bundle must not be group/other writable')
    if not owner_allowed(info):
        refuse('bundle_not_root_owned', 'provisioning bundle must be root-owned')
    if os.geteuid() == 0:
        current = Path('/')
        for part in bundle.parts[1:-1]:
            current = current / part
            try:
                ancestor = os.lstat(current)
            except OSError:
                refuse('bundle_unsafe', 'provisioning bundle ancestor is missing: %s' % current)
            if ancestor.st_mode & 0o022:
                refuse('bundle_ancestor_writable',
                       'provisioning bundle ancestor is writable by group/other: %s' % current)
    if bundle.resolve() != Path(__file__).resolve().parent:
        refuse('adapter_outside_bundle',
               'adapter must run from the provisioning bundle, not %s'
               % Path(__file__).resolve().parent)
    return bundle


def check_bundle_file(bundle, name, limit, needles):
    path = bundle / name
    info = stat_regular(path, name)
    if info.st_mode & 0o022:
        refuse('bundle_not_immutable', '%s must not be group/other writable' % name)
    if not owner_allowed(info):
        refuse('bundle_not_root_owned', '%s must be root-owned' % name)
    data = read_regular(path, name, limit)
    if not data.startswith(b'#!') or b'python' not in data.splitlines()[0]:
        refuse('bundle_invalid', '%s is not a Python entry point' % name)
    for needle in needles:
        if needle not in data:
            refuse('bundle_invalid', '%s is missing expected content' % name)
    return data


def load_root_config():
    raw = os.environ.get('SOKRAT_PROVISIONING_ADAPTERS_CONFIG', DEFAULT_CONFIG)
    path = Path(raw)
    if not path.is_absolute():
        refuse('config_unsafe', 'root adapter config must be an absolute path')
    info = stat_regular(path, 'root adapter config')
    if (info.st_mode & 0o777) != 0o600:
        refuse('unsafe_permissions', 'root adapter config must be mode 0600: %s' % path)
    if not owner_allowed(info):
        refuse('unsafe_owner', 'root adapter config must be root-owned: %s' % path)
    data = read_regular(path, 'root adapter config', MAX_CONFIG)
    try:
        config = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        refuse('config_invalid', 'root adapter config is not valid JSON: %s' % path)
    if not isinstance(config, dict):
        refuse('config_invalid', 'root adapter config must be a JSON object')
    return config


def load_pbx(config, pbx_id):
    pbx = config.get('pbx')
    if not isinstance(pbx, dict):
        refuse('config_invalid', 'root adapter config has no pbx object')
    entry = pbx.get(pbx_id)
    if not isinstance(entry, dict):
        refuse('pbx_unconfigured', 'no provisioning adapter config for %s' % pbx_id)
    return entry


def valid_host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    if any(character in value for character in ' \t\r\n@/\\$`\'"'):
        return False
    if value.startswith('-') or '..' in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(HOSTNAME_RE.match(value))


def safe_remote_path(value, label):
    if not isinstance(value, str) or not value.startswith('/') or len(value) > 4096:
        refuse('pbx_unconfigured', '%s must be an absolute path' % label)
    if (not PATH_RE.match(value) or value.endswith('/') or '//' in value
            or '/./' in value or '/../' in value):
        refuse('pbx_unconfigured', '%s contains unsafe characters' % label)
    return value


def parse_mode(value):
    if isinstance(value, bool):
        refuse('pbx_unconfigured', 'hookConfigMode must be 0600 or 0640')
    if isinstance(value, int):
        mode = value
    elif isinstance(value, str) and re.match(r'^0?[0-7]{3,4}$', value):
        mode = int(value, 8)
    else:
        refuse('pbx_unconfigured', 'hookConfigMode must be 0600 or 0640')
    if mode not in (0o600, 0o640):
        refuse('pbx_unconfigured', 'hookConfigMode must be 0600 or 0640')
    return mode


def known_hosts_has_host(path, host, port):
    data = read_regular(path, 'known_hostsFile', MAX_KNOWN_HOSTS)
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        refuse('known_hosts_invalid', 'known_hostsFile is not valid UTF-8')
    targets = {host} if port == 22 else {'[%s]:%d' % (host, port)}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        pattern = fields[0]
        if pattern.startswith('|1|'):
            return True
        if any(item in targets for item in pattern.split(',')):
            return True
    refuse('known_hosts_missing_host',
           'known_hostsFile has no pinned entry for %s' % ', '.join(sorted(targets)))


def parse_ssh_config(entry, pbx_id):
    ssh = entry.get('ssh', entry)
    if not isinstance(ssh, dict):
        refuse('pbx_unconfigured', 'ssh config for %s must be an object' % pbx_id)
    required = ('sshHost', 'sshUser', 'identityFile', 'knownHostsFile',
                'calleeVar', 'callerVar', 'nameVar', 'gatewayUrl',
                'dialplanFile', 'hookPath', 'hookConfigPath')
    for key in required:
        if not isinstance(ssh.get(key), str) or not ssh.get(key):
            refuse('pbx_unconfigured', 'ssh.%s is required for %s' % (key, pbx_id))
    host = ssh['sshHost']
    if not valid_host(host):
        refuse('pbx_unconfigured', 'ssh.sshHost is not a valid hostname or address')
    if ssh['sshUser'] != 'root':
        refuse('ssh_user_not_root', 'ssh.sshUser must be root for --apply installs')
    identity = Path(ssh['identityFile'])
    if not identity.is_absolute():
        refuse('pbx_unconfigured', 'ssh.identityFile must be an absolute path')
    info = stat_regular(identity, 'ssh.identityFile')
    if info.st_mode & 0o077:
        refuse('unsafe_permissions', 'ssh.identityFile must be mode 0600: %s' % identity)
    if not owner_allowed(info):
        refuse('unsafe_owner', 'ssh.identityFile must be root-owned: %s' % identity)
    if info.st_size > MAX_IDENTITY:
        refuse('path_unsafe', 'ssh.identityFile is unexpectedly large')
    known_hosts = Path(ssh['knownHostsFile'])
    if not known_hosts.is_absolute():
        refuse('pbx_unconfigured', 'ssh.knownHostsFile must be an absolute path')
    host_info = stat_regular(known_hosts, 'ssh.knownHostsFile')
    if host_info.st_mode & 0o022:
        refuse('unsafe_permissions', 'ssh.knownHostsFile must not be group/other writable')
    if not owner_allowed(host_info):
        refuse('unsafe_owner', 'ssh.knownHostsFile must be root-owned: %s' % known_hosts)

    port = ssh.get('port', 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        refuse('pbx_unconfigured', 'ssh.port must be an integer between 1 and 65535')
    connect_timeout = ssh.get('connectTimeout', 10)
    if (isinstance(connect_timeout, bool) or not isinstance(connect_timeout, int)
            or not 5 <= connect_timeout <= 60):
        refuse('pbx_unconfigured', 'ssh.connectTimeout must be between 5 and 60 seconds')
    timeout_seconds = ssh.get('timeoutSeconds', 120)
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int)
            or not 30 <= timeout_seconds <= 300):
        refuse('pbx_unconfigured', 'ssh.timeoutSeconds must be between 30 and 300 seconds')

    callee = ssh['calleeVar']
    caller = ssh['callerVar']
    name = ssh['nameVar']
    call_id = ssh.get('callIdVar', 'SOKRAT_CALL_ID')
    for label, value in (('calleeVar', callee), ('callerVar', caller),
                         ('nameVar', name), ('callIdVar', call_id)):
        if not isinstance(value, str) or not VAR_RE.match(value):
            refuse('pbx_unconfigured', 'ssh.%s must be a plain dialplan variable' % label)

    hook_config_group = ssh.get('hookConfigGroup')
    if not isinstance(hook_config_group, str) or not GROUP_RE.match(hook_config_group):
        refuse('pbx_unconfigured',
               'ssh.hookConfigGroup is required (normally "asterisk") so the runner can read the hook config')
    hook_runner_user = ssh.get('hookRunnerUser', 'asterisk')
    if not isinstance(hook_runner_user, str) or not GROUP_RE.match(hook_runner_user):
        refuse('pbx_unconfigured', 'ssh.hookRunnerUser is not a valid user name')

    gateway = validate_gateway_url(ssh['gatewayUrl'])
    reload_dialplan = ssh.get('reloadDialplan', False)
    if not isinstance(reload_dialplan, bool):
        refuse('pbx_unconfigured', 'ssh.reloadDialplan must be a boolean')

    known_hosts_has_host(known_hosts, host, port)
    return {
        'sshHost': host,
        'sshUser': ssh['sshUser'],
        'identityFile': str(identity),
        'knownHostsFile': str(known_hosts),
        'calleeVar': callee,
        'callerVar': caller,
        'nameVar': name,
        'callIdVar': call_id,
        'dialplanFile': safe_remote_path(ssh['dialplanFile'], 'ssh.dialplanFile'),
        'hookPath': safe_remote_path(ssh['hookPath'], 'ssh.hookPath'),
        'hookConfigPath': safe_remote_path(ssh['hookConfigPath'], 'ssh.hookConfigPath'),
        'gatewayUrl': gateway,
        'reloadDialplan': reload_dialplan,
        'hookConfigMode': parse_mode(ssh.get('hookConfigMode', '0640')),
        'hookConfigGroup': hook_config_group,
        'hookRunnerUser': hook_runner_user,
        'port': port,
        'connectTimeout': connect_timeout,
        'timeoutSeconds': timeout_seconds,
    }


def read_request():
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw) > MAX_STDIN:
        refuse('request_too_large', 'worker request exceeds %d bytes' % MAX_STDIN)
    if not raw:
        refuse('request_empty', 'worker request is empty')
    try:
        request = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        refuse('request_invalid', 'worker request is not valid JSON')
    if not isinstance(request, dict):
        refuse('request_invalid', 'worker request must be a JSON object')
    return request


def validate_shared(request, pbx_id):
    if request.get('pbxId') != pbx_id:
        refuse('pbx_mismatch', 'worker request pbxId does not match argv')
    enabled = request.get('enabled')
    if not isinstance(enabled, bool):
        refuse('request_invalid', 'worker request enabled must be a boolean')
    return enabled


def validate_gateway_url(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 2048:
        refuse('request_invalid', 'gatewayUrl must be an http(s) URL')
    if re.search(r'[\s\x00-\x1f\x7f]', value):
        refuse('request_invalid', 'gatewayUrl contains whitespace or control characters')
    try:
        parts = urlsplit(value)
        parts.port
    except ValueError:
        refuse('request_invalid', 'gatewayUrl is malformed')
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        refuse('request_invalid', 'gatewayUrl must be an http(s) URL')
    if parts.username or parts.password or parts.query or parts.fragment:
        refuse('request_invalid', 'gatewayUrl must not contain credentials, query or fragment')
    if parts.path not in ('', '/'):
        if (not re.match(r'^/[A-Za-z0-9._~/-]*$', parts.path)
                or '//' in parts.path or '/../' in parts.path):
            refuse('request_invalid', 'gatewayUrl path is unsafe')
    return value


def validate_listener_port(request):
    if 'listenerPort' not in request:
        return
    port = request['listenerPort']
    if isinstance(port, bool) or not isinstance(port, int) or not LISTENER_MIN <= port <= LISTENER_MAX:
        refuse('request_invalid', 'listenerPort must be an integer in %d..%d'
               % (LISTENER_MIN, LISTENER_MAX))


def validate_peer_ips(request):
    peers = request.get('peerIps')
    if peers is None:
        return
    if not isinstance(peers, list) or len(peers) > 64:
        refuse('request_invalid', 'peerIps must be an array of at most 64 addresses')
    for peer in peers:
        if not isinstance(peer, str) or len(peer) > 64:
            refuse('request_invalid', 'peerIps contains a non-string address')
        try:
            ipaddress.ip_address(peer)
        except ValueError:
            refuse('request_invalid', 'peerIps contains an invalid address')


def validate_request_pins(request, config):
    for key in ('sshHost', 'host', 'address'):
        if key in request and request[key] != config['sshHost']:
            refuse('request_host_mismatch', 'worker request %s is pinned by the root config' % key)
    if 'sshUser' in request and request['sshUser'] != 'root':
        refuse('request_host_mismatch', 'worker request sshUser is pinned to root')


def check_executable(raw, label):
    """Resolve a binary (official packages often symlink it) and validate the target."""
    try:
        resolved = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError):
        refuse('binary_unavailable', '%s is not available: %s' % (label, raw))
    info = stat_regular(resolved, label)
    if info.st_mode & 0o022:
        refuse('binary_unsafe', '%s must not be group/other writable' % label)
    if not owner_allowed(info):
        refuse('binary_unsafe', '%s must be root-owned' % label)
    return str(resolved)


def ssh_binary():
    raw = os.environ.get('SOKRAT_PROVISIONING_SSH', '/usr/bin/ssh')
    if not os.path.isabs(raw):
        refuse('ssh_binary_unsafe', 'SOKRAT_PROVISIONING_SSH must be an absolute path')
    if not os.path.exists(raw):
        fail('ssh_unavailable', 'ssh binary is not available: %s' % raw)
    return check_executable(raw, 'ssh binary')


def ssh_argv(binary, config, remote_command):
    identity = config['identityFile']
    known_hosts = config['knownHostsFile']
    options = [
        '-F', '/dev/null',
        '-e', 'none',
        '-T',
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=%s' % known_hosts,
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'CheckHostIP=yes',
        '-o', 'VerifyHostKeyDNS=no',
        '-o', 'UpdateHostKeys=no',
        '-o', 'HashKnownHosts=no',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'IdentityAgent=none',
        '-o', 'AddKeysToAgent=no',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PubkeyAuthentication=yes',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'ChallengeResponseAuthentication=no',
        '-o', 'HostbasedAuthentication=no',
        '-o', 'GSSAPIAuthentication=no',
        '-o', 'ProxyCommand=none',
        '-o', 'ProxyJump=none',
        '-o', 'PermitLocalCommand=no',
        '-o', 'ClearAllForwardings=yes',
        '-o', 'ForwardAgent=no',
        '-o', 'ForwardX11=no',
        '-o', 'ForwardX11Trusted=no',
        '-o', 'ControlMaster=no',
        '-o', 'ControlPath=none',
        '-o', 'ControlPersist=no',
        '-o', 'ConnectTimeout=%d' % config['connectTimeout'],
        '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=2',
        '-o', 'TCPKeepAlive=yes',
        '-o', 'CanonicalizeHostname=no',
        '-i', identity,
        '-p', str(config['port']),
        '-l', config['sshUser'],
        config['sshHost'],
        remote_command,
    ]
    return [binary] + options


REMOTE_CODE = r"""
import base64
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

MAX_PAYLOAD = 2 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
PBX_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
VAR_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PATH_RE = re.compile(r'^/[A-Za-z0-9._+/-]+$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9._~+/=-]{16,512}$')
SECRETS = []


def sanitize(text):
    text = str(text).replace('\r', ' ').replace('\n', ' ')
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, '[redacted]')
    text = re.sub(r'(?i)(token|secret|bearer|authorization|password)\s*[=:]\s*\S+',
                  r'\1=[redacted]', text)
    return text[:200]


def out(obj):
    sys.stdout.write(json.dumps(obj, sort_keys=True) + '\n')
    sys.stdout.flush()


def fail(code, detail=''):
    out({'ok': False, 'error': {'code': code, 'detail': sanitize(detail)}})
    raise SystemExit(0)


def need(obj, key):
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        fail('payload_invalid', 'missing ' + key)
    return value


def safe_path(raw, label):
    if not isinstance(raw, str) or not raw.startswith('/') or len(raw) > 4096:
        fail('payload_invalid', label + ' must be an absolute path')
    if (not PATH_RE.match(raw) or raw.endswith('/') or '//' in raw
            or '/./' in raw or '/../' in raw):
        fail('payload_invalid', label + ' is unsafe')
    return raw


def check_ancestors(path):
    current = '/'
    parts = [part for part in path.split('/') if part]
    for part in parts[:-1]:
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except OSError:
            fail('remote_path_unsafe', 'missing directory for ' + path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail('remote_path_unsafe', 'unsafe ancestor for ' + path)
        if info.st_uid != 0 or info.st_mode & 0o022:
            fail('remote_path_unsafe', 'ancestor is not root-owned or is group/other writable: ' + current)


def atomic_write(path, data, mode, uid, gid):
    check_ancestors(path)
    if os.path.islink(path):
        fail('remote_path_unsafe', 'target is a symlink')
    directory = os.path.dirname(path) or '/'
    tmp = os.path.join(directory, '.' + os.path.basename(path) + '.tmp-'
                       + str(os.getpid()) + '-' + os.urandom(4).hex())
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0:
            os.chown(tmp, uid, gid)
        os.replace(tmp, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_existing(path):
    if not os.path.exists(path):
        return None
    if os.path.islink(path):
        fail('remote_path_unsafe', 'target is a symlink')
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        fail('remote_path_unsafe', 'target is not a regular file')
    if info.st_size > MAX_FILE:
        fail('remote_path_unsafe', 'target is too large')
    with open(path, 'rb') as handle:
        return handle.read()


def install(path, data, mode, uid, gid, stamp):
    existing = read_existing(path)
    if existing == data:
        os.chmod(path, mode)
        if os.geteuid() == 0:
            os.chown(path, uid, gid)
        return None
    backup = None
    if existing is not None:
        backup = path + '.bak-tenant-provision-' + stamp
        if os.path.exists(backup):
            fail('backup_exists', backup)
        shutil.copy2(path, backup)
        os.chmod(backup, os.lstat(path).st_mode & 0o7777)
    atomic_write(path, data, mode, uid, gid)
    return backup


def restore(path, existing, mode, uid, gid):
    if existing is None:
        try:
            if os.path.exists(path) and not os.path.islink(path):
                os.unlink(path)
        except OSError:
            pass
    else:
        atomic_write(path, existing, mode, uid, gid)


class InstallerTimeout(Exception):
    pass


def runner_can_read(path, runner, gid):
    try:
        account = pwd.getpwnam(runner)
    except KeyError:
        fail('hook_runner_missing', runner)
    groups = set(os.getgrouplist(runner, account.pw_gid))
    info = os.stat(path)
    if info.st_gid != gid:
        fail('hook_group_unreadable', 'hook config group was not applied')
    if info.st_uid == account.pw_uid:
        if not info.st_mode & 0o400:
            fail('hook_group_unreadable', 'hook runner cannot read the hook config')
    elif info.st_gid in groups:
        if not info.st_mode & 0o040:
            fail('hook_group_unreadable', 'hook runner cannot read the hook config')
    else:
        fail('hook_group_unreadable', 'hook runner is not in the configured group')


def run_asterisk(args, timeout=15):
    binary = shutil.which('asterisk')
    if not binary:
        fail('asterisk_unavailable', 'Asterisk CLI is not available')
    try:
        process = subprocess.run(
            [binary] + args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        fail('asterisk_failed', 'Asterisk CLI could not be executed')
    return process


def verify_effective_dialplan():
    process = run_asterisk(['-rx', 'dialplan show sub-sokrat-push-send'])
    text = process.stdout.decode('utf-8', 'replace')
    if process.returncode != 0 or 'pbx-tenant-push-hook.py' not in text:
        fail('dialplan_not_effective',
             'additive hook is not visible in the running dialplan')


def main():
    raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
    if len(raw) > MAX_PAYLOAD:
        fail('payload_too_large', 'remote payload exceeds limit')
    try:
        payload = json.loads(raw.decode('utf-8'))
    except Exception:
        fail('payload_invalid', 'remote payload is not JSON')
    if not isinstance(payload, dict):
        fail('payload_invalid', 'remote payload must be an object')
    if os.geteuid() != 0:
        fail('root_required', 'remote adapter must run as root')
    pbx = need(payload, 'pbxId')
    if not PBX_RE.match(pbx):
        fail('payload_invalid', 'invalid pbxId')
    gateway = need(payload, 'gatewayUrl')
    dialplan = safe_path(need(payload, 'dialplanFile'), 'dialplanFile')
    hook_path = safe_path(need(payload, 'hookPath'), 'hookPath')
    config_path = safe_path(need(payload, 'hookConfigPath'), 'hookConfigPath')
    if len({dialplan, hook_path, config_path}) != 3:
        fail('payload_invalid', 'target paths must be distinct')
    callee = need(payload, 'calleeVar')
    caller = need(payload, 'callerVar')
    name = need(payload, 'nameVar')
    call_id = need(payload, 'callIdVar')
    for label, value in (('calleeVar', callee), ('callerVar', caller),
                         ('nameVar', name), ('callIdVar', call_id)):
        if not VAR_RE.match(value):
            fail('payload_invalid', label + ' is not a dialplan variable')
    mode = payload.get('hookConfigMode')
    if mode not in (0o600, 0o640):
        fail('payload_invalid', 'hookConfigMode must be 0600 or 0640')
    reload_requested = payload.get('reloadDialplan')
    if not isinstance(reload_requested, bool):
        fail('payload_invalid', 'reloadDialplan must be a boolean')
    group = payload.get('hookConfigGroup')
    if not isinstance(group, str) or not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', group):
        fail('payload_invalid', 'hookConfigGroup is required')
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        fail('hook_group_missing', group)
    runner = payload.get('hookRunnerUser', 'asterisk')
    if not isinstance(runner, str) or not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', runner):
        fail('payload_invalid', 'hookRunnerUser is invalid')
    try:
        runner_account = pwd.getpwnam(runner)
    except KeyError:
        fail('hook_runner_missing', runner)
    if runner_account.pw_uid != 0:
        runner_groups = set(os.getgrouplist(runner, runner_account.pw_gid))
        if gid not in runner_groups:
            fail('hook_group_unreadable', 'hook runner is not in the configured group')
    installer_b64 = need(payload, 'installerB64')
    hook_b64 = need(payload, 'hookB64')
    config_b64 = need(payload, 'hookConfigB64')
    try:
        installer = base64.b64decode(installer_b64, validate=True)
        hook = base64.b64decode(hook_b64, validate=True)
        config_bytes = base64.b64decode(config_b64, validate=True)
    except Exception:
        fail('payload_invalid', 'payload is not valid base64')
    if len(installer) > MAX_FILE or len(hook) > MAX_FILE or len(config_bytes) > 65536:
        fail('payload_too_large', 'embedded file exceeds limit')
    if b'sub-sokrat-push-send' not in installer or b'--config' not in installer:
        fail('payload_invalid', 'installer content is not recognized')
    if not hook.startswith(b'#!') or b'unquote(' not in hook:
        fail('payload_invalid', 'hook content is not recognized')
    try:
        config = json.loads(config_bytes.decode('utf-8'))
    except Exception:
        fail('payload_invalid', 'hook config is not JSON')
    if not isinstance(config, dict):
        fail('payload_invalid', 'hook config must be an object')
    token = config.get('token')
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        fail('payload_invalid', 'hook token is invalid')
    SECRETS.append(token)
    if config.get('pbxId') != pbx:
        fail('hook_config_mismatch', 'hook config pbxId does not match')
    if config.get('gatewayUrl') != gateway:
        fail('hook_config_mismatch', 'hook config gatewayUrl does not match')
    rendered_config = (json.dumps({'gatewayUrl': gateway, 'pbxId': pbx, 'token': token},
                                  separators=(',', ':')) + '\n').encode('utf-8')
    hook_existed = read_existing(hook_path)
    hook_orig_mode = 0o755 if hook_existed is None else (os.lstat(hook_path).st_mode & 0o7777)
    hook_orig_uid = 0 if hook_existed is None else os.lstat(hook_path).st_uid
    hook_orig_gid = 0 if hook_existed is None else os.lstat(hook_path).st_gid
    config_existed = read_existing(config_path)
    config_orig_mode = 0o600 if config_existed is None else (os.lstat(config_path).st_mode & 0o7777)
    config_orig_uid = 0 if config_existed is None else os.lstat(config_path).st_uid
    config_orig_gid = 0 if config_existed is None else os.lstat(config_path).st_gid
    if config_existed is not None:
        try:
            existing_config = json.loads(config_existed.decode('utf-8'))
        except Exception:
            fail('hook_config_conflict',
                 'existing hook config is not recognized; refusing to overwrite it')
        if not isinstance(existing_config, dict) or existing_config.get('pbxId') != pbx:
            fail('hook_config_conflict',
                 'existing hook config belongs to a different PBX; refusing to overwrite it')
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    base = '/run' if os.path.isdir('/run') and os.access('/run', os.W_OK) else '/tmp'
    tmpdir = tempfile.mkdtemp(prefix='sokrat-provision-', dir=base)
    os.chmod(tmpdir, 0o700)
    hook_backup = None
    config_backup = None
    try:
        installer_tmp = os.path.join(tmpdir, 'install-tenant-push-hook.py')
        hook_tmp = os.path.join(tmpdir, 'pbx-tenant-push-hook.py')
        config_tmp = os.path.join(tmpdir, 'gateway-hook.json')
        for path, data in ((installer_tmp, installer), (hook_tmp, hook),
                           (config_tmp, rendered_config)):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, 0o600)
        def installer_argv(apply):
            argv = ['/usr/bin/python3', installer_tmp]
            if apply:
                argv.append('--apply')
            argv.extend(['--dialplan-file', dialplan, '--hook-script', hook_path,
                         '--config', config_path, '--callee-var', callee,
                         '--caller-var', caller, '--name-var', name,
                         '--call-id-var', call_id])
            return argv

        def run_installer(apply):
            try:
                return subprocess.run(
                    installer_argv(apply), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=120, check=False,
                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'})
            except subprocess.TimeoutExpired:
                raise InstallerTimeout()

        def rollback():
            restore(hook_path, hook_existed, hook_orig_mode, hook_orig_uid, hook_orig_gid)
            restore(config_path, config_existed, config_orig_mode, config_orig_uid, config_orig_gid)

        try:
            hook_backup = install(hook_path, hook, 0o755, 0, 0, stamp)
            config_backup = install(config_path, rendered_config, mode, 0, gid, stamp)
            runner_can_read(config_path, runner, gid)
        except BaseException:
            rollback()
            raise
        try:
            dry_run = run_installer(False)
        except InstallerTimeout:
            rollback()
            fail('installer_timeout', 'installer timed out')
        if dry_run.returncode != 0:
            rollback()
            fail('installer_refused', 'installer refused the dialplan change')
        dry_run_text = dry_run.stdout.decode('utf-8', 'replace')
        planned_change = 'already installed' not in dry_run_text
        if planned_change and reload_requested is not True:
            rollback()
            fail('reload_required',
                 'reloadDialplan must be true before applying a changed dialplan')
        try:
            process = run_installer(True)
        except InstallerTimeout:
            rollback()
            fail('installer_timeout', 'installer timed out')
        if process.returncode != 0:
            rollback()
            fail('installer_refused', 'installer refused the dialplan change')
        installer_stdout = process.stdout.decode('utf-8', 'replace')
        action = 'unchanged' if 'already installed' in installer_stdout else 'installed'
        reload_status = 'not-requested'
        if reload_requested is True and action == 'installed':
            reload_process = run_asterisk(['-rx', 'dialplan reload'])
            if reload_process.returncode != 0:
                fail('reload_failed', 'Asterisk dialplan reload failed')
            reload_status = 'reloaded'
        elif action == 'unchanged':
            reload_status = 'unchanged'
        verify_effective_dialplan()
        out({'ok': True, 'action': action, 'pbxId': pbx, 'dialplanFile': dialplan,
             'hookPath': hook_path, 'hookConfigPath': config_path,
             'reload': reload_status,
             'hookBackup': hook_backup is not None,
             'configBackup': config_backup is not None})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


try:
    main()
except SystemExit:
    raise
except BaseException as exc:
    out({'ok': False, 'error': {'code': 'remote_failed', 'detail': sanitize(exc)}})
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pbx_id = None
    try:
        if len(argv) != 1:
            refuse('usage', 'usage: provisioning-hook-ssh.py <pbxId>')
        pbx_id = argv[0]
        if not PBX_ID_RE.match(pbx_id):
            refuse('usage', 'pbxId must match %s' % PBX_ID_RE.pattern)
        request = read_request()
        enabled = validate_shared(request, pbx_id)
        if not enabled:
            return success(pbx_id, action='skipped', reason='disabled')
        validate_listener_port(request)
        validate_peer_ips(request)

        gateway_url = validate_gateway_url(request.get('gatewayUrl'))
        token = request.get('token')
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            refuse('request_invalid', 'token must be a 16..512 character opaque secret')
        SECRETS.append(token)

        bundle = check_bundle()
        installer = check_bundle_file(
            bundle, INSTALLER_NAME, MAX_INSTALLER,
            (b'sub-sokrat-push-send', b'--config', b'--apply'))
        hook = check_bundle_file(bundle, HOOK_NAME, MAX_HOOK, (b'unquote(',))

        config = load_root_config()
        entry = load_pbx(config, pbx_id)
        ssh_config = parse_ssh_config(entry, pbx_id)
        validate_request_pins(request, ssh_config)
        if gateway_url != ssh_config['gatewayUrl']:
            refuse('gateway_pin_mismatch',
                   'worker request gatewayUrl does not match the root config pin')

        hook_config = {'gatewayUrl': gateway_url, 'pbxId': pbx_id, 'token': token}
        hook_config_bytes = (json.dumps(hook_config, separators=(',', ':')) + '\n').encode('utf-8')
        payload = {
            'pbxId': pbx_id,
            'gatewayUrl': gateway_url,
            'dialplanFile': ssh_config['dialplanFile'],
            'hookPath': ssh_config['hookPath'],
            'hookConfigPath': ssh_config['hookConfigPath'],
            'calleeVar': ssh_config['calleeVar'],
            'callerVar': ssh_config['callerVar'],
            'nameVar': ssh_config['nameVar'],
            'callIdVar': ssh_config['callIdVar'],
            'hookConfigMode': ssh_config['hookConfigMode'],
            'hookConfigGroup': ssh_config['hookConfigGroup'],
            'hookRunnerUser': ssh_config['hookRunnerUser'],
            'reloadDialplan': ssh_config['reloadDialplan'],
            'installerB64': base64.b64encode(installer).decode('ascii'),
            'hookB64': base64.b64encode(hook).decode('ascii'),
            'hookConfigB64': base64.b64encode(hook_config_bytes).decode('ascii'),
        }
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        if len(payload_bytes) > MAX_PAYLOAD:
            refuse('payload_too_large', 'remote payload exceeds %d bytes' % MAX_PAYLOAD)

        binary = ssh_binary()
        remote_command = '/usr/bin/python3 -c ' + shlex.quote(REMOTE_CODE)
        command = ssh_argv(binary, ssh_config, remote_command)
        environment = {
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
            'HOME': os.environ.get('HOME', '/'),
            'LANG': 'C',
            'LC_ALL': 'C',
        }
        try:
            process = subprocess.run(
                command, input=payload_bytes, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=ssh_config['timeoutSeconds'],
                check=False, env=environment)
        except FileNotFoundError:
            fail('ssh_unavailable', 'ssh binary is not available: %s' % binary)
        except subprocess.TimeoutExpired:
            fail('ssh_timeout', 'ssh provisioning timed out')
        if len(process.stdout) > MAX_REMOTE_OUTPUT or len(process.stderr) > MAX_REMOTE_OUTPUT:
            fail('ssh_output_too_large', 'ssh produced too much output')
        if process.returncode != 0:
            fail('ssh_failed', 'ssh exited with status %d' % process.returncode)
        text = process.stdout.decode('utf-8', 'replace').strip()
        if not text:
            fail('remote_protocol_error', 'remote installer returned no JSON')
        try:
            remote = json.loads(text)
        except ValueError:
            fail('remote_protocol_error', 'remote installer returned invalid JSON')
        if not isinstance(remote, dict):
            fail('remote_protocol_error', 'remote installer returned a non-object')
        if remote.get('ok') is not True:
            error = remote.get('error')
            code = error.get('code') if isinstance(error, dict) else None
            detail = error.get('detail') if isinstance(error, dict) else None
            if not isinstance(code, str) or not re.match(r'^[a-z0-9_]{1,64}$', code):
                code = 'remote_refused'
            del detail
            fail(code, 'remote installer refused')
        action = remote.get('action')
        if action not in ('installed', 'unchanged'):
            action = 'installed'
        return success(
            pbx_id,
            action=action,
            host=ssh_config['sshHost'],
            user=ssh_config['sshUser'],
            dialplanFile=ssh_config['dialplanFile'],
            hookPath=ssh_config['hookPath'],
            hookConfigPath=ssh_config['hookConfigPath'],
            reload=remote.get('reload') if isinstance(remote.get('reload'), str) else None,
            hookBackup=bool(remote.get('hookBackup')),
            configBackup=bool(remote.get('configBackup')),
        )
    except Refusal as error:
        return refusal(pbx_id, error.code, error.message)
    except Failure as error:
        return failure(pbx_id, error.code, error.message)


if __name__ == '__main__':
    raise SystemExit(main())
