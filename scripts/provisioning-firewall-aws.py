#!/usr/bin/env python3
"""Optional root provisioning adapter: permit one tenant listener in AWS EC2.

Contract (worker -> adapter):

    provisioning-firewall-aws.py <pbxId>   (exactly one argv element, never a secret)

The worker writes one bounded JSON object to stdin:

    {pbxId, gatewayUrl, listenerPort, peerIps, enabled, token}

This adapter never reads, forwards, or logs ``token``. When ``enabled`` is
false it returns ``{"action": "skipped"}`` and makes no AWS call, so disabling a
PBX never removes or rewrites an existing customer rule.

The adapter itself must live in the immutable root bundle
``/usr/local/lib/sokrat-tenant-provisioning`` (override only for tests with
``SOKRAT_PROVISIONING_BUNDLE``). Root config (default
``/etc/sokrat/gateway-provisioning-adapters.json``, mode 0600, root-owned, no
symlink ancestors; override for tests with
``SOKRAT_PROVISIONING_ADAPTERS_CONFIG``)::

    {
      "firewall": {
        "region": "us-east-1",
        "securityGroupId": "sg-0123456789abcdef0",
        "profile": null
      },
      "pbx": {
        "pbx_example": {
          "firewall": {
            "region": "eu-central-1",
            "securityGroupId": "sg-0123456789abcdef0"
          }
        }
      }
    }

``firewall`` may be supplied globally, per PBX, or both (per-PBX fields
override global fields). The adapter requires an IAM instance-role environment
(the normal AWS CLI credential chain); it never accepts access keys in argv or
stdin. If the AWS CLI is not installed it fails closed with
``cloud_unavailable``.

Scope is deliberately tiny: only the allocated tenant listener port
(``3500..3654``) is considered, and only exact TCP and UDP rules from
``0.0.0.0/0`` are added. Existing rules are queried first and an exact rule is
never duplicated. This adapter never authorizes the private relay range, never
authorizes a broad RTP range, never uses ``0-65535``, and never deletes or
revokes any rule.

Request compatibility: ``listenerPort`` may be top-level, or nested under
``allocation``, ``tenant``, or ``relay``. Conflicting values are refused. A
request may set ``dryRun: true`` for a read-only preview (the worker invocation
itself is considered apply and needs no flag).

Output is one JSON object on stdout (no secrets), exit 0 on success/unchanged/
skipped, 2 on a safe refusal, 1 on an operational failure.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

ADAPTER = 'firewall-aws'
DEFAULT_CONFIG = '/etc/sokrat/gateway-provisioning-adapters.json'
DEFAULT_BUNDLE = '/usr/local/lib/sokrat-tenant-provisioning'

MAX_STDIN = 64 * 1024
MAX_CONFIG = 64 * 1024
MAX_AWS_OUTPUT = 4 * 1024 * 1024

PBX_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
REGION_RE = re.compile(r'^[a-z]{2,}(?:-[a-z0-9]+)+$')
SECURITY_GROUP_RE = re.compile(r'^sg-[0-9a-f]{8,17}$')
PROFILE_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
LISTENER_MIN = 3500
LISTENER_MAX = 3654
LISTENER_PROTOCOLS = ('tcp', 'udp')
PUBLIC_CIDR = '0.0.0.0/0'
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


def resolve_firewall(config, pbx_id):
    global_firewall = config.get('firewall')
    if global_firewall is None:
        global_firewall = {}
    if not isinstance(global_firewall, dict):
        refuse('config_invalid', 'global firewall config must be an object')
    merged = dict(global_firewall)
    pbx = config.get('pbx')
    entry = None
    if isinstance(pbx, dict):
        entry = pbx.get(pbx_id)
    if entry is not None:
        if not isinstance(entry, dict):
            refuse('config_invalid', 'pbx entry for %s must be an object' % pbx_id)
        scoped = entry.get('firewall')
        if scoped is None and any(key in entry for key in ('region', 'securityGroupId', 'profile')):
            scoped = entry
        if scoped is not None:
            if not isinstance(scoped, dict):
                refuse('config_invalid', 'pbx firewall config for %s must be an object' % pbx_id)
            merged.update(scoped)
    region = merged.get('region')
    security_group = merged.get('securityGroupId')
    if not isinstance(region, str) or not REGION_RE.match(region):
        refuse('firewall_unconfigured', 'firewall.region is not configured for %s' % pbx_id)
    if not isinstance(security_group, str) or not SECURITY_GROUP_RE.match(security_group):
        refuse('firewall_unconfigured',
               'firewall.securityGroupId is not configured for %s' % pbx_id)
    profile = merged.get('profile')
    if profile is not None:
        if not isinstance(profile, str) or not PROFILE_RE.match(profile):
            refuse('config_invalid', 'firewall.profile is invalid')
    return {'region': region, 'securityGroupId': security_group, 'profile': profile}


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


def extract_listener_port(request):
    candidates = []
    if 'listenerPort' in request:
        candidates.append(('listenerPort', request['listenerPort']))
    for parent in ('allocation', 'tenant', 'relay'):
        nested = request.get(parent)
        if isinstance(nested, dict) and 'listenerPort' in nested:
            candidates.append(('%s.listenerPort' % parent, nested['listenerPort']))
    if not candidates:
        refuse('listener_port_missing', 'worker request has no listenerPort')
    for label, value in candidates:
        if isinstance(value, bool) or not isinstance(value, int):
            refuse('request_invalid', '%s must be an integer' % label)
        if not LISTENER_MIN <= value <= LISTENER_MAX:
            refuse('listener_port_out_of_scope',
                   '%s must be in %d..%d' % (label, LISTENER_MIN, LISTENER_MAX))
    values = {value for _, value in candidates}
    if len(values) != 1:
        refuse('listener_port_conflict', 'worker request listenerPort values conflict')
    return candidates[0][1]


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


def validate_scope_pins(request, firewall):
    for key in ('region', 'securityGroupId'):
        if key in request and request[key] != firewall[key]:
            refuse('request_scope_override',
                   'worker request %s is pinned by the root config' % key)


def validate_dry_run(request):
    if 'dryRun' not in request:
        return False
    value = request['dryRun']
    if not isinstance(value, bool):
        refuse('request_invalid', 'dryRun must be a boolean')
    return value


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


def aws_binary():
    override = os.environ.get('SOKRAT_PROVISIONING_AWS')
    if override:
        if not os.path.isabs(override):
            refuse('aws_binary_unsafe', 'SOKRAT_PROVISIONING_AWS must be an absolute path')
        candidate = override
    else:
        candidate = shutil.which('aws')
        if not candidate:
            fail('cloud_unavailable', 'AWS CLI is not installed on this gateway')
    if not os.path.exists(candidate):
        fail('cloud_unavailable', 'AWS CLI is not installed on this gateway')
    try:
        return check_executable(candidate, 'AWS CLI')
    except Refusal as error:
        fail('cloud_unavailable', error.message)


def aws_environment():
    environment = {}
    for key, value in os.environ.items():
        if key.startswith('AWS_') or key in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ'):
            environment[key] = value
    environment['AWS_PAGER'] = ''
    environment['AWS_CLI_AUTO_PROMPT'] = 'off'
    return environment


def aws_error_code(stderr):
    text = stderr.decode('utf-8', 'replace')
    match = re.search(r'An error occurred \(([A-Za-z0-9._-]+)\)', text)
    if match:
        return match.group(1)
    match = re.search(r'Error Code:\s*([A-Za-z0-9._-]+)', text)
    if match:
        return match.group(1)
    return 'aws_error'


def run_aws(binary, profile, args, timeout=60):
    command = [binary]
    if profile:
        command.extend(['--profile', profile])
    command.extend(args)
    try:
        process = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
            env=aws_environment())
    except FileNotFoundError:
        fail('cloud_unavailable', 'AWS CLI is not installed on this gateway')
    except subprocess.TimeoutExpired:
        fail('aws_timeout', 'AWS CLI timed out')
    if len(process.stdout) > MAX_AWS_OUTPUT or len(process.stderr) > MAX_AWS_OUTPUT:
        fail('aws_output_too_large', 'AWS CLI produced too much output')
    if process.returncode != 0:
        fail('aws_error', aws_error_code(process.stderr))
    return process.stdout


def describe_group(binary, firewall):
    args = ['ec2', 'describe-security-groups',
            '--region', firewall['region'],
            '--group-ids', firewall['securityGroupId'],
            '--output', 'json']
    stdout = run_aws(binary, firewall['profile'], args)
    try:
        data = json.loads(stdout.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        fail('aws_invalid_response', 'AWS CLI returned invalid JSON')
    groups = data.get('SecurityGroups') if isinstance(data, dict) else None
    if not isinstance(groups, list):
        fail('aws_invalid_response', 'AWS CLI response has no SecurityGroups')
    for group in groups:
        if isinstance(group, dict) and group.get('GroupId') == firewall['securityGroupId']:
            return group
    fail('security_group_not_found',
         'security group %s was not found' % firewall['securityGroupId'])


def has_exact_rule(group, protocol, port):
    permissions = group.get('IpPermissions')
    if not isinstance(permissions, list):
        return False
    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        if permission.get('IpProtocol') != protocol:
            continue
        if permission.get('FromPort') != port or permission.get('ToPort') != port:
            continue
        ranges = permission.get('IpRanges')
        if not isinstance(ranges, list):
            continue
        for entry in ranges:
            if isinstance(entry, dict) and entry.get('CidrIp') == PUBLIC_CIDR:
                return True
    return False


def authorize_missing(binary, firewall, port, protocols):
    permissions = []
    for protocol in protocols:
        permissions.append({
            'IpProtocol': protocol,
            'FromPort': port,
            'ToPort': port,
            'IpRanges': [{
                'CidrIp': PUBLIC_CIDR,
                'Description': 'Sokrat tenant listener %s/%d' % (protocol, port),
            }],
        })
    args = ['ec2', 'authorize-security-group-ingress',
            '--region', firewall['region'],
            '--group-id', firewall['securityGroupId'],
            '--ip-permissions', json.dumps(permissions, separators=(',', ':'))]
    try:
        run_aws(binary, firewall['profile'], args)
    except Failure as error:
        if error.code == 'aws_error' and error.message == 'InvalidPermission.Duplicate':
            return
        raise


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pbx_id = None
    try:
        if len(argv) != 1:
            refuse('usage', 'usage: provisioning-firewall-aws.py <pbxId>')
        pbx_id = argv[0]
        if not PBX_ID_RE.match(pbx_id):
            refuse('usage', 'pbxId must match %s' % PBX_ID_RE.pattern)
        request = read_request()
        enabled = validate_shared(request, pbx_id)
        if not enabled:
            return success(pbx_id, action='skipped', reason='disabled')
        port = extract_listener_port(request)
        validate_peer_ips(request)
        dry_run = validate_dry_run(request)

        bundle = check_bundle()
        del bundle
        config = load_root_config()
        firewall = resolve_firewall(config, pbx_id)
        validate_scope_pins(request, firewall)
        binary = aws_binary()

        group = describe_group(binary, firewall)
        present = [protocol for protocol in LISTENER_PROTOCOLS
                   if has_exact_rule(group, protocol, port)]
        missing = [protocol for protocol in LISTENER_PROTOCOLS if protocol not in present]
        if not missing:
            return success(pbx_id, action='unchanged', listenerPort=port,
                           region=firewall['region'],
                           securityGroupId=firewall['securityGroupId'],
                           present=present, authorized=[], pending=[])
        if dry_run:
            return success(pbx_id, action='would-authorize', listenerPort=port,
                           region=firewall['region'],
                           securityGroupId=firewall['securityGroupId'],
                           present=present, authorized=[], pending=missing)

        authorize_missing(binary, firewall, port, missing)
        verified = None
        for attempt in range(3):
            group = describe_group(binary, firewall)
            verified = [protocol for protocol in LISTENER_PROTOCOLS
                        if has_exact_rule(group, protocol, port)]
            if len(verified) == len(LISTENER_PROTOCOLS):
                break
            if attempt < 2:
                time.sleep(1)
        if verified is None or len(verified) != len(LISTENER_PROTOCOLS):
            fail('firewall_verification_failed',
                 'listener rules were not visible after authorization')
        return success(pbx_id, action='authorized', listenerPort=port,
                       region=firewall['region'],
                       securityGroupId=firewall['securityGroupId'],
                       present=verified, authorized=missing, pending=[])
    except Refusal as error:
        return refusal(pbx_id, error.code, error.message)
    except Failure as error:
        return failure(pbx_id, error.code, error.message)


if __name__ == '__main__':
    raise SystemExit(main())
