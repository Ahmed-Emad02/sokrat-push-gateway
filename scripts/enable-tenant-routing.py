#!/usr/bin/env python3
"""Staged activation of the multi-PBX tenant routing.

Modes (mutually exclusive):

  --prepare   Expose the tenant HTTP API under /api/gateway/ only. Legacy SIP,
              ICE and registration stay untouched. No readiness gate.
  --coexist   Transitional, NOT global approval enforcement: a /ws upgrade that
              carries a nonempty `ticket` query parameter is proxied to the
              tenant runtime on loopback 9097. A bare legacy /ws, legacy ICE and
              legacy registration keep going to the existing PBX. The ticket is
              authoritative: an invalid ticket is answered by the tenant runtime
              (403) and NEVER falls back to the PBX.
  (default)   Full activation: /ws, ICE and registration move to the tenant
              runtime and the legacy public routes return 410. Requires
              --confirm-device-migration plus the readiness gate below.

Readiness for full activation is derived only from the private control store and
runtime manifest named by CONTROL_DATA_FILE / TENANT_RUNTIME_FILE (environment,
or --env-file parsed without a shell). It requires:

  * at least one approved device with an activated credential for an enabled PBX,
  * every enabled PBX has a relay whose peers match that PBX's mediaIps,
  * every enabled PBX has a valid hook hash,
  * any enabled PBX that opted into management is approved.

`/api/gateway/capabilities` is a static liveness document. It is never treated as
proof that devices, relays or hooks are ready. No secret value is ever printed.
Updates existing nginx gateway sites, keeping timestamped rollback copies.
No PBX edits.
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.request

WS_LOCATION = re.compile(r'location\s*=\s*/ws\s*\{')
COEXIST_MARKER = '$sokrat_ws_upstream'
TENANT_WS_UPSTREAM = 'http://127.0.0.1:9097'
ENV_LINE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
HASH = re.compile(r'[a-f0-9]{64}')
PBX_ID = re.compile(r'[A-Za-z0-9_-]{1,80}')


def prepare(push):
    if 'location /api/gateway/' in push:
        return push
    if push.count('    location / {') != 1:
        raise ValueError('HTTP nginx fallback configuration not recognized')
    return push.replace('    location / {', '''    location /api/gateway/ {
        limit_req zone=push_reg burst=20 nodelay;
        proxy_pass http://127.0.0.1:9097;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 16k;
        access_log off;
    }

    location / {''')


def _ws_span(sip):
    """Return (start, end) of the single `location = /ws { ... }` block."""
    matches = list(WS_LOCATION.finditer(sip))
    if len(matches) != 1:
        raise ValueError('SIP nginx configuration must contain exactly one /ws location')
    start = matches[0].start()
    depth = 0
    for index in range(matches[0].end() - 1, len(sip)):
        if sip[index] == '{':
            depth += 1
        elif sip[index] == '}':
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise ValueError('SIP nginx /ws location is not terminated')


def render_coexist(sip, push):
    """Route only ticketed /ws upgrades to the tenant runtime.

    The upstream is chosen by a variable, never by a conditional proxy_pass, so
    a nonempty ticket can only ever select the tenant runtime. The bare legacy
    upgrade keeps the original PBX upstream and the original Host header.
    Legacy ICE and registration stay untouched.
    """
    start, end = _ws_span(sip)
    block = sip[start:end]
    if COEXIST_MARKER in block:
        if (block.count('proxy_pass') != 1
                or 'if ($arg_ticket != "")' not in block
                or 'set $sokrat_ws_upstream ' + TENANT_WS_UPSTREAM + ';' not in block
                or 'proxy_pass $sokrat_ws_upstream$request_uri;' not in block):
            raise ValueError('Coexist SIP configuration is not recognized')
        return sip, prepare(push)
    if 'proxy_http_version 1.1;' not in block:
        raise ValueError('SIP /ws location is not the recognized gateway site')
    upstreams = list(re.finditer(r'proxy_pass http://([A-Za-z0-9.:-]+):8088/ws;', block))
    if len(upstreams) != 1 or block.count('proxy_pass') != 1:
        raise ValueError('SIP /ws upstream is not recognized')
    match = upstreams[0]
    upstream = match.group(1)
    try:
        ipaddress.ip_address(upstream)
    except ValueError:
        # A variable proxy_pass needs a resolver for names; refuse instead of
        # writing a config that only fails at runtime.
        raise ValueError('SIP /ws upstream must be a literal IP for a variable proxy_pass')
    line_start = block.rfind('\n', 0, match.start()) + 1
    indent = block[line_start:match.start()]
    if indent.strip():
        raise ValueError('SIP /ws upstream is not recognized')
    replacement = (
        f'set $sokrat_ws_host {upstream}:8088;\n'
        f'{indent}set $sokrat_ws_upstream http://{upstream}:8088;\n'
        f'{indent}# A nonempty ticket is authoritative: tenant runtime only, never the PBX.\n'
        f'{indent}if ($arg_ticket != "") {{\n'
        f'{indent}    set $sokrat_ws_upstream {TENANT_WS_UPSTREAM};\n'
        f'{indent}    set $sokrat_ws_host 127.0.0.1:9097;\n'
        f'{indent}}}\n'
        f'{indent}proxy_pass $sokrat_ws_upstream$request_uri;'
    )
    block = block[:match.start()] + replacement + block[match.end():]
    # A variable proxy_pass does not define $proxy_host; keep the legacy Host.
    block = block.replace('proxy_set_header Host $proxy_host;', 'proxy_set_header Host $sokrat_ws_host;')
    return sip[:start] + block + sip[end:], prepare(push)


def render(sip, push):
    if COEXIST_MARKER in sip:
        raise ValueError('SIP site is in coexist mode; restore the pre-coexist backup before full activation')
    sip, count = re.subn(r'proxy_pass http://[^;]+:8088/ws;', 'proxy_pass http://127.0.0.1:9097/ws;', sip)
    if count != 1 and sip.count('proxy_pass http://127.0.0.1:9097/ws;') != 1:
        raise ValueError('SIP nginx configuration not recognized')
    push = prepare(push)
    # Remove exact legacy routes, then add explicit denial before any prefix
    # proxy. This also works for already-cut-over one-line denial locations.
    for endpoint in ('/api/push/register-device', '/api/push/remove-device', '/api/mobile/ice'):
        pattern = r'\s*location\s*=\s*' + re.escape(endpoint) + r'\s*\{[^{}]*\}'
        push, count = re.subn(pattern, '\n    location = ' + endpoint + ' { return 410; }', push)
        if count != 1:
            raise ValueError('Expected one legacy route for ' + endpoint)
    return sip, push


def _is_hash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def _is_ip(value):
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _device_ready(device, enabled_ids):
    """A device the tenant runtime can actually authenticate.

    `verifyDeviceSecret` needs an approved record with a secret digest; a claim
    device only holds its credential after redemption. Invite devices receive
    their secret at approval, so they have no claim to redeem.
    """
    if not isinstance(device, dict) or device.get('status') != 'approved':
        return False
    if not _is_hash(device.get('secretHash')):
        return False
    if not isinstance(device.get('extension'), str) or not device['extension'].strip():
        return False
    if device.get('pbxId') not in enabled_ids:
        return False
    if device.get('claimRedeemedAt'):
        return True
    return device.get('enrollmentMode') == 'invite'


def validate_readiness(state, manifest):
    """Pure readiness gate. Returns a list of problem strings (empty = ready).

    Never raises, never touches the filesystem, and never includes a secret.
    """
    problems = []
    if not isinstance(state, dict):
        return ['control store: not an object']
    pbxs = state.get('pbx')
    devices = state.get('devices')
    if not isinstance(pbxs, list):
        problems.append('control store: pbx list is missing')
    if not isinstance(devices, list):
        problems.append('control store: device list is missing')
    schema = state.get('schemaVersion')
    if schema is not None and schema not in (1, 2):
        problems.append('control store: unsupported schema version')
    if problems:
        return problems
    if not isinstance(manifest, dict):
        return ['runtime manifest: not an object']
    relays = manifest.get('relays')
    hooks = manifest.get('hookHashes')
    if not isinstance(relays, dict):
        problems.append('runtime manifest: relays are missing')
    if not isinstance(hooks, dict):
        problems.append('runtime manifest: hookHashes are missing')
    if problems:
        return problems

    enabled = [pbx for pbx in pbxs if isinstance(pbx, dict) and pbx.get('enabled') is True]
    enabled_ids = {pbx.get('id') for pbx in enabled}
    if not any(_device_ready(device, enabled_ids) for device in devices):
        problems.append('no approved claimed device credential for an enabled PBX')

    for pbx in enabled:
        pbx_id = pbx.get('id')
        if not isinstance(pbx_id, str) or PBX_ID.fullmatch(pbx_id) is None:
            problems.append('enabled PBX with an invalid id')
            continue
        management = pbx.get('management')
        if isinstance(management, dict) and management.get('approvalStatus') != 'approved':
            problems.append(f'PBX {pbx_id}: management approval is not approved')

        relay = relays.get(pbx_id)
        if not isinstance(relay, dict):
            problems.append(f'PBX {pbx_id}: no tenant relay provisioned')
        else:
            if not isinstance(relay.get('host'), str) or not relay['host']:
                problems.append(f'PBX {pbx_id}: relay host is missing')
            port = relay.get('port')
            if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
                problems.append(f'PBX {pbx_id}: relay port is invalid')
            secret_file = relay.get('secretFile')
            if not isinstance(secret_file, str) or not os.path.isabs(secret_file):
                problems.append(f'PBX {pbx_id}: relay secret path is invalid')
            peers = relay.get('peerIps')
            if not isinstance(peers, list) or not peers or not all(_is_ip(ip) for ip in peers):
                problems.append(f'PBX {pbx_id}: relay peer list is invalid')
            else:
                media = pbx.get('mediaIps')
                if not isinstance(media, list) or not media:
                    problems.append(f'PBX {pbx_id}: mediaIps are missing')
                elif sorted(str(ip) for ip in peers) != sorted(str(ip) for ip in media):
                    problems.append(f'PBX {pbx_id}: relay peers do not match mediaIps')

        if not _is_hash(hooks.get(pbx_id)):
            problems.append(f'PBX {pbx_id}: hook hash is missing or invalid')
    return problems


def relay_secret_problems(state, manifest):
    """Check the relay secrets the runtime will read. Values are never printed."""
    problems = []
    relays = manifest.get('relays') if isinstance(manifest, dict) else None
    if not isinstance(relays, dict) or not isinstance(state, dict):
        return problems
    for pbx in state.get('pbx') or []:
        if not isinstance(pbx, dict) or pbx.get('enabled') is not True:
            continue
        pbx_id = pbx.get('id')
        relay = relays.get(pbx_id)
        if not isinstance(relay, dict):
            continue
        path = relay.get('secretFile')
        if not isinstance(path, str) or not os.path.isabs(path):
            continue
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except OSError:
            problems.append(f'PBX {pbx_id}: relay secret file is missing or unreadable')
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                problems.append(f'PBX {pbx_id}: relay secret file is not private')
                continue
            secret = os.read(fd, 128).decode('utf-8', 'replace').strip()
            if HASH.fullmatch(secret) is None:
                problems.append(f'PBX {pbx_id}: relay secret is not a 64-hex value')
        finally:
            os.close(fd)
    return problems


def parse_env_text(text):
    """Parse KEY=VALUE lines without a shell: no sourcing, no expansion."""
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        match = ENV_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key] = value
    return values


def parse_env_file(path):
    if os.path.islink(path):
        raise SystemExit('Environment file must not be a symlink')
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return parse_env_text(handle.read(256 * 1024))
    except OSError:
        raise SystemExit('Environment file is not readable')


def resolve_private_paths(env_file=None):
    values = {}
    default = '/etc/sokrat/gateway-control.env'
    if env_file or os.path.exists(default):
        values = parse_env_file(env_file or default)
    control = os.environ.get('CONTROL_DATA_FILE') or values.get('CONTROL_DATA_FILE')
    manifest = os.environ.get('TENANT_RUNTIME_FILE') or values.get('TENANT_RUNTIME_FILE')
    if not control or not manifest:
        raise SystemExit('CONTROL_DATA_FILE and TENANT_RUNTIME_FILE are required (environment or --env-file)')
    return control, manifest


def read_private_json(path, label):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise SystemExit(label + ' is missing or not readable')
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(label + ' must be a regular file')
        if info.st_mode & 0o007:
            raise SystemExit(label + ' must not be world-accessible')
        handle = os.fdopen(fd, 'r', encoding='utf-8')
        fd = -1
        with handle:
            text = handle.read()
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        return json.loads(text)
    except ValueError:
        raise SystemExit(label + ' is not valid JSON')


def readiness_problems(env_file=None):
    control_path, manifest_path = resolve_private_paths(env_file)
    state = read_private_json(control_path, 'Control store')
    manifest = read_private_json(manifest_path, 'Runtime manifest')
    problems = validate_readiness(state, manifest)
    if not problems:
        problems = relay_secret_problems(state, manifest)
    return problems


def require_tenant_runtime():
    """Liveness only. This document is static and is never a readiness proof."""
    try:
        with urllib.request.urlopen(TENANT_WS_UPSTREAM + '/api/gateway/capabilities', timeout=5) as response:
            ready = response.status == 200 and json.load(response).get('deviceApproval') is True
    except Exception:
        ready = False
    if not ready:
        raise SystemExit('Tenant runtime is not answering on loopback 9097')


def main():
    parser = argparse.ArgumentParser(description='Staged activation of tenant routing.')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--prepare', action='store_true', help='Expose enrollment/tenant HTTP APIs only; preserve legacy SIP and ICE until devices are approved')
    modes.add_argument('--coexist', action='store_true', help='Transitional: ticketed /ws upgrades use the tenant runtime; bare legacy /ws, ICE and registration stay on the existing PBX')
    parser.add_argument('--confirm-device-migration', action='store_true', help='Required for full activation: legacy public /ws, registration and ICE are blocked')
    parser.add_argument('--env-file', default=None, help='Private KEY=VALUE file providing CONTROL_DATA_FILE/TENANT_RUNTIME_FILE (never sourced)')
    args = parser.parse_args()

    if args.prepare or args.coexist:
        require_tenant_runtime()
    if args.prepare:
        mode = 'prepare'
    elif args.coexist:
        mode = 'coexist'
    else:
        if not args.confirm_device_migration:
            raise SystemExit('Full activation blocks legacy clients; re-run with --confirm-device-migration (or use --coexist)')
        problems = readiness_problems(args.env_file)
        if problems:
            for problem in problems:
                print('readiness: ' + problem, file=sys.stderr)
            raise SystemExit('Full activation refused: tenant device migration is not ready')
        require_tenant_runtime()
        mode = 'full'

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    paths = [Path('/etc/nginx/sites-available/sokrat-sip'), Path('/etc/nginx/sites-available/sokrat-push')]
    originals = {path: path.read_text() for path in paths}
    if mode == 'prepare':
        rendered = (originals[paths[0]], prepare(originals[paths[1]]))
    elif mode == 'coexist':
        rendered = render_coexist(*(originals[path] for path in paths))
    else:
        rendered = render(*(originals[path] for path in paths))
    try:
        for path, text in zip(paths, rendered):
            shutil.copy2(path, str(path) + '.bak-tenant-' + stamp)
            path.write_text(text)
        subprocess.run(['nginx', '-t'], check=True)
        subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
    except Exception:
        for path, text in originals.items():
            path.write_text(text)
        subprocess.run(['nginx', '-t'], check=True)
        subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
        raise
    if mode == 'prepare':
        print('Enrollment APIs staged; legacy routing unchanged.')
    elif mode == 'coexist':
        print('Coexist routing enabled: ticketed /ws upgrades use the tenant runtime; bare legacy /ws, ICE and registration stay on the existing PBX.')
    else:
        print('Approval routing enabled. Legacy public registration/ICE endpoints disabled.')


if __name__ == '__main__':
    main()
