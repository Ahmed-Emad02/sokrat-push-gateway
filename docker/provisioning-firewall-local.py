#!/usr/bin/env python3
"""Fail-closed, per-tenant TURN listener gate for a host-networked gateway.

Rules precede UFW's general listener-range allowance. Disabling one tenant must
therefore deny its listener even on hosts that previously opened the full range.
No firewall flush, policy change or unrelated port modification is performed.
"""
import json
import http.client
from pathlib import Path
import re
import shutil
import subprocess
import sys

LISTENER_MIN = 3500
LISTENER_MAX = 3654
PBX_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')


def run_cmd(cmd, check=True):
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, universal_newlines=True, timeout=15)


def configure(port, enabled):
    binary = shutil.which('iptables')
    if not binary:
        raise ValueError('iptables is required for the tenant listener gate')
    chain = 'SKGL' + str(port)
    prefix = [binary, '-w', '5']
    existing = run_cmd(prefix + ['-S', chain], check=False)
    if existing.returncode:
        run_cmd(prefix + ['-N', chain])
        run_cmd(prefix + ['-A', chain, '-j', 'DROP'])
    else:
        lines = existing.stdout.strip().splitlines()
        if lines not in ([f'-N {chain}', f'-A {chain} -j ACCEPT'],
                         [f'-N {chain}', f'-A {chain} -j DROP']):
            raise ValueError('Refusing an unmanaged listener gate')
    # Atomic rule replacement avoids a fail-open flush window. Revoke before
    # installing missing jumps; enable only after both protocol jumps exist.
    if not enabled:
        run_cmd(prefix + ['-R', chain, '1', '-j', 'DROP'])
    for proto in ('tcp', 'udp'):
        rule = ['INPUT', '-p', proto, '--dport', str(port), '-j', chain]
        if run_cmd(prefix + ['-C'] + rule, check=False).returncode:
            run_cmd(prefix + ['-I', 'INPUT', '1'] + rule[1:])
    if enabled:
        run_cmd(prefix + ['-R', chain, '1', '-j', 'ACCEPT'])


def delegate(request):
    """No Docker NET_ADMIN: ask the root host service to validate and gate it."""
    config = json.loads(Path('/etc/sokrat/tunnel-enrollment/firewall-client.json').read_text())
    token = Path('/etc/sokrat/gateway-tunnel-bridge.token').read_text().strip()
    conn = http.client.HTTPConnection('127.0.0.1', config['pluginPort'], timeout=20)
    try:
        conn.request('POST','/firewall',json.dumps(request),
                     {'Content-Type':'application/json','X-Sokrat-Tunnel-Bridge':token})
        response = conn.getresponse()
        body = response.read(4097)
        if response.status != 200 or len(body)>4096 or json.loads(body).get('success') is not True:
            raise ValueError('Host firewall refused')
    finally:
        conn.close()


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: provisioning-firewall-local.py <pbxId>\n")
        sys.exit(2)

    pbx_id = sys.argv[1]
    if not PBX_ID_RE.match(pbx_id):
        sys.stderr.write("Invalid pbxId format\n")
        sys.exit(2)

    try:
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            raise ValueError('Request too large')
        request = json.loads(raw)
        if not isinstance(request, dict) or request.get('pbxId') != pbx_id:
            raise ValueError('PBX identity mismatch')
        if type(request.get('enabled')) is not bool:
            raise ValueError('Explicit enabled flag required')
    except (ValueError, TypeError):
        sys.stderr.write('Invalid firewall request\n')
        sys.exit(1)

    port = request.get("listenerPort")
    if type(port) is not int or port < LISTENER_MIN or port > LISTENER_MAX:
        sys.stderr.write(f"Invalid listener port: {port}\n")
        sys.exit(2)

    try:
        if Path('/etc/sokrat/tunnel-enrollment/firewall-client.json').exists():
            delegate(request)
        else:
            configure(port, request['enabled'])
    except (ValueError, OSError, subprocess.SubprocessError):
        sys.stderr.write('Tenant listener firewall update failed\n')
        return 1

    print(json.dumps({"action": "applied" if request['enabled'] else 'revoked',
                      "pbxId": pbx_id, "listenerPort": port}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
