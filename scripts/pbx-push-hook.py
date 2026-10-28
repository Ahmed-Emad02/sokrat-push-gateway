#!/usr/bin/env python3
"""Tenant PBX push hook: invoke from the existing mobile-only predial hook.

Usage: pbx-push-hook.py CALLEE CALLER NAME CALL_ID
Root-owned config /etc/sokrat/gateway-hook.json (override SOKRAT_HOOK_CONFIG):
{gatewayUrl, pbxId, token}. Install readable by Asterisk only (0640 root:asterisk).
No credentials in argv/URL. This script does not install any dialplan patterns.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import time
import urllib.request

try:
    file = Path(os.environ.get('SOKRAT_HOOK_CONFIG', '/etc/sokrat/gateway-hook.json'))
    if file.is_symlink() or file.stat().st_mode & 0o007:
        raise ValueError('Hook config must not be public')
    config = json.loads(file.read_text())
    callee, caller, name, call_id = sys.argv[1:5]
    if not config['gatewayUrl'].startswith(('http://', 'https://')):
        raise ValueError('Invalid gateway URL')
    body = json.dumps({'callee': callee, 'caller': caller, 'callerName': name, 'callId': call_id}).encode()
    request = urllib.request.Request(config['gatewayUrl'].rstrip('/') + '/api/gateway/incoming-call', data=body,
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + config['token'],
                 'X-Sokrat-Pbx': config['pbxId'], 'X-Sokrat-Timestamp': str(int(time.time() * 1000)),
                 'X-Sokrat-Nonce': secrets.token_hex(16)}, method='POST')
    with urllib.request.urlopen(request, timeout=3) as response:
        print('Gateway push hook HTTP', response.status)
except Exception:
    # Never print HTTP request headers, body, tokens or provider details.
    print('Gateway push hook failed', file=sys.stderr)
    raise SystemExit(1)
