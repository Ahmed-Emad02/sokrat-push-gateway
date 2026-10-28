#!/usr/bin/env python3
"""Explicit cutover after client enrollment and relay validation.

Updates existing nginx gateway sites, keeping timestamped rollback copies.
No PBX edits. Requires the local tenant runtime to respond before cutover.
"""
import datetime
from pathlib import Path
import shutil
import subprocess
import urllib.request
import re

def render(sip, push):
    sip, count = re.subn(r'proxy_pass http://[^;]+:8088/ws;', 'proxy_pass http://127.0.0.1:9097/ws;', sip)
    if count != 1 and sip.count('proxy_pass http://127.0.0.1:9097/ws;') != 1:
        raise ValueError('SIP nginx configuration not recognized')
    if 'location /api/gateway/' not in push:
        if push.count('    location / {') != 1:
            raise ValueError('HTTP nginx fallback configuration not recognized')
        push = push.replace('    location / {', '''    location /api/gateway/ {
        limit_req zone=push_reg burst=20 nodelay;
        proxy_pass http://127.0.0.1:9097;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 16k;
        access_log off;
    }

    location / {''')
    # Remove exact legacy routes, then add explicit denial before any prefix
    # proxy. This also works for already-cut-over one-line denial locations.
    for endpoint in ('/api/push/register-device', '/api/push/remove-device', '/api/mobile/ice'):
        pattern = r'\s*location\s*=\s*' + re.escape(endpoint) + r'\s*\{[^{}]*\}'
        push, count = re.subn(pattern, '\n    location = ' + endpoint + ' { return 410; }', push)
        if count != 1:
            raise ValueError('Expected one legacy route for ' + endpoint)
    return sip, push


def main():
    with urllib.request.urlopen('http://127.0.0.1:9097/api/gateway/capabilities', timeout=5) as response:
        import json
        if response.status != 200 or json.load(response).get('deviceApproval') is not True:
            raise SystemExit('Tenant approval runtime is not ready')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    paths = [Path('/etc/nginx/sites-available/sokrat-sip'), Path('/etc/nginx/sites-available/sokrat-push')]
    originals = {path: path.read_text() for path in paths}
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
    print('Approval routing enabled. Legacy public registration/ICE endpoints disabled.')


if __name__ == '__main__':
    main()
