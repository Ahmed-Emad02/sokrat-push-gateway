#!/usr/bin/env python3
"""Run as root on the gateway. Deployment values come from environment.

Does not change PBX transports, endpoints or dialplan. Backups are kept beside
modified files. TURN relays on the private link: no public RTP range is needed.
"""
import datetime
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess


def required(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise SystemExit(f'{name} is required')
    return value


def run(*args):
    subprocess.run(args, check=True)


def write(path, text, mode=0o644):
    path = Path(path)
    if path.exists():
        shutil.copy2(path, str(path) + '.bak-' + stamp)
    path.write_text(text)
    path.chmod(mode)


stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
public = required('GATEWAY_PUBLIC_HOST')
if not re.fullmatch(r'[a-zA-Z0-9.-]+', public):
    raise SystemExit('Invalid public hostname')
pbx = str(ipaddress.IPv4Address(required('PBX_PRIVATE_IP')))
relay = str(ipaddress.IPv4Address(required('GATEWAY_PRIVATE_IP')))
listen = str(ipaddress.IPv4Address(required('GATEWAY_LISTEN_IP')))
root = Path(os.environ.get('GATEWAY_APP_DIR', '/opt/sokrat-push-gateway'))
envpath = root / '.env'
env = envpath.read_text()
secret_match = re.search(r'^TURN_SHARED_SECRET=(.*)$', env, re.M)
secret = secret_match.group(1) if secret_match else secrets.token_hex(32)
if not re.fullmatch(r'[a-f0-9]{64}', secret):
    raise SystemExit('Expected a 32-byte hexadecimal TURN secret')
for name, value in {
    'TURN_SHARED_SECRET': secret,
    'TURN_PUBLIC_HOST': public,
    'PBX_AUTH_URL': f'http://{pbx}:8080',
}.items():
    env = re.sub(r'^' + name + r'=.*\n?', '', env, flags=re.M)
    env = env.rstrip() + '\n' + name + '=' + value + '\n'
write(envpath, env, 0o600)

write('/etc/turnserver.conf', f'''# Managed by configure-public-gateway.py
listening-port=3478
listening-ip={listen}
listening-ip={relay}
relay-ip={relay}
min-port=49160
max-port=49260
fingerprint
use-auth-secret
static-auth-secret={secret}
realm=sokrat-gateway
server-name=sokrat-gateway
user-quota=12
total-quota=400
max-bps=256000
no-tls
no-dtls
no-tcp-relay
no-multicast-peers
denied-peer-ip=0.0.0.0-255.255.255.255
allowed-peer-ip={pbx}
no-cli
no-loopback-peers
log-file=syslog
simple-log
''', 0o640)
run('chown', 'root:turnserver', '/etc/turnserver.conf')
write('/etc/nginx/conf.d/sokrat-ws-limit.conf', '''limit_conn_zone $binary_remote_addr zone=sokrat_ws:10m;
''')
write('/etc/nginx/sites-available/sokrat-sip', f'''# Only WebSocket SIP is exposed. No ARI/HTTP PBX endpoints.
server {{
    listen 8088;
    server_name {public};
    location = /ws {{
        access_log off;
        limit_conn sokrat_ws 10;
        if ($http_upgrade !~* "^websocket$") {{ return 426; }}
        proxy_pass http://{pbx}:8088/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $proxy_host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }}
    location / {{ return 404; }}
}}
''')
link = Path('/etc/nginx/sites-enabled/sokrat-sip')
if not link.exists():
    link.symlink_to('/etc/nginx/sites-available/sokrat-sip')
pushsite = Path('/etc/nginx/sites-available/sokrat-push')
site = pushsite.read_text()
if 'location = /api/mobile/ice' not in site:
    site = site.replace('    location / {', '''    location = /api/mobile/ice {
        limit_req zone=push_reg burst=10 nodelay;
        proxy_pass http://127.0.0.1:8095;
        proxy_set_header Host $host;
        add_header Cache-Control "no-store" always;
    }

    location / {''')
    write(pushsite, site)
run('nginx', '-t')
run('ufw', 'allow', '8088/tcp')
run('ufw', 'allow', '3478/tcp')
run('ufw', 'allow', '3478/udp')
run('ufw', 'allow', 'in', 'on', 'tailscale0', 'from', pbx, 'to', relay,
    'port', '49160:49260', 'proto', 'udp')
run('systemctl', 'enable', 'coturn')
run('systemctl', 'restart', 'coturn', 'sokrat-push-gateway')
run('systemctl', 'reload', 'nginx')
print('Gateway configured. AWS must allow TCP 8088, TCP/UDP 3478, HTTP 80.')
