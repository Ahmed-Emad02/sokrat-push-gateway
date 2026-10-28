#!/usr/bin/env python3
"""Provision one isolated TURN process per PBX from a private JSON manifest.

Input: {publicHost, listenIp, relayIp, tenants:[{id,port,minPort,maxPort,peerIps}]}.
Secrets stay under /etc/sokrat/turn and are not printed. Does not delete existing
instances or change the single-PBX service. Run as root after operator review.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


def run(*args):
    subprocess.run(args, check=True)


manifest = json.loads(Path(sys.argv[1]).read_text())
host = manifest['publicHost']
if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
    raise SystemExit('Invalid public hostname')
listen = str(ipaddress.IPv4Address(manifest['listenIp']))
relay = str(ipaddress.IPv4Address(manifest['relayIp']))
tenants = manifest['tenants']
ports = set()
ranges = []
ids = set()
# Validate everything before touching the machine.
for tenant in tenants:
    name = tenant['id']
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,18}', name) or name in ids:
        raise SystemExit('Invalid or duplicate tenant ID')
    ids.add(name)
    port, low, high = tenant['port'], tenant['minPort'], tenant['maxPort']
    if any(type(n) is not int or not 1024 <= n <= 65535 for n in (port, low, high)) or low > high:
        raise SystemExit('Invalid port range')
    if port in ports or port == 3478 or low <= port <= high:
        raise SystemExit('Duplicate/reserved listener port')
    ports.add(port)
    if low <= 49260 and high >= 49160:
        raise SystemExit('Range overlaps existing single-PBX relay')
    if any(low <= prev_high and high >= prev_low for prev_low, prev_high in ranges):
        raise SystemExit('Overlapping relay ranges')
    ranges.append((low, high))
    tenant['peerIps'] = [str(ipaddress.IPv4Address(ip)) for ip in tenant['peerIps']]
    if not tenant['peerIps']:
        raise SystemExit('Each relay must have explicit PBX media IPs')
if any(low <= p <= high for low, high in ranges for p in ports):
    raise SystemExit('Listener overlaps relay range')
root = Path('/etc/sokrat/turn')
root.mkdir(parents=True, exist_ok=True)
root.chmod(0o711)
run('chown', 'root:root', str(root))
unit = '''[Unit]
Description=Sokrat isolated TURN relay %i
After=network-online.target tailscaled.service
Wants=network-online.target
[Service]
User=sokrat-turn-%i
Group=sokrat-turn-%i
ExecStart=/usr/bin/turnserver -c /etc/sokrat/turn/%i/turnserver.conf --pidfile=
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_UNIX
[Install]
WantedBy=multi-user.target
'''
Path('/etc/systemd/system/sokrat-turn@.service').write_text(unit)
for tenant in tenants:
    name, port = tenant['id'], tenant['port']
    user = f'sokrat-turn-{name}'
    exists = subprocess.run(['id', '-u', user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not exists:
        run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', user)
    tenant_dir = root / name
    tenant_dir.mkdir(exist_ok=True)
    tenant_dir.chmod(0o750)
    run('chown', f'root:{user}', str(tenant_dir))
    secret_file = tenant_dir / 'secret'
    if not secret_file.exists():
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secrets.token_hex(32))
    secret = secret_file.read_text().strip()
    if not re.fullmatch(r'[a-f0-9]{64}', secret):
        raise SystemExit('Invalid existing TURN secret')
    config = f'''listening-port={port}
listening-ip={listen}
relay-ip={relay}
min-port={tenant['minPort']}
max-port={tenant['maxPort']}
fingerprint
use-auth-secret
static-auth-secret={secret}
realm=sokrat-{name}
user-quota=12
total-quota=200
max-bps=256000
bps-capacity=16000000
no-tls
no-dtls
no-tcp-relay
no-cli
no-loopback-peers
no-multicast-peers
denied-peer-ip=0.0.0.0-255.255.255.255
log-file=stdout
simple-log
'''
    config += ''.join(f'allowed-peer-ip={peer}\n' for peer in tenant['peerIps'])
    path = tenant_dir / 'turnserver.conf'
    path.write_text(config)
    path.chmod(0o640)
    run('chown', f'root:{user}', str(path))
    for proto in ('tcp', 'udp'):
        run('ufw', 'allow', f'{port}/{proto}')
    for peer in tenant['peerIps']:
        run('ufw', 'allow', 'in', 'on', 'tailscale0', 'from', peer, 'to', relay,
            'port', f"{tenant['minPort']}:{tenant['maxPort']}", 'proto', 'udp')
run('systemctl', 'daemon-reload')
for tenant in tenants:
    run('systemctl', 'enable', '--now', f"sokrat-turn@{tenant['id']}")
    run('systemctl', 'restart', f"sokrat-turn@{tenant['id']}")
print('Tenant relays provisioned. Permit their TCP/UDP listener ports in the cloud firewall.')
