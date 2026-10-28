#!/usr/bin/env python3
"""Read-only deployment readiness check; does not print secret values."""
import json
from pathlib import Path
import subprocess

checks = []
for unit in ('nginx', 'coturn', 'sokrat-push-gateway', 'sokrat-gateway-control'):
    result = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True)
    checks.append((f'service {unit}', result.returncode == 0))
for name in ('/etc/sokrat/gateway-control.env', '/var/lib/sokrat-gateway/control.json'):
    file = Path(name)
    checks.append((f'private permissions {name}', file.is_file() and file.stat().st_mode & 0o077 == 0))
control = Path('/var/lib/sokrat-gateway/control.json')
if control.exists():
    data = json.loads(control.read_text())
    print('Configured PBX servers:', len(data.get('pbx', [])))
    print('Approved devices:', sum(d.get('status') == 'approved' for d in data.get('devices', [])))
for description, success in checks:
    print(('PASS' if success else 'FAIL'), description)
raise SystemExit(0 if all(result for _, result in checks) else 1)
