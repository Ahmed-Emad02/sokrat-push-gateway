#!/bin/bash
# Host dependencies only. Never install a tunnel, route, firewall rule or PBX hook.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
if [ "$(id -u)" -ne 0 ]; then echo 'Root is required for host reverse-TLS dependencies' >&2; exit 1; fi
if ! command -v openvpn >/dev/null || ! command -v iptables >/dev/null ||
   ! command -v ip >/dev/null || ! python3 -c 'import cryptography' >/dev/null 2>&1; then
    if command -v apt-get >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openvpn iptables iproute2 python3-cryptography
    elif command -v dnf >/dev/null; then
        dnf install -y openvpn iptables iproute python3-cryptography
    else
        echo 'Install OpenVPN >=2.4, iptables, iproute and Python cryptography using the host package manager' >&2
        exit 1
    fi
fi
python3 - <<'PY'
import cryptography
import re
import subprocess
result = subprocess.run(['openvpn', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
match = re.search(r'^OpenVPN (\d+)\.(\d+)', result.stdout)
if result.returncode not in (0, 1) or not match or tuple(map(int, match.groups())) < (2, 4):
    raise SystemExit('Supported OpenVPN >=2.4 required')
PY
test -c /dev/net/tun
echo 'Host reverse-TLS dependencies verified; no network configuration changed'
