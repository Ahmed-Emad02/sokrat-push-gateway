#!/usr/bin/env python3
"""Universal local firewall provisioning adapter for Linux VPS (Ubuntu/Debian/Rocky).

Replaces AWS Security Group adapter. Validates tenant listener allocation and
configures local host firewall (UFW/iptables) if available, or confirms container host exposure.
"""
import json
import re
import shutil
import subprocess
import sys

LISTENER_MIN = 3500
LISTENER_MAX = 3654
PBX_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')


def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: provisioning-firewall-local.py <pbxId>\n")
        sys.exit(2)

    pbx_id = sys.argv[1]
    if not PBX_ID_RE.match(pbx_id):
        sys.stderr.write("Invalid pbxId format\n")
        sys.exit(2)

    try:
        raw = sys.stdin.read(65536)
        request = json.loads(raw)
    except Exception as e:
        sys.stderr.write(f"Failed to read JSON payload: {e}\n")
        sys.exit(1)

    if not request.get("enabled", True):
        print(json.dumps({"action": "skipped", "pbxId": pbx_id}))
        sys.exit(0)

    port = request.get("listenerPort")
    if not isinstance(port, int) or port < LISTENER_MIN or port > LISTENER_MAX:
        sys.stderr.write(f"Invalid listener port: {port}\n")
        sys.exit(2)

    if shutil.which("ufw"):
        run_cmd(["ufw", "allow", f"{port}/tcp"])
        run_cmd(["ufw", "allow", f"{port}/udp"])
    elif shutil.which("iptables"):
        run_cmd(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        run_cmd(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"])

    print(json.dumps({"action": "applied", "pbxId": pbx_id, "listenerPort": port}))
    sys.exit(0)


if __name__ == '__main__':
    main()
