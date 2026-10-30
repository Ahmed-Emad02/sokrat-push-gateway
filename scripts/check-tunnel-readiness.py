#!/usr/bin/env python3
"""Trusted hook adapter: verify installed hook AND real bidirectional media."""
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import socket
import sys

from tunnel_media import validate_plan


def main():
    pbx_id = sys.argv[1]
    request = json.loads(sys.stdin.read(65536))
    if request['pbxId'] != pbx_id or request.get('enabled') is not True:
        return 1
    root = Path('/etc/sokrat/tunnel-enrollment')
    registry = json.loads((root / 'installations.json').read_text())
    row = next(row for row in registry.values() if row['pbxId'] == pbx_id)
    plan = validate_plan(row['plan'])
    if request.get('peerIps') != [plan['pbxIp']]:
        return 1
    # Gateway has only the credential hash, so use an independent per-tenant
    # readiness key provisioned over pinned TLS, not an employee SIP password.
    material = json.loads((root / pbx_id / 'material.json').read_text())
    key = material['readinessKey']
    nonce = secrets.token_hex(16)
    conn = http.client.HTTPConnection('127.0.0.1', row['ports']['api'], timeout=8)
    conn.request('POST', '/api/gateway-tunnel/readiness', json.dumps({'nonce':nonce}),
                 {'Content-Type':'application/json','X-Sokrat-Readiness':key})
    response = conn.getresponse()
    raw = response.read(8193)
    conn.close()
    if response.status != 200 or len(raw)>8192:
        return 1
    report = json.loads(raw)
    if report.get('pbxId') != pbx_id or report.get('hookHash') != hashlib.sha256(request['token'].encode()).hexdigest():
        return 1
    port = report.get('echoPort')
    if type(port) is not int or not 10000 <= port <= 20000 or report.get('ready') is not True:
        return 1
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        bound = False
        for port_offset in range(100):
            try:
                sock.bind((plan['gatewayIp'],50000+plan['slot']*100+port_offset))
                bound = True;break
            except OSError:
                continue
        if not bound:return 1
        sock.settimeout(5)
        payload = nonce.encode()
        sock.sendto(payload,(plan['pbxIp'],port))
        reply,peer = sock.recvfrom(256)
        return 0 if reply==payload and peer==(plan['pbxIp'],port) else 1
    finally:
        sock.close()


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:sys.exit(1)
