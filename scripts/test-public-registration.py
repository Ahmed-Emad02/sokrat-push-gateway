#!/usr/bin/env python3
"""Run on PBX: env GATEWAY_HOST=... TEST_EXTENSION=... python3 script.
Reads existing auth locally, never prints passwords; removes its own contact.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import socket
import struct

host = os.environ['GATEWAY_HOST']
extension = os.environ['TEST_EXTENSION']
text = Path('/etc/asterisk/pjsip_additional.conf').read_text()
password = None
for block in re.split(r'^\[', text, flags=re.M):
    if re.search(r'^username\s*=\s*' + re.escape(extension) + r'\s*$', block, re.M):
        found = re.search(r'^password\s*=\s*(.*)$', block, re.M)
        if found:
            password = found.group(1).strip()
            break
if not password:
    raise SystemExit('No existing test extension auth found')
s = socket.create_connection((host, 8088), timeout=10)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f'GET /ws HTTP/1.1\r\nHost: {host}:8088\r\nUpgrade: websocket\r\n'
           f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
           'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n').encode())
header = b''
while not header.endswith(b'\r\n\r\n'):
    header += s.recv(1)
assert b'101 Switching' in header, header.split(b'\r\n')[0]


def send(message):
    data = message.encode()
    mask = os.urandom(4)
    length = len(data)
    prefix = bytes([0x81, 0x80 | length]) if length < 126 else bytes([0x81, 0xfe]) + struct.pack('!H', length)
    s.sendall(prefix + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(data)))


def readn(n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise RuntimeError('WebSocket closed')
        data += chunk
    return data


def receive():
    _, length = readn(2)
    length &= 127
    if length == 126:
        length = struct.unpack('!H', readn(2))[0]
    elif length == 127:
        length = struct.unpack('!Q', readn(8))[0]
    return readn(length).decode()


callid = secrets.token_hex(12)
contact = f'sip:gateway-probe-{callid}@probe.invalid;transport=ws'
uri = f'sip:{host}'
tag = secrets.token_hex(6)


def register(cseq, expires, auth=''):
    return (f'REGISTER {uri} SIP/2.0\r\nVia: SIP/2.0/WS probe.invalid;branch=z9hG4bK{secrets.token_hex(8)}\r\n'
            f'Max-Forwards: 70\r\nFrom: <sip:{extension}@{host}>;tag={tag}\r\n'
            f'To: <sip:{extension}@{host}>\r\nCall-ID: {callid}\r\nCSeq: {cseq} REGISTER\r\n'
            f'Contact: <{contact}>\r\nExpires: {expires}\r\n{auth}Content-Length: 0\r\n\r\n')


send(register(1, 120))
challenge = receive()
assert challenge.startswith('SIP/2.0 401'), challenge.splitlines()[0]
realm = re.search(r'realm="([^"]+)"', challenge).group(1)
nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
md5 = lambda v: hashlib.md5(v.encode()).hexdigest()
ha1 = md5(f'{extension}:{realm}:{password}')
ha2 = md5(f'REGISTER:{uri}')
cnonce = secrets.token_hex(8)


def authorization(nc):
    count = f'{nc:08x}'
    response = md5(f'{ha1}:{nonce}:{count}:{cnonce}:auth:{ha2}')
    return (f'Authorization: Digest username="{extension}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response}", algorithm=MD5, qop=auth, nc={count}, cnonce="{cnonce}"\r\n')


try:
    send(register(2, 120, authorization(1)))
    result = receive()
    assert result.startswith('SIP/2.0 200'), result.splitlines()[0]
    print('Public SIP digest registration: 200 OK')
finally:
    send(register(3, 0, authorization(2)))
    for _ in range(10):
        result = receive()
        if result.startswith('SIP/2.0') and re.search(r'^CSeq: 3 REGISTER', result, re.M):
            break
    print('Probe contact removal:', result.splitlines()[0])
    s.close()
