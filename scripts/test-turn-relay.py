#!/usr/bin/env python3
"""External TURN roundtrip probe. Credentials are read as JSON from stdin.
Usage: credential-command | python3 test-turn-relay.py HOST PEER PORT
Credential JSON: {"username": "...", "credential": "..."}.
"""
import hashlib
import hmac
import json
import os
import socket
import struct
import sys

host, peer, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
listener_port = int(sys.argv[4]) if len(sys.argv) > 4 else 3478
credential = json.load(sys.stdin)
cookie = 0x2112a442


def attr(kind, value):
    return struct.pack('!HH', kind, len(value)) + value + b'\0' * ((-len(value)) % 4)


def parse(packet):
    result = {}
    pos = 20
    while pos + 4 <= len(packet):
        kind, length = struct.unpack('!HH', packet[pos:pos + 4])
        result[kind] = packet[pos + 4:pos + 4 + length]
        pos += 4 + length + (-length % 4)
    return result


for transport in ('udp', 'tcp'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM)
    s.settimeout(8)
    s.connect((host, listener_port))

    def readn(n):
        data = b''
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                raise RuntimeError('TURN connection closed')
            data += chunk
        return data

    def receive():
        if transport == 'udp':
            return s.recv(4096)
        header = readn(20)
        return header + readn(struct.unpack('!H', header[2:4])[0])

    def send(kind, attrs, authenticated=False):
        transaction = os.urandom(12)
        body = attrs
        if authenticated:
            body += attr(6, credential['username'].encode()) + attr(0x14, realm) + attr(0x15, nonce)
            header = struct.pack('!HHI', kind, len(body) + 24, cookie) + transaction
            key = hashlib.md5(credential['username'].encode() + b':' + realm + b':' + credential['credential'].encode()).digest()
            body += attr(8, hmac.new(key, header + body, hashlib.sha1).digest())
        header = struct.pack('!HHI', kind, len(body), cookie) + transaction
        s.sendall(header + body)

    send(3, attr(0x19, b'\x11\0\0\0'))
    response = parse(receive())
    realm, nonce = response[0x14], response[0x15]
    send(3, attr(0x19, b'\x11\0\0\0'), True)
    allocation = receive()
    assert struct.unpack('!H', allocation[:2])[0] == 0x103, ('Allocation failed', parse(allocation))
    address = b'\0\x01' + struct.pack('!H', port ^ (cookie >> 16)) + bytes(a ^ b for a, b in zip(socket.inet_aton(peer), struct.pack('!I', cookie)))
    send(8, attr(0x12, address), True)
    permission = receive()
    assert struct.unpack('!H', permission[:2])[0] == 0x108, 'Peer permission rejected'
    payload = b'sokrat-relay-probe-' + os.urandom(16)
    send(0x16, attr(0x12, address) + attr(0x13, payload))
    answer = receive()
    assert struct.unpack('!H', answer[:2])[0] == 0x17, 'No data indication'
    assert parse(answer)[0x13] == payload, 'Echo mismatch'
    send(4, attr(0xd, struct.pack('!I', 0)), True)
    receive()
    s.close()
    print(f'Public {transport.upper()} TURN authenticated allocation and PBX roundtrip: PASS')
