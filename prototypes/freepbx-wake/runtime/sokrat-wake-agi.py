#!/usr/bin/env python3
"""Prototype AGI. Trusts only a root-owned local identity service; absent means off."""
import json
import os
import re
import socket
import stat
import struct
import sys
import time

SOCKET_PATH = '/run/sokrat-wake/identity.sock'
EXTENSION = re.compile(r'^[0-9]{1,32}$')
ENDPOINT = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')
CONTACT = re.compile(r'^PJSIP/([A-Za-z0-9_.-]{1,80})/sip:[A-Za-z0-9_.!~*+%@:\[\];=-]{1,1024}$')
MAX_RESPONSE = 16384
WAIT_SECONDS = 8.0
SOCKET_TIMEOUT = 0.15


def valid_contact(contact, endpoint):
    if not isinstance(contact, str):
        return False
    found = CONTACT.fullmatch(contact)
    return bool(found and found.group(1) == endpoint)


def choose_contact(endpoint, candidate, current, baseline):
    """Only a newly present, explicitly attested contact may be dialled."""
    if not ENDPOINT.fullmatch(endpoint) or not valid_contact(candidate, endpoint):
        return ''
    return candidate if candidate in current.split('&') and candidate not in baseline.split('&') else ''


def trusted_socket(path):
    # Every directory is immutable to non-root; the socket may grant asterisk
    # group access, but cannot be replaced by that group.
    current = '/'
    for part in path.strip('/').split('/')[:-1]:
        current = os.path.join(current, part)
        item = os.lstat(current)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise ValueError('unsafe socket directory')
    item = os.lstat(path)
    if not stat.S_ISSOCK(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o007:
        raise ValueError('unsafe socket')


def identity_request(request):
    trusted_socket(SOCKET_PATH)
    deadline = time.monotonic() + SOCKET_TIMEOUT
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(SOCKET_TIMEOUT)
        conn.connect(SOCKET_PATH)
        _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise ValueError('untrusted peer')
        conn.sendall((json.dumps(request, separators=(',', ':')) + '\n').encode())
        chunks = bytearray()
        while b'\n' not in chunks:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('identity deadline exceeded')
            conn.settimeout(remaining)
            part = conn.recv(4096)
            if not part:
                raise ValueError('incomplete response')
            chunks.extend(part)
            if len(chunks) > MAX_RESPONSE:
                raise ValueError('oversized response')
        raw, trailing = bytes(chunks).split(b'\n', 1)
        if trailing:
            raise ValueError('unexpected trailing data')
        result = json.loads(raw.decode('utf-8'))
        if not isinstance(result, dict):
            raise ValueError('invalid response')
        return result


class AGI:
    def __init__(self, source, target):
        self.source, self.target = source, target
        while True:
            line = source.readline()
            if not line:
                raise EOFError()
            if line in ('\n', '\r\n'):
                break

    def command(self, command):
        if '\n' in command or '\r' in command:
            raise ValueError('invalid AGI command')
        self.target.write(command + '\n')
        self.target.flush()
        result = self.source.readline()
        match = re.match(r'^200 result=1 \((.*)\)\s*$', result)
        return match.group(1) if match else ''

    def get(self, variable):
        return self.command('GET VARIABLE ' + variable)

    def contacts(self, endpoint):
        return self.command('GET FULL VARIABLE ${PJSIP_DIAL_CONTACTS(' + endpoint + ')}')

    def set(self, variable, value):
        # Values are generated locally from strict allowlists, never escaped
        # untrusted strings or caller-provided AGI commands.
        self.command('SET VARIABLE ' + variable + ' "' + value + '"')


def run(agi, mode, extension, request=identity_request, clock=time.monotonic, sleep=time.sleep):
    if not EXTENSION.fullmatch(extension):
        return
    if mode == 'prepare':
        response = request({'operation': 'prepare', 'extension': extension})
        endpoint = response.get('endpoint', '')
        if response.get('eligible') is True and isinstance(endpoint, str) and ENDPOINT.fullmatch(endpoint):
            agi.set('SOKRAT_WAKE_ENDPOINT', endpoint)
            agi.set('SOKRAT_WAKE_ARMED', '1')
        return
    if mode != 'wait':
        return
    endpoint = agi.get('SOKRAT_WAKE_ENDPOINT')
    baseline = agi.get('SOKRAT_WAKE_BASELINE')
    if not ENDPOINT.fullmatch(endpoint) or len(baseline) > MAX_RESPONSE:
        return
    deadline = clock() + WAIT_SECONDS
    while clock() < deadline:
        current = agi.contacts(endpoint)
        if len(current) > MAX_RESPONSE:
            return
        response = request({'operation': 'select', 'extension': extension, 'endpoint': endpoint,
                            'contacts': current.split('&') if current else []})
        if response.get('eligible') is not True or response.get('endpoint') != endpoint:
            return
        selected = choose_contact(endpoint, response.get('contact'), current, baseline)
        if selected:
            agi.set('SOKRAT_WAKE_CONTACT', selected)
            return
        sleep(0.25)


def main():
    try:
        agi = AGI(sys.stdin, sys.stdout)
        if len(sys.argv) == 3:
            run(agi, sys.argv[1], sys.argv[2])
    except (OSError, ValueError, EOFError, UnicodeError, TypeError):
        # No service, malformed proof, hangup, or IPC failure: never dial.
        return


if __name__ == '__main__':
    main()
