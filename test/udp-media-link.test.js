'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

function python(body) {
    return execFileSync('python3', ['-B', '-c', body], {
        cwd: path.join(__dirname, '../scripts'), encoding: 'utf8',
    });
}

const common = `
import importlib.util
import os
import socket
import sys

sys.path.insert(0, os.getcwd())


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('udp_media_link', 'udp-media-link.py')
tm = importlib.import_module('tunnel_media')
plan = tm.allocation('pbx_0123456789abcdef', 3, '10.253.0.0/22')
key = bytes([7]) * 32
GATEWAY = ('192.0.2.10', 26003)
PBX = ('198.51.100.9', 50000)


def inner(src, dst, payload=b'x', proto=17):
    total = 20 + len(payload)
    header = bytearray(20)
    header[0] = 0x45
    header[2] = (total >> 8) & 255
    header[3] = total & 255
    header[8] = 64
    header[9] = proto
    header[12:16] = socket.inet_aton(src)
    header[16:20] = socket.inet_aton(dst)
    return bytes(header) + payload


def make_links(real_nonces=False):
    now = [1000.0]

    def clock():
        return now[0]

    gateway_nonces = [bytes([65 + i]) * 16 for i in range(16)]
    client_nonces = [bytes([97 + i]) * 16 for i in range(16)]
    gateway_iter = iter(gateway_nonces)
    client_iter = iter(client_nonces)
    if real_nonces:
        gw = m.GatewayLink(key, plan, clock)
        cl = m.ClientLink(key, plan, GATEWAY, clock)
    else:
        gw = m.GatewayLink(key, plan, clock, lambda: next(gateway_iter))
        cl = m.ClientLink(key, plan, GATEWAY, clock, lambda: next(client_iter))
    gout = []
    cout = []
    gtun = []
    ctun = []

    def gateway_emit(data, address):
        gout.append((data, address))

    def client_emit(data, address):
        cout.append((data, address))

    gw.emit = gateway_emit
    cl.emit = client_emit
    gw.tun_write = gtun.append
    cl.tun_write = ctun.append
    return now, gw, cl, gout, cout, gtun, ctun


def complete(gw, cl, gout, cout):
    gw.handle_datagram(cout.pop(0)[0], PBX)
    cl.handle_datagram(gout.pop(0)[0], GATEWAY)
    gw.handle_datagram(cout.pop(0)[0], PBX)
    ack, address = gout.pop(0)
    assert address == PBX
    cl.handle_datagram(ack, GATEWAY)


def handshake(gw, cl, gout, cout):
    cl.start()
    complete(gw, cl, gout, cout)
    assert cl.active and gw.active_address == PBX
    assert cl.session == gw.active_session
    assert cl.session == m.session_id(key, cl.client_nonce, cl.server_nonce)
`;

test('frames require direction-scoped HMAC and reject every tampered region', () => {
    assert.equal(python(common + `
gateway_key = m.mac_key(key, b'gateway')
pbx_key = m.mac_key(key, b'pbx')
assert gateway_key != pbx_key and len(gateway_key) == 32
session = b'Q' * 16
payload = b'payload'
frame = m.pack_frame(gateway_key, m.DATA, 5, session, payload)
assert frame[:4] == b'SKMU'
assert m.parse_frame(gateway_key, frame) == (m.DATA, 5, session, payload)


def rejected(call):
    try:
        call()
    except m.ProtocolError:
        return True
    return False


# A frame emitted with the sender key must not verify with the peer key.
assert rejected(lambda: m.parse_frame(pbx_key, frame))
assert rejected(lambda: m.parse_frame(gateway_key, frame[:-1]))
assert rejected(lambda: m.parse_frame(gateway_key, frame + b'x'))
for index in range(len(frame)):
    broken = bytearray(frame)
    broken[index] ^= 1
    assert rejected(lambda: m.parse_frame(gateway_key, bytes(broken))), index
assert m.parse_frame(gateway_key, m.pack_frame(
    gateway_key, m.DATA, 1, session, b''))[3] == b''
assert len(m.pack_frame(gateway_key, m.DATA, 1, session, b'x' * 1400)) == 1464
for arguments in [(0, 1, session, b''), (7, 1, session, b''),
                  (1, 1, session[:-1], b''), (1, -1, session, b''),
                  (1, 1 << 64, session, b''), (1, 1, session, b'x' * 1401)]:
    try:
        m.pack_frame(gateway_key, *arguments)
        raise AssertionError('invalid frame accepted')
    except ValueError:
        pass
try:
    m.pack_frame(gateway_key, m.DATA, 1, session, 'text')
    raise AssertionError('text payload accepted')
except ValueError:
    pass
print('ok')
`).trim(), 'ok');
});

test('handshake establishes one shared session and carries validated inner UDP both ways', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links(real_nonces=True)
handshake(gw, cl, gout, cout)
packet = inner(plan['pbxIp'], plan['gatewayIp'], b'voice')
assert cl.send_data(packet)
outbound = cout.pop(0)[0]
wire = m.parse_frame(m.mac_key(key, b'pbx'), outbound)[3]
assert wire == packet[:12] + packet[20:]
gw.handle_datagram(outbound, PBX)
assert gtun == [packet]
reply = inner(plan['gatewayIp'], plan['pbxIp'], b'reply')
assert gw.send_data(reply)
outbound = gout.pop(0)[0]
wire = m.parse_frame(m.mac_key(key, b'gateway'), outbound)[3]
assert wire == reply[:12] + reply[20:]
cl.handle_datagram(outbound, GATEWAY)
assert ctun == [reply]
# Sending validates the same peer/local addresses, so each side refuses the
# other direction's packet instead of crossing traffic through its own TUN.
assert not cl.send_data(inner(plan['gatewayIp'], plan['pbxIp']))
assert not gw.send_data(inner(plan['pbxIp'], plan['gatewayIp']))
for bad in [inner(plan['pbxIp'], plan['gatewayIp'], proto=6),
            inner(plan['pbxIp'], '10.0.0.1'),
            inner('10.0.0.9', plan['gatewayIp']),
            b'not-ip']:
    assert not gw.send_data(bad)
assert gtun == [packet] and ctun == [reply]
print('ok')
`).trim(), 'ok');
});

test('a valid frame reflected at its own sender is rejected without replay mutation', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
handshake(gw, cl, gout, cout)
# Client emits DATA sequence 1; reflect it to the client as if from the peer.
outbound = inner(plan['pbxIp'], plan['gatewayIp'], b'outbound')
assert cl.send_data(outbound)
reflected = cout.pop(0)[0]
cl.handle_datagram(reflected, GATEWAY)
assert ctun == []
assert cl.replay.highest == 0
assert cl.last_received == now[0]
# A genuine gateway DATA with the same sequence is still accepted.
genuine = inner(plan['gatewayIp'], plan['pbxIp'], b'genuine')
assert gw.send_data(genuine)
cl.handle_datagram(gout.pop(0)[0], GATEWAY)
assert ctun == [genuine]
assert cl.replay.highest == 1
# Gateway emits DATA; reflect it to the gateway as if from the PBX.
gateway_packet = inner(plan['gatewayIp'], plan['pbxIp'], b'echo')
assert gw.send_data(gateway_packet)
gw.handle_datagram(gout.pop(0)[0], PBX)
assert gtun == []
assert gw.replay.highest == 0
# A genuine client DATA sequence 2 is still accepted.
uplink = inner(plan['pbxIp'], plan['gatewayIp'], b'uplink')
assert cl.send_data(uplink)
gw.handle_datagram(cout.pop(0)[0], PBX)
assert gtun == [uplink]
assert gw.replay.highest == 2
print('ok')
`).trim(), 'ok');
});

test('replay window accepts bounded reordering and rejects duplicates and old packets', () => {
    assert.equal(python(common + `
window = m.ReplayWindow(8)
assert window.accept(1)
assert not window.accept(1)
assert window.accept(2) and not window.accept(2)
assert window.accept(10)
assert window.accept(4)
assert not window.accept(4)
assert not window.accept(2)
assert window.accept(9)
assert window.accept(8)
assert window.accept(3)
assert not window.accept(1)
assert not window.accept(0)
assert not window.accept(-1)
assert window.accept(100)
assert not window.accept(100)
assert not window.accept(92)
assert window.accept(93)
assert window.accept(99)
window.reset()
assert window.accept(1) and not window.accept(1)
print('ok')
`).trim(), 'ok');
});

test('handshake binds source, single candidate, expiry and never displaces an active session alone', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
# The client ignores a challenge that does not come from the configured peer.
cl.start()
hello = cout.pop(0)[0]
gw.handle_datagram(hello, PBX)
challenge = gout.pop(0)[0]
cl.handle_datagram(challenge, ('203.0.113.5', 26003))
assert cl.server_nonce is None and not cout
cl.handle_datagram(challenge, GATEWAY)
response = cout.pop(0)[0]
# A response replayed from another source cannot activate the candidate.
gw.handle_datagram(response, ('203.0.113.5', 40000))
assert gw.active_address is None and not gout
gw.handle_datagram(response, PBX)
ack = gout.pop(0)[0]
cl.handle_datagram(ack, GATEWAY)
assert cl.active
session = gw.active_session
# A replayed HELLO creates only a bounded candidate; the captured RESPONSE
# cannot activate it and the active endpoint/session stay untouched.
gw.handle_datagram(hello, ('203.0.113.6', 41000))
assert gw.active_address == PBX and gw.active_session == session
assert gout.pop(0)[1] == ('203.0.113.6', 41000)
gw.handle_datagram(response, ('203.0.113.6', 41000))
assert gw.active_address == PBX and gw.active_session == session
assert not gout
# Active clients ignore replayed challenges.
cl.handle_datagram(challenge, GATEWAY)
assert cl.active and cl.session == session and not cout
# Only one candidate is retained: the newest HELLO's challenge wins.
session_b = b'K' * 16
hello_b = m.pack_frame(m.mac_key(key, b'pbx'), m.HELLO, 0, session_b, b'')
gw.handle_datagram(hello_b, PBX)
first = m.unpad_control(
    m.parse_frame(m.mac_key(key, b'gateway'), gout.pop(0)[0])[3], 16)
other = ('198.51.100.10', 50000)
gw.handle_datagram(hello_b, other)
second = m.unpad_control(
    m.parse_frame(m.mac_key(key, b'gateway'), gout.pop(0)[0])[3], 16)
stale = m.pack_frame(m.mac_key(key, b'pbx'), m.RESPONSE, 0, session_b, first)
gw.handle_datagram(stale, other)
assert gw.active_address == PBX and gw.active_session == session
assert not gout
fresh_response = m.pack_frame(m.mac_key(key, b'pbx'), m.RESPONSE, 0,
                              session_b, second)
gw.handle_datagram(fresh_response, other)
assert gw.active_address == other
assert gw.active_session == m.session_id(key, session_b, second)
assert gout.pop(0)[1] == other
# An expired candidate is dropped, even for a matching response.
now2, gw2, cl2, gout2, cout2, gtun2, ctun2 = make_links()
cl2.start()
gw2.handle_datagram(cout2.pop(0)[0], PBX)
cl2.handle_datagram(gout2.pop(0)[0], GATEWAY)
delayed = cout2.pop(0)[0]
now2[0] += 5.01
gw2.handle_datagram(delayed, PBX)
assert gw2.active_address is None and not gout2
# Control payloads may only carry zero padding; a non-zero tail is ignored.
bad_tail = m.pack_frame(m.mac_key(key, b'pbx'), m.HELLO, 0, b'M' * 16,
                        b'\\x00' * (m.CONTROL_PADDING - 1) + b'\\x01')
gw.handle_datagram(bad_tail, PBX)
assert not gout
print('ok')
`).trim(), 'ok');
});

test('lost ACK recovery resends ACK without resetting gateway counters or replay', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
cl.start()
gw.handle_datagram(cout.pop(0)[0], PBX)
cl.handle_datagram(gout.pop(0)[0], GATEWAY)
gw.handle_datagram(cout.pop(0)[0], PBX)
lost, address = gout.pop(0)
assert address == PBX and not cl.active
session = gw.active_session
first_packet = inner(plan['gatewayIp'], plan['pbxIp'], b'first')
assert gw.send_data(first_packet)
first = gout.pop(0)[0]
assert m.parse_frame(m.mac_key(key, b'gateway'), first)[1] == 1
now[0] += 1.0
cl.poll()
gw.handle_datagram(cout.pop(0)[0], PBX)
resent = gout.pop(0)[0]
assert m.parse_frame(m.mac_key(key, b'gateway'), resent)[2] == session
assert gw.send_sequence == 1
second_packet = inner(plan['gatewayIp'], plan['pbxIp'], b'second')
assert gw.send_data(second_packet)
second = gout.pop(0)[0]
assert m.parse_frame(m.mac_key(key, b'gateway'), second)[1] == 2
cl.handle_datagram(resent, GATEWAY)
assert cl.active
cl.handle_datagram(first, GATEWAY)
cl.handle_datagram(second, GATEWAY)
assert ctun == [first_packet, second_packet]
# A duplicate ACK after activation must not reset client counters or replay.
cl.handle_datagram(resent, GATEWAY)
third_packet = inner(plan['gatewayIp'], plan['pbxIp'], b'third')
assert gw.send_data(third_packet)
cl.handle_datagram(gout.pop(0)[0], GATEWAY)
assert ctun == [first_packet, second_packet, third_packet]
assert gw.replay.highest == 0
print('ok')
`).trim(), 'ok');
});

test('keepalives are authenticated and a receiver timeout performs a fresh handshake', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
handshake(gw, cl, gout, cout)
old_session = cl.session
old_nonce = cl.client_nonce
now[0] += 10.0
cl.poll()
keepalive = cout.pop(0)[0]
frame_type, sequence, session, payload = m.parse_frame(
    m.mac_key(key, b'pbx'), keepalive)
assert frame_type == m.KEEPALIVE and sequence == 1
assert session == old_session and payload.strip(b'\\x00') == b''
assert len(payload) == m.CONTROL_PADDING
gw.handle_datagram(keepalive, PBX)
reply = gout.pop(0)[0]
frame_type, sequence, session, payload = m.parse_frame(
    m.mac_key(key, b'gateway'), reply)
assert frame_type == m.KEEPALIVE and sequence == 1
assert session == old_session and payload.strip(b'\\x00') == b''
assert len(payload) == m.CONTROL_PADDING
cl.handle_datagram(reply, GATEWAY)
assert cl.active and cl.last_received == now[0]
now[0] += m.KEEPALIVE_INTERVAL / 2
cl.poll()
assert not cout
# Data with a stale session or from the wrong source is dropped.
reply_packet = inner(plan['pbxIp'], plan['gatewayIp'], b'one')
wire_reply = reply_packet[:12] + reply_packet[20:]
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 4,
                               b'Z' * 16, wire_reply), PBX)
assert gtun == []
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 5,
                               old_session, wire_reply), PBX)
assert gtun == [reply_packet]
# Silence beyond the receiver timeout starts a new handshake with a new nonce.
now[0] += 45.0
cl.poll()
assert cl.pending and not cl.active and cl.client_nonce != old_nonce
complete(gw, cl, gout, cout)
assert cl.session == gw.active_session != old_session
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 6,
                               old_session, wire_reply), PBX)
assert gtun == [reply_packet]
print('ok')
`).trim(), 'ok');
});

test('authentication precedes state mutation and invalid inner packets never reach TUN', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
packet = inner(plan['pbxIp'], plan['gatewayIp'], b'voice')
wire_packet = packet[:12] + packet[20:]
# No data before activation and no challenge for unauthenticated garbage.
for junk in [b'', b'x' * 63, b'SKMU' + bytes(60), bytes(200)]:
    gw.handle_datagram(junk, PBX)
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 1,
                               b'Q' * 16, wire_packet), PBX)
assert gw.active_address is None and not gout
handshake(gw, cl, gout, cout)
assert gw.replay.highest == 0
# A bad tag does not consume a replay slot; the valid packet still passes.
forged = bytearray(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 1,
                               cl.session, wire_packet))
forged[-1] ^= 1
gw.handle_datagram(bytes(forged), PBX)
assert gw.replay.highest == 0 and gtun == []
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 1,
                               cl.session, wire_packet), PBX)
assert gtun == [packet] and gw.replay.highest == 1
# Wrong source, old session and unauthenticated keepalive are silent.
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 2,
                               cl.session, wire_packet),
                   ('198.51.100.10', 50000))
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.KEEPALIVE, 3,
                               b'W' * 16, b''), PBX)
tampered_keepalive = bytearray(m.pack_frame(m.mac_key(key, b'pbx'),
                                           m.KEEPALIVE, 4, cl.session, b''))
tampered_keepalive[-1] ^= 1
gw.handle_datagram(bytes(tampered_keepalive), PBX)
assert gtun == [packet] and not gout
# Authenticated malformed headers are dropped; addresses are never peer input.
bad_packets = [inner(plan['pbxIp'], plan['gatewayIp'], proto=6),
               inner(plan['pbxIp'], plan['gatewayIp'])[:-1],
               bytes([69]) + bytes(18)]
for index, bad in enumerate(bad_packets):
    gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 10 + index,
                                   cl.session, bad[:12] + bad[20:]), PBX)
assert gtun == [packet]
high = gw.replay.highest
# A duplicate valid RESPONSE resends ACK but does not reset replay state.
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.RESPONSE, 0,
                               cl.client_nonce, cl.server_nonce), PBX)
assert gw.replay.highest == high
print('ok')
`).trim(), 'ok');
});

test('config schema, trusted-directory paths and key syntax are strict', () => {
    assert.equal(python(common + `
plan154 = tm.allocation('pbx_0123456789abcdef', 154, '10.253.0.0/22')
transport = {'mode': 'plain-udp', 'host': '203.0.113.7', 'port': 26154}
directory = '/var/backups/sokrat-media/pbx_0123456789abcdef/probe/gateway'
config_path = directory + '/media.conf'
document = {'role': 'gateway', 'plan': plan154, 'transport': transport,
            'keyFile': directory + '/udp.key',
            'up': directory + '/link-up', 'down': directory + '/link-down'}
config = m.validate_config(document, config_path)
assert config['plan'] == plan154 and config['transport'] == transport
assert config['directory'] == directory
assert config['role'] == 'gateway'


def rejected(candidate, candidate_path=config_path):
    try:
        m.validate_config(candidate, candidate_path)
        return False
    except ValueError:
        return True


broken = []
extra = dict(document)
extra['extra'] = 1
broken.append(extra)
missing = dict(document)
del missing['down']
broken.append(missing)
wrong_role = dict(document)
wrong_role['role'] = 'peer'
broken.append(wrong_role)
legacy = dict(document)
legacy['transport'] = None
broken.append(legacy)
direct = dict(document)
direct['transport'] = {'mode': 'direct-udp', 'host': '203.0.113.7',
                       'port': 26154}
broken.append(direct)
wrong_key = dict(document)
wrong_key['keyFile'] = directory + '/../gateway/udp.key'
broken.append(wrong_key)
wrong_hook = dict(document)
wrong_hook['up'] = directory + '/other'
broken.append(wrong_hook)
wrong_plan = dict(document)
wrong_plan['plan'] = dict(plan154)
wrong_plan['plan']['slot'] = 155
broken.append(wrong_plan)
for candidate in broken:
    assert rejected(candidate)
assert rejected(document, 'relative/media.conf')
assert rejected(document, directory + '/../gateway/media.conf')
assert m.decode_key('a' * 64 + '\\n') == bytes.fromhex('a' * 64)
for text in ['a' * 64, 'A' * 64 + '\\n', 'a' * 63 + '\\n',
             'g' * 64 + '\\n', 'a' * 64 + '\\n\\n', '']:
    try:
        m.decode_key(text)
        raise AssertionError('invalid key accepted: %r' % (text,))
    except ValueError:
        pass
print('ok')
`).trim(), 'ok');
});

test('HELLO retransmission preserves an in-flight response without extending challenge lifetime', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
cl.start()
gw.handle_datagram(cout.pop(0)[0], PBX)
original = gout.pop(0)[0]
now[0] += 1.2
cl.poll()
gw.handle_datagram(cout.pop(0)[0], PBX)
gout.pop(0)  # The response to the retry can also be delayed or lost.
cl.handle_datagram(original, GATEWAY)
gw.handle_datagram(cout.pop(0)[0], PBX)
cl.handle_datagram(gout.pop(0)[0], GATEWAY)
packet = inner(plan['pbxIp'], plan['gatewayIp'], b'after-delayed-challenge')
assert cl.send_data(packet)
gw.handle_datagram(cout.pop(0)[0], PBX)
assert gtun == [packet] and cl.active

now, gw, cl, gout, cout, gtun, ctun = make_links()
cl.start()
hello = cout.pop(0)[0]
gw.handle_datagram(hello, PBX)
challenge = gout.pop(0)[0]
_, _, nonce, server_nonce = m.parse_frame(m.mac_key(key,b'gateway'),challenge)
now[0] += 4.9
gw.handle_datagram(hello, PBX)
now[0] += 0.2
response = m.pack_frame(m.mac_key(key,b'pbx'),m.RESPONSE,0,nonce,server_nonce)
gw.handle_datagram(response,PBX)
assert gw.active_address is None
print('ok')
`).trim(), 'ok');
});

test('address-elided data reconstructs exact IPv4 headers and enforces the TUN MTU', () => {
    assert.equal(python(common + `
plan = tm.allocation('pbx_0123456789abcdef', 0, '10.253.0.0/22')
now, gw, cl, gout, cout, gtun, ctun = make_links()
handshake(gw, cl, gout, cout)
# Preserve options, checksums, TTL, flags and datagram bytes verbatim.
packet = bytearray(inner(plan['pbxIp'], plan['gatewayIp'], b'z' * 1380))
packet[0] = 0x46
packet[1] = 184
packet[10:12] = bytes([123, 45])
packet = bytes(packet[:20]) + bytes([1, 1, 1, 1]) + bytes(packet[20:-4])
assert len(packet) == 1400
assert cl.send_data(packet)
frame = cout.pop(0)[0]
wire = m.parse_frame(m.mac_key(key, b'pbx'), frame)[3]
assert wire == packet[:12] + packet[20:]
gw.handle_datagram(frame, PBX)
assert gtun == [packet]
# The authenticated wire body may fit its bound while expansion exceeds MTU.
oversized = inner(plan['pbxIp'], plan['gatewayIp'], b'z' * 1388)
wire = oversized[:12] + oversized[20:]
gw.handle_datagram(m.pack_frame(m.mac_key(key, b'pbx'), m.DATA, 2, cl.session, wire), PBX)
assert gtun == [packet] and not cl.send_data(oversized)
print('ok')
`).trim(), 'ok');
});

test('a stalled client tuple is replaced by a fresh local port that recovers DATA', () => {
    assert.equal(python(common + `
import errno


def pump(sock, handler):
    while True:
        try:
            data, address = sock.recvfrom(4096)
        except socket.error as error:
            if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            return
        handler(data, address)


plan = tm.allocation('pbx_0123456789abcdef', 3, '10.253.0.0/22')
gateway_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
gateway_socket.bind(('127.0.0.1', 0))
gateway_socket.setblocking(False)
gateway_address = gateway_socket.getsockname()
gtun = []
gw = m.GatewayLink(key, plan)
gw.tun_write = gtun.append
gw.emit = lambda data, address: gateway_socket.sendto(data, address)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.bind(('', 0))
client_socket.setblocking(False)
stalled_port = client_socket.getsockname()[1]
ctun = []
cl = m.ClientLink(key, plan, gateway_address)
cl.tun_write = ctun.append
cl.emit = lambda data, address: client_socket.sendto(data, address)

# Complete the handshake over real loopback sockets, then exchange DATA.
cl.start()
pump(gateway_socket, gw.handle_datagram)
pump(client_socket, cl.handle_datagram)
pump(gateway_socket, gw.handle_datagram)
pump(client_socket, cl.handle_datagram)
assert cl.active and gw.active_address == ('127.0.0.1', stalled_port)
first = inner(plan['pbxIp'], plan['gatewayIp'], b'before-stall')
assert cl.send_data(first)
pump(gateway_socket, gw.handle_datagram)
assert gtun == [first]

# The path blackholes this tuple: no authenticated frame ever arrives again.
replacement = m.rebind_client_socket(client_socket)
assert client_socket.fileno() == -1
assert replacement.gettimeout() == 0.0
fresh_port = replacement.getsockname()[1]
assert fresh_port != stalled_port
client_socket = replacement
cl.start()

pump(gateway_socket, gw.handle_datagram)
pump(client_socket, cl.handle_datagram)
pump(gateway_socket, gw.handle_datagram)
pump(client_socket, cl.handle_datagram)
assert cl.active and gw.active_address == ('127.0.0.1', fresh_port)
assert cl.session == gw.active_session

second = inner(plan['pbxIp'], plan['gatewayIp'], b'after-rebind')
assert cl.send_data(second)
pump(gateway_socket, gw.handle_datagram)
assert gtun == [first, second]
downlink = inner(plan['gatewayIp'], plan['pbxIp'], b'gateway-reply')
assert gw.send_data(downlink)
pump(client_socket, cl.handle_datagram)
assert ctun == [downlink]
client_socket.close()
gateway_socket.close()
print('ok')
`).trim(), 'ok');
});

test('a healthy session never reaches the rebind deadline', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
handshake(gw, cl, gout, cout)
created = now[0]
assert cl.last_received == created

# Three keepalive intervals of silence from creation would otherwise rebind.
now[0] += m.CLIENT_REBIND_TIMEOUT - 0.1
assert not m.client_rebind_due(now[0], created, 0.0)

keepalive = m.pack_frame(m.mac_key(key, b'gateway'), m.KEEPALIVE, 1,
                         cl.session, b'')
cl.handle_datagram(keepalive, GATEWAY)
assert cl.last_received == now[0]
now[0] += m.CLIENT_REBIND_TIMEOUT - 0.1
assert not m.client_rebind_due(now[0], created, cl.last_received)
now[0] += 0.1
assert m.client_rebind_due(now[0], created, cl.last_received)
assert cl.active
print('ok')
`).trim(), 'ok');
});

test('unauthenticated or replayed reception cannot postpone client recovery', () => {
    assert.equal(python(common + `
now, gw, cl, gout, cout, gtun, ctun = make_links()
handshake(gw, cl, gout, cout)
created = now[0]
now[0] += 45.0
assert m.client_rebind_due(now[0], created, cl.last_received)
baseline = cl.last_received

forged = m.pack_frame(m.mac_key(key, b'pbx'), m.KEEPALIVE, 9, cl.session, b'')
cl.handle_datagram(forged, GATEWAY)
tampered = bytearray(m.pack_frame(m.mac_key(key, b'gateway'), m.KEEPALIVE, 10,
                                  cl.session, b''))
tampered[-1] ^= 1
cl.handle_datagram(bytes(tampered), GATEWAY)
cl.handle_datagram(m.pack_frame(m.mac_key(key, b'gateway'), m.DATA, 11,
                                cl.session, b'x' * 8), ('192.0.2.99', 26003))
assert cl.last_received == baseline
assert m.client_rebind_due(now[0], created, cl.last_received)

# A replayed or old authenticated frame passes neither replay nor the clock.
accepted = m.pack_frame(m.mac_key(key, b'gateway'), m.KEEPALIVE, 12,
                        cl.session, b'')
cl.handle_datagram(accepted, GATEWAY)
assert cl.last_received == now[0]
now[0] += 40.0
cl.handle_datagram(accepted, GATEWAY)
assert cl.last_received != now[0]
assert m.client_rebind_due(now[0], created, cl.last_received)
print('ok')
`).trim(), 'ok');
});
