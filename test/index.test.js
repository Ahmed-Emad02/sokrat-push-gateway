'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeCallId, tokenFingerprint, androidCallMessage } = require('../src/index');

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test('normalizes an Asterisk linked ID deterministically', () => {
    const first = normalizeCallId('1756821342.91');
    const second = normalizeCallId('1756821342.91');
    assert.equal(first, second);
    assert.match(first, UUID_PATTERN);
});

test('different linked IDs produce different call IDs', () => {
    assert.notEqual(normalizeCallId('1756821342.91'), normalizeCallId('1756821342.92'));
});

test('preserves and lowercases an existing UUID', () => {
    const value = 'A9E89B44-CB09-4F7C-A9E5-4DA631DF95ED';
    assert.equal(normalizeCallId(value), value.toLowerCase());
});

test('rejects a missing call ID', () => {
    assert.throws(() => normalizeCallId(''), /callId is required/);
});

test('token fingerprints are stable and do not expose the token', () => {
    const token = 'private-fcm-token';
    const fingerprint = tokenFingerprint(token);
    assert.equal(fingerprint, tokenFingerprint(token));
    assert.equal(fingerprint.length, 12);
    assert.equal(fingerprint.includes(token), false);
});

test('Android call pushes carry a bounded data-only lifetime and cancel type', () => {
    const incoming = androidCallMessage({ token: 'device-token' }, {
        msg: 'incoming-call', callId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        callerId: '150', callerName: 'Caller', extension: '102', timestamp: 1234,
    });
    assert.equal(incoming.token, 'device-token');
    assert.equal(incoming.android.priority, 'high');
    assert.equal(incoming.android.ttl, 15000);
    assert.equal(incoming.notification, undefined);
    assert.equal(incoming.data.msg, 'incoming-call');
    assert.equal(incoming.data.type, 'incoming-call');
    assert.equal(incoming.data.callId, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    assert.equal(incoming.data.extension, '102');
    assert.equal(incoming.data.timestamp, '1234');

    const cancel = androidCallMessage({ token: 'device-token' }, {
        msg: 'cancel-call', callId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', extension: '102',
    });
    assert.equal(cancel.android.priority, 'high');
    assert.equal(cancel.android.ttl, 120000);
    assert.equal(cancel.data.msg, 'cancel-call');
    assert.equal(cancel.data.type, 'cancel-call');

    const conflicting = androidCallMessage({ token: 'device-token' }, {
        msg: 'cancel-call', type: 'incoming-call', callId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    });
    assert.equal(conflicting.data.msg, 'cancel-call');
    assert.equal(conflicting.data.type, 'cancel-call');
    assert.equal(conflicting.android.ttl, 120000);

    const legacyIncoming = androidCallMessage({ token: 'device-token' }, {
        callId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', extension: '102', timestamp: 1234,
    });
    assert.equal(legacyIncoming.android.ttl, 15000);
    assert.equal(legacyIncoming.data.msg, 'incoming-call');
    assert.equal(legacyIncoming.data.type, 'incoming-call');

    const keepalive = androidCallMessage({ token: 'device-token' }, {
        msg: 'wake', type: 'keepalive', timestamp: 1234,
    });
    assert.equal(keepalive.android.ttl, undefined);
    assert.equal(keepalive.data.msg, 'wake');
    assert.equal(keepalive.data.type, 'keepalive');
});
