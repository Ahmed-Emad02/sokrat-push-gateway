'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeCallId, tokenFingerprint } = require('../src/index');

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
