'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { fingerprintToken, isPermanentTokenError } = require('../src/push-errors');

test('fingerprints tokens without exposing the value', () => {
    assert.equal(fingerprintToken('abc'), fingerprintToken('abc'));
    assert.notEqual(fingerprintToken('abc'), fingerprintToken('abd'));
    assert.equal(fingerprintToken(''), '');
});

test('classifies only permanent token errors as invalidating', () => {
    for (const code of [
        'messaging/registration-token-not-registered',
        'messaging/invalid-registration-token',
        'messaging/unregistered',
        'BadDeviceToken',
        'Unregistered',
    ]) assert.equal(isPermanentTokenError({ code }), true, code);
    for (const code of [
        'messaging/server-unavailable',
        'messaging/internal-error',
        'messaging/third-party-auth-error',
        'messaging/invalid-argument',
        'network-request-failed',
    ]) assert.equal(isPermanentTokenError({ code }), false, code);
});
