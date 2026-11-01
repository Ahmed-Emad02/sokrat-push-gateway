'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createCallTracker, RINGING_TTL_MS, ACTIVE_TTL_MS } = require('../src/sip-call-tracker');

function invite(callId, method = 'INVITE', status = null) {
    return `${status ? `SIP/2.0 ${status} OK` : `${method} sip:pbx SIP/2.0`}\r\nCall-ID: ${callId}\r\nCSeq: 1 ${method}\r\nContent-Length: 0\r\n\r\n`;
}

test('tracks established calls per PBX and removes them on BYE', () => {
    let now = 1000;
    const tracker = createCallTracker({ now: () => now });
    const session = {};
    tracker.observe(invite('call-a'), 'pbx-a', session);
    assert.deepEqual(tracker.snapshot(), [{ pbxId: 'pbx-a', active: 0, ringing: 1, total: 1 }]);
    tracker.observe(invite('call-a', 'INVITE', 200), 'pbx-a', session);
    assert.deepEqual(tracker.snapshot(), [{ pbxId: 'pbx-a', active: 1, ringing: 0, total: 1 }]);
    tracker.observe(invite('call-a', 'BYE'), 'pbx-a', session);
    assert.deepEqual(tracker.snapshot(), []);
});

test('keeps PBX buckets independent and removes cancelled calls', () => {
    const tracker = createCallTracker();
    const a = {};
    const b = {};
    tracker.observe(invite('same-id'), 'pbx-a', a);
    tracker.observe(invite('same-id'), 'pbx-b', b);
    tracker.observe(invite('same-id', 'INVITE', 200), 'pbx-a', a);
    assert.deepEqual(tracker.snapshot(), [
        { pbxId: 'pbx-a', active: 1, ringing: 0, total: 1 },
        { pbxId: 'pbx-b', active: 0, ringing: 1, total: 1 },
    ]);
    tracker.observe(invite('same-id', 'CANCEL'), 'pbx-b', b);
    assert.deepEqual(tracker.snapshot(), [{ pbxId: 'pbx-a', active: 1, ringing: 0, total: 1 }]);
});

test('prunes abandoned ringing calls and session-owned calls', () => {
    let now = 1000;
    const tracker = createCallTracker({ now: () => now });
    const session = {};
    tracker.observe(invite('ringing'), 'pbx-a', session);
    tracker.observe(invite('active'), 'pbx-a', session);
    tracker.observe(invite('active', 'INVITE', 200), 'pbx-a', session);
    now += RINGING_TTL_MS + 1;
    tracker.prune();
    assert.deepEqual(tracker.snapshot(), [{ pbxId: 'pbx-a', active: 1, ringing: 0, total: 1 }]);
    now += ACTIVE_TTL_MS + 1;
    tracker.prune();
    assert.deepEqual(tracker.snapshot(), []);
    tracker.observe(invite('owned'), 'pbx-a', session);
    tracker.removeSession(session);
    assert.deepEqual(tracker.snapshot(), []);
});
