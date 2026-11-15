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

test('detail reports identity and durations without altering tracking state', () => {
    let now = 1000;
    const tracker = createCallTracker({ now: () => now });
    const session = { device: 'dev_1', route: { extension: '151' } };
    const frame = Buffer.from(invite('call-z'));
    const untouched = Buffer.from(frame);

    tracker.observe(frame, 'pbx-a', session);
    assert.deepEqual(frame, untouched, 'observing must not rewrite signaling bytes');

    now = 4000;
    let rows = tracker.detail();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].pbxId, 'pbx-a');
    assert.equal(rows[0].callId, 'call-z');
    assert.equal(rows[0].state, 'ringing');
    assert.equal(rows[0].extension, '151');
    assert.equal(rows[0].device, 'dev_1');
    assert.equal(rows[0].answeredAt, null);
    assert.equal(rows[0].durationMs, 3000);
    assert.equal(rows[0].talkMs, 0);

    tracker.observe(invite('call-z', 'INVITE', 200), 'pbx-a', session);
    now = 9000;
    rows = tracker.detail();
    assert.equal(rows[0].state, 'active');
    assert.equal(rows[0].durationMs, 8000);
    assert.equal(rows[0].talkMs, 5000);
    assert.match(rows[0].answeredAt, /^1970-01-01T00:00:04/);

    // The metrics path keeps its aggregate-only shape.
    assert.deepEqual(tracker.snapshot(), [{ pbxId: 'pbx-a', active: 1, ringing: 0, total: 1 }]);

    tracker.observe(invite('call-z', 'BYE'), 'pbx-a', session);
    assert.deepEqual(tracker.detail(), []);
});
