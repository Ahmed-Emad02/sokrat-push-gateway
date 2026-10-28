'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createDeviceTickets } = require('../src/device-tickets');
test('upgrade tickets expire, are single-use and recheck authorization', async () => {
    let time = 0, approved = true;
    const tickets = createDeviceTickets({ now: () => time, authorize: async () => approved ? { pbxId: 'A' } : null });
    const first = tickets.issue('device', 'secret');
    assert.equal((await tickets.consume(first)).route.pbxId, 'A');
    assert.equal(await tickets.consume(first), null);
    const expired = tickets.issue('device', 'secret'); time = 31000;
    assert.equal(await tickets.consume(expired), null);
    const revoked = tickets.issue('device', 'secret'); approved = false;
    assert.equal(await tickets.consume(revoked), null);
});
