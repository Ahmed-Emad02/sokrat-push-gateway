'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createTenantPushStore } = require('../src/tenant-push-store');
test('push registry is durable, private, serialized and tenant scoped', async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-push-test-'));
    const file = path.join(dir, 'devices.json');
    const store = createTenantPushStore(file, async () => null);
    try {
        await Promise.all(['A', 'B'].map(pbxId => store.savePush({ deviceId: pbxId, pbxId, extension: 'same', token: pbxId, updatedAt: Date.now() })));
        assert.equal((await store.listPush('A', 'same')).length, 1);
        assert.equal((await store.listPush('B', 'same')).length, 1);
        const second = createTenantPushStore(file);
        assert.equal((await second.listPush('A', 'same'))[0].deviceId, 'A');
        assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
        await assert.rejects(store.savePush({ deviceId: 'attacker', pbxId: 'B', extension: 'same', token: 'A', updatedAt: Date.now() }), /another device/);
        assert.equal((await store.listPush('A', 'same')).length, 1);
        await store.removePush('A');
        assert.equal((await store.listPush('A', 'same')).length, 0);
    } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
