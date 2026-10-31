'use strict';

/**
 * Extension management + PBX management metadata — contract tests.
 *
 * This suite pins the *planned* store integration described in
 * `APPROVAL-SCALING-PLAN.md` and `MANAGEMENT-IMPLEMENTATION.md`:
 *
 *   store.addPbx({ ...pbx, management: { customer, loginHostname,
 *                    approvalStatus, extensionPolicyRequired } })
 *   store.addExtension({ pbxId, extension, name, status, maxDevices,
 *                        allowedPlatforms })
 *   store.updateExtension(id, patch)
 *   store.listExtensions(pbxId?)            // pbxId is optional
 *   store.snapshot().extensions
 *   store.approveDevice(...)  honours PBX approval + extension policy
 *   store.verifyDeviceSecret(...) fails when the PBX or extension is suspended
 *
 * Legacy PBXs (no `management` metadata) must keep their current behaviour.
 * Durability is covered too: metadata and policies survive a reload, a schema-1
 * document upgrades to schema 2 on the next mutation only, malformed extension
 * records fail closed without rewriting the file, endpoint URL changes reset a
 * managed PBX to `pending` approval, extension identity is immutable, and a
 * policy cannot be lowered below its live approved-device count.
 *
 * No credentials are hardcoded here: enrollment tokens are minted by the store
 * and device UUIDs come from `crypto.randomUUID()`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fsp = require('node:fs').promises;
const os = require('node:os');
const path = require('node:path');

const { ControlStore, ControlStoreError } = require('../src/control/store');

// --- fixtures --------------------------------------------------------------

test('missing persisted authorization fields fail closed rather than adopting creation defaults', async () => {
    const ctx = await makeStore();
    try {
        const pbx = await ctx.store.addPbx(pbxInput('Strict persisted policy', { management: management() }));
        await ctx.store.addExtension(extensionInput(pbx.id, '001'));
        const original = JSON.parse(await fsp.readFile(ctx.filePath, 'utf8'));
        for (const [collection, key] of [['extensions', 'allowedPlatforms'], ['extensions', 'maxDevices'],
            ['extensions', 'status'], ['management', 'extensionPolicyRequired'], ['management', 'approvalStatus']]) {
            const corrupt = structuredClone(original);
            delete (collection === 'management' ? corrupt.pbx[0].management : corrupt.extensions[0])[key];
            const bytes = JSON.stringify(corrupt);
            await fsp.writeFile(ctx.filePath, bytes);
            const reloaded = new ControlStore({ filePath: ctx.filePath });
            await assert.rejects(reloaded.init(), { code: 'control_store_corrupt' });
            assert.equal(await fsp.readFile(ctx.filePath, 'utf8'), bytes);
        }
    } finally { await ctx.close(); }
});

test('reducing extension admission limit preserves persisted policies and permits administration', async () => {
    const ctx = await makeStore();
    try {
        const pbx = await ctx.store.addPbx(pbxInput('Capacity', { management: management() }));
        const first = await ctx.store.addExtension(extensionInput(pbx.id, '001'));
        await ctx.store.addExtension(extensionInput(pbx.id, '002'));
        const before = await fsp.readFile(ctx.filePath, 'utf8');
        const reloaded = new ControlStore({ filePath: ctx.filePath, maxExtensions: 1 });
        await reloaded.init();
        assert.equal(await fsp.readFile(ctx.filePath, 'utf8'), before);
        assert.equal(reloaded.listExtensions().length, 2);
        await reloaded.updateExtension(first.id, { status: 'suspended' });
        await assert.rejects(reloaded.addExtension(extensionInput(pbx.id, '003')), { code: 'extension_limit_reached' });
        assert.equal(reloaded.listExtensions().length, 2);
    } finally { await ctx.close(); }
});

const CUSTOMER_HOSTNAME = 'customer.gateway.example.com';

async function makeStore(options = {}) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-ext-management-'));
    const filePath = path.join(dir, 'control.json');
    const store = new ControlStore({ filePath, ...options });
    await store.init();
    return {
        dir,
        filePath,
        store,
        close: () => fsp.rm(dir, { recursive: true, force: true })
    };
}

function pbxInput(name, overrides = {}) {
    return {
        name,
        wsURL: 'wss://pbx.example.com:8089/ws',
        apiURL: 'https://pbx.example.com:8080',
        mediaIps: '203.0.113.10',
        enabled: true,
        ...overrides
    };
}

function management(overrides = {}) {
    return {
        customer: 'Acme Telecom',
        loginHostname: CUSTOMER_HOSTNAME,
        approvalStatus: 'approved',
        extensionPolicyRequired: true,
        ...overrides
    };
}

function extensionInput(pbxId, extension, overrides = {}) {
    return {
        pbxId,
        extension,
        name: `Desk ${extension}`,
        status: 'enabled',
        maxDevices: 2,
        allowedPlatforms: ['android', 'desktop'],
        ...overrides
    };
}

/** Creates an invite and enrolls one pending device for it. */
async function pendingDevice(store, platform = 'android') {
    const { token } = await store.createEnrollmentToken({
        label: `invite ${platform}`,
        maxUses: 10
    });
    const { device } = await store.enrollDevice({
        token,
        platform,
        deviceUuid: crypto.randomUUID(),
        deviceName: `${platform} test device`
    });
    return device;
}

/** Approves a fresh pending device and returns `{ device, secret }`. */
async function approvedDevice(store, pbxId, extension, platform = 'android') {
    const device = await pendingDevice(store, platform);
    const approved = await store.approveDevice(device.id, { pbxId, extension });
    assert.equal(approved.device.status, 'approved');
    return { device, secret: approved.secret };
}

/**
 * Asserts a policy rejection. The exact `code` is deliberately not pinned —
 * the plan leaves naming to the implementation — but the failure must be a
 * `ControlStoreError` carrying a client-error status.
 */
async function rejectsWithStoreError(promise, allowedStatuses = [400, 403, 409, 422]) {
    await assert.rejects(promise, (error) => {
        assert.ok(
            error instanceof ControlStoreError,
            `expected ControlStoreError, got ${error && error.name}: ${error && error.message}`
        );
        assert.ok(
            allowedStatuses.includes(error.status),
            `expected status in ${allowedStatuses.join('/')}, got ${error.status} (${error.code})`
        );
        return true;
    });
}

function approvedFor(store, pbxId, extension) {
    return store
        .listDevices('approved')
        .filter((device) => device.pbxId === pbxId && device.extension === extension);
}

/** Asserts a rejection with an exact error code (used for contract-stable codes). */
async function rejectsWithCode(promise, code, status) {
    await assert.rejects(promise, (error) => {
        assert.ok(
            error instanceof ControlStoreError,
            `expected ControlStoreError, got ${error && error.name}: ${error && error.message}`
        );
        assert.equal(error.code, code);
        if (status !== undefined) assert.equal(error.status, status);
        return true;
    });
}

async function reloadStore(filePath, options = {}) {
    const store = new ControlStore({ filePath, ...options });
    await store.init();
    return store;
}

async function rawDocument(filePath) {
    return JSON.parse(await fsp.readFile(filePath, 'utf8'));
}

/** Writes a hand-built control document so schema/migration paths can be tested. */
async function seedStore(document) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-ext-seed-'));
    const filePath = path.join(dir, 'control.json');
    const raw = `${JSON.stringify(document, null, 2)}\n`;
    await fsp.writeFile(filePath, raw, 'utf8');
    return {
        dir,
        filePath,
        raw,
        store: new ControlStore({ filePath }),
        close: () => fsp.rm(dir, { recursive: true, force: true })
    };
}

/** Minimal valid schema-1 document: a legacy PBX and no `extensions` key at all. */
function schemaOneDocument(pbxId) {
    const at = '2026-01-01T00:00:00.000Z';
    return {
        schemaVersion: 1,
        createdAt: at,
        updatedAt: at,
        pbx: [
            {
                id: pbxId,
                name: 'Legacy PBX',
                wsURL: 'wss://legacy.example.com:8089/ws',
                apiURL: 'https://legacy.example.com:8080',
                mediaIps: [],
                enabled: true,
                createdAt: at,
                updatedAt: at
            }
        ],
        enrollmentTokens: [],
        devices: [],
        audit: []
    };
}

// --- PBX management metadata ----------------------------------------------

test('stores management metadata on a PBX and canonicalises the login hostname', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(
            pbxInput('Managed HQ', { management: management({ loginHostname: 'Customer.Gateway.Example.COM' }) })
        );

        const stored = store.getPbx(pbx.id);
        assert.ok(stored.management, 'management metadata must round-trip through the store');
        assert.equal(stored.management.customer, 'Acme Telecom');
        assert.equal(
            String(stored.management.loginHostname).toLowerCase(),
            CUSTOMER_HOSTNAME,
            'login hostname is reserved in canonical (lower-case) form'
        );
        assert.equal(stored.management.approvalStatus, 'approved');
        assert.equal(stored.management.extensionPolicyRequired, true);
    } finally {
        await close();
    }
});

test('rejects a duplicate login hostname regardless of casing', async () => {
    const { store, close } = await makeStore();
    try {
        await store.addPbx(pbxInput('Acme primary', { management: management() }));
        const before = store.listPbx().length;

        await rejectsWithStoreError(
            store.addPbx(
                pbxInput('Acme secondary', {
                    management: management({ loginHostname: 'CUSTOMER.GATEWAY.EXAMPLE.COM' })
                })
            )
        );

        assert.equal(store.listPbx().length, before, 'a rejected PBX must not be persisted');
        const hostnames = store
            .listPbx()
            .map((record) => String(record.management && record.management.loginHostname).toLowerCase());
        assert.deepEqual(hostnames, [CUSTOMER_HOSTNAME]);
    } finally {
        await close();
    }
});

test('rejects approving a device onto a PBX whose management approval is not approved', async () => {
    const { store, close } = await makeStore();
    try {
        const pending = await store.addPbx(
            pbxInput('Acme pending', {
                management: management({
                    loginHostname: 'pending.gateway.example.com',
                    approvalStatus: 'pending'
                })
            })
        );
        const suspended = await store.addPbx(
            pbxInput('Acme suspended', {
                management: management({
                    loginHostname: 'suspended.gateway.example.com',
                    approvalStatus: 'suspended'
                })
            })
        );
        await store.addExtension(extensionInput(pending.id, '150'));
        await store.addExtension(extensionInput(suspended.id, '150'));

        const first = await pendingDevice(store, 'android');
        await rejectsWithStoreError(
            store.approveDevice(first.id, { pbxId: pending.id, extension: '150' })
        );
        assert.equal(store.listDevices('pending').length, 1, 'device must stay pending');

        await rejectsWithStoreError(
            store.approveDevice(first.id, { pbxId: suspended.id, extension: '150' })
        );
        assert.equal(store.listDevices('pending').length, 1);
    } finally {
        await close();
    }
});

// --- extension policy ------------------------------------------------------

test('allows the same extension number on two different PBXs', async () => {
    const { store, close } = await makeStore();
    try {
        const alpha = await store.addPbx(
            pbxInput('Alpha', {
                management: management({ loginHostname: 'alpha.gateway.example.com' })
            })
        );
        const beta = await store.addPbx(
            pbxInput('Beta', {
                management: management({ loginHostname: 'beta.gateway.example.com' })
            })
        );

        const alphaExt = await store.addExtension(extensionInput(alpha.id, '150'));
        const betaExt = await store.addExtension(extensionInput(beta.id, '150'));

        assert.equal(alphaExt.pbxId, alpha.id);
        assert.equal(betaExt.pbxId, beta.id);
        assert.notEqual(alphaExt.id, betaExt.id);
        assert.equal(alphaExt.extension, '150');
        assert.equal(betaExt.extension, '150');
        assert.equal((await store.listExtensions(alpha.id)).length, 1);
        assert.equal((await store.listExtensions(beta.id)).length, 1);
    } finally {
        await close();
    }
});

test('rejects a duplicate extension inside the same PBX', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        await store.addExtension(extensionInput(pbx.id, '150'));

        await rejectsWithStoreError(
            store.addExtension(extensionInput(pbx.id, '150', { name: 'Duplicate desk' }))
        );

        const list = await store.listExtensions(pbx.id);
        assert.equal(list.length, 1);
        assert.equal(list[0].name, 'Desk 150');
    } finally {
        await close();
    }
});

test('lists extensions globally and per PBX, and exposes them in the snapshot', async () => {
    const { store, close } = await makeStore();
    try {
        const alpha = await store.addPbx(
            pbxInput('Alpha', {
                management: management({ loginHostname: 'alpha.gateway.example.com' })
            })
        );
        const beta = await store.addPbx(
            pbxInput('Beta', {
                management: management({ loginHostname: 'beta.gateway.example.com' })
            })
        );
        await store.addExtension(extensionInput(alpha.id, '150'));
        await store.addExtension(extensionInput(alpha.id, '151'));
        await store.addExtension(extensionInput(beta.id, '200'));

        assert.equal((await store.listExtensions()).length, 3);
        assert.equal((await store.listExtensions(alpha.id)).length, 2);
        assert.equal((await store.listExtensions(beta.id)).length, 1);

        const snapshot = store.snapshot();
        assert.ok(Array.isArray(snapshot.extensions), 'snapshot.extensions must be an array');
        assert.equal(snapshot.extensions.length, 3);

        const record = snapshot.extensions.find(
            (item) => item.pbxId === alpha.id && item.extension === '151'
        );
        assert.ok(record, 'snapshot must include the extension record');
        assert.equal(record.status, 'enabled');
        assert.equal(record.maxDevices, 2);
        assert.deepEqual([...record.allowedPlatforms].sort(), ['android', 'desktop']);
        assert.equal(JSON.stringify(snapshot).includes('password'), false);
    } finally {
        await close();
    }
});

test('updateExtension suspends and re-enables a policy', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        const created = await store.addExtension(extensionInput(pbx.id, '150'));

        const suspended = await store.updateExtension(created.id, { status: 'suspended' });
        assert.equal(suspended.status, 'suspended');
        assert.equal((await store.listExtensions(pbx.id))[0].status, 'suspended');

        const resumed = await store.updateExtension(created.id, { status: 'enabled' });
        assert.equal(resumed.status, 'enabled');
    } finally {
        await close();
    }
});

// --- approval enforcement --------------------------------------------------

test('approveDevice requires a registered enabled extension when the PBX policy is required', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        const device = await pendingDevice(store, 'android');

        await rejectsWithStoreError(
            store.approveDevice(device.id, { pbxId: pbx.id, extension: '150' })
        );
        assert.equal(store.listDevices('pending').length, 1);

        await store.addExtension(extensionInput(pbx.id, '150'));
        const approved = await store.approveDevice(device.id, {
            pbxId: pbx.id,
            extension: '150'
        });
        assert.equal(approved.device.status, 'approved');
        assert.equal(approved.device.extension, '150');
        assert.equal(store.verifyDeviceSecret(device.id, approved.secret).ok, true);
    } finally {
        await close();
    }
});

test('a disabled extension blocks device approval', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        await store.addExtension(extensionInput(pbx.id, '150', { status: 'disabled' }));
        const device = await pendingDevice(store, 'android');

        await rejectsWithStoreError(
            store.approveDevice(device.id, { pbxId: pbx.id, extension: '150' })
        );

        assert.equal(store.listDevices('pending').length, 1);
        assert.equal(approvedFor(store, pbx.id, '150').length, 0);
        const wrongSecret = `sk_device_v1_${crypto.randomBytes(24).toString('base64url')}`;
        assert.equal(store.verifyDeviceSecret(device.id, wrongSecret).ok, false);
    } finally {
        await close();
    }
});

test('a device platform outside allowedPlatforms is rejected at approval', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        await store.addExtension(extensionInput(pbx.id, '150'));

        const iosDevice = await pendingDevice(store, 'ios');
        await rejectsWithStoreError(
            store.approveDevice(iosDevice.id, { pbxId: pbx.id, extension: '150' })
        );
        assert.equal(store.listDevices('pending').length, 1);

        // A platform that *is* allowed still approves on the same extension.
        const android = await approvedDevice(store, pbx.id, '150', 'android');
        assert.equal(approvedFor(store, pbx.id, '150').length, 1);
        assert.equal(store.verifyDeviceSecret(android.device.id, android.secret).ok, true);
    } finally {
        await close();
    }
});

test('per-extension maxDevices is enforced atomically under concurrent approval', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        await store.addExtension(extensionInput(pbx.id, '150', { maxDevices: 1 }));

        const first = await pendingDevice(store, 'android');
        const second = await pendingDevice(store, 'desktop');

        const results = await Promise.allSettled([
            store.approveDevice(first.id, { pbxId: pbx.id, extension: '150' }),
            store.approveDevice(second.id, { pbxId: pbx.id, extension: '150' })
        ]);

        const fulfilled = results.filter((entry) => entry.status === 'fulfilled');
        const rejected = results.filter((entry) => entry.status === 'rejected');
        assert.equal(fulfilled.length, 1, 'exactly one concurrent approval may win the last slot');
        assert.equal(rejected.length, 1, 'the losing approval must be refused, not silently queued');
        assert.ok(
            rejected[0].reason instanceof ControlStoreError,
            `expected ControlStoreError, got ${rejected[0].reason && rejected[0].reason.name}`
        );

        assert.equal(approvedFor(store, pbx.id, '150').length, 1, 'quota must hold on disk');
        assert.equal(store.listDevices('pending').length, 1, 'the losing device stays pending');

        // The surviving device keeps a working secret; the loser has none.
        const winningApproval = fulfilled[0].value;
        assert.equal(winningApproval.device.hasSecret, true);
        assert.equal(
            store.verifyDeviceSecret(winningApproval.device.id, winningApproval.secret).ok,
            true
        );
        const loser = store.listDevices('pending')[0];
        assert.equal(loser.hasSecret, false);
        assert.equal(store.verifyDeviceSecret(loser.id, winningApproval.secret).ok, false);
    } finally {
        await close();
    }
});

// --- revocation semantics --------------------------------------------------

test('suspending an extension invalidates its device auth but not an unrelated PBX', async () => {
    const { store, close } = await makeStore();
    try {
        const alpha = await store.addPbx(
            pbxInput('Alpha', {
                management: management({ loginHostname: 'alpha.gateway.example.com' })
            })
        );
        const beta = await store.addPbx(
            pbxInput('Beta', {
                management: management({ loginHostname: 'beta.gateway.example.com' })
            })
        );
        const alphaExt = await store.addExtension(extensionInput(alpha.id, '150'));
        await store.addExtension(extensionInput(beta.id, '150'));

        const alphaDevice = await approvedDevice(store, alpha.id, '150', 'android');
        const betaDevice = await approvedDevice(store, beta.id, '150', 'android');

        assert.equal(store.verifyDeviceSecret(alphaDevice.device.id, alphaDevice.secret).ok, true);
        assert.equal(store.verifyDeviceSecret(betaDevice.device.id, betaDevice.secret).ok, true);

        await store.updateExtension(alphaExt.id, { status: 'suspended' });

        assert.equal(
            store.verifyDeviceSecret(alphaDevice.device.id, alphaDevice.secret).ok,
            false,
            'a suspended extension must invalidate its approved devices'
        );
        assert.equal(
            store.verifyDeviceSecret(betaDevice.device.id, betaDevice.secret).ok,
            true,
            'an unrelated PBX must be unaffected'
        );

        // Suspension is a reversible policy, not a revocation: resuming the
        // extension restores the same device credential.
        await store.updateExtension(alphaExt.id, { status: 'enabled' });
        assert.equal(store.verifyDeviceSecret(alphaDevice.device.id, alphaDevice.secret).ok, true);
        assert.equal(store.verifyDeviceSecret(betaDevice.device.id, betaDevice.secret).ok, true);
    } finally {
        await close();
    }
});

// --- legacy compatibility --------------------------------------------------

test('a legacy PBX without management metadata keeps its approval behaviour', async () => {
    const { store, close } = await makeStore();
    try {
        const legacy = await store.addPbx(pbxInput('Legacy PBX'));
        assert.ok(!store.getPbx(legacy.id).management, 'legacy PBX must not gain management metadata');

        // No extension record exists and none is required: approval still works.
        const approved = await approvedDevice(store, legacy.id, '150', 'ios');
        assert.equal(approvedFor(store, legacy.id, '150').length, 1);
        assert.equal(store.verifyDeviceSecret(approved.device.id, approved.secret).ok, true);

        // Legacy PBXs are not affected by other PBXs' extension policy either.
        const managed = await store.addPbx(
            pbxInput('Managed', {
                management: management({ loginHostname: 'managed.gateway.example.com' })
            })
        );
        await store.addExtension(extensionInput(managed.id, '150', { status: 'disabled' }));
        assert.equal(store.verifyDeviceSecret(approved.device.id, approved.secret).ok, true);
        assert.equal((await store.listExtensions(legacy.id)).length, 0);
    } finally {
        await close();
    }
});

// --- durability ------------------------------------------------------------

test('management metadata and extension policies survive a reload', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(
            pbxInput('Acme primary', { management: management() })
        );
        const second = await store.addPbx(
            pbxInput('Acme branch', {
                management: management({
                    customer: 'Acme Telecom',
                    loginHostname: 'branch.gateway.example.com',
                    extensionPolicyRequired: false,
                    approvalStatus: 'pending'
                })
            })
        );
        await store.addExtension(extensionInput(pbx.id, '150'));
        await store.addExtension(
            extensionInput(pbx.id, '151', { status: 'suspended', maxDevices: 1 })
        );
        await store.addExtension(
            extensionInput(second.id, '150', { allowedPlatforms: ['desktop'] })
        );

        const beforePbx = store.listPbx();
        const beforeExtensions = await store.listExtensions();

        const reloaded = await reloadStore(filePath);
        assert.deepEqual(reloaded.listPbx(), beforePbx, 'PBX records including management must round-trip');
        assert.deepEqual(await reloaded.listExtensions(), beforeExtensions);
        assert.deepEqual(reloaded.snapshot().extensions, beforeExtensions);

        const reloadedPbx = reloaded.getPbx(pbx.id);
        assert.equal(reloadedPbx.management.customer, 'Acme Telecom');
        assert.equal(reloadedPbx.management.loginHostname, CUSTOMER_HOSTNAME);
        assert.equal(reloadedPbx.management.extensionPolicyRequired, true);
        assert.equal(reloadedPbx.management.approvalStatus, 'approved');
        assert.equal(reloaded.getPbx(second.id).management.approvalStatus, 'pending');
        assert.equal(reloaded.getPbx(second.id).management.extensionPolicyRequired, false);

        const reloadedExtensions = await reloaded.listExtensions(pbx.id);
        assert.equal(reloadedExtensions.length, 2);
        const suspended = reloadedExtensions.find((record) => record.extension === '151');
        assert.equal(suspended.status, 'suspended');
        assert.equal(suspended.maxDevices, 1);
        assert.deepEqual([...suspended.allowedPlatforms].sort(), ['android', 'desktop']);
    } finally {
        await close();
    }
});

test('a schema-1 document upgrades to schema 2 on the next mutation only', async () => {
    const pbxId = `pbx_${crypto.randomBytes(8).toString('hex')}`;
    const { filePath, raw, store, close } = await seedStore(schemaOneDocument(pbxId));
    try {
        await store.init();
        assert.equal(
            await fsp.readFile(filePath, 'utf8'),
            raw,
            'loading must not rewrite the document'
        );
        assert.deepEqual(await store.listExtensions(), [], 'a v1 document has no policies yet');

        // Reading is pure; the file only moves forward when a mutation commits.
        const updated = await store.updatePbx(pbxId, { name: 'Legacy PBX renamed' });
        assert.equal(updated.name, 'Legacy PBX renamed');

        const document = await rawDocument(filePath);
        assert.equal(document.schemaVersion, 2);
        assert.ok(Array.isArray(document.extensions));
        assert.deepEqual(document.extensions, []);
        assert.equal(document.pbx.length, 1);
        assert.equal(document.pbx[0].name, 'Legacy PBX renamed');

        // The upgraded document is loadable by a fresh store instance.
        const reloaded = await reloadStore(filePath);
        assert.equal(reloaded.snapshot().schemaVersion, 2);
        assert.equal(reloaded.listPbx()[0].name, 'Legacy PBX renamed');
    } finally {
        await close();
    }
});

test('a schema-2 document with malformed extensions fails closed without overwriting', async () => {
    const at = '2026-01-01T00:00:00.000Z';
    const pbxId = `pbx_${crypto.randomBytes(8).toString('hex')}`;
    const validPbx = {
        id: pbxId,
        name: 'Managed PBX',
        wsURL: 'wss://pbx.example.com:8089/ws',
        apiURL: 'https://pbx.example.com:8080',
        mediaIps: [],
        enabled: true,
        management: {
            customer: 'Acme Telecom',
            loginHostname: CUSTOMER_HOSTNAME,
            extensionPolicyRequired: true,
            approvalStatus: 'approved',
            reviewedInstallationId: null
        },
        createdAt: at,
        updatedAt: at
    };
    const validPolicy = {
        id: `ext_${crypto.randomBytes(8).toString('hex')}`,
        pbxId,
        extension: '150',
        name: 'Desk 150',
        status: 'enabled',
        maxDevices: 2,
        allowedPlatforms: ['android', 'desktop'],
        createdAt: at,
        updatedAt: at
    };

    const base = () => ({ ...schemaOneDocument(pbxId), schemaVersion: 2, pbx: [validPbx] });

    const cases = [
        ['extensions is not an array', { ...base(), extensions: {} }],
        [
            'policy points at a missing PBX',
            {
                ...base(),
                extensions: [{ ...validPolicy, pbxId: `pbx_${'0'.repeat(16)}` }]
            }
        ],
        [
            'duplicate policy for the same PBX extension',
            {
                ...base(),
                extensions: [validPolicy, { ...validPolicy, id: `ext_${crypto.randomBytes(8).toString('hex')}` }]
            }
        ],
        [
            'policy status is unknown',
            {
                ...base(),
                extensions: [{ ...validPolicy, status: 'half-enabled' }]
            }
        ],
        [
            'policy has no pbxId',
            {
                ...base(),
                extensions: [{ ...validPolicy, pbxId: undefined }]
            }
        ]
    ];

    for (const [label, document] of cases) {
        const seeded = await seedStore(document);
        try {
            await assert.rejects(seeded.store.init(), (error) => {
                assert.ok(error instanceof ControlStoreError, `${label}: expected ControlStoreError`);
                assert.equal(error.code, 'control_store_corrupt', `${label}: expected control_store_corrupt`);
                assert.equal(error.status, 500, `${label}: corrupt stores fail with 500`);
                return true;
            }, label);
            assert.equal(
                await fsp.readFile(seeded.filePath, 'utf8'),
                seeded.raw,
                `${label}: the corrupt document must never be overwritten`
            );
            assert.equal(seeded.store.ready, false, `${label}: the store must stay unready`);
        } finally {
            await seeded.close();
        }
    }

    // Control: the same document with a well-formed policy loads cleanly.
    const good = await seedStore({
        ...base(),
        extensions: [validPolicy]
    });
    try {
        await good.store.init();
        assert.equal(good.store.ready, true);
        assert.equal((await good.store.listExtensions(pbxId)).length, 1);
        assert.equal(good.store.getPbx(pbxId).management.approvalStatus, 'approved');
    } finally {
        await good.close();
    }
});

// --- managed PBX revalidation ---------------------------------------------

test('endpoint URL changes reset managed approval to pending even when the same PATCH asks for approved', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Acme primary', { management: management() }));
        assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'approved');

        // A non-endpoint change keeps the recorded approval.
        const renamed = await store.updatePbx(pbx.id, {
            name: 'Acme primary renamed',
            management: { ...store.getPbx(pbx.id).management, approvalStatus: 'approved' }
        });
        assert.equal(renamed.management.approvalStatus, 'approved');

        // Changing the WebSocket endpoint invalidates it, despite the explicit ask.
        const movedWs = await store.updatePbx(pbx.id, {
            wsURL: 'wss://pbx2.example.com:8089/ws',
            management: { ...store.getPbx(pbx.id).management, approvalStatus: 'approved' }
        });
        assert.equal(movedWs.wsURL, 'wss://pbx2.example.com:8089/ws');
        assert.equal(movedWs.management.approvalStatus, 'pending');
        assert.equal(movedWs.management.loginHostname, CUSTOMER_HOSTNAME, 'other metadata is preserved');

        // Re-approval without an endpoint change is allowed again.
        const reapproved = await store.updatePbx(pbx.id, {
            management: { ...store.getPbx(pbx.id).management, approvalStatus: 'approved' }
        });
        assert.equal(reapproved.management.approvalStatus, 'approved');

        // The API endpoint is equally load-bearing.
        const movedApi = await store.updatePbx(pbx.id, {
            apiURL: 'https://pbx2.example.com:8080',
            management: { ...store.getPbx(pbx.id).management, approvalStatus: 'approved' }
        });
        assert.equal(movedApi.apiURL, 'https://pbx2.example.com:8080/');
        assert.equal(movedApi.management.approvalStatus, 'pending');

        // The reset is durable, and a pending PBX cannot keep authorising devices.
        const reloaded = await reloadStore(store.filePath);
        assert.equal(reloaded.getPbx(pbx.id).management.approvalStatus, 'pending');

        const device = await pendingDevice(reloaded, 'android');
        await reloaded.addExtension(extensionInput(pbx.id, '150'));
        await rejectsWithCode(
            reloaded.approveDevice(device.id, { pbxId: pbx.id, extension: '150' }),
            'pbx_not_approved',
            403
        );
    } finally {
        await close();
    }
});

// --- immutable identity and quota floors ----------------------------------

test('extension identity is immutable: identity fields are rejected and nothing changes', async () => {
    const { store, close } = await makeStore();
    try {
        const alpha = await store.addPbx(
            pbxInput('Alpha', {
                management: management({ loginHostname: 'alpha.gateway.example.com' })
            })
        );
        const beta = await store.addPbx(
            pbxInput('Beta', {
                management: management({ loginHostname: 'beta.gateway.example.com' })
            })
        );
        const policy = await store.addExtension(extensionInput(alpha.id, '150'));

        await rejectsWithCode(
            store.updateExtension(policy.id, { extension: '151' }),
            'invalid_extension_policy',
            400
        );
        await rejectsWithCode(
            store.updateExtension(policy.id, { pbxId: beta.id }),
            'invalid_extension_policy',
            400
        );
        await rejectsWithCode(
            store.updateExtension(policy.id, { extension: '151', status: 'suspended' }),
            'invalid_extension_policy',
            400
        );
        await rejectsWithCode(
            store.updateExtension(policy.id, { id: `ext_${'0'.repeat(16)}` }),
            'invalid_extension_policy',
            400
        );

        const [stored] = await store.listExtensions(alpha.id);
        assert.equal(stored.id, policy.id);
        assert.equal(stored.pbxId, alpha.id);
        assert.equal(stored.extension, '150');
        assert.equal(stored.status, 'enabled', 'a rejected patch must not partially apply');
        assert.equal((await store.listExtensions(beta.id)).length, 0);
    } finally {
        await close();
    }
});

test('lowering maxDevices below the approved-device count is rejected atomically', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        const policy = await store.addExtension(extensionInput(pbx.id, '150', { maxDevices: 2 }));

        const first = await approvedDevice(store, pbx.id, '150', 'android');
        const second = await approvedDevice(store, pbx.id, '150', 'android');
        assert.equal(approvedFor(store, pbx.id, '150').length, 2);

        await rejectsWithCode(
            store.updateExtension(policy.id, { maxDevices: 1 }),
            'device_cap_below_usage',
            409
        );

        // The rejection is atomic: policy, devices and the file are untouched.
        const [unchanged] = await store.listExtensions(pbx.id);
        assert.equal(unchanged.maxDevices, 2);
        assert.equal(approvedFor(store, pbx.id, '150').length, 2);
        assert.equal(store.verifyDeviceSecret(first.device.id, first.secret).ok, true);
        assert.equal(store.verifyDeviceSecret(second.device.id, second.secret).ok, true);
        const onDisk = await rawDocument(filePath);
        assert.equal(onDisk.extensions.find((record) => record.id === policy.id).maxDevices, 2);
        assert.equal(onDisk.devices.filter((device) => device.status === 'approved').length, 2);

        // Equal to current usage is allowed; below it only after a revocation.
        const tightened = await store.updateExtension(policy.id, { maxDevices: 2 });
        assert.equal(tightened.maxDevices, 2);

        await store.revokeDevice(first.device.id);
        const lowered = await store.updateExtension(policy.id, { maxDevices: 1 });
        assert.equal(lowered.maxDevices, 1);
        assert.equal(store.verifyDeviceSecret(first.device.id, first.secret).ok, false);
        assert.equal(store.verifyDeviceSecret(second.device.id, second.secret).ok, true);
    } finally {
        await close();
    }
});

test('extension policy stays enforced after a reload', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Alpha', { management: management() }));
        const policy = await store.addExtension(extensionInput(pbx.id, '150', { maxDevices: 1 }));
        const approved = await approvedDevice(store, pbx.id, '150', 'android');

        const reloaded = await reloadStore(filePath);
        const [restored] = await reloaded.listExtensions(pbx.id);
        assert.equal(restored.id, policy.id);
        assert.equal(restored.status, 'enabled');
        assert.equal(restored.maxDevices, 1);

        // Quota still holds on the reloaded store.
        const extra = await pendingDevice(reloaded, 'android');
        await rejectsWithCode(
            reloaded.approveDevice(extra.id, { pbxId: pbx.id, extension: '150' }),
            'extension_device_limit',
            409
        );
        assert.equal(reloaded.verifyDeviceSecret(approved.device.id, approved.secret).ok, true);

        // A suspension applied before the reload still invalidates the device.
        await reloaded.updateExtension(policy.id, { status: 'suspended' });
        const afterSuspension = await reloadStore(filePath);
        assert.equal((await afterSuspension.listExtensions(pbx.id))[0].status, 'suspended');
        assert.equal(
            afterSuspension.verifyDeviceSecret(approved.device.id, approved.secret).ok,
            false
        );
        assert.equal(afterSuspension.listDevices('pending').length, 1, 'the pending device is untouched');
    } finally {
        await close();
    }
});

test('removeExtension revokes its approved devices and matching invites', async () => {
    const { store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Removal', { management: management() }));
        const policy = await store.addExtension(extensionInput(pbx.id, '150'));
        const approved = await approvedDevice(store, pbx.id, '150', 'android');
        assert.equal(store.verifyDeviceSecret(approved.device.id, approved.secret).ok, true);

        const invite = await store.createEnrollmentToken({
            label: 'extension invite', pbxId: pbx.id, extension: '150'
        });
        const otherInvite = await store.createEnrollmentToken({
            label: 'other extension', pbxId: pbx.id, extension: '151'
        });

        const result = await store.removeExtension(policy.id, { actor: 'operator' });
        assert.equal(result.extension.id, policy.id);
        assert.equal(result.revokedDevices, 1);
        assert.equal(result.revokedInvites, 1);
        assert.deepEqual(store.listExtensions(), []);

        const revoked = store.listDevices('revoked').find(d => d.id === approved.device.id);
        assert.equal(revoked.reviewReason, 'extension-removed');
        assert.equal(revoked.hasSecret, false);
        assert.equal(store.verifyDeviceSecret(approved.device.id, approved.secret).ok, false);

        const invites = store.snapshot().enrollmentTokens;
        assert.ok(invites.find(i => i.id === invite.record.id).revokedAt);
        assert.equal(invites.find(i => i.id === otherInvite.record.id).revokedAt, null);

        await rejectsWithCode(store.removeExtension(policy.id), 'extension_not_found', 404);
    } finally {
        await close();
    }
});
