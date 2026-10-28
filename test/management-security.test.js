'use strict';

/**
 * Management security regressions — persistence and revalidation edges.
 *
 * Pins three fail-closed behaviours around the managed control plane:
 *
 *  1. Persisted devices may only carry an enrollment platform the gateway can
 *     actually push to (`ios`, `android`, `desktop`). A schema-2 document that
 *     stores `chrome` or any other unsupported value must refuse to load
 *     (`control_store_corrupt`, 500) and must never be rewritten. Enrollment
 *     itself keeps rejecting `chrome`.
 *  2. A managed PBX with optional extension policies can already hold approved
 *     devices. Creating a policy whose `maxDevices` is below that live usage
 *     must be refused atomically with `device_cap_below_usage`; a cap equal to
 *     the usage is accepted.
 *  3. Approval is tied to the reviewed endpoints. Changing `mediaIps` or
 *     `loginHostname` — including on the first opt-in PATCH — resets a managed
 *     PBX to `pending` even when the same PATCH asks for `approved`, while
 *     re-submitting equivalent (normalised) values must not reset anything.
 *
 * No credentials are hardcoded: enrollment tokens are minted by the store and
 * device UUIDs come from `crypto.randomUUID()`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fsp = require('node:fs').promises;
const os = require('node:os');
const path = require('node:path');

const { ControlStore, ControlStoreError } = require('../src/control/store');

// --- fixtures --------------------------------------------------------------

const CUSTOMER_HOSTNAME = 'customer.gateway.example.com';
const AT = '2026-01-01T00:00:00.000Z';

async function makeStore(options = {}) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-management-security-'));
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

/** Writes a hand-built control document so corrupt-persistence paths can be tested. */
async function seedStore(document) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-management-security-seed-'));
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

function seededPbx(pbxId, overrides = {}) {
    return {
        id: pbxId,
        name: 'Managed PBX',
        wsURL: 'wss://pbx.example.com:8089/ws',
        apiURL: 'https://pbx.example.com:8080',
        mediaIps: ['203.0.113.10'],
        enabled: true,
        management: {
            customer: 'Acme Telecom',
            loginHostname: CUSTOMER_HOSTNAME,
            extensionPolicyRequired: true,
            approvalStatus: 'approved',
            reviewedInstallationId: null
        },
        createdAt: AT,
        updatedAt: AT,
        ...overrides
    };
}

function seededDevice(pbxId, overrides = {}) {
    return {
        id: `dev_${crypto.randomBytes(10).toString('hex')}`,
        status: 'approved',
        enrollmentMode: 'invite',
        platform: 'android',
        deviceUuid: crypto.randomUUID(),
        deviceName: 'seeded device',
        requestedAt: AT,
        reviewedAt: AT,
        pbxId,
        extension: '150',
        secretHash: null,
        createdAt: AT,
        updatedAt: AT,
        ...overrides
    };
}

function schemaTwoDocument(pbxId, { pbx = seededPbx(pbxId), devices = [], extensions = [] } = {}) {
    return {
        schemaVersion: 2,
        createdAt: AT,
        updatedAt: AT,
        pbx: [pbx],
        extensions,
        enrollmentTokens: [],
        devices,
        audit: []
    };
}

// --- 1. persisted device platforms ----------------------------------------

test('a schema-2 document with an unsupported device platform fails closed and is not rewritten', async () => {
    const pbxId = `pbx_${crypto.randomBytes(8).toString('hex')}`;

    const cases = [
        ['chrome is a policy platform, never an enrollment platform', seededDevice(pbxId, { platform: 'chrome' })],
        ['an arbitrary platform is rejected', seededDevice(pbxId, { platform: 'windows' })],
        ['a device without a platform is rejected', seededDevice(pbxId, { platform: undefined })],
        ['a numeric platform is rejected', seededDevice(pbxId, { platform: 7 })]
    ];

    for (const [label, device] of cases) {
        const seeded = await seedStore(schemaTwoDocument(pbxId, { devices: [device] }));
        try {
            await assert.rejects(
                seeded.store.init(),
                (error) => {
                    assert.ok(error instanceof ControlStoreError, `${label}: expected ControlStoreError`);
                    assert.equal(
                        error.code,
                        'control_store_corrupt',
                        `${label}: expected control_store_corrupt (got ${error.code})`
                    );
                    assert.equal(error.status, 500, `${label}: corrupt stores fail with 500`);
                    return true;
                },
                label
            );
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

    // Control: the same document with supported platforms loads and keeps them.
    const good = await seedStore(
        schemaTwoDocument(pbxId, {
            devices: [
                seededDevice(pbxId, { platform: 'android' }),
                seededDevice(pbxId, { platform: 'ios' }),
                seededDevice(pbxId, { platform: 'desktop' })
            ]
        })
    );
    try {
        await good.store.init();
        assert.equal(good.store.ready, true);
        const platforms = good.store
            .listDevices('approved')
            .map((device) => device.platform)
            .sort();
        assert.deepEqual(platforms, ['android', 'desktop', 'ios']);
    } finally {
        await good.close();
    }
});

test('enrollment keeps rejecting chrome while android still enrolls', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const { token } = await store.createEnrollmentToken({ label: 'invite platform check', maxUses: 5 });
        const before = await fsp.readFile(filePath, 'utf8');

        await rejectsWithCode(
            store.enrollDevice({ token, platform: 'chrome', deviceUuid: crypto.randomUUID() }),
            'invalid_platform',
            400
        );

        assert.equal(store.listDevices().length, 0, 'a rejected enrollment must not create a device');
        assert.equal(
            await fsp.readFile(filePath, 'utf8'),
            before,
            'a rejected enrollment must not rewrite the store'
        );

        const { device } = await store.enrollDevice({
            token,
            platform: 'android',
            deviceUuid: crypto.randomUUID()
        });
        assert.equal(device.platform, 'android');
        assert.equal(store.listDevices('pending').length, 1);
    } finally {
        await close();
    }
});

// --- 2. policy creation vs live usage -------------------------------------

test('adding a policy below the already approved device usage is rejected atomically', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        // Optional policies: devices may be approved before any policy exists.
        const pbx = await store.addPbx(
            pbxInput('Acme optional', { management: management({ extensionPolicyRequired: false }) })
        );
        assert.equal(store.getPbx(pbx.id).management.extensionPolicyRequired, false);

        const devices = [];
        for (let index = 0; index < 3; index += 1) {
            devices.push(await approvedDevice(store, pbx.id, '150', 'android'));
        }
        assert.equal(approvedFor(store, pbx.id, '150').length, 3);
        assert.equal((await store.listExtensions(pbx.id)).length, 0, 'no policy exists yet');

        const before = await fsp.readFile(filePath, 'utf8');

        for (const maxDevices of [1, 2]) {
            await rejectsWithCode(
                store.addExtension(extensionInput(pbx.id, '150', { maxDevices })),
                'device_cap_below_usage',
                409
            );
            assert.equal(
                await fsp.readFile(filePath, 'utf8'),
                before,
                `a rejected maxDevices=${maxDevices} policy must not touch the file`
            );
            assert.equal((await store.listExtensions(pbx.id)).length, 0);
            assert.equal(approvedFor(store, pbx.id, '150').length, 3);
        }

        // A cap equal to the live usage is accepted.
        const created = await store.addExtension(extensionInput(pbx.id, '150', { maxDevices: 3 }));
        assert.equal(created.maxDevices, 3);
        assert.equal(created.status, 'enabled');
        assert.equal((await store.listExtensions(pbx.id)).length, 1);

        const onDisk = await rawDocument(filePath);
        assert.equal(onDisk.extensions.length, 1);
        assert.equal(onDisk.extensions[0].maxDevices, 3);
        assert.equal(onDisk.devices.filter((device) => device.status === 'approved').length, 3);

        // Existing credentials survive both the rejection and the creation.
        for (const entry of devices) {
            assert.equal(store.verifyDeviceSecret(entry.device.id, entry.secret).ok, true);
        }

        const reloaded = await reloadStore(filePath);
        assert.equal((await reloaded.listExtensions(pbx.id))[0].maxDevices, 3);
        for (const entry of devices) {
            assert.equal(reloaded.verifyDeviceSecret(entry.device.id, entry.secret).ok, true);
        }
    } finally {
        await close();
    }
});

// --- 3. approval revalidation ---------------------------------------------

test('changing mediaIps or loginHostname resets managed approval despite an approved ask', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Acme primary', { management: management() }));
        assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'approved');

        const askedApproved = () => ({
            ...store.getPbx(pbx.id).management,
            approvalStatus: 'approved'
        });

        // Media endpoints are reviewed too: a change invalidates the approval.
        const movedMedia = await store.updatePbx(pbx.id, {
            mediaIps: ['203.0.113.11'],
            management: askedApproved()
        });
        assert.deepEqual(movedMedia.mediaIps, ['203.0.113.11']);
        assert.equal(movedMedia.management.approvalStatus, 'pending');
        assert.equal(movedMedia.management.loginHostname, CUSTOMER_HOSTNAME, 'other metadata is preserved');

        // An approval-only PATCH succeeds without touching any endpoint.
        const reapproved = await store.updatePbx(pbx.id, {
            management: { approvalStatus: 'approved' }
        });
        assert.equal(reapproved.management.approvalStatus, 'approved');
        assert.deepEqual(reapproved.mediaIps, ['203.0.113.11']);
        assert.equal(reapproved.wsURL, 'wss://pbx.example.com:8089/ws');
        assert.equal(reapproved.apiURL, 'https://pbx.example.com:8080/');

        // The login hostname is part of the reviewed identity.
        const movedHostname = await store.updatePbx(pbx.id, {
            management: {
                loginHostname: 'Branch.Gateway.Example.COM',
                approvalStatus: 'approved'
            }
        });
        assert.equal(movedHostname.management.loginHostname, 'branch.gateway.example.com');
        assert.equal(movedHostname.management.approvalStatus, 'pending');

        // The reset is durable, and a pending PBX cannot authorise devices.
        const reloaded = await reloadStore(filePath);
        assert.equal(reloaded.getPbx(pbx.id).management.approvalStatus, 'pending');
        await reloaded.addExtension(extensionInput(pbx.id, '150'));
        const device = await pendingDevice(reloaded, 'android');
        await rejectsWithCode(
            reloaded.approveDevice(device.id, { pbxId: pbx.id, extension: '150' }),
            'pbx_not_approved',
            403
        );

        // Approval-only on the reloaded store restores access.
        const approvedAgain = await reloaded.updatePbx(pbx.id, {
            management: { approvalStatus: 'approved' }
        });
        assert.equal(approvedAgain.management.approvalStatus, 'approved');
        const approved = await reloaded.approveDevice(device.id, {
            pbxId: pbx.id,
            extension: '150'
        });
        assert.equal(approved.device.status, 'approved');
        assert.equal(reloaded.verifyDeviceSecret(device.id, approved.secret).ok, true);
    } finally {
        await close();
    }
});

test('first opt-in management with a changed ws, api or media endpoint resets to pending', async () => {
    const { store, close } = await makeStore();
    try {
        const cases = [
            ['wsURL', { wsURL: 'wss://moved.example.com:8089/ws' }, 'opt-ws.gateway.example.com'],
            ['apiURL', { apiURL: 'https://moved.example.com:8080' }, 'opt-api.gateway.example.com'],
            ['mediaIps', { mediaIps: ['198.51.100.20'] }, 'opt-media.gateway.example.com']
        ];

        for (const [field, patch, loginHostname] of cases) {
            const legacy = await store.addPbx(pbxInput(`Legacy ${field}`));
            assert.ok(!store.getPbx(legacy.id).management, `${field}: legacy PBX starts unmanaged`);

            const optedIn = await store.updatePbx(legacy.id, {
                ...patch,
                management: management({ loginHostname, approvalStatus: 'approved' })
            });

            assert.ok(optedIn.management, `${field}: opt-in must persist management metadata`);
            assert.equal(
                optedIn.management.approvalStatus,
                'pending',
                `${field}: an endpoint change during opt-in must force pending approval`
            );
            assert.equal(optedIn.management.loginHostname, loginHostname);
            assert.equal(optedIn.management.extensionPolicyRequired, true);
        }

        // Control: opting in without an endpoint change keeps the recorded ask.
        const unchanged = await store.addPbx(pbxInput('Legacy unchanged'));
        const optedIn = await store.updatePbx(unchanged.id, {
            management: management({ loginHostname: 'opt-stable.gateway.example.com' })
        });
        assert.equal(optedIn.management.approvalStatus, 'approved');
    } finally {
        await close();
    }
});

test('re-submitting equivalent endpoints, media values or login hostname keeps approval', async () => {
    const { filePath, store, close } = await makeStore();
    try {
        const pbx = await store.addPbx(pbxInput('Acme primary', { management: management() }));
        assert.equal(store.getPbx(pbx.id).management.approvalStatus, 'approved');

        const resubmitted = await store.updatePbx(pbx.id, {
            // Same endpoints once normalised (case, trailing slash, spacing,
            // duplicated media entries).
            wsURL: 'WSS://PBX.Example.COM:8089/ws',
            apiURL: 'https://pbx.example.com:8080',
            mediaIps: ' 203.0.113.10 , 203.0.113.10 ',
            management: {
                ...store.getPbx(pbx.id).management,
                loginHostname: 'Customer.Gateway.Example.COM.',
                approvalStatus: 'approved'
            }
        });

        assert.equal(resubmitted.wsURL, 'wss://pbx.example.com:8089/ws');
        assert.equal(resubmitted.apiURL, 'https://pbx.example.com:8080/');
        assert.deepEqual(resubmitted.mediaIps, ['203.0.113.10']);
        assert.equal(resubmitted.management.loginHostname, CUSTOMER_HOSTNAME);
        assert.equal(
            resubmitted.management.approvalStatus,
            'approved',
            'equivalent values are not a change and must not reset approval'
        );

        const reloaded = await reloadStore(filePath);
        assert.equal(reloaded.getPbx(pbx.id).management.approvalStatus, 'approved');

        // A genuinely different endpoint still resets, so the comparison is real.
        const moved = await reloaded.updatePbx(pbx.id, {
            apiURL: 'https://moved.example.com:8080',
            management: { ...reloaded.getPbx(pbx.id).management, approvalStatus: 'approved' }
        });
        assert.equal(moved.apiURL, 'https://moved.example.com:8080/');
        assert.equal(moved.management.approvalStatus, 'pending');
    } finally {
        await close();
    }
});
