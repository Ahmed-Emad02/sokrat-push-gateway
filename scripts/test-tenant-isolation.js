'use strict';
// Offline smoke test using the real control store and runtime. No PBX required.
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { ControlStore } = require('../src/control');
const { createTenantRuntime } = require('../src/tenant-runtime');

async function main() {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'sokrat-tenant-smoke-'));
    try {
        const store = new ControlStore({ filePath: path.join(directory, 'control.json'), maxEnabledPbx: 2 });
        await store.init();
        const pbx = await store.addPbx({ name: 'Isolation test', wsURL: 'ws://pbx.example:8088/ws', apiURL: 'http://pbx.example:8080', mediaIps: ['10.0.0.2'], enabled: true });
        const runtime = createTenantRuntime({ control: { store }, pushFile: path.join(directory, 'push.json'),
            getRelay: async () => null, authorizePbx: async () => null, sendToDevice: async () => {}, normalizeCallId: x => x });
        assert.equal(await runtime.authorize('unknown', 'invalid'), null);
        assert.ok(pbx.wsURL);
        const invite = await store.createEnrollmentToken({ label: 'Fixture', pbxId: pbx.id, extension: 'fixture', maxUses: 1 });
        const enrollment = await store.enrollDevice({ token: invite.token, platform: 'android', deviceUuid: '12345678-1234-4123-8123-123456789abc' });
        const approved = await store.approveDevice(enrollment.device.id, { pbxId: pbx.id, extension: 'fixture' });
        const secret = approved.secret || approved.deviceSecret;
        assert.ok(secret, 'Approval must return a one-time device credential');
        const assignment = await runtime.authorize(enrollment.device.id, secret);
        assert.equal(assignment.wsUrl, pbx.wsURL);
        assert.equal(assignment.extension, 'fixture');
        await store.revokeDevice(enrollment.device.id);
        assert.equal(await runtime.authorize(enrollment.device.id, secret), null);
        console.log('Real control store + runtime fail-closed smoke test: PASS');
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
