'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function loadModule(directory) {
    process.env.SOKRAT_PUSH_CREDENTIALS_DIR = directory;
    delete require.cache[require.resolve('../src/control/push-credentials')];
    return require('../src/control/push-credentials');
}

test('push credential store writes private files and reports sanitized status', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-push-'));
    try {
        const store = loadModule(directory);
        assert.deepEqual(store.status(), {
            fcm: { configured: false },
            apns: { configured: false, keyId: null, teamId: null, topic: null, environment: null }
        });

        const serviceAccount = {
            type: 'service_account',
            project_id: 'test-project',
            client_email: 'test@test-project.iam.gserviceaccount.com',
            private_key: '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n'
        };
        const fcmStatus = store.saveFcm(serviceAccount);
        assert.equal(fcmStatus.fcm.configured, true);
        assert.equal(fs.statSync(store.FCM_FILE).mode & 0o077, 0);
        assert.equal(JSON.parse(fs.readFileSync(store.FCM_FILE, 'utf8')).project_id, 'test-project');

        const apnsStatus = store.saveApns({
            keyBase64: Buffer.from('-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n').toString('base64'),
            keyId: 'ABCDEFGHIJ',
            teamId: 'KLMNOPQRST',
            topic: 'com.sokrat.voice.voip',
            environment: 'production'
        });
        assert.equal(apnsStatus.apns.configured, true);
        assert.equal(apnsStatus.apns.keyId, 'ABCDEFGHIJ');
        assert.equal(fs.statSync(store.APNS_KEY).mode & 0o077, 0);
        assert.equal(fs.statSync(store.APNS_META).mode & 0o077, 0);
        assert.equal(fs.existsSync(store.REVISION), true);
        assert.equal(JSON.stringify(store.status()).includes('PRIVATE KEY'), false);

        assert.throws(() => store.saveFcm({}), /missing required fields/);
        assert.throws(() => store.saveApns({ keyBase64: '', keyId: '', teamId: '' }), /key file is required/);
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
        delete process.env.SOKRAT_PUSH_CREDENTIALS_DIR;
    }
});
