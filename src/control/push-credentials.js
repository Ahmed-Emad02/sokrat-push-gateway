'use strict';

const fs = require('node:fs');
const path = require('node:path');

const PUSH_DIR = process.env.SOKRAT_PUSH_CREDENTIALS_DIR || '/var/lib/sokrat-gateway/push';
const FCM_FILE = path.join(PUSH_DIR, 'firebase-service-account.json');
const APNS_DIR = path.join(PUSH_DIR, 'apns');
const APNS_KEY = path.join(APNS_DIR, 'AuthKey.p8');
const APNS_META = path.join(PUSH_DIR, 'apns.json');
const REVISION = path.join(PUSH_DIR, 'revision');

const MAX_FCM_BYTES = 64 * 1024;
const MAX_APNS_KEY_BYTES = 16 * 1024;

function ensureDirectory(directory) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(directory, 0o700);
}

function writeAtomic(file, content, mode = 0o600) {
    ensureDirectory(path.dirname(file));
    const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
    try {
        fs.writeFileSync(temporary, content, { mode });
        fs.chmodSync(temporary, mode);
        fs.renameSync(temporary, file);
        fs.chmodSync(file, mode);
    } finally {
        if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
}

function touchRevision() {
    ensureDirectory(PUSH_DIR);
    writeAtomic(REVISION, `${Date.now()}\n`, 0o600);
}

function readJson(file) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (_) {
        return null;
    }
}

function status() {
    const meta = readJson(APNS_META);
    const fcm = fs.existsSync(FCM_FILE);
    const apns = fs.existsSync(APNS_KEY) && Boolean(meta);
    return {
        fcm: { configured: fcm },
        apns: {
            configured: apns,
            keyId: meta && typeof meta.keyId === 'string' ? meta.keyId : null,
            teamId: meta && typeof meta.teamId === 'string' ? meta.teamId : null,
            topic: meta && typeof meta.topic === 'string' ? meta.topic : null,
            environment: meta && typeof meta.environment === 'string' ? meta.environment : null
        }
    };
}

function saveFcm(serviceAccount) {
    const raw = typeof serviceAccount === 'string' ? serviceAccount : JSON.stringify(serviceAccount);
    if (Buffer.byteLength(raw, 'utf8') > MAX_FCM_BYTES) throw new Error('FCM service account is too large');
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch (_) {
        throw new Error('FCM service account must be valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('FCM service account must be a JSON object');
    }
    if (parsed.type !== 'service_account' ||
        typeof parsed.project_id !== 'string' || !parsed.project_id ||
        typeof parsed.private_key !== 'string' || !parsed.private_key.includes('BEGIN PRIVATE KEY') ||
        typeof parsed.client_email !== 'string' || !parsed.client_email.includes('@')) {
        throw new Error('FCM service account is missing required fields');
    }
    writeAtomic(FCM_FILE, `${JSON.stringify(parsed, null, 2)}\n`);
    touchRevision();
    return status();
}

function saveApns({ keyBase64, keyId, teamId, topic, environment } = {}) {
    if (typeof keyBase64 !== 'string' || !keyBase64.trim()) throw new Error('APNs key file is required');
    if (Buffer.byteLength(keyBase64, 'base64') > MAX_APNS_KEY_BYTES) throw new Error('APNs key is too large');
    const key = Buffer.from(keyBase64, 'base64').toString('utf8');
    if (!key.includes('BEGIN PRIVATE KEY') || !key.includes('END PRIVATE KEY')) {
        throw new Error('APNs key must be a PKCS#8 private key');
    }
    const normalizedKeyId = String(keyId || '').trim();
    const normalizedTeamId = String(teamId || '').trim();
    const normalizedTopic = String(topic || 'com.sokrat.voice.voip').trim();
    const normalizedEnvironment = String(environment || 'production').trim();
    if (!/^[A-Z0-9]{10}$/.test(normalizedKeyId)) throw new Error('APNs key ID must be 10 uppercase letters or digits');
    if (!/^[A-Z0-9]{10}$/.test(normalizedTeamId)) throw new Error('APNs team ID must be 10 uppercase letters or digits');
    if (!/^[A-Za-z0-9.-]{1,128}$/.test(normalizedTopic)) throw new Error('APNs topic is invalid');
    if (!['production', 'development'].includes(normalizedEnvironment)) {
        throw new Error('APNs environment must be production or development');
    }
    ensureDirectory(APNS_DIR);
    writeAtomic(APNS_KEY, key.endsWith('\n') ? key : `${key}\n`);
    writeAtomic(APNS_META, `${JSON.stringify({
        keyId: normalizedKeyId,
        teamId: normalizedTeamId,
        topic: normalizedTopic,
        environment: normalizedEnvironment
    }, null, 2)}\n`);
    touchRevision();
    return status();
}

module.exports = {
    PUSH_DIR,
    FCM_FILE,
    APNS_DIR,
    APNS_KEY,
    APNS_META,
    REVISION,
    status,
    saveFcm,
    saveApns
};
