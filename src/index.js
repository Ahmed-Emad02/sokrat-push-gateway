/**
 * Sokrat VOICE Push-to-Wake Gateway
 * ---------------------------------------------------------
 * Maps PBX extensions -> mobile device push tokens and wakes the
 * Sokrat mobile app on incoming calls so it can connect to
 * Asterisk over a fresh WebSocket. iOS uses CallKit; Android uses
 * the app's native full-screen incoming-call notification.
 *
 * Endpoints
 *   POST /api/push/register-device   Mobile app token registration
 *   POST /api/push/remove-device     Token de-registration (logout)
 *   GET  /api/push/incoming-call     Asterisk dialplan webhook
 *   GET  /health                     Liveness
 *
 * Env (.env)
 *   PORT            default 8095
 *   DB_HOST         default 127.0.0.1
 *   DB_USER         default root
 *   DB_PASS         default admin
 *   DB_NAME         default asterisk
 *   APNS_ENABLED    true / false
 *   APNS_KEY_FILE   path to VoIP .p8 key
 *   APNS_KEY_ID     key id
 *   APNS_TEAM_ID    team id
 *   APNS_TOPIC      default com.sokrat.voice.voip
 *   APNS_ENV        production | development
 *   FCM_ENABLED     true / false
 *   GOOGLE_APPLICATION_CREDENTIALS  path to firebase service-account json
 */
'use strict';

require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');

const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CALL_NAMESPACE = Buffer.from('b32a7f284bcc5a56a51f2ad6f65f746b', 'hex');

function formatUuid(bytes) {
    const hex = bytes.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
        `${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function normalizeCallId(value) {
    const input = String(value || '').trim();
    if (!input || input.length > 128) throw new Error('callId is required');
    if (UUID_PATTERN.test(input)) return input.toLowerCase();
    const digest = crypto.createHash('sha1')
        .update(Buffer.concat([CALL_NAMESPACE, Buffer.from(input, 'utf8')]))
        .digest()
        .subarray(0, 16);
    digest[6] = (digest[6] & 0x0f) | 0x50;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    return formatUuid(digest);
}

function tokenFingerprint(token) {
    return crypto.createHash('sha256').update(String(token)).digest('hex').slice(0, 12);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = parseInt(process.env.PORT, 10) || 8095;

// ----------------------------------------------------------------------------
// MySQL device registry
// ----------------------------------------------------------------------------
const dbConfig = {
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || 'admin',
    database: process.env.DB_NAME || 'asterisk',
    connectionLimit: 10,
    waitForConnections: true
};

let pool;
try {
    pool = mysql.createPool(dbConfig);
} catch (err) {
    console.error('[push-gateway] MySQL pool init failed:', err.message);
}

// Push providers (loaded lazily; health reports disabled/failed providers)
let apnsProvider = null;
let apnsReady = false;
let fcmApp = null;
let fcmMessaging = null;
let fcmReady = false;

async function initApns() {
    try {
        if (process.env.APNS_ENABLED !== 'true') return;
        const { ApnsClient, Notification } = require('apns2');
        const path = require('path');
        const keyFile = process.env.APNS_KEY_FILE;
        if (!keyFile) throw new Error('APNS_KEY_FILE not set');

        const client = new ApnsClient({
            token: {
                key: path.resolve(keyFile),
                keyId: process.env.APNS_KEY_ID,
                teamId: process.env.APNS_TEAM_ID
            },
            // 'production' | 'development' — voip push issues are sent to production
            environment: process.env.APNS_ENV || 'production'
        });

        apnsProvider = {
            async send(deviceToken, payload) {
                const notification = new Notification(deviceToken, {
                    payload: {
                        callerId: payload.callerId || '',
                        callerName: payload.callerName || 'Incoming Call',
                        extension: payload.extension || '',
                        timestamp: payload.timestamp || Date.now(),
                        msg: 'incoming-call',
                        callId: payload.callId,
                        sipWss: payload.sipWss || ''
                    },
                    apns: {
                        topic: process.env.APNS_TOPIC || 'com.sokrat.voice.voip',
                        pushType: 'voip',
                        priority: 10,
                        expiration: Math.floor(Date.now() / 1000) + 60
                    }
                });
                return client.send(notification);
            }
        };
        apnsReady = true;
        console.log('[push-gateway] APNs provider ready');
    } catch (err) {
        console.error('[push-gateway] APNs init failed (continue without):', err.message);
    }
}

async function initFcm() {
    try {
        if (process.env.FCM_ENABLED !== 'true') return;
        const { initializeApp, cert } = require('firebase-admin/app');
        const { getMessaging } = require('firebase-admin/messaging');
        const serviceAccount = process.env.GOOGLE_APPLICATION_CREDENTIALS;
        if (!serviceAccount) throw new Error('GOOGLE_APPLICATION_CREDENTIALS not set');

        if (!fcmApp) {
            fcmApp = initializeApp({
                credential: cert(serviceAccount)
            });
        }
        fcmMessaging = getMessaging(fcmApp);
        fcmReady = true;
        console.log('[push-gateway] FCM provider ready');
    } catch (err) {
        console.error('[push-gateway] FCM init failed (continue without):', err.message);
    }
}

async function buildCtx() {
    const ctx = { apnsReady, fcmReady, apnsProvider, fcmApp };
    ctx.sendToDevice = async function (dev, call) {
        if (dev.platform === 'ios') {
            if (!apnsReady || !apnsProvider) throw new Error('APNs provider unavailable');
            await apnsProvider.send(dev.voip_token, call);
            return;
        }
        if (dev.platform === 'android') {
            if (!fcmReady || !fcmMessaging) throw new Error('FCM provider unavailable');
            await fcmMessaging.send({
                token: dev.token,
                android: { priority: 'high' },
                data: {
                    msg: 'incoming-call',
                    callerId: call.callerId || '',
                    callerName: call.callerName || 'Incoming Call',
                    extension: call.extension || '',
                    timestamp: String(call.timestamp || Date.now()),
                    callId: call.callId,
                    sipWss: call.sipWss || ''
                }
            });
            return;
        }
        throw new Error(`Unsupported platform: ${dev.platform}`);
    };
    return ctx;
}

// ----------------------------------------------------------------------------
// Routes
// ----------------------------------------------------------------------------

function dbGuard(res) {
    if (!pool) {
        console.error('[push-gateway] MySQL pool unavailable (check DB_HOST/DB_USER/DB_PASS)');
        return res.status(503).json({ success: false, error: 'database unavailable' });
    }
    return null;
}

// Mobile app calls this on login / token refresh to bind a device to an extension
app.post('/api/push/register-device', async (req, res) => {
    try {
        if (dbGuard(res)) return;
        const { extension, platform, token, voipToken, deviceUuid, appVersion } = req.body || {};
        if (!extension || !platform || !token || !deviceUuid) {
            return res.status(400).json({
                success: false,
                error: 'extension, platform, token and deviceUuid are required'
            });
        }
        if (!['ios', 'android'].includes(platform)) {
            return res.status(400).json({ success: false, error: 'platform must be ios or android' });
        }
        if (!UUID_PATTERN.test(String(deviceUuid))) {
            return res.status(400).json({ success: false, error: 'deviceUuid must be a UUID' });
        }
        if (platform === 'ios' && !voipToken) {
            return res.status(400).json({ success: false, error: 'voipToken is required for ios' });
        }

        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                await pool.execute(
                    'DELETE FROM mobile_devices WHERE token = ? AND NOT (platform = ? AND device_uuid = ?)',
                    [String(token), platform, String(deviceUuid)]
                );
                await pool.execute(
                    `INSERT INTO mobile_devices
                        (extension, platform, token, voip_token, device_uuid, app_version, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, NOW())
                     ON DUPLICATE KEY UPDATE
                        extension = VALUES(extension),
                        token = VALUES(token),
                        voip_token = VALUES(voip_token),
                        app_version = VALUES(app_version),
                        updated_at = NOW(),
                        last_push_error = NULL`,
                    [
                        String(extension),
                        platform,
                        String(token),
                        platform === 'ios' ? String(voipToken) : null,
                        String(deviceUuid),
                        String(appVersion || '').slice(0, 40) || null
                    ]
                );
                break;
            } catch (retryErr) {
                if (retryErr.code === 'ER_LOCK_DEADLOCK' && attempt < 2) {
                    await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
                    continue;
                }
                throw retryErr;
            }
        }

        console.log(
            `[device=${deviceUuid} token=${tokenFingerprint(token)}] registered extension=${extension}`
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[push-gateway] register-device error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});
// Logout: remove a single device token (de-register, do not hurt other tokens)
app.post('/api/push/remove-device', async (req, res) => {
    try {
        if (dbGuard(res)) return;
        const { platform, deviceUuid } = req.body || {};
        if (!platform || !UUID_PATTERN.test(String(deviceUuid || ''))) {
            return res.status(400).json({
                success: false,
                error: 'platform and valid deviceUuid are required'
            });
        }
        await pool.execute(
            'DELETE FROM mobile_devices WHERE platform = ? AND device_uuid = ?',
            [String(platform), String(deviceUuid)]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[push-gateway] remove-device error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Asterisk dialplan triggers this when an incoming call targets a mobile extension
app.get('/api/push/incoming-call', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    try {
        const callee = String(req.query.callee || '').trim();
        const caller = String(req.query.caller || '').trim();
        const callerName = String(req.query.callerName || caller || 'Incoming Call').trim();
        const sipWss = String(req.query.sipWss || '').trim();
        let callId;
        try {
            callId = normalizeCallId(req.query.callId);
        } catch (error) {
            return res.status(400).json({ success: false, error: error.message });
        }
        if (!callee) {
            return res.status(400).json({ success: false, error: 'callee is required' });
        }
        if (dbGuard(res)) return;

        const [devices] = await pool.execute(
            `SELECT * FROM mobile_devices
             WHERE extension = ? AND updated_at > (NOW() - INTERVAL 90 DAY)
             ORDER BY updated_at DESC`,
            [callee]
        );
        const ctx = await buildCtx();
        const callPayload = {
            callerId: caller,
            callerName,
            extension: callee,
            timestamp: Date.now(),
            callId,
            sipWss
        };

        console.log(`[callId=${callId}] dispatching callee=${callee} devices=${devices.length}`);
        let dispatched = 0;
        const errors = [];
        for (const dev of devices) {
            try {
                await ctx.sendToDevice(dev, callPayload);
                dispatched++;
                console.log(
                    `[callId=${callId} device=${dev.device_uuid || dev.id}] provider accepted`
                );
            } catch (err) {
                const message = String(err.message || err);
                errors.push({ platform: dev.platform, err: message });
                console.warn(
                    `[callId=${callId} device=${dev.device_uuid || dev.id}] push failed: ${message}`
                );
                if (/bad.*token|registration-token-not-registered|unregistered|invalid/i.test(message)) {
                    await pool.execute('DELETE FROM mobile_devices WHERE id = ?', [dev.id]);
                    console.warn(`[callId=${callId} device=${dev.id}] invalid token deleted`);
                } else {
                    await pool.execute(
                        'UPDATE mobile_devices SET last_push_error = CURRENT_TIMESTAMP WHERE id = ?',
                        [dev.id]
                    );
                }
            }
        }
        res.json({ status: 'dispatched', callId, count: dispatched, errors });
    } catch (err) {
        console.error('[push-gateway] incoming-call error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Liveness
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'sokrat-push-gateway',
        apns: apnsReady,
        fcm: fcmReady,
        timestamp: new Date().toISOString()
    });
});

// ----------------------------------------------------------------------------
// Boot
// ----------------------------------------------------------------------------
async function start() {
    await Promise.all([initApns(), initFcm()]);
    app.listen(PORT, () => {
        console.log(`[Sokrat Push Gateway] listening on :${PORT}`);
        console.log(`[Sokrat Push Gateway] APNs=${apnsReady ? 'ON' : 'OFF'}  FCM=${fcmReady ? 'ON' : 'OFF'}`);
    });
}

if (require.main === module) {
    start().catch((err) => {
        console.error('[push-gateway] fatal:', err);
        process.exit(1);
    });
}

module.exports = { app, buildCtx, dbConfig, normalizeCallId, tokenFingerprint };
