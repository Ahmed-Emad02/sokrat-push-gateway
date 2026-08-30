/**
 * Sokrat VOICE Push-to-Wake Gateway
 * ---------------------------------------------------------
 * Maps PBX extensions -> mobile device push tokens and wakes the
 * Sokrat mobile app on incoming calls so it can connect to
 * Asterisk over a fresh WebSocket and display the native
 * CallKit (iOS) / Telecom (Android) incoming call screen.
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

// ----------------------------------------------------------------------------
// Push providers (loaded lazily, fail-open if not configured)
// ----------------------------------------------------------------------------
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
        if (dev.platform === 'ios' && apnsReady && apnsProvider) {
            await apnsProvider.send(dev.voip_token, call);
        } else if (dev.platform === 'android' && fcmReady && fcmMessaging) {
            await fcmMessaging.send({
                token: dev.token,
                android: { priority: 'high' },
                data: {
                    msg: 'incoming-call',
                    callerId: call.callerId || '',
                    callerName: call.callerName || 'Incoming Call',
                    extension: call.extension || '',
                    timestamp: String(call.timestamp || Date.now()),
                    sipWss: call.sipWss || ''
                }
            });
        }
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
        const {
            extension, platform, token, voipToken
        } = req.body || {};

        if (!extension || !platform || !token) {
            return res.status(400).json({ success: false, error: 'extension, platform and token are required' });
        }
        if (!['ios', 'android'].includes(platform)) {
            return res.status(400).json({ success: false, error: 'platform must be ios or android' });
        }
        if (platform === 'ios' && !voipToken) {
            return res.status(400).json({ success: false, error: 'voipToken (PushKit) is required for ios' });
        }

        const deviceUuid = (req.body.deviceUuid || '').toString().slice(0, 128) || null;

        await pool.execute(
            `INSERT INTO mobile_devices
                (extension, platform, token, voip_token, device_uuid, app_version, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
                token = VALUES(token),
                voip_token = VALUES(voip_token),
                device_uuid = VALUES(device_uuid),
                app_version = VALUES(app_version),
                updated_at = NOW()`,
            [
                String(extension),
                platform,
                String(token),
                platform === 'ios' ? String(voipToken) : null,
                deviceUuid,
                (req.body.appVersion || '').toString().slice(0, 40) || null
            ]
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
        const { token } = req.body || {};
        if (dbGuard(res)) return;
        if (!token) return res.status(400).json({ success: false, error: 'token is required' });
        await pool.execute('DELETE FROM mobile_devices WHERE token = ?', [String(token)]);
        res.json({ success: true });
    } catch (err) {
        console.error('[push-gateway] remove-device error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Asterisk dialplan triggers this when an incoming call targets a mobile extension
app.get('/api/push/incoming-call', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    let callee, caller, callerName;
    try {
        callee = (req.query.callee || '').toString().trim();
        caller = (req.query.caller || '').toString().trim();
        callerName = (req.query.callerName || caller || 'Incoming Call').toString().trim();
        const sipWss = (req.query.sipWss || '').toString().trim();

        if (!callee) {
            return res.status(400).json({ success: false, error: 'callee is required' });
        }
        if (dbGuard(res)) return;

        const [devices] = await pool.execute(
            'SELECT * FROM mobile_devices WHERE extension = ? AND updated_at > (NOW() - INTERVAL 90 DAY)',
            [callee]
        );

        const ctx = await buildCtx();
        const callPayload = {
            callerId: caller,
            callerName,
            extension: callee,
            timestamp: Date.now(),
            sipWss
        };

        let dispatched = 0;
        const errors = [];
        for (const dev of devices) {
            try {
                await ctx.sendToDevice(dev, callPayload);
                // Refresh token staleness marking is handled by provider errors below
                dispatched++;
            } catch (err) {
                errors.push({ platform: dev.platform, err: err.message });
                // Token likely invalid — mark for cleanup so we stop pushing dead tokens
                console.warn('[push-gateway] push failed for', dev.platform, err.message);
                try {
                    if (/bad.*token|unregistered|invalid/i.test(String(err.message))) {
                        await pool.execute(
                            'UPDATE mobile_devices SET last_push_error = CURRENT_TIMESTAMP WHERE id = ?',
                            [dev.id]
                        );
                    }
                } catch (_) {}
            }
        }

        res.json({ status: 'dispatched', count: dispatched, errors });
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

module.exports = { app, buildCtx, dbConfig };
