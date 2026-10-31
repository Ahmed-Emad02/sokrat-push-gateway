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
 *   DB_PASS         supplied through deployment environment
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

const fs = require('fs');
const path = require('path');
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
require('./mobile-ice')(app);
require('./contacts-proxy').installContactsProxy(app);

const PORT = parseInt(process.env.PORT, 10) || 8095;

// ----------------------------------------------------------------------------
// MySQL device registry
// ----------------------------------------------------------------------------
const dbConfig = {
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS !== undefined ? process.env.DB_PASS : '',
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
                        msg: payload.msg || 'incoming-call',
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
        if (process.env.FCM_ENABLED === 'false') {
            console.log('[push-gateway] FCM explicitly disabled via FCM_ENABLED=false');
            return;
        }
        const { initializeApp, cert } = require('firebase-admin/app');
        const { getMessaging } = require('firebase-admin/messaging');

        let credentialSource = null;
        const envPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
        const standardPath = '/etc/sokrat/firebase/service-account.json';
        const bundledJsonPath = path.join(__dirname, '../config/firebase-service-account.json');
        const bundledB64Path = path.join(__dirname, '../config/firebase-service-account.b64');

        if (envPath && fs.existsSync(envPath)) {
            credentialSource = envPath;
        } else if (fs.existsSync(standardPath)) {
            credentialSource = standardPath;
        } else if (fs.existsSync(bundledJsonPath)) {
            credentialSource = bundledJsonPath;
        } else if (fs.existsSync(bundledB64Path)) {
            try {
                const rawB64 = fs.readFileSync(bundledB64Path, 'utf8').trim();
                credentialSource = JSON.parse(Buffer.from(rawB64, 'base64').toString('utf8'));
            } catch (b64Err) {
                console.warn('[push-gateway] Failed to parse bundled base64 credentials:', b64Err.message);
            }
        }

        if (!credentialSource) {
            console.warn('[push-gateway] No Firebase service account credentials found. FCM disabled.');
            return;
        }

        if (!fcmApp) {
            fcmApp = initializeApp({
                credential: cert(credentialSource)
            });
        }
        fcmMessaging = getMessaging(fcmApp);
        fcmReady = true;
        console.log(`[push-gateway] FCM provider ready (using ${path.basename(credentialSource)})`);
    } catch (err) {
        console.error('[push-gateway] FCM init failed (continue without):', err.message);
    }
}

async function buildCtx() {
    const ctx = { apnsReady, fcmReady, apnsProvider, fcmApp };
    ctx.sendToDevice = async function (dev, call) {
        if (dev.platform === 'ios') {
            if (!apnsReady || !apnsProvider) throw new Error('APNs provider unavailable');
            return await apnsProvider.send(dev.voip_token, call);
        }
        if (dev.platform === 'android') {
            if (!fcmReady || !fcmMessaging) throw new Error('FCM provider unavailable');
            return await fcmMessaging.send({
                token: dev.token,
                android: { priority: 'high' },
                data: {
                    msg: call.msg || 'incoming-call',
                    callerId: call.callerId || '',
                    callerName: call.callerName || 'Incoming Call',
                    extension: call.extension || '',
                    timestamp: String(call.timestamp || Date.now()),
                    callId: call.callId,
                    sipWss: call.sipWss || ''
                }
            });
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

// Asterisk dialplan triggers this when a caller hangs up before the mobile answers
app.get('/api/push/cancel-call', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    try {
        const callee = String(req.query.callee || '').trim();
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
            msg: 'cancel-call',
            callerId: '',
            callerName: '',
            extension: callee,
            timestamp: Date.now(),
            callId,
            sipWss: ''
        };

        console.log(`[callId=${callId}] cancel callee=${callee} devices=${devices.length}`);
        let count = 0;
        for (const dev of devices) {
            try {
                await ctx.sendToDevice(dev, callPayload);
                count++;
                console.log(
                    `[callId=${callId} device=${dev.device_uuid || dev.id}] cancel accepted`
                );
            } catch (err) {
                console.warn(
                    `[callId=${callId} device=${dev.device_uuid || dev.id}] cancel push failed: ${err.message}`
                );
            }
        }
        res.json({ status: 'cancelled', callId, count });
    } catch (err) {
        console.error('[push-gateway] cancel-call error:', err);
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

// List PBX extensions for 1-click call transfer
app.get('/api/push/extensions', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    try {
        if (dbGuard(res)) return;
        const [users] = await pool.execute(
            'SELECT extension, name FROM users ORDER BY CAST(extension AS UNSIGNED) ASC, extension ASC'
        );
        res.json({ success: true, extensions: users });
    } catch (err) {
        console.error('[push-gateway] get extensions error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ----------------------------------------------------------------------------
// Asterisk AMI live volume control (mid-call mic gain via VOLUME(RX))
// ----------------------------------------------------------------------------
const net = require('net');
const AMI_HOST = process.env.AMI_HOST || '127.0.0.1';
const AMI_PORT = parseInt(process.env.AMI_PORT, 10) || 5038;

function amiCommand(actions) {
    const amiUser = process.env.AMI_USER;
    const amiPass = process.env.AMI_PASS;
    if (!amiUser || !amiPass) return Promise.reject(new Error('AMI credentials are not configured'));
    return new Promise((resolve, reject) => {
        const client = net.createConnection({ host: AMI_HOST, port: AMI_PORT }, () => {
            let req = `Action: Login\r\nUsername: ${amiUser}\r\nSecret: ${amiPass}\r\nEvents: off\r\n\r\n`;
            for (const act of actions) {
                for (const [k, v] of Object.entries(act)) {
                    req += `${k}: ${v}\r\n`;
                }
                req += '\r\n';
            }
            req += 'Action: Logoff\r\n\r\n';
            client.write(req);
        });

        let data = '';
        client.on('data', (chunk) => {
            data += chunk.toString();
        });

        client.on('end', () => {
            resolve(data);
        });

        client.on('error', (err) => {
            reject(err);
        });

        client.setTimeout(3000, () => {
            client.destroy();
            resolve(data);
        });
    });
}
function dbToAsteriskVolume(db) {
    const num = Math.max(-12, Math.min(6, parseFloat(db) || 0));
    if (num === 0) return 0;
    if (num > 0) {
        return parseFloat(Math.pow(10, num / 20).toFixed(4));
    } else {
        return -parseFloat(Math.pow(10, -num / 20).toFixed(4));
    }
}

function matchPjsipChannel(lines, ext) {
    if (!ext || !Array.isArray(lines)) return null;
    let targetChannel = null;
    // Pass 1: Strict scan for direct PJSIP channel prefix match (e.g. PJSIP/150-0000000a)
    for (const line of lines) {
        const cleanLine = line.replace(/^Output:\s*/, '').trim();
        if (!cleanLine || !cleanLine.includes('!')) continue;
        const parts = cleanLine.split('!');
        const ch = parts[0] || '';
        if (ch.startsWith(`PJSIP/${ext}-`)) {
            targetChannel = ch;
            break;
        }
    }

    // Pass 2: Fallback scan strictly among PJSIP channels matching callerid
    if (!targetChannel) {
        for (const line of lines) {
            const cleanLine = line.replace(/^Output:\s*/, '').trim();
            if (!cleanLine || !cleanLine.includes('!')) continue;
            const parts = cleanLine.split('!');
            const ch = parts[0] || '';
            const cid = parts[7] || '';
            if (ch.startsWith('PJSIP/') && (cid === ext || cid.includes(`<${ext}>`))) {
                targetChannel = ch;
                break;
            }
        }
    }

    return targetChannel;
}

async function setAsteriskChannelVolume({ extension, callId, gainDb }) {
    const ext = String(extension || '').trim();
    if (!/^[0-9]{2,6}$/.test(ext)) {
        return { success: false, error: 'Invalid extension format' };
    }
    const targetGain = dbToAsteriskVolume(gainDb);
    let targetChannel = null;
    try {
        const resp = await amiCommand([{ Action: 'Command', Command: 'core show channels concise' }]);
        const lines = (resp || '').split('\n');
        targetChannel = matchPjsipChannel(lines, ext);
    } catch (amiErr) {
        console.warn('[push-gateway] AMI core show channels concise notice:', amiErr.message);
    }
    if (!targetChannel) {
        return { success: false, error: 'No active channel found for extension ' + ext };
    }

    if (!/^PJSIP\/[0-9]{2,6}-[0-9a-f]+$/i.test(targetChannel)) {
        return { success: false, error: 'Unexpected channel name format: ' + targetChannel };
    }

    // 2. Set variable VOLUME(RX) on target channel via Asterisk CLI:
    // Command in Asterisk 18: 'dialplan set chanvar <channel> <varname> <value>'
    try {
        const setResp = await amiCommand([{
            Action: 'Command',
            Command: `dialplan set chanvar ${targetChannel} VOLUME(RX) ${targetGain}`
        }]);

        if (/no such command|no such channel|response:\s*error/i.test(setResp)) {
            console.error(`[push-gateway] dialplan set chanvar rejected on ${targetChannel}:`, setResp);
            return { success: false, error: 'Asterisk rejected volume command: ' + setResp.trim() };
        }

        console.log(`[push-gateway] live volume applied on ${targetChannel}: VOLUME(RX)=${targetGain}`);
        return { success: true, channel: targetChannel, gainDb: targetGain, detail: setResp.trim() };
    } catch (setErr) {
        console.error(`[push-gateway] failed to set VOLUME(RX) on ${targetChannel}:`, setErr.message);
        return { success: false, error: 'AMI command error: ' + setErr.message };
    }
}

app.post('/api/call/volume', async (req, res) => {
    try {
        const { extension, callId } = req.body || {};
        if (!extension && !callId) {
            return res.status(400).json({ success: false, error: 'extension or callId is required' });
        }
        const rawGain = req.body?.micGainDb !== undefined
            ? req.body.micGainDb
            : (req.body?.gainDb !== undefined ? req.body.gainDb : req.body?.gain);
        const gain = Math.max(-12, Math.min(12, parseInt(rawGain, 10) || 0));
        const result = await setAsteriskChannelVolume({ extension, callId, gainDb: gain });
        if (!result.success) {
            return res.status(404).json(result);
        }
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
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
module.exports = { app, buildCtx, dbConfig, normalizeCallId, tokenFingerprint, matchPjsipChannel, dbToAsteriskVolume,
    initializePush: () => Promise.all([initApns(), initFcm()]) };

if (require.main === module) {
    start().catch((err) => {
        process.exit(1);
    });
}
