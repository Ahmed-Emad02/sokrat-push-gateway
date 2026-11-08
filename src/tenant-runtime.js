'use strict';
const fs = require('node:fs/promises');
const express = require('express');
const { attachSipProxy } = require('./sip-proxy');
const { installTenantIce } = require('./tenant-ice');
const { installTenantPush } = require('./tenant-push');
const { createTenantPushStore } = require('./tenant-push-store');
const { createDeviceTickets } = require('./device-tickets');
const { tenantCallId } = require('./tenant-call-id');
const { createHeartbeatScheduler } = require('./heartbeat-scheduler');
const { createChatProxy } = require('./tenant-chat-proxy');
const { createChatTickets } = require('./chat-tickets');
const { attachChatSocketProxy } = require('./tenant-chat-socket');

// Explicit integration factory: opt in only after enrollment clients have been
// deployed. No fallback to the legacy/single-PBX route is permitted here.
function createTenantRuntime({ control, pushFile, getRelay, authorizePbx, sendToDevice, normalizeCallId, heartbeatOptions = {} }) {
    function assignment(deviceId) {
        const device = control.store.getApprovedDevice(deviceId);
        const pbx = device && control.store.getPbx(device.pbxId);
        if (!device || !pbx?.enabled) return null;
        return { deviceId: device.id, deviceUuid: device.deviceUuid,
            pbxId: pbx.id, extension: device.extension, wsUrl: pbx.wsURL, apiUrl: pbx.apiURL,
            authorizationRevision: device.authorizationRevision || 0 };
    }
    async function authorize(deviceId, token) {
        if (!control.store.verifyDeviceSecret(deviceId, token).ok) return null;
        return assignment(deviceId);
    }
    async function authorizeDevice(req) {
        const deviceId = req.get('X-Sokrat-Device');
            const match = /^Bearer (\S{16,256})$/.exec(req.get('Authorization') || '');
        return match && deviceId ? authorize(deviceId, match[1]) : null;
    }
    const pushStore = createTenantPushStore(pushFile, assignment);
    const chatTickets = createChatTickets();
    const chatProxy = createChatProxy({ authorizeDevice });
    const hasLiveSession = (pbxId, extension) => attachedProxy?.hasLiveSession?.(pbxId, extension) === true;
    const heartbeat = createHeartbeatScheduler({
        listDevices: () => pushStore.listAllPush(),
        sendToDevice,
        markInvalid: heartbeatOptions.markInvalid || ((deviceId, tokenFingerprint, code) =>
            pushStore.markInvalid(deviceId, tokenFingerprint, code)),
        markDelivered: heartbeatOptions.markDelivered || (device =>
            pushStore.markDelivered(device.deviceId, require('./push-errors').fingerprintToken(device.token))),
        enabled: heartbeatOptions.enabled === true,
        staleMs: heartbeatOptions.staleMs,
        tickMs: heartbeatOptions.tickMs,
        pbxIds: heartbeatOptions.pbxIds,
        logger: heartbeatOptions.logger,
        now: heartbeatOptions.now,
        sleep: heartbeatOptions.sleep,
    });
    let attachedProxy = null;
    let cleanupTimer = null;
    const router = express.Router();
    router.use(express.json({ limit: '16kb' }));
    router.get('/capabilities', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.json({ version: 1, deviceApproval: true, sipPort: 8088,
            enrollmentPath: '/api/gateway/enrollment', ticketPath: '/api/gateway/sip-ticket',
            liveSessionGate: true });
    });
    const tickets = createDeviceTickets({ authorize });
    router.post('/sip-ticket', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const route = await authorizeDevice(req);
            if (!route) return res.status(403).json({ error: 'Device approval required' });
            const token = req.get('Authorization').slice(7);
            const ticket = tickets.issue(route.deviceId, token, route);
            return res.json({ ticket, expiresIn: 30 });
        } catch (_) { return res.status(503).json({ error: 'Ticket unavailable' }); }
    });
    router.post('/chat-ticket', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const route = await authorizeDevice(req);
            if (!route) return res.status(403).json({ error: 'Device approval required' });
            return res.json(chatTickets.issue(route));
        } catch (_) {
            return res.status(503).json({ error: 'Chat ticket unavailable' });
        }
    });
    router.post('/device/heartbeat', async (req, res) => {
        try {
            const route = await authorizeDevice(req);
            if (!route) return res.status(403).json({ error: 'Device approval required' });
            heartbeat.markSeen(route.deviceId);
            try {
                const heartbeatBody = req.body || {};
                // The wake ACK is deliberately minimal (sipState=wake). It
                // must not replace the device's full diagnostic snapshot.
                if (heartbeatBody.reportedAt || heartbeatBody.appVersion) {
                    await pushStore.recordTelemetry(route.deviceId, heartbeatBody);
                }
            } catch (_) {
                // Telemetry is diagnostic only; never fail the heartbeat.
            }
            console.log(`[heartbeat] seen extension=${route.extension} pbx=${route.pbxId}`);
            res.json({ ok: true, nextWakeInMs: heartbeat.staleMs });
        } catch (_) {
            res.status(503).json({ error: 'Heartbeat unavailable' });
        }
    });
    router.post('/call/state', async (req, res) => {
        const route = await authorizeDevice(req);
        if (!route) return res.status(403).json({ success: false, error: 'Device approval required' });
        const headers = { Accept: 'application/json' };
        for (const name of ['X-Sokrat-Extension', 'X-Sokrat-Timestamp', 'X-Sokrat-Signature']) {
            const value = req.get(name);
            if (!value || value.length > 256) return res.status(401).json({ success: false, error: 'Extension authentication required' });
            headers[name] = value;
        }
        if (headers['X-Sokrat-Extension'] !== route.extension) {
            return res.status(403).json({ success: false, error: 'Extension does not belong to device' });
        }
        if (!route.apiUrl) return res.status(503).json({ success: false, error: 'Call state unavailable' });
        try {
            const upstream = await fetch(`${route.apiUrl.replace(/\/+$/, '')}/api/extension/v1/call-state`, {
                method: 'GET',
                headers,
                signal: AbortSignal.timeout(5000),
                redirect: 'error',
            });
            const result = await upstream.json().catch(() => ({ success: false, error: 'Invalid call-state response' }));
            return res.status(upstream.status).json(result);
        } catch (_) {
            return res.status(503).json({ success: false, error: 'Call state unavailable' });
        }
    });
    router.post('/call/volume', async (req, res) => {
        const route = await authorizeDevice(req);
        if (!route) return res.status(403).json({ success: false, error: 'Device approval required' });
        const raw = req.body?.micGainDb !== undefined ? req.body.micGainDb : req.body?.gainDb;
        const gain = Math.max(-24, Math.min(42, parseFloat(raw) || 0));
        const signed = {};
        for (const name of ['X-Sokrat-Extension', 'X-Sokrat-Timestamp', 'X-Sokrat-Signature']) {
            const value = req.get(name);
            if (value) signed[name] = value;
        }
        const hasExtensionProof = signed['X-Sokrat-Extension'] && signed['X-Sokrat-Timestamp'] && signed['X-Sokrat-Signature'];
        if (hasExtensionProof) {
            if (signed['X-Sokrat-Extension'] !== route.extension) {
                return res.status(403).json({ success: false, error: 'Extension does not belong to device' });
            }
            if (!route.apiUrl) return res.status(503).json({ success: false, error: 'Volume control unavailable' });
            try {
                const upstream = await fetch(`${route.apiUrl.replace(/\/+$/, '')}/api/extension/v1/call-volume`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', ...signed },
                    body: JSON.stringify({ micGainDb: gain }),
                    signal: AbortSignal.timeout(5000),
                    redirect: 'error',
                });
                const result = await upstream.json().catch(() => ({ success: false, error: 'Invalid volume response' }));
                return res.status(upstream.status).json(result);
            } catch (_) {
                return res.status(503).json({ success: false, error: 'Volume control unavailable' });
            }
        }
        // Legacy clients without extension proof keep the old local-AMI path.
        try {
            const upstream = await fetch('http://127.0.0.1:8095/api/call/volume', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ extension: route.extension, callId: req.body?.callId, micGainDb: gain }),
            });
            const result = await upstream.json().catch(() => ({ success: false, error: 'Invalid volume response' }));
            res.status(upstream.status).json(result);
        } catch (_) {
            res.status(503).json({ success: false, error: 'Volume control unavailable' });
        }
    });
    installTenantIce(router, { authorizeDevice, getRelay });
    require('./contacts-proxy').installContactsProxy(router, { authorizeDevice });
    installTenantPush(router, { store: pushStore, authorizeDevice, authorizePbx, sendToDevice, normalizeCallId, hasLiveSession });
    return {
        router, assignment, authorize, pushStore, heartbeat, chatProxy,
        getActiveCalls: () => attachedProxy?.getActiveCalls?.() || [],
        getNetworkStats: () => attachedProxy?.getNetworkStats?.() || { inBytes: 0, outBytes: 0, byPbx: [] },
        start() {
            heartbeat.start();
            const cleanup = async () => {
                try { await pushStore.pruneInvalidPush(); }
                catch (error) { console.warn('[push-store] invalid-token cleanup skipped:', error?.message || error); }
                try { await pushStore.pruneExpiredPush(); }
                catch (error) { console.warn('[push-store] expired-token cleanup skipped:', error?.message || error); }
            };
            void cleanup();
            if (!cleanupTimer) {
                cleanupTimer = setInterval(() => { void cleanup(); }, 6 * 60 * 60 * 1000);
                cleanupTimer.unref?.();
            }
        },
        stop() {
            heartbeat.stop();
            if (cleanupTimer) { clearInterval(cleanupTimer); cleanupTimer = null; }
        },
        attach(server) {
            attachedProxy = attachSipProxy(server, { authorize, consumeTicket: tickets.consume,
                scopeIncomingCallId: (value, route) => tenantCallId(normalizeCallId, route.pbxId, value),
                isAuthorized: async (id, previous, token) => {
                    const current = await authorize(id, token);
                    return !!current && current.pbxId === previous.pbxId && current.extension === previous.extension
                        && current.wsUrl === previous.wsUrl && current.authorizationRevision === previous.authorizationRevision;
                } });
            const closeChatProxy = attachChatSocketProxy(server, { consume: chatTickets.consume });
            const closeSip = attachedProxy.close.bind(attachedProxy);
            attachedProxy.close = () => { closeChatProxy(); closeSip(); };
            return attachedProxy;
        }
    };
}

// Runtime manifest is root/operator managed, outside dashboard state. Keeping
// per-PBX TURN secrets and hook keys outside public PBX records avoids accidental
// disclosure through the admin CRUD API.
const MAX_RUNTIME_MANIFEST_BYTES = 1024 * 1024;
async function readPrivateRuntimeManifest(file) {
    const handle = await fs.open(file, require('node:fs').constants.O_RDONLY |
        require('node:fs').constants.O_NOFOLLOW | require('node:fs').constants.O_NONBLOCK);
    try {
        const stat = await handle.stat();
        if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error('Runtime manifest must be a private regular file');
        // Bound the read before allocating: the file is operator-managed, but a
        // runaway or accidentally huge replacement must fail closed, not exhaust
        // memory or stall every authorization lookup.
        if (stat.size > MAX_RUNTIME_MANIFEST_BYTES) throw new Error('Runtime manifest is too large');
        const text = await handle.readFile('utf8');
        if (Buffer.byteLength(text) > MAX_RUNTIME_MANIFEST_BYTES) throw new Error('Runtime manifest is too large');
        const manifest = JSON.parse(text);
        if (!manifest || typeof manifest !== 'object' || !manifest.relays) throw new Error('Invalid runtime manifest');
        for (const [id, relay] of Object.entries(manifest.relays)) {
            if (!/^[A-Za-z0-9_-]{1,80}$/.test(id) || !relay || typeof relay.host !== 'string' || !/^[A-Za-z0-9.-]+$/.test(relay.host) ||
                !Number.isInteger(relay.port) || relay.port < 1024 || relay.port > 65535 ||
                typeof relay.secretFile !== 'string' || !require('node:path').isAbsolute(relay.secretFile) ||
                !Array.isArray(relay.peerIps) || !relay.peerIps.length || relay.peerIps.some(ip => !require('node:net').isIP(ip))) {
                throw new Error('Invalid tenant relay configuration');
            }
        }
        return manifest;
    } finally { await handle.close(); }
}
module.exports = { createTenantRuntime, readPrivateRuntimeManifest };
