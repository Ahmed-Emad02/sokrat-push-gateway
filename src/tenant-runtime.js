'use strict';
const fs = require('node:fs/promises');
const express = require('express');
const { attachSipProxy } = require('./sip-proxy');
const { installTenantIce } = require('./tenant-ice');
const { installTenantPush } = require('./tenant-push');
const { createTenantPushStore } = require('./tenant-push-store');
const { createDeviceTickets } = require('./device-tickets');

// Explicit integration factory: opt in only after enrollment clients have been
// deployed. No fallback to the legacy/single-PBX route is permitted here.
function createTenantRuntime({ control, pushFile, getRelay, authorizePbx, sendToDevice, normalizeCallId }) {
    function assignment(deviceId) {
        const device = control.store.getApprovedDevice(deviceId);
        const pbx = device && control.store.getPbx(device.pbxId);
        if (!device || !pbx?.enabled) return null;
        return { deviceId: device.id, deviceUuid: device.deviceUuid,
            pbxId: pbx.id, extension: device.extension, wsUrl: pbx.wsURL, apiUrl: pbx.apiURL };
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
    const router = express.Router();
    router.use(express.json({ limit: '16kb' }));
    const requests = new Map();
    router.use((req, res, next) => {
        const now = Date.now();
        for (const [key, entry] of requests) if (entry.reset <= now) requests.delete(key);
        const key = `${req.socket.remoteAddress}|${String(req.get('X-Sokrat-Device') || req.get('X-Sokrat-Pbx') || '').slice(0, 128)}`;
        const entry = requests.get(key) || { count: 0, reset: now + 60000 };
        if (requests.size >= 10000 && !requests.has(key)) return res.status(429).json({ error: 'Request capacity exceeded' });
        requests.set(key, entry);
        if (++entry.count > 120) return res.status(429).json({ error: 'Request limit reached' });
        next();
    });
    router.get('/capabilities', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.json({ version: 1, deviceApproval: true, sipPort: 8088,
            enrollmentPath: '/api/gateway/enrollment', ticketPath: '/api/gateway/sip-ticket' });
    });
    const tickets = createDeviceTickets({ authorize });
    router.post('/sip-ticket', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const route = await authorizeDevice(req);
            if (!route) return res.status(403).json({ error: 'Device approval required' });
            const token = req.get('Authorization').slice(7);
            const ticket = tickets.issue(route.deviceId, token);
            return ticket ? res.json({ ticket, expiresIn: 30 }) : res.status(429).json({ error: 'Ticket limit reached' });
        } catch (_) { return res.status(503).json({ error: 'Ticket unavailable' }); }
    });
    installTenantIce(router, { authorizeDevice, getRelay });
    require('./contacts-proxy').installContactsProxy(router, { authorizeDevice });
    installTenantPush(router, { store: pushStore, authorizeDevice, authorizePbx, sendToDevice, normalizeCallId });
    return {
        router, assignment, authorize, pushStore,
        attach(server) {
            return attachSipProxy(server, { authorize, consumeTicket: tickets.consume,
                isAuthorized: async (id, previous, token) => {
                    const current = await authorize(id, token);
                    return !!current && current.pbxId === previous.pbxId && current.extension === previous.extension && current.wsUrl === previous.wsUrl;
                } });
        }
    };
}

// Runtime manifest is root/operator managed, outside dashboard state. Keeping
// per-PBX TURN secrets and hook keys outside public PBX records avoids accidental
// disclosure through the admin CRUD API.
async function readPrivateRuntimeManifest(file) {
    const handle = await fs.open(file, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
    try {
        const stat = await handle.stat();
        if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error('Runtime manifest must be a private regular file');
        const manifest = JSON.parse(await handle.readFile('utf8'));
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
