'use strict';
const crypto = require('node:crypto');

// Each PBX must have its own TURN instance/port and peer ACL, not merely a
// different username on a shared relay that permits all customer PBXs.
function installTenantIce(router, { authorizeDevice, getRelay }) {
    const issued = new Map();
    router.get('/ice', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const assignment = await authorizeDevice(req);
            if (!assignment) return res.status(403).json({ error: 'Device approval required' });
            const now = Date.now();
            for (const [key, entry] of issued) if (entry.reset <= now) issued.delete(key);
            const entry = issued.get(assignment.deviceId) || { count: 0, reset: now + 60000 };
            if (++entry.count > 12) return res.status(429).json({ error: 'Relay request limit reached' });
            issued.set(assignment.deviceId, entry);
            const relay = await getRelay(assignment.pbxId);
            if (!relay || !relay.secret || !relay.host || !Number.isInteger(relay.port)) {
                return res.status(503).json({ error: 'PBX media relay is not provisioned' });
            }
            const username = `${Math.floor(Date.now() / 60000) * 60 + 900}:${assignment.pbxId}:${assignment.deviceId}`;
            res.json({ iceServers: [{
                urls: [`turn:${relay.host}:${relay.port}?transport=udp`, `turn:${relay.host}:${relay.port}?transport=tcp`],
                username, credential: crypto.createHmac('sha1', relay.secret).update(username).digest('base64')
            }] });
        } catch (_) { res.status(503).json({ error: 'Relay unavailable' }); }
    });
}
module.exports = { installTenantIce };
