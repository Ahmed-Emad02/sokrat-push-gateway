'use strict';
const crypto = require('node:crypto');
// In-memory one-use upgrade tickets avoid permanent credentials in WS URLs.
// Restart discards outstanding tickets; the device can request a new one.
function createDeviceTickets({ authorize, now = Date.now }) {
    const tickets = new Map();
    const bucket = new Map();
    function prune() {
        const time = now();
        for (const [id, entry] of tickets) if (entry.expires <= time) tickets.delete(id);
        for (const [id, entry] of bucket) if (entry.reset <= time) bucket.delete(id);
    }
    return {
        issue(deviceId, token, route) {
            prune();
            if (tickets.size >= 10000) return null;
            const limits = bucket.get(deviceId) || { count: 0, reset: now() + 60000 };
            if (++limits.count > 12) return null;
            bucket.set(deviceId, limits);
            const ticket = crypto.randomBytes(32).toString('base64url');
            tickets.set(ticket, { deviceId, token, route: route ? structuredClone(route) : null, expires: now() + 30000 });
            return ticket;
        },
        async consume(ticket) {
            prune();
            const entry = tickets.get(ticket);
            tickets.delete(ticket);
            if (!entry || entry.expires <= now()) return null;
            const route = await authorize(entry.deviceId, entry.token);
            // A ticket authorizes the assignment reviewed at issuance, not a
            // later tenant/extension or a newly approved incarnation of it.
            if (entry.route && (!route || ['pbxId', 'extension', 'wsUrl', 'apiUrl', 'authorizationRevision']
                .some(key => route[key] !== entry.route[key]))) return null;
            return route ? { route, deviceId: entry.deviceId, token: entry.token } : null;
        }
    };
}
module.exports = { createDeviceTickets };
