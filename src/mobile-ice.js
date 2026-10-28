'use strict';
const crypto = require('node:crypto');

// Authenticate with the PBX's existing SIP-password HMAC verifier. No SIP
// passwords or TURN master secret are sent to clients or stored here.
module.exports = function installMobileIce(app) {
    app.get('/api/mobile/ice', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        const secret = process.env.TURN_SHARED_SECRET;
        const publicHost = process.env.TURN_PUBLIC_HOST;
        const pbx = process.env.PBX_AUTH_URL;
        if (!secret || !publicHost || !pbx) return res.status(503).json({ error: 'Relay not configured' });
        const headers = {};
        for (const name of ['X-Sokrat-Extension', 'X-Sokrat-Timestamp', 'X-Sokrat-Signature']) {
            const value = req.get(name);
            if (!value || value.length > 256) return res.status(401).json({ error: 'Extension authentication required' });
            headers[name] = value;
        }
        try {
            const auth = await fetch(`${pbx}/api/extension/v1/whoami`, {
                headers, signal: AbortSignal.timeout(5000), redirect: 'error'
            });
            if (!auth.ok) return res.status(auth.status === 429 ? 429 : 401).json({ error: 'Extension authentication failed' });
            const identity = await auth.json();
            if (!identity.success || identity.extension !== headers['X-Sokrat-Extension']) {
                return res.status(401).json({ error: 'Invalid identity' });
            }
            const username = `${Math.floor(Date.now() / 1000) + 3600}:${identity.extension}`;
            const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');
            return res.json({ iceServers: [{
                urls: [`turn:${publicHost}:3478?transport=udp`, `turn:${publicHost}:3478?transport=tcp`],
                username, credential
            }] });
        } catch (error) {
            console.error('[mobile-ice] authentication service unavailable:', error.message);
            return res.status(503).json({ error: 'Relay authentication unavailable' });
        }
    });
};
