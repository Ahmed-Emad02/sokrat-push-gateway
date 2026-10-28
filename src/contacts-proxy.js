'use strict';

// Only the address-book GET is forwarded. The target is operator-controlled,
// never taken from request input; the PBX still verifies the SIP-password HMAC.
function installContactsProxy(router, { authorizeDevice, pbxBase, fetcher = fetch } = {}) {
    router.get(authorizeDevice ? '/contacts' : '/api/extension/v1/contacts', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const route = authorizeDevice ? await authorizeDevice(req) : null;
            if (authorizeDevice && !route) return res.status(403).json({ error: 'Device approval required' });
            const base = route ? route.apiUrl : (pbxBase || process.env.PBX_AUTH_URL);
            if (!base) return res.status(503).json({ error: 'Contacts unavailable' });
            const headers = { Accept: 'application/json' };
            for (const name of ['X-Sokrat-Extension', 'X-Sokrat-Timestamp', 'X-Sokrat-Signature']) {
                const value = req.get(name);
                if (!value || value.length > 256) return res.status(401).json({ error: 'Extension authentication required' });
                headers[name] = value;
            }
            if (route && headers['X-Sokrat-Extension'] !== route.extension) {
                return res.status(403).json({ error: 'Extension does not belong to device' });
            }
            const query = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
            const response = await fetcher(base.replace(/\/+$/, '') + '/api/extension/v1/contacts' + query, {
                headers, signal: AbortSignal.timeout(5000), redirect: 'error'
            });
            if (!response.ok) return res.status([401, 403, 429].includes(response.status) ? response.status : 503).json({ error: 'Contacts unavailable' });
            const data = await response.json();
            return res.json({ contacts: Array.isArray(data.contacts) ? data.contacts : [] });
        } catch (_) {
            return res.status(503).json({ error: 'Contacts unavailable' });
        }
    });
}

module.exports = { installContactsProxy };
