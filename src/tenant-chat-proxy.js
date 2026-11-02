'use strict';

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

const MAX_BODY = 50 * 1024 * 1024;
const PREFIX = '/api/extension-chat/v1';

function removeHopHeaders(headers) {
    const copy = { ...headers };
    for (const name of ['host', 'connection', 'keep-alive', 'transfer-encoding',
        'upgrade', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer',
        'authorization', 'x-sokrat-device']) delete copy[name];
    return copy;
}

/**
 * Stream the authenticated mobile chat request to the assigned PBX API.
 * The PBX still verifies its HMAC signature; the gateway only proves that
 * this device is approved and bound to the same extension/PBX.
 */
function createChatProxy({ authorizeDevice }) {
    return async function chatProxy(req, res) {
        try {
            const assignment = await authorizeDevice(req);
            if (!assignment) return res.status(403).json({ error: 'Device approval required' });
            const extension = String(req.get('X-Sokrat-Extension') || '').trim();
            if (!extension || extension !== assignment.extension) {
                return res.status(403).json({ error: 'Extension does not match approval' });
            }
            const declared = Number(req.get('Content-Length') || 0);
            if (declared > MAX_BODY) return res.status(413).json({ error: 'File too large' });
            if (!req.originalUrl.startsWith(PREFIX)) return res.status(404).json({ error: 'Not found' });

            const upstream = new URL(assignment.apiUrl);
            const basePath = upstream.pathname.replace(/\/+$/, '');
            const targetPath = `${basePath}${req.originalUrl}`;
            const transport = upstream.protocol === 'https:' ? https : http;
            const options = {
                hostname: upstream.hostname,
                port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
                path: targetPath,
                method: req.method,
                headers: {
                    ...removeHopHeaders(req.headers),
                    host: upstream.host,
                },
            };
            const proxy = transport.request(options, (pbxResponse) => {
                res.status(pbxResponse.statusCode || 502);
                for (const [name, value] of Object.entries(pbxResponse.headers)) {
                    if (value !== undefined && !['connection', 'transfer-encoding', 'keep-alive'].includes(name)) {
                        res.setHeader(name, value);
                    }
                }
                pbxResponse.pipe(res);
            });
            proxy.setTimeout(300000, () => proxy.destroy(new Error('chat proxy timeout')));
            proxy.on('error', () => {
                if (!res.headersSent) res.status(502).json({ error: 'PBX chat unavailable' });
                else res.destroy();
            });
            req.on('aborted', () => proxy.destroy());
            req.pipe(proxy);
        } catch (_) {
            if (!res.headersSent) res.status(503).json({ error: 'Chat proxy unavailable' });
        }
    };
}

module.exports = { createChatProxy, MAX_BODY, PREFIX };
