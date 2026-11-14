'use strict';

const fs = require('node:fs/promises');
const http = require('node:http');
const https = require('node:https');

const CONFIG_PATH = '/etc/sokrat/wg-admission.json';
const MAX_RESPONSE_BYTES = 64 * 1024;

async function admissionToken() {
    let raw;
    try {
        raw = await fs.readFile(CONFIG_PATH, 'utf8');
    } catch {
        throw new Error('WireGuard admission config is unavailable');
    }
    let config;
    try {
        config = JSON.parse(raw);
    } catch {
        throw new Error('WireGuard admission config is invalid');
    }
    if (!config || typeof config.token !== 'string' || !/^[a-f0-9]{64}$/.test(config.token)) {
        throw new Error('WireGuard admission config is invalid');
    }
    return config.token;
}

function request(url, body, token, pbxId) {
    return new Promise((resolve, reject) => {
        const transport = url.protocol === 'https:' ? https : http;
        const payload = Buffer.from(JSON.stringify(body));
        const req = transport.request(url, {
            method: 'POST',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                'Content-Length': payload.length,
                Authorization: `Bearer ${token}`,
                'X-Sokrat-Pbx': pbxId
            },
            timeout: 8000
        }, (response) => {
            const chunks = [];
            let size = 0;
            response.on('data', (chunk) => {
                size += chunk.length;
                if (size > MAX_RESPONSE_BYTES) {
                    response.destroy(new Error('WireGuard admission response is too large'));
                    return;
                }
                chunks.push(chunk);
            });
            response.on('end', () => {
                if (response.statusCode !== 200) {
                    reject(new Error(`WireGuard admission returned HTTP ${response.statusCode}`));
                    return;
                }
                try {
                    resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
                } catch {
                    reject(new Error('WireGuard admission returned invalid JSON'));
                }
            });
        });
        req.on('timeout', () => req.destroy(new Error('WireGuard admission timed out')));
        req.on('error', reject);
        req.end(payload);
    });
}

/**
 * Send the complete desired peer state for one PBX. The PBX applies only these
 * managed peers and preserves its other WireGuard peers.
 */
async function syncVpnPeers(pbx, peers) {
    if (!pbx || !pbx.vpn || pbx.vpn.enabled !== true) return { skipped: true };
    if (!pbx.apiURL) throw new Error('PBX API URL is unavailable');
    const base = pbx.apiURL.endsWith('/') ? pbx.apiURL : `${pbx.apiURL}/`;
    const url = new URL('api/gateway/wg/apply', base);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' &&
        ['127.0.0.1', '[::1]'].includes(url.hostname))) {
        throw new Error('VPN admission requires HTTPS or literal loopback HTTP');
    }
    const token = await admissionToken();
    const normalized = (Array.isArray(peers) ? peers : []).map(peer => ({
        deviceId: String(peer.deviceId || '').slice(0, 64),
        publicKey: String(peer.publicKey || ''),
        address: String(peer.address || '')
    }));
    return request(url, { peers: normalized }, token, pbx.id);
}

module.exports = { syncVpnPeers };
