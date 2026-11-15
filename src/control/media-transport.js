'use strict';

/**
 * Read-only view of each tenant's persisted media transport.
 *
 * The enrollment registry is the authority: a row with a `plain-udp` or
 * `direct-udp` transport carries call media as datagrams straight from the
 * PBX, while a row without a transport still relays media over the legacy FRP
 * TCP proxy. The file is small, so it is cached by mtime and never written.
 */

const REGISTRY_FILE = process.env.TUNNEL_ENROLLMENT_REGISTRY
    || '/etc/sokrat/tunnel-enrollment/installations.json';

function parseRegistry(text) {
    const rows = JSON.parse(text);
    const byPbx = new Map();
    for (const row of Object.values(rows || {})) {
        if (!row || typeof row.pbxId !== 'string') continue;
        const transport = row.mediaTransport;
        if (!transport || typeof transport !== 'object') {
            byPbx.set(row.pbxId, { media: 'tcp', port: null, mode: 'legacy-tcp' });
            continue;
        }
        const mode = String(transport.mode || '');
        const udp = mode === 'plain-udp' || mode === 'direct-udp';
        byPbx.set(row.pbxId, {
            media: udp ? 'udp' : 'tcp',
            port: Number.isInteger(transport.port) ? transport.port : null,
            mode: mode || null
        });
    }
    return byPbx;
}

function createMediaTransportReader({ file = REGISTRY_FILE, statSync, readFileSync } = {}) {
    const stat = statSync || require('node:fs').statSync;
    const read = readFileSync || require('node:fs').readFileSync;
    let cache = { mtimeMs: -1, byPbx: new Map() };

    function load() {
        let info;
        try {
            info = stat(file);
        } catch {
            return new Map();
        }
        if (info.mtimeMs === cache.mtimeMs) return cache.byPbx;
        let byPbx;
        try {
            byPbx = parseRegistry(read(file, 'utf8'));
        } catch {
            return cache.byPbx;
        }
        cache = { mtimeMs: info.mtimeMs, byPbx };
        return byPbx;
    }

    return {
        lookup(pbxId) {
            return load().get(String(pbxId)) || { media: 'unknown', port: null, mode: null };
        }
    };
}

module.exports = { createMediaTransportReader, parseRegistry, REGISTRY_FILE };
