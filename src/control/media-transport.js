'use strict';

/**
 * Read-only view of each tenant's media transport for the dashboard.
 *
 * The enrollment registry is the authority but stays 0600 root:root — the
 * enrollment broker refuses a looser file, so the dashboard (which runs as
 * `sokrat-push`) cannot read it. Root-side enrollment code therefore publishes
 * this non-secret projection: pbxId -> { mode, port }. The registry remains a
 * fallback for privileged callers and tests.
 */

const PROJECTION_FILE = process.env.MEDIA_TRANSPORT_PROJECTION
    || '/var/lib/sokrat-gateway/media-transport.json';
const REGISTRY_FILE = process.env.TUNNEL_ENROLLMENT_REGISTRY
    || '/etc/sokrat/tunnel-enrollment/installations.json';

function describe(mode, port) {
    const udp = mode === 'plain-udp' || mode === 'direct-udp';
    return {
        media: udp ? 'udp' : 'tcp',
        port: Number.isInteger(port) ? port : null,
        mode: mode || null
    };
}

/** pbxId -> { mode, port } as written by the root-side enrollment scripts. */
function parseProjection(text) {
    const rows = JSON.parse(text);
    const byPbx = new Map();
    for (const [pbxId, value] of Object.entries(rows || {})) {
        if (!value || typeof value !== 'object') continue;
        byPbx.set(pbxId, describe(value.mode, value.port));
    }
    return byPbx;
}

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
        byPbx.set(row.pbxId, describe(transport.mode, transport.port));
    }
    return byPbx;
}

function readCached(file, parse, stat, read) {
    let cache = { mtimeMs: -1, byPbx: null };
    return function load() {
        let info;
        try {
            info = stat(file);
        } catch {
            return cache.byPbx || new Map();
        }
        if (info.mtimeMs === cache.mtimeMs && cache.byPbx) return cache.byPbx;
        try {
            cache = { mtimeMs: info.mtimeMs, byPbx: parse(read(file, 'utf8')) };
        } catch {
            // Keep the last good projection rather than flapping to unknown.
        }
        return cache.byPbx || new Map();
    };
}

function createMediaTransportReader(options = {}) {
    const stat = options.statSync || require('node:fs').statSync;
    const read = options.readFileSync || require('node:fs').readFileSync;
    const loadProjection = readCached(options.file || PROJECTION_FILE, parseProjection, stat, read);
    const loadRegistry = readCached(options.fallbackFile || REGISTRY_FILE, parseRegistry, stat, read);

    return {
        lookup(pbxId) {
            const projection = loadProjection();
            if (projection.has(String(pbxId))) return projection.get(String(pbxId));
            const registry = loadRegistry();
            return registry.get(String(pbxId)) || { media: 'unknown', port: null, mode: null };
        }
    };
}

module.exports = {
    createMediaTransportReader,
    parseProjection,
    parseRegistry,
    PROJECTION_FILE,
    REGISTRY_FILE
};
