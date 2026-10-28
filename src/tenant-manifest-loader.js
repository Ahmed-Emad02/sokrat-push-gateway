'use strict';
const { readPrivateRuntimeManifest } = require('./tenant-runtime');

const RELAY_ID = /^[A-Za-z0-9_-]{1,80}$/;
const HOOK_HASH = /^[a-f0-9]{64}$/;

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value);
}

// readPrivateRuntimeManifest already enforces the relay schema. Hook hashes are
// optional but must be strict when present: a malformed hash must not silently
// disable (or weaken) PBX webhook authentication.
function validateManifest(manifest) {
    if (!isPlainObject(manifest) || !isPlainObject(manifest.relays)) throw new Error('Invalid runtime manifest');
    if (manifest.hookHashes !== undefined) {
        if (!isPlainObject(manifest.hookHashes)) throw new Error('Invalid runtime hook hashes');
        for (const [id, hash] of Object.entries(manifest.hookHashes)) {
            if (!RELAY_ID.test(id) || typeof hash !== 'string' || !HOOK_HASH.test(hash)) {
                throw new Error('Invalid runtime hook hash');
            }
        }
    }
    return manifest;
}

// The runtime manifest is replaced atomically by the provisioner. Authorizations
// must reflect the file on disk, so lookups read it every time by default: a
// stale manifest would otherwise keep issuing relay credentials or accepting a
// rotated PBX hook key. Concurrent lookups wait for an already open read and then
// read again, so a replacement that lands mid-read is still observed by new
// lookups while concurrent file descriptors stay bounded. The last good copy is
// kept for diagnostics only and is never used to authorize.
function createTenantManifestLoader(file, options = {}) {
    const readManifest = options.readManifest || readPrivateRuntimeManifest;
    let cached = null;
    let inFlight = null;
    const stats = { reads: 0, coalesced: 0, reloads: 0, failures: 0, lastLoadedAt: null, lastError: null };

    async function readFresh() {
        if (typeof file !== 'string' || !file) throw new Error('Tenant runtime manifest file is not configured');
        const manifest = validateManifest(await readManifest(file));
        cached = { manifest, loadedAt: Date.now() };
        stats.reloads += 1;
        stats.lastLoadedAt = cached.loadedAt;
        stats.lastError = null;
        return manifest;
    }

    function startRead() {
        stats.reads += 1;
        const promise = readFresh().catch(error => {
            stats.failures += 1;
            stats.lastError = error && error.message ? error.message : String(error);
            throw error;
        });
        inFlight = promise;
        const clear = () => { if (inFlight === promise) inFlight = null; };
        promise.then(clear, clear);
        return promise;
    }

    // Startup still requires a valid manifest; failures reject startTenantServer.
    function load() {
        return startRead();
    }

    // Fresh validated manifest. Rejects when the file is missing, unreadable,
    // non-private or malformed; callers must fail closed rather than reuse the
    // last good copy.
    async function getManifest() {
        if (inFlight) {
            stats.coalesced += 1;
            // Never return a read that was already open when this lookup arrived:
            // the file may have been replaced while it was in flight. Wait for it
            // to settle, then read again; a newer shared read already started
            // after this lookup may be reused.
            try { await inFlight; } catch (_) { /* the re-read decides the outcome */ }
            if (inFlight) return inFlight;
        }
        return startRead();
    }

    // Fail closed: no relay entry (and therefore no TURN credential) on any
    // manifest error, rather than falling back to a previously valid entry.
    async function getRelay(id) {
        if (typeof id !== 'string' || !RELAY_ID.test(id)) return null;
        try {
            const manifest = await getManifest();
            const relay = Object.hasOwn(manifest.relays, id) ? manifest.relays[id] : null;
            if (!relay || !Array.isArray(relay.peerIps)) return null;
            return { ...relay, peerIps: relay.peerIps.slice() };
        } catch (_) { return null; }
    }

    // Fail closed: no credential hash on any manifest error, so PBX hook requests
    // are rejected instead of being validated against a rotated-away key.
    async function getHookHash(id) {
        if (typeof id !== 'string' || !RELAY_ID.test(id)) return undefined;
        try {
            const manifest = await getManifest();
            const hash = manifest.hookHashes && Object.hasOwn(manifest.hookHashes, id) ? manifest.hookHashes[id] : undefined;
            return typeof hash === 'string' && HOOK_HASH.test(hash) ? hash : undefined;
        } catch (_) { return undefined; }
    }

    // Diagnostics only. Never authorize from this snapshot.
    function peek() {
        return cached ? cached.manifest : null;
    }

    function getStats() {
        return { ...stats };
    }

    return { load, getManifest, getRelay, getHookHash, peek, getStats };
}

module.exports = { createTenantManifestLoader, validateManifest };
