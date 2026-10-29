'use strict';
const express = require('express');
const http = require('node:http');
const fs = require('node:fs/promises');
const { createTenantRuntime } = require('./tenant-runtime');
const { createTenantManifestLoader } = require('./tenant-manifest-loader');
const { createPbxAuthorizer } = require('./tenant-hook-auth');
const { createEnrollmentRouter } = require('./control');

// Relay lookups are intentionally per request: the provisioner may atomically
// replace the runtime manifest, and serving a stale relay would issue TURN
// credentials for a peer set that is no longer provisioned.
function createRelayResolver(control, manifestLoader) {
    return async id => {
        const relay = await manifestLoader.getRelay(id);
        const pbx = control.store.getPbx(id);
        if (!relay || !pbx?.enabled || !Array.isArray(relay.peerIps) || !Array.isArray(pbx.mediaIps)) return null;
        // Changing PBX media peers requires relay re-provisioning first.
        if (relay.peerIps.slice().sort().join(',') !== pbx.mediaIps.slice().sort().join(',')) return null;
        const handle = await fs.open(relay.secretFile, require('node:fs').constants.O_RDONLY |
            require('node:fs').constants.O_NOFOLLOW | require('node:fs').constants.O_NONBLOCK);
        let secret;
        try {
            const stat = await handle.stat();
            if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error('Relay secret permissions are not private');
            if (stat.size > 128) throw new Error('Relay secret is too large');
            secret = (await handle.readFile('utf8')).trim();
        } finally { await handle.close(); }
        if (!/^[a-f0-9]{64}$/.test(secret)) return null;
        return { ...relay, secret };
    };
}

async function startTenantServer(control, env = process.env) {
    // Startup requires a valid manifest, but the provisioner may atomically
    // replace it later. Relay and hook-key lookups then read the current file, so
    // a replacement takes effect for new requests without restarting the server
    // or dropping established SIP sockets.
    const manifestLoader = createTenantManifestLoader(env.TENANT_RUNTIME_FILE);
    await manifestLoader.load();
    const providers = require('./index');
    await providers.initializePush();
    const getRelay = createRelayResolver(control, manifestLoader);
    const runtime = createTenantRuntime({ control,
        pushFile: env.TENANT_PUSH_FILE || '/var/lib/sokrat-gateway/push.json',
        getRelay, authorizePbx: createPbxAuthorizer(control, id => manifestLoader.getHookHash(id)),
        normalizeCallId: providers.normalizeCallId,
        sendToDevice: async (device, payload) => (await providers.buildCtx()).sendToDevice(device, payload)
    });
    const app = express();
    app.disable('x-powered-by');
    app.use((req, res, next) => {
        res.set('Cache-Control', 'no-store');
        res.set('X-Content-Type-Options', 'nosniff');
        next();
    });
    // The listener is loopback-only; nginx must overwrite X-Forwarded-For
    // rather than append untrusted client headers. Admin proxy trust is separate.
    app.use('/api/gateway/enrollment', createEnrollmentRouter({ store: control.store, trustProxy: true }));
    app.post('/api/gateway/tunnel/register', control.router);
    app.use('/api/gateway', runtime.router);
    app.use((error, req, res, next) => {
        if (res.headersSent) return next(error);
        return res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: 'Invalid gateway request' });
    });
    const server = http.createServer(app);
    server.maxConnections = 1200;
    server.headersTimeout = 10000;
    const proxy = runtime.attach(server);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(Number(env.TENANT_PORT) || 9097, '127.0.0.1', resolve);
    });
    console.log('[tenant] gateway runtime listening on loopback');
    return { server, runtime, close() { proxy.close(); server.close(); } };
}
module.exports = { startTenantServer, createRelayResolver };
