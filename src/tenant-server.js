'use strict';
const express = require('express');
const http = require('node:http');
const fs = require('node:fs/promises');
const { createTenantRuntime, readPrivateRuntimeManifest } = require('./tenant-runtime');
const { createPbxAuthorizer } = require('./tenant-hook-auth');
const { createEnrollmentRouter } = require('./control');

async function startTenantServer(control, env = process.env) {
    const manifest = await readPrivateRuntimeManifest(env.TENANT_RUNTIME_FILE);
    const providers = require('./index');
    await providers.initializePush();
    const getRelay = async id => {
        const relay = manifest.relays[id];
        const pbx = control.store.getPbx(id);
        if (!relay || !pbx?.enabled || !Array.isArray(relay.peerIps) || !Array.isArray(pbx.mediaIps)) return null;
        // Changing PBX media peers requires relay re-provisioning first.
        if (relay.peerIps.slice().sort().join(',') !== pbx.mediaIps.slice().sort().join(',')) return null;
        const handle = await fs.open(relay.secretFile, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
        let secret;
        try {
            const stat = await handle.stat();
            if (!stat.isFile() || (stat.mode & 0o077) !== 0) throw new Error('Relay secret permissions are not private');
            secret = (await handle.readFile('utf8')).trim();
        } finally { await handle.close(); }
        if (!/^[a-f0-9]{64}$/.test(secret)) return null;
        return { ...relay, secret };
    };
    const runtime = createTenantRuntime({ control,
        pushFile: env.TENANT_PUSH_FILE || '/var/lib/sokrat-gateway/push.json',
        getRelay, authorizePbx: createPbxAuthorizer(control, async id => manifest.hookHashes?.[id]),
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
module.exports = { startTenantServer };
