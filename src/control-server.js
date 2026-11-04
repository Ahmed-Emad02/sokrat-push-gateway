'use strict';
require('dotenv').config();
const express = require('express');
const { createControl } = require('./control');
const { readHostFirewall } = require('./control/host-firewall');
const { createSystemMetrics } = require('./system-metrics');


function createLegacyPushLookup() {
    let pool = null;
    let cachedAt = 0;
    let cached = [];
    return async function getLegacyPushRows() {
        if (Date.now() - cachedAt < 5000) return cached;
        if (!process.env.DB_HOST || !process.env.DB_NAME) return [];
        try {
            const mysql = require('mysql2/promise');
            pool ||= mysql.createPool({
                host: process.env.DB_HOST,
                port: Number(process.env.DB_PORT) || 3306,
                user: process.env.DB_USER || 'root',
                password: process.env.DB_PASS !== undefined ? process.env.DB_PASS : '',
                database: process.env.DB_NAME,
                connectionLimit: 2,
                waitForConnections: true,
            });
            const [rows] = await pool.query(
                'SELECT extension, platform, device_uuid, app_version, last_push_error, updated_at FROM mobile_devices'
            );
            cached = rows.map((row) => ({
                extension: row.extension,
                platform: row.platform,
                deviceUuid: row.device_uuid,
                appVersion: row.app_version,
                lastError: row.last_push_error,
                updatedAt: row.updated_at,
            }));
            cachedAt = Date.now();
            return cached;
        } catch (error) {
            console.warn('[control] legacy push lookup failed:', error.message);
            return cached;
        }
    };
}

async function start() {
    let tenant = null;
    let metrics = null;
    const isPublic = process.env.CONTROL_ALLOW_PUBLIC === 'true';
    const control = createControl({
        filePath: process.env.CONTROL_DATA_FILE,
        maxEnabledPbx: Number(process.env.CONTROL_MAX_ENABLED_PBX) || 10,
        allowPublic: isPublic,
        getActiveCalls: () => tenant?.runtime?.getActiveCalls?.() || [],
        getMetrics: () => metrics?.snapshot?.() || null,
        getHostFirewall: () => readHostFirewall(),
        getLegacyPushRows: createLegacyPushLookup(),
        onDeviceApproved: async (device) => {
            const pushStore = tenant?.runtime?.pushStore;
            if (pushStore && typeof pushStore.reassign === 'function') {
                await pushStore.reassign(device.id, device);
            }
        }
    });
    await control.init();
    const app = express();
    app.disable('x-powered-by');
    app.use('/control', control.router);
    app.post('/api/tunnel/register', control.router);
    app.post('/api/gateway/tunnel/register', control.router);
    app.get('/', (req, res) => res.redirect('/control/'));
    tenant = process.env.TENANT_RUNTIME_FILE
        ? await require('./tenant-server').startTenantServer(control) : null;
    metrics = createSystemMetrics({
        getNetwork: () => tenant?.runtime?.getNetworkStats?.() || { inBytes: 0, outBytes: 0, byPbx: [] },
        getActiveCalls: () => tenant?.runtime?.getActiveCalls?.() || [],
    });
    metrics.start();
    const port = Number(process.env.CONTROL_PORT) || 8002;
    const host = process.env.CONTROL_LISTEN_HOST || (isPublic ? '0.0.0.0' : '127.0.0.1');
    const server = app.listen(port, host, () => {
        console.log(`[control] administrative dashboard listening on ${host}:${port}`);
    });
    const stop = () => { metrics?.stop(); tenant?.close(); server.close(() => { control.close(); process.exit(0); }); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
    return { control, server };
}
if (require.main === module) start().catch(error => { console.error('[control] startup failed:', error.message); process.exitCode = 1; });
module.exports = { start };
