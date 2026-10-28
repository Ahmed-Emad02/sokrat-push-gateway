'use strict';
require('dotenv').config();
const express = require('express');
const { createControl } = require('./control');

async function start() {
    const control = createControl({ filePath: process.env.CONTROL_DATA_FILE,
        maxEnabledPbx: Number(process.env.CONTROL_MAX_ENABLED_PBX) || 5 });
    await control.init();
    const app = express();
    app.disable('x-powered-by');
    app.use('/control', control.router);
    app.get('/', (req, res) => res.redirect('/control/'));
    const tenant = process.env.TENANT_RUNTIME_FILE
        ? await require('./tenant-server').startTenantServer(control) : null;
    // Admin remains reachable only through an SSH tunnel. Never bind this
    // bootstrap administrative listener to a public interface over HTTP.
    const server = app.listen(Number(process.env.CONTROL_PORT) || 9096, '127.0.0.1', () => {
        console.log('[control] administrative dashboard listening on loopback');
    });
    const stop = () => { tenant?.close(); server.close(() => { control.close(); process.exit(0); }); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
    return { control, server };
}
if (require.main === module) start().catch(error => { console.error('[control] startup failed:', error.message); process.exitCode = 1; });
module.exports = { start };
