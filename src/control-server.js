'use strict';
require('dotenv').config();
const express = require('express');
const { createControl } = require('./control');

async function start() {
    const isPublic = process.env.CONTROL_ALLOW_PUBLIC === 'true';
    const control = createControl({
        filePath: process.env.CONTROL_DATA_FILE,
        maxEnabledPbx: Number(process.env.CONTROL_MAX_ENABLED_PBX) || 10,
        allowPublic: isPublic
    });
    await control.init();
    const app = express();
    app.disable('x-powered-by');
    app.use('/control', control.router);
    app.get('/', (req, res) => res.redirect('/control/'));
    const tenant = process.env.TENANT_RUNTIME_FILE
        ? await require('./tenant-server').startTenantServer(control) : null;
    const port = Number(process.env.CONTROL_PORT) || 8002;
    const host = process.env.CONTROL_LISTEN_HOST || (isPublic ? '0.0.0.0' : '127.0.0.1');
    const server = app.listen(port, host, () => {
        console.log(`[control] administrative dashboard listening on ${host}:${port}`);
    });
    const stop = () => { tenant?.close(); server.close(() => { control.close(); process.exit(0); }); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
    return { control, server };
}
if (require.main === module) start().catch(error => { console.error('[control] startup failed:', error.message); process.exitCode = 1; });
module.exports = { start };
