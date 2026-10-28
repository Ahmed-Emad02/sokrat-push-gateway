'use strict';
// Run once as root. Password is read from stdin (not process arguments/logs).
const fs = require('node:fs/promises');
const { hashPassword } = require('../src/control/auth');

async function main() {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const password = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
    if (password.length < 12 || password.length > 1024) throw new Error('Use an admin password of 12–1024 characters');
    const hash = await hashPassword(password);
    const file = process.env.CONTROL_ENV_FILE || '/etc/sokrat/gateway-control.env';
    await fs.mkdir(require('node:path').dirname(file), { recursive: true, mode: 0o700 });
    const max = Number(process.env.CONTROL_MAX_ENABLED_PBX) || 5;
    if (!Number.isInteger(max) || max < 1 || max > 64) throw new Error('Invalid PBX limit');
    await fs.writeFile(file, `CONTROL_DATA_FILE=/var/lib/sokrat-gateway/control.json\nCONTROL_MAX_ENABLED_PBX=${max}\nCONTROL_ADMIN_PASSWORD_HASH=${hash}\n`, { flag: 'wx', mode: 0o600 });
    console.log('Dashboard credentials initialized; password not stored. Listener is loopback only.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
