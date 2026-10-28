'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

function createTenantPushStore(file, approvedAssignment) {
    let tail = Promise.resolve();
    async function load() {
        try {
            const entry = await fs.lstat(file);
            if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('Push registry must be a regular file');
            const stat = await fs.stat(file);
            if ((stat.mode & 0o077) !== 0) throw new Error('Push registry permissions must be private');
            if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('Push registry ownership mismatch');
            const data = JSON.parse(await fs.readFile(file, 'utf8'));
            if (data.version !== 1 || !Array.isArray(data.devices)) throw new Error('Invalid push registry');
            return data;
        } catch (err) {
            if (err.code === 'ENOENT') return { version: 1, devices: [] };
            throw err;
        }
    }
    function update(fn) {
        const task = tail.then(async () => {
            const data = await load();
            fn(data);
            await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
            await fs.chmod(path.dirname(file), 0o700);
            const temporary = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
            const handle = await fs.open(temporary, 'wx', 0o600);
            try { await handle.writeFile(JSON.stringify(data)); await handle.sync(); }
            finally { await handle.close(); }
            await fs.rename(temporary, file);
            const dir = await fs.open(path.dirname(file), 'r');
            try { await dir.sync(); } finally { await dir.close(); }
        });
        tail = task.catch(() => {});
        return task;
    }
    return {
        approvedAssignment,
        savePush(device) {
            return update(data => {
                if (data.devices.some(d => d.deviceId !== device.deviceId &&
                    (d.token === device.token || (device.voipToken && d.voipToken === device.voipToken)))) {
                    const error = new Error('Push token already belongs to another device');
                    error.status = 409; throw error;
                }
                data.devices = data.devices.filter(d => d.deviceId !== device.deviceId);
                data.devices.push(device);
            });
        },
        removePush(deviceId) { return update(data => { data.devices = data.devices.filter(d => d.deviceId !== deviceId); }); },
        async listPush(pbxId, extension) {
            await tail;
            const data = await load();
            return data.devices.filter(d => d.pbxId === pbxId && d.extension === extension && d.updatedAt > Date.now() - 90 * 86400000);
        }
    };
}
module.exports = { createTenantPushStore };
