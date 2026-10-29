'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

function createTenantPushStore(file, approvedAssignment) {
    let tail = Promise.resolve();
    function matchesAssignment(device, assignment) {
        return !!assignment && ['deviceId', 'deviceUuid', 'pbxId', 'extension'].every(key =>
            typeof device[key] === 'string' && device[key] && assignment[key] === device[key]) &&
            (device.authorizationRevision || 0) === (assignment.authorizationRevision || 0);
    }
    async function isCurrent(device) {
        return typeof approvedAssignment === 'function' && matchesAssignment(device, await approvedAssignment(device.deviceId));
    }
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
            const result = await fn(data);
            await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
            await fs.chmod(path.dirname(file), 0o700);
            const temporary = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
            const handle = await fs.open(temporary, 'wx', 0o600);
            try { await handle.writeFile(JSON.stringify(data)); await handle.sync(); }
            finally { await handle.close(); }
            await fs.rename(temporary, file);
            const dir = await fs.open(path.dirname(file), 'r');
            try { await dir.sync(); } finally { await dir.close(); }
            return result;
        });
        tail = task.catch(() => {});
        return task;
    }
    return {
        approvedAssignment,
        savePush(device) {
            // Keep the authenticated registration fixed while queued/awaiting approval.
            const registration = { ...device };
            return update(async data => {
                const conflicts = data.devices.filter(d => d.deviceId !== registration.deviceId &&
                    (d.token === registration.token || (registration.voipToken && d.voipToken === registration.voipToken)));
                const conflict = () => {
                    const error = new Error('Push token already belongs to another device');
                    error.status = 409; throw error;
                };
                for (const previous of conflicts) {
                    // A UUID alone is not authority: only retire an unapproved owner
                    // of this same installation, never an active device in any tenant.
                    if (!registration.deviceUuid || previous.deviceUuid !== registration.deviceUuid ||
                        typeof approvedAssignment !== 'function' || await approvedAssignment(previous.deviceId)) conflict();
                }
                // Authorization at the HTTP boundary can go stale while this write
                // waits in the queue or looks up an old owner. Check it again here.
                if (!await isCurrent(registration)) {
                    throw new Error('Device approval changed');
                }
                data.devices = data.devices.filter(d => d.deviceId !== registration.deviceId && !conflicts.includes(d));
                data.devices.push(registration);
            });
        },
        removePush(deviceId) { return update(data => { data.devices = data.devices.filter(d => d.deviceId !== deviceId); }); },
        // Optional lifecycle cleanup after retirement/reassignment. Never treat a
        // lookup failure as revocation: the mutation must fail without writing.
        pruneInvalidPush() {
            return update(async data => {
                if (typeof approvedAssignment !== 'function') throw new Error('Device approval lookup unavailable');
                const current = await Promise.all(data.devices.map(isCurrent));
                const removed = current.filter(valid => !valid).length;
                data.devices = data.devices.filter((_, index) => current[index]);
                return removed;
            });
        },
        async listPush(pbxId, extension) {
            await tail;
            const data = await load();
            const candidates = data.devices.filter(d => d.pbxId === pbxId && d.extension === extension && d.updatedAt > Date.now() - 90 * 86400000);
            const current = await Promise.all(candidates.map(isCurrent));
            return candidates.filter((_, index) => current[index]);
        }
    };
}
module.exports = { createTenantPushStore };
