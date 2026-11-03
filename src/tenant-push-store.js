'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { fingerprintToken } = require('./push-errors');

const TOKEN_TTL_MS = 90 * 86400000;

function tokenFreshness(row) {
    return Number(row.lastSuccessAt || row.updatedAt) || 0;
}

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
            // A new registration always clears a previous invalid-token mark.
            const registration = { ...device };
            delete registration.pushState;
            delete registration.lastError;
            delete registration.invalidAt;
            return update(async data => {
                const conflicts = data.devices.filter(d => d.deviceId !== registration.deviceId &&
                    d.pushState !== 'invalid' &&
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
                const previous = data.devices.find(d => d.deviceId === registration.deviceId);
                if (previous?.telemetry) {
                    registration.telemetry = previous.telemetry;
                    registration.telemetryAt = previous.telemetryAt;
                }
                data.devices = data.devices.filter(d => d.deviceId !== registration.deviceId && !conflicts.includes(d));
                data.devices.push(registration);
            });
        },
        /**
         * Keep a registered token with the same installation when an operator
         * re-approves it for a new PBX/extension. The token is re-bound only
         * after the control store confirms the new approved assignment.
         */
        reassign(deviceId, assignment) {
            return update(async data => {
                const row = data.devices.find(d => d.deviceId === deviceId);
                if (!row) return false;
                const current = typeof approvedAssignment === 'function'
                    ? await approvedAssignment(deviceId) : null;
                if (!current || current.pbxId !== assignment?.pbxId ||
                    current.extension !== assignment?.extension ||
                    (current.authorizationRevision || 0) !== (assignment?.authorizationRevision || 0)) {
                    throw new Error('Device approval changed');
                }
                row.pbxId = current.pbxId;
                row.extension = current.extension;
                row.deviceUuid = current.deviceUuid;
                row.authorizationRevision = current.authorizationRevision || 0;
                row.updatedAt = Date.now();
                return true;
            });
        },
        removePush(deviceId) { return update(data => { data.devices = data.devices.filter(d => d.deviceId !== deviceId); }); },
        recordMissed(record) {
            return update(data => {
                const now = Number(record.timestamp) || Date.now();
                const cutoff = now - 30 * 86400000;
                data.missedCalls = Array.isArray(data.missedCalls) ? data.missedCalls : [];
                data.missedCalls = data.missedCalls.filter(item => item && item.timestamp >= cutoff);
                if (data.missedCalls.some(item => item && item.callId === record.callId)) return;
                data.missedCalls.push({
                    pbxId: record.pbxId,
                    extension: record.extension,
                    callId: record.callId,
                    callerId: String(record.callerId || '').slice(0, 128),
                    callerName: String(record.callerName || record.callerId || '').slice(0, 256),
                    timestamp: now,
                });
                if (data.missedCalls.length > 500) {
                    data.missedCalls = data.missedCalls.slice(-500);
                }
            });
        },
        async listMissed(pbxId, extension, since = 0) {
            await tail;
            const data = await load();
            return (Array.isArray(data.missedCalls) ? data.missedCalls : [])
                .filter(item => item && item.pbxId === pbxId && item.extension === extension && item.timestamp >= since)
                .sort((a, b) => a.timestamp - b.timestamp);
        },
        /**
         * Persist a small, sanitized diagnostic snapshot from the authenticated
         * device. Raw tokens, credentials and caller data are never accepted.
         */
        recordTelemetry(deviceId, telemetry) {
            const allowed = new Set(['appVersion', 'sipState', 'gatewayState', 'appState',
                'networkConnected', 'networkType', 'activeCall', 'fcmTokenPresent',
                'fcmLastTokenAt', 'fcmLastError', 'pushRegisteredAt', 'pushLastError',
                'reportedAt']);
            if (!deviceId || !telemetry || typeof telemetry !== 'object' || Array.isArray(telemetry)) return false;
            const clean = {};
            for (const [key, value] of Object.entries(telemetry)) {
                if (!allowed.has(key) || value === null || value === undefined) continue;
                if (!['string', 'number', 'boolean'].includes(typeof value)) continue;
                clean[key] = String(value).slice(0, 256);
            }
            return update(async data => {
                let row = data.devices.find(d => d.deviceId === deviceId);
                if (!row) {
                    const assignment = typeof approvedAssignment === 'function'
                        ? await approvedAssignment(deviceId) : null;
                    if (!assignment) return false;
                    row = {
                        deviceId,
                        deviceUuid: assignment.deviceUuid,
                        pbxId: assignment.pbxId,
                        extension: assignment.extension,
                        authorizationRevision: assignment.authorizationRevision || 0,
                        updatedAt: Date.now(),
                    };
                    data.devices.push(row);
                } else if (typeof approvedAssignment === 'function' && !await isCurrent(row)) {
                    return false;
                }
                row.telemetry = clean;
                row.telemetryAt = Date.now();
                return true;
            });
        },
        /**
         * Quarantine the token that actually failed. The caller supplies the
         * fingerprint captured at dispatch time; if the device has since
         * registered a newer token, this is a no-op. This prevents a slow error
         * for token A from invalidating freshly registered token B.
         */
        markInvalid(deviceId, tokenFingerprint, code) {
            return update(data => {
                const row = data.devices.find(d => d.deviceId === deviceId);
                if (!row || !tokenFingerprint || fingerprintToken(row.token) !== tokenFingerprint) return false;
                row.pushState = 'invalid';
                row.lastError = String(code || 'invalid-token').slice(0, 96);
                row.invalidAt = Date.now();
                return true;
            });
        },
        // Optional lifecycle cleanup after retirement/reassignment. Never treat a
        // lookup failure as revocation: the mutation must fail without writing.
        pruneInvalidPush() {
            return update(async data => {
                if (typeof approvedAssignment !== 'function') throw new Error('Device approval lookup unavailable');
                const current = await Promise.all(data.devices.map(isCurrent));
                const removed = data.devices.filter((row, index) =>
                    !current[index] || row.pushState === 'invalid').length;
                data.devices = data.devices.filter((row, index) =>
                    current[index] && row.pushState !== 'invalid');
                return removed;
            });
        },
        /**
         * Record a successful provider send. The delivery timestamp is the
         * authoritative freshness signal for TTL cleanup; registration time is
         * only a fallback for tokens that have never delivered.
         */
        markDelivered(deviceId, tokenFingerprint) {
            return update(data => {
                const row = data.devices.find(d => d.deviceId === deviceId);
                if (!row || !tokenFingerprint || fingerprintToken(row.token) !== tokenFingerprint) return false;
                row.lastSuccessAt = Date.now();
                return true;
            });
        },
        /**
         * Drop registrations whose token has exceeded the delivery TTL. The
         * 90-day filter in listPush/listAllPush prevents delivery but leaving
         * the rows behind kept stale devices visible in the dashboard forever.
         * This is a hard cleanup: a device must register again after expiry.
         */
        pruneExpiredPush(now = Date.now()) {
            return update(data => {
                const cutoff = now - TOKEN_TTL_MS;
                const before = data.devices.length;
                data.devices = data.devices.filter(row => tokenFreshness(row) > cutoff);
                return before - data.devices.length;
            });
        },
        async listPush(pbxId, extension) {
            await tail;
            const data = await load();
            const candidates = data.devices.filter(d => d.pbxId === pbxId && d.extension === extension &&
                d.pushState !== 'invalid' && tokenFreshness(d) > Date.now() - TOKEN_TTL_MS);
            const current = await Promise.all(candidates.map(isCurrent));
            return candidates.filter((_, index) => current[index]);
        },
        async listAllPush() {
            await tail;
            const data = await load();
            const candidates = data.devices.filter(d => d.pushState !== 'invalid' &&
                d.updatedAt > Date.now() - 90 * 86400000);
            const current = await Promise.all(candidates.map(isCurrent));
            return candidates.filter((_, index) => current[index]);
        }
    };
}
module.exports = { createTenantPushStore, TOKEN_TTL_MS };
