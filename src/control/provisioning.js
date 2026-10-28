'use strict';

/**
 * Sanitized view of the provisioning worker's reconciliation snapshot.
 *
 * The worker (a separate, root-owned process) owns the real provisioning state:
 * relay allocation, cloud firewall permits and the PBX push hook. It publishes a
 * small JSON document that this control plane only *reads*; the dashboard never
 * mutates it and never issues commands back to the worker.
 *
 * Everything in that file is untrusted input from this module's point of view.
 * Nothing is echoed verbatim: only enumerated state/stage/reason values, a
 * SHA-256-shaped fingerprint and timestamps that parse are returned, and PBX
 * identifiers are always the ones already stored by the control store — a key
 * found only in the file (including `__proto__`, `constructor`, ...) is dropped.
 * File access is bounded and hardened: no symlinks, no hardlinks, regular file
 * only, private mode 0600/0640, root-owned, at most MAX_BYTES.
 *
 * Publication contract (must match the worker):
 *   - default path: /var/lib/sokrat-tenant-provisioning/status.json
 *     (override: CONTROL_PROVISIONING_STATUS_FILE)
 *   - parent directory: root-owned, not group/other-writable, so the service
 *     cannot unlink or symlink-swap the status file
 *   - status file: regular, root-owned, mode 0640 root:<service-group> (or 0600)
 *     and readable by the gateway service; anything else is `unavailable`
 *
 * Worker contract (schemaVersion 1):
 *
 *   {
 *     "schemaVersion": 1,
 *     "updatedAt": "2026-10-28T12:00:00.000Z",
 *     "pbx": {
 *       "pbx_1a2b3c4d": {
 *         "state": "ready" | "blocked" | "error" | "planned",
 *         "stages": { "relay": ..., "firewall": ..., "hook": ... },
 *         "reason": "<enum below>",
 *         "fingerprint": "<64 hex chars>",
 *         "capturedUpdatedAt": "<the PBX record updatedAt the worker reconciled>"
 *       }
 *     }
 *   }
 *
 * Stage values are exactly: pending, ready, blocked, error, planned, skipped
 * (plus `unknown` for a missing or unrecognized value). Reason values are the
 * enumerated list below plus `unknown`.
 *
 * `capturedUpdatedAt` is the identity signal: it must equal the control store's
 * current `pbx.updatedAt` for the worker's verdict to count as current. A
 * `ready` entry without it is downgraded to `pending`, because an old-schema
 * snapshot cannot prove which record revision it reconciled. When the field is
 * absent on a non-ready entry, the file's completion `updatedAt` is used as a
 * weaker fallback so legacy snapshots still show blocked/error/planned states.
 *
 * `fingerprint` is an opaque SHA-256-shaped value computed by the worker. This
 * module validates the shape and forwards it, but does NOT compare it: its
 * canonical definition lives in the worker (Python), and duplicating that
 * definition in JavaScript would be a cross-language dependency we do not want.
 * Identity freshness is enforced by `capturedUpdatedAt` plus the two-minute
 * staleness bound, not by the fingerprint.
 */

const fs = require('node:fs');

const DEFAULT_STATUS_FILE = '/var/lib/sokrat-tenant-provisioning/status.json';
const ENV_STATUS_FILE = 'CONTROL_PROVISIONING_STATUS_FILE';
const SCHEMA_VERSION = 1;
const MAX_BYTES = 64 * 1024;
const STALE_AFTER_MS = 2 * 60 * 1000;
const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

const PBX_STATES = new Set(['ready', 'blocked', 'error', 'planned']);
const STAGE_NAMES = Object.freeze(['relay', 'firewall', 'hook']);
// Stage vocabulary agreed with the worker. A missing/unreported stage is
// `unknown`; a stage value outside this set is also `unknown` (never echoed).
const STAGE_STATES = new Set([
    'pending',
    'ready',
    'blocked',
    'error',
    'planned',
    'skipped',
    'unknown'
]);
// Generic, non-revealing reasons. Anything else in the file becomes `unknown`
// so free-form worker text (stdout, paths, secrets) can never reach the browser.
const REASONS = new Set([
    'not_configured',
    'identity_mismatch',
    'approval_required',
    'relay_failed',
    'firewall_required',
    'firewall_failed',
    'hook_required',
    'hook_failed',
    'ready',
    'planned',
    'stale',
    'worker_failed',
    'configuration_invalid',
    'unknown'
]);
// File-level failure codes (enumerated; no system error text is forwarded).
const CODES = new Set([
    'ok',
    'stale',
    'missing',
    'unreadable',
    'symlink',
    'hardlink',
    'not_regular',
    'permissions_invalid',
    'owner_invalid',
    'too_large',
    'invalid_json',
    'invalid_schema',
    'invalid_timestamp',
    'internal_error'
]);

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

function resolveStatusFile(env = process.env) {
    const configured = env && typeof env[ENV_STATUS_FILE] === 'string'
        ? env[ENV_STATUS_FILE].trim()
        : '';
    return configured || DEFAULT_STATUS_FILE;
}

function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}

function failure(status, code) {
    return {
        status,
        code: CODES.has(code) ? code : 'internal_error',
        schemaVersion: null,
        updatedAt: null
    };
}

function parseTimestamp(value) {
    if (typeof value !== 'string' || value.length < 10 || value.length > 64) return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
}

async function openStatusFile(filePath) {
    // O_NONBLOCK keeps a FIFO/device from blocking the open() before fstat can
    // reject it; it has no effect on regular files. O_NOFOLLOW refuses symlinks.
    const flags = fs.constants.O_RDONLY |
        (fs.constants.O_NOFOLLOW || 0) |
        (fs.constants.O_NONBLOCK || 0);
    try {
        return { handle: await fs.promises.open(filePath, flags) };
    } catch (error) {
        const code = error && error.code;
        if (code === 'ENOENT' || code === 'ENOTDIR') {
            return { failure: failure('not_configured', 'missing') };
        }
        if (code === 'ELOOP' || code === 'EMLINK') {
            return { failure: failure('unavailable', 'symlink') };
        }
        return { failure: failure('unavailable', 'unreadable') };
    }
}

async function readBounded(handle) {
    const buffer = Buffer.allocUnsafe(MAX_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_BYTES) return { failure: failure('unavailable', 'too_large') };
    return { text: buffer.subarray(0, bytesRead).toString('utf8') };
}

/**
 * Load and strictly sanitize the worker snapshot.
 *
 * @param {object} [options]
 * @param {string} [options.filePath]        defaults to CONTROL_PROVISIONING_STATUS_FILE
 * @param {string[]} [options.ownerUids]     accepted owner uids (default: root only)
 * @param {number} [options.now]
 * @param {number} [options.staleAfterMs]
 * @returns {Promise<object>} `{ status, code, schemaVersion, updatedAt, updatedAtMs, rawPbx }`
 */
async function loadStatusDocument(options = {}) {
    const filePath = options.filePath || resolveStatusFile(options.env);
    const ownerUids = Array.isArray(options.ownerUids) && options.ownerUids.length
        ? options.ownerUids
        : [0];
    const now = Number.isFinite(options.now) ? Number(options.now) : Date.now();
    const staleAfterMs = Number.isFinite(options.staleAfterMs) && options.staleAfterMs > 0
        ? Number(options.staleAfterMs)
        : STALE_AFTER_MS;

    const opened = await openStatusFile(filePath);
    if (opened.failure) return opened.failure;

    let text;
    try {
        const stat = await opened.handle.stat();
        if (!stat.isFile()) return failure('unavailable', 'not_regular');
        if (stat.nlink !== 1) return failure('unavailable', 'hardlink');
        const mode = stat.mode & 0o777;
        if (mode !== 0o600 && mode !== 0o640) {
            return failure('unavailable', 'permissions_invalid');
        }
        if (!ownerUids.includes(stat.uid)) return failure('unavailable', 'owner_invalid');
        if (stat.size > MAX_BYTES) return failure('unavailable', 'too_large');
        const read = await readBounded(opened.handle);
        if (read.failure) return read.failure;
        text = read.text;
    } catch {
        return failure('unavailable', 'unreadable');
    } finally {
        await opened.handle.close().catch(() => {});
    }

    let document;
    try {
        document = JSON.parse(text);
    } catch {
        return failure('unavailable', 'invalid_json');
    }
    if (!isPlainObject(document)) return failure('unavailable', 'invalid_schema');
    if (document.schemaVersion !== SCHEMA_VERSION) {
        return failure('unavailable', 'invalid_schema');
    }
    if (!isPlainObject(document.pbx)) return failure('unavailable', 'invalid_schema');

    const updatedAtMs = parseTimestamp(document.updatedAt);
    if (updatedAtMs === null) return failure('unavailable', 'invalid_timestamp');
    if (updatedAtMs - now > FUTURE_TOLERANCE_MS) {
        return failure('unavailable', 'invalid_timestamp');
    }

    return {
        status: now - updatedAtMs > staleAfterMs ? 'stale' : 'ok',
        code: now - updatedAtMs > staleAfterMs ? 'stale' : 'ok',
        schemaVersion: SCHEMA_VERSION,
        updatedAt: new Date(updatedAtMs).toISOString(),
        updatedAtMs,
        rawPbx: document.pbx
    };
}

function sanitizeEntry(entry) {
    if (!isPlainObject(entry)) {
        return {
            state: 'error',
            reason: 'configuration_invalid',
            stages: { relay: 'unknown', firewall: 'unknown', hook: 'unknown' },
            fingerprint: null
        };
    }
    const state = PBX_STATES.has(entry.state) ? entry.state : 'error';
    const reason = REASONS.has(entry.reason) ? entry.reason : 'unknown';
    const rawStages = isPlainObject(entry.stages) ? entry.stages : {};
    const stages = {};
    for (const name of STAGE_NAMES) {
        const value = rawStages[name];
        stages[name] = STAGE_STATES.has(value) ? value : 'unknown';
    }
    const fingerprint = typeof entry.fingerprint === 'string'
        && FINGERPRINT_PATTERN.test(entry.fingerprint)
        ? entry.fingerprint
        : null;
    return { state, reason, stages, fingerprint };
}

function entryFor(rawPbx, id) {
    if (!rawPbx || !Object.hasOwn(rawPbx, id)) return null;
    return rawPbx[id];
}

/**
 * Build the API/UI payload.
 *
 * @param {object} options
 * @param {string} [options.filePath]
 * @param {Array<{id:string,updatedAt?:string}>} [options.pbx] configured PBX records
 * @param {string[]} [options.ownerUids]
 * @param {number} [options.now]
 * @param {number} [options.staleAfterMs]
 */
async function getProvisioningStatus(options = {}) {
    const now = Number.isFinite(options.now) ? Number(options.now) : Date.now();
    const staleAfterMs = Number.isFinite(options.staleAfterMs) && options.staleAfterMs > 0
        ? Number(options.staleAfterMs)
        : STALE_AFTER_MS;

    let document;
    try {
        document = await loadStatusDocument({ ...options, now, staleAfterMs });
    } catch {
        document = failure('unavailable', 'internal_error');
    }

    const records = Array.isArray(options.pbx) ? options.pbx : [];
    const rawPbx = document.rawPbx || null;
    const updatedAtMs = Number.isFinite(document.updatedAtMs) ? document.updatedAtMs : null;

    const entries = records.map((record) => {
        const id = String(record && record.id ? record.id : '');
        const raw = entryFor(rawPbx, id);
        const rawEntry = raw !== null && isPlainObject(raw) ? raw : null;
        const entry = raw === null
            ? {
                state: 'not_configured',
                reason: 'not_configured',
                stages: { relay: 'unknown', firewall: 'unknown', hook: 'unknown' },
                fingerprint: null
            }
            : sanitizeEntry(raw);

        const recordUpdatedMs = parseTimestamp(record && record.updatedAt);
        const capturedMs = rawEntry ? parseTimestamp(rawEntry.capturedUpdatedAt) : null;

        let reconciliation = 'unknown';
        if (document.status === 'ok' || document.status === 'stale') {
            if (document.status === 'stale') {
                reconciliation = 'stale';
            } else if (capturedMs !== null) {
                // Exact identity check: the worker must have reconciled the very
                // record revision the control store holds right now.
                reconciliation = recordUpdatedMs !== null && capturedMs === recordUpdatedMs
                    ? 'current'
                    : 'pending';
            } else if (entry.state === 'ready') {
                // An old-schema "ready" cannot prove which revision it saw.
                reconciliation = 'pending';
            } else if (recordUpdatedMs !== null && updatedAtMs !== null && recordUpdatedMs > updatedAtMs) {
                // Compatibility fallback for snapshots without capturedUpdatedAt.
                reconciliation = 'pending';
            } else {
                reconciliation = 'current';
            }
        }

        // Never claim "ready" for a snapshot that is stale, pending or absent.
        const effectiveState = reconciliation === 'current'
            ? entry.state
            : document.status === 'unavailable'
                ? 'unavailable'
                : document.status === 'not_configured'
                    ? 'not_configured'
                    : reconciliation;

        return {
            id,
            state: entry.state,
            effectiveState,
            stages: entry.stages,
            reason: entry.reason,
            fingerprint: entry.fingerprint,
            reconciliation
        };
    });

    return {
        status: document.status,
        code: document.code,
        schemaVersion: document.schemaVersion,
        updatedAt: document.updatedAt,
        ageMs: updatedAtMs === null ? null : Math.max(0, now - updatedAtMs),
        staleAfterMs,
        pbx: entries
    };
}

module.exports = {
    DEFAULT_STATUS_FILE,
    ENV_STATUS_FILE,
    MAX_BYTES,
    STALE_AFTER_MS,
    PBX_STATES,
    STAGE_NAMES,
    STAGE_STATES,
    REASONS,
    CODES,
    resolveStatusFile,
    loadStatusDocument,
    getProvisioningStatus
};
