'use strict';

/**
 * Durable control-plane store for the multi-PBX / device approval dashboard.
 *
 * Design notes
 * ------------
 * - Node built-ins only (`fs`, `crypto`, `net`, `path`).
 * - The whole dataset lives in one JSON document written **atomically**:
 *   write a sibling temp file (mode 0600, fsynced), rename it over the target,
 *   then fsync the containing directory. A crash never leaves a half file.
 * - The file is created 0600 inside a 0700 directory; an existing file found
 *   with looser permissions is tightened on load.
 * - Mutations are serialised through a promise chain and applied to a private
 *   clone. A failed mutation never leaves the in-memory state dirty and never
 *   touches the file.
 * - Enrollment tokens and per-device secrets are 256-bit CSPRNG values and are
 *   stored **only** as SHA-256 digests. The plaintext is returned exactly once,
 *   to the caller that created it. A device UUID / app instance is *recorded*
 *   for operator review but is never authentication material.
 *
 * Two enrollment modes coexist on the same device table:
 *
 * - `invite` (operator-driven): a device redeems an administrator-created
 *   enrollment token; approval mints a `sk_device_v1_…` secret that is handed
 *   to the device once and never retrievable again.
 * - `claim` (automatic): an unapproved device calls in with its gateway
 *   extension plus a **client-generated** claim secret. Only the digest is
 *   stored and the pending row is keyed by that digest, never by UUID. Approval
 *   preserves the claim; the device then completes redemption with the claim
 *   secret it already holds and receives its assignment. No secret is ever
 *   minted, transmitted or displayed for this mode, which makes redemption
 *   retry-safe and leaves nothing to retrieve.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = fs.promises;
const net = require('node:net');
const path = require('node:path');
const managementPolicy = require('./management');

const SCHEMA_VERSION = 2;

const ENROLLMENT_TOKEN_PREFIX = 'sk_enroll_v1_';
const DEVICE_SECRET_PREFIX = 'sk_device_v1_';

const CLAIM_SECRET_MIN_LENGTH = 32;
const CLAIM_SECRET_MAX_LENGTH = 256;
const DEFAULT_CLAIM_TTL_MS = 24 * 60 * 60 * 1000;
const CLAIM_RETRY_HINT_MS = 3000;

const WS_PROTOCOLS = new Set(['ws:', 'wss:']);
const API_PROTOCOLS = new Set(['http:', 'https:']);
const PLATFORMS = new Set(['ios', 'android', 'desktop', 'chrome']);
const DEVICE_STATUSES = new Set(['pending', 'approved', 'rejected', 'revoked']);
const ENROLLMENT_MODES = new Set(['invite', 'claim']);

const EXTENSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,31}$/;
const UUID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const DEFAULT_LIMITS = Object.freeze({
    maxEnabledPbx: 5,
    maxPbx: 25,
    maxPendingDevices: 200,
    maxDevices: 2000,
    maxEnrollmentTokens: 100,
    maxExtensions: 5000,
    claimTtlMs: DEFAULT_CLAIM_TTL_MS,
    auditEntries: 200
});

class ControlStoreError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.name = 'ControlStoreError';
        this.code = code;
        this.status = status;
    }
}

function fail(code, message, status = 400) {
    return new ControlStoreError(code, message, status);
}

function clone(value) {
    return structuredClone(value);
}

function isoAt(ms) {
    return new Date(ms).toISOString();
}

function isoOrNull(value) {
    if (typeof value !== 'string' || !value) return null;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function randomHex(bytes) {
    return crypto.randomBytes(bytes).toString('hex');
}

function createOpaqueToken(prefix) {
    return prefix + crypto.randomBytes(32).toString('base64url');
}

function hashSecret(value) {
    return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function timingSafeEqualHex(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;
    if (left.length !== right.length || left.length === 0) return false;
    let leftBuffer;
    let rightBuffer;
    try {
        leftBuffer = Buffer.from(left, 'hex');
        rightBuffer = Buffer.from(right, 'hex');
    } catch {
        return false;
    }
    if (leftBuffer.length !== rightBuffer.length || leftBuffer.length === 0) return false;
    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireString(value, field, options = {}) {
    const { min = 1, max = 128, pattern, label = field } = options;
    if (typeof value !== 'string') {
        throw fail(`invalid_${field}`, `${label} is required`);
    }
    const text = value.trim();
    if (text.length < min || text.length > max) {
        throw fail(
            `invalid_${field}`,
            `${label} must be between ${min} and ${max} characters`
        );
    }
    if (CONTROL_CHARS.test(text)) {
        throw fail(`invalid_${field}`, `${label} must not contain control characters`);
    }
    if (pattern && !pattern.test(text)) {
        throw fail(`invalid_${field}`, `${label} has an unexpected format`);
    }
    return text;
}

function toBoolean(value, field, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    if (value === true || value === 'true' || value === 1 || value === '1') return true;
    if (value === false || value === 'false' || value === 0 || value === '0') return false;
    throw fail(`invalid_${field}`, `${field} must be a boolean`);
}

function normalizeUrl(value, field, protocols) {
    const raw = requireString(value, field, { max: 512 });
    let parsed;
    try {
        parsed = new URL(raw);
    } catch {
        throw fail(`invalid_${field}`, `${field} must be an absolute URL`);
    }
    if (!protocols.has(parsed.protocol)) {
        const allowed = [...protocols].join(' or ');
        throw fail(`invalid_${field}`, `${field} must use ${allowed}`);
    }
    if (parsed.username || parsed.password) {
        throw fail(`invalid_${field}`, `${field} must not embed credentials`);
    }
    if (parsed.hash) {
        throw fail(`invalid_${field}`, `${field} must not include a fragment`);
    }
    if (!parsed.hostname) {
        throw fail(`invalid_${field}`, `${field} must include a host`);
    }
    return parsed.href;
}

function normalizeMediaIps(value) {
    if (value === undefined || value === null || value === '') return [];
    const items = Array.isArray(value) ? value : String(value).split(/[\s,]+/);
    if (items.length > 16) {
        throw fail('invalid_mediaIps', 'mediaIps accepts at most 16 entries');
    }
    const result = [];
    for (const item of items) {
        const text = String(item).trim();
        if (!text) continue;
        if (text.length > 64) {
            throw fail('invalid_mediaIps', 'mediaIps entry is too long');
        }
        const segments = text.split('/');
        if (segments.length > 2) {
            throw fail('invalid_mediaIps', `mediaIps entry "${text}" is not an IP address or CIDR block`);
        }
        const family = net.isIP(segments[0]);
        if (!family) {
            throw fail('invalid_mediaIps', `mediaIps entry "${text}" is not an IP address or CIDR block`);
        }
        if (segments.length === 2) {
            if (!/^\d{1,3}$/.test(segments[1])) {
                throw fail('invalid_mediaIps', `mediaIps entry "${text}" has an invalid prefix length`);
            }
            const bits = Number(segments[1]);
            const maxBits = family === 4 ? 32 : 128;
            if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) {
                throw fail('invalid_mediaIps', `mediaIps entry "${text}" has an invalid prefix length`);
            }
        }
        if (!result.includes(text)) result.push(text);
    }
    return result;
}

function normalizeExtension(value, field = 'extension') {
    return requireString(value, field, {
        max: 32,
        label: 'Extension',
        pattern: EXTENSION_PATTERN
    });
}

function normalizePlatform(value) {
    const platform = requireString(value, 'platform', { max: 16, label: 'Platform' }).toLowerCase();
    if (!PLATFORMS.has(platform)) {
        throw fail('invalid_platform', 'platform must be ios, android, desktop or chrome');
    }
    return platform;
}

function normalizeDeviceUuid(value) {
    const uuid = requireString(value, 'deviceUuid', { max: 64, label: 'deviceUuid' });
    if (!UUID_PATTERN.test(uuid)) {
        throw fail('invalid_deviceUuid', 'deviceUuid must be a UUID');
    }
    return uuid.toLowerCase();
}

function optionalText(value, field, max) {
    if (value === undefined || value === null || value === '') return null;
    return requireString(value, field, { max, label: field });
}

/**
 * Claim secrets are generated by the device, so their shape is the client's
 * business. We only enforce a floor that makes guessing hopeless (32 characters
 * ≈ 190 bits for a base64url string) and reject values that would be mangled in
 * transit (control characters or surrounding whitespace).
 */
function normalizeClaimSecret(value) {
    if (typeof value !== 'string') {
        throw fail('invalid_claimSecret', 'claimSecret is required');
    }
    if (value.length < CLAIM_SECRET_MIN_LENGTH || value.length > CLAIM_SECRET_MAX_LENGTH) {
        throw fail(
            'invalid_claimSecret',
            `claimSecret must be between ${CLAIM_SECRET_MIN_LENGTH} and ${CLAIM_SECRET_MAX_LENGTH} characters`
        );
    }
    if (CONTROL_CHARS.test(value) || value.trim() !== value || /\s/.test(value)) {
        throw fail('invalid_claimSecret', 'claimSecret must not contain whitespace or control characters');
    }
    return value;
}

function normalizeDeviceId(value) {
    return requireString(value, 'deviceId', { max: 64, label: 'deviceId' });
}

function sanitizeActor(value) {
    const text = String(value || 'admin').trim().slice(0, 64);
    return CONTROL_CHARS.test(text) ? 'admin' : text || 'admin';
}

function normalizePbxInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw fail('invalid_pbx', 'PBX payload must be an object');
    }
    return {
        name: requireString(input.name, 'name', { max: 64, label: 'PBX name' }),
        wsURL: normalizeUrl(input.wsURL, 'wsURL', WS_PROTOCOLS),
        apiURL: normalizeUrl(input.apiURL, 'apiURL', API_PROTOCOLS),
        mediaIps: normalizeMediaIps(input.mediaIps),
        enabled: toBoolean(input.enabled, 'enabled', true)
    };
}

function positiveInt(value, fallback, { min, max }) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
}

function minutesToMs(value) {
    if (value === undefined || value === null || value === '') return undefined;
    const minutes = Number(value);
    if (!Number.isFinite(minutes) || minutes <= 0) return undefined;
    return Math.round(minutes * 60 * 1000);
}

function normalizeLimits(options = {}) {
    const env = process.env;
    const maxEnabledPbx = positiveInt(
        options.maxEnabledPbx ?? env.CONTROL_MAX_ENABLED_PBX,
        DEFAULT_LIMITS.maxEnabledPbx,
        { min: 1, max: 64 }
    );
    return {
        maxEnabledPbx,
        maxExtensions: positiveInt(options.maxExtensions ?? env.CONTROL_MAX_EXTENSIONS,
            DEFAULT_LIMITS.maxExtensions, { min: 1, max: 20000 }),
        maxPbx: Math.max(
            maxEnabledPbx,
            positiveInt(options.maxPbx ?? env.CONTROL_MAX_PBX, DEFAULT_LIMITS.maxPbx, { min: 1, max: 128 })
        ),
        maxPendingDevices: positiveInt(
            options.maxPendingDevices ?? env.CONTROL_MAX_PENDING_DEVICES,
            DEFAULT_LIMITS.maxPendingDevices,
            { min: 1, max: 5000 }
        ),
        maxDevices: positiveInt(
            options.maxDevices ?? env.CONTROL_MAX_DEVICES,
            DEFAULT_LIMITS.maxDevices,
            { min: 10, max: 20000 }
        ),
        maxEnrollmentTokens: positiveInt(
            options.maxEnrollmentTokens ?? env.CONTROL_MAX_INVITES,
            DEFAULT_LIMITS.maxEnrollmentTokens,
            { min: 1, max: 1000 }
        ),
        claimTtlMs: positiveInt(
            options.claimTtlMs ?? minutesToMs(env.CONTROL_CLAIM_TTL_MINUTES),
            DEFAULT_LIMITS.claimTtlMs,
            { min: 5 * 60 * 1000, max: 7 * 24 * 60 * 60 * 1000 }
        ),
        auditEntries: DEFAULT_LIMITS.auditEntries
    };
}

// ---------------------------------------------------------------------------
// Public projections (never expose digests or plaintext secrets)
// ---------------------------------------------------------------------------

function publicDevice(device) {
    return {
        id: device.id,
        status: device.status,
        enrollmentMode: device.enrollmentMode || (device.claimHash ? 'claim' : 'invite'),
        platform: device.platform,
        deviceUuid: device.deviceUuid,
        instanceId: device.instanceId,
        deviceName: device.deviceName,
        appVersion: device.appVersion,
        model: device.model,
        osVersion: device.osVersion,
        requestIp: device.requestIp,
        enrollmentTokenId: device.enrollmentTokenId,
        suggestedPbxId: device.suggestedPbxId,
        suggestedExtension: device.suggestedExtension,
        claimExpiresAt: device.claimExpiresAt || null,
        claimRedeemedAt: device.claimRedeemedAt || null,
        hasClaim: Boolean(device.claimHash),
        requestedAt: device.requestedAt,
        reviewedAt: device.reviewedAt,
        reviewedBy: device.reviewedBy,
        reviewReason: device.reviewReason,
        pbxId: device.pbxId,
        extension: device.extension,
        authorizationRevision: device.authorizationRevision || 0,
        secretIssuedAt: device.secretIssuedAt,
        hasSecret: Boolean(device.secretHash),
        lastSeenAt: device.lastSeenAt
    };
}

function publicEnrollment(record) {
    return {
        id: record.id,
        label: record.label,
        pbxId: record.pbxId,
        extension: record.extension,
        maxUses: record.maxUses,
        usedCount: record.usedCount,
        expiresAt: record.expiresAt,
        revokedAt: record.revokedAt,
        createdAt: record.createdAt,
        createdBy: record.createdBy,
        lastUsedAt: record.lastUsedAt,
        lastUsedIp: record.lastUsedIp
    };
}

function publicPbx(pbx) {
    return {
        id: pbx.id,
        name: pbx.name,
        wsURL: pbx.wsURL,
        apiURL: pbx.apiURL,
        mediaIps: [...pbx.mediaIps],
        enabled: pbx.enabled,
        createdAt: pbx.createdAt,
        updatedAt: pbx.updatedAt,
        ...(pbx.management ? { management: clone(pbx.management) } : {})
    };
}

function pushAudit(draft, entry, limit) {
    draft.audit.push({
        at: entry.at,
        actor: sanitizeActor(entry.actor),
        action: entry.action,
        target: entry.target || null,
        detail: entry.detail ? String(entry.detail).slice(0, 200) : null
    });
    if (draft.audit.length > limit) {
        draft.audit.splice(0, draft.audit.length - limit);
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

class ControlStore {
    constructor(options = {}) {
        const filePath = options.filePath || process.env.CONTROL_DATA_FILE;
        if (!filePath || typeof filePath !== 'string') {
            throw new Error(
                'ControlStore requires a filePath option (or CONTROL_DATA_FILE) for its durable JSON document'
            );
        }
        this.filePath = path.resolve(filePath);
        this.limits = normalizeLimits(options);
        this._now = typeof options.now === 'function' ? options.now : Date.now;
        this.state = null;
        this._initPromise = null;
        this._chain = Promise.resolve();
    }

    // --- lifecycle ---------------------------------------------------------

    init() {
        if (!this._initPromise) {
            // The promise is cached on failure too, so a corrupt file is never
            // raced by a retry that could overwrite good data.
            this._initPromise = this._load();
            this._initPromise.catch(() => {});
        }
        return this._initPromise;
    }

    get ready() {
        return Boolean(this.state);
    }

    async _load() {
        const directory = path.dirname(this.filePath);
        await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
        await this._tightenMode(directory, 0o700);

        let raw;
        try {
            raw = await fsp.readFile(this.filePath, 'utf8');
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
            const now = isoAt(this._now());
            const fresh = {
                schemaVersion: SCHEMA_VERSION,
                createdAt: now,
                updatedAt: now,
                pbx: [],
                extensions: [],
                enrollmentTokens: [],
                devices: [],
                audit: []
            };
            await this._flush(fresh);
            this.state = fresh;
            return this;
        }

        await this._tightenMode(this.filePath, 0o600);

        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch {
            throw fail('control_store_corrupt', 'Control store is not valid JSON', 500);
        }
        try {
            this.state = this._validateState(parsed);
        } catch (error) {
            if (error instanceof ControlStoreError && error.code.startsWith('control_store_')) {
                throw error;
            }
            throw fail('control_store_corrupt', `Control store is invalid: ${error.message}`, 500);
        }
        return this;
    }

    async _tightenMode(target, mode) {
        try {
            const stat = await fsp.stat(target);
            if ((stat.mode & 0o777) !== mode) await fsp.chmod(target, mode);
        } catch {
            // Best effort: Windows and some filesystems do not model POSIX modes.
        }
    }

    _assertReady() {
        if (!this.state) {
            throw fail('control_store_not_ready', 'Control store has not been initialized', 503);
        }
    }

    _validateState(parsed) {
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw fail('control_store_corrupt', 'Control store must contain a JSON object', 500);
        }
        const version = Number(parsed.schemaVersion ?? parsed.version);
        if (!Number.isInteger(version) || version < 1) {
            throw fail('control_store_corrupt', 'Control store is missing a schema version', 500);
        }
        if (version > SCHEMA_VERSION) {
            throw fail(
                'control_store_version_unsupported',
                `Control store schema ${version} is newer than this build supports (${SCHEMA_VERSION})`,
                500
            );
        }
        if (version >= 2 && !Array.isArray(parsed.extensions)) {
            throw fail('control_store_corrupt', 'Schema2 requires an extension policy collection', 500);
        }
        for (const key of ['pbx', 'extensions', 'enrollmentTokens', 'devices', 'audit']) {
            if (parsed[key] !== undefined && !Array.isArray(parsed[key])) {
                throw fail('control_store_corrupt', `Control store field "${key}" must be an array`, 500);
            }
        }

        const now = isoAt(this._now());
        const state = {
            schemaVersion: SCHEMA_VERSION,
            createdAt: isoOrNull(parsed.createdAt) || now,
            updatedAt: isoOrNull(parsed.updatedAt) || now,
            pbx: [],
            extensions: [],
            enrollmentTokens: [],
            devices: [],
            audit: []
        };

        const seenIds = new Set();
        for (const record of parsed.pbx || []) {
            if (!record || typeof record !== 'object') {
                throw fail('control_store_corrupt', 'Control store contains an invalid PBX record', 500);
            }
            const id = requireString(record.id, 'id', { max: 64, label: 'PBX id' });
            if (seenIds.has(id)) {
                throw fail('control_store_corrupt', `Control store contains duplicate ids (${id})`, 500);
            }
            seenIds.add(id);
            if (Object.hasOwn(record, 'management') && (!record.management
                || !['approvalStatus', 'extensionPolicyRequired'].every(key => Object.hasOwn(record.management, key)))) {
                throw fail('control_store_corrupt', 'Persisted management authorization fields are required', 500);
            }
            state.pbx.push({
                id,
                name: requireString(record.name, 'name', { max: 64, label: 'PBX name' }),
                wsURL: String(record.wsURL || ''),
                apiURL: String(record.apiURL || ''),
                mediaIps: Array.isArray(record.mediaIps) ? record.mediaIps.map(String) : [],
                enabled: record.enabled === true,
                ...(Object.hasOwn(record, 'management') ? { management: this._normalizeManagement(record.management) } : {}),
                createdAt: isoOrNull(record.createdAt) || now,
                updatedAt: isoOrNull(record.updatedAt) || now
            });
        }

        for (const pbx of state.pbx) this._assertHostnameFree(state, pbx.management, pbx.id);
        // maxExtensions is an admission limit, not a load-time repair policy.
        // A reduced limit must not discard restrictions or prevent revocation.
        const seenExtensions = new Set();
        for (const record of parsed.extensions || []) {
            if (!record || !state.pbx.some(p => p.id === record.pbxId)
                || typeof record.id !== 'string' || seenIds.has(record.id)
                || !['status', 'maxDevices', 'allowedPlatforms'].every(key => Object.hasOwn(record, key))) {
                throw fail('control_store_corrupt', 'Invalid extension policy record', 500);
            }
            seenIds.add(record.id);
            const normalized = this._normalizeExtensionPolicy(record);
            const key = `${record.pbxId}\n${normalized.extension}`;
            if (seenExtensions.has(key)) throw fail('control_store_corrupt', 'Duplicate extension policy', 500);
            seenExtensions.add(key);
            state.extensions.push({ id: record.id, pbxId: record.pbxId, ...normalized,
                createdAt: isoOrNull(record.createdAt) || now, updatedAt: isoOrNull(record.updatedAt) || now });
        }

        for (const record of parsed.enrollmentTokens || []) {
            if (!record || typeof record !== 'object' || typeof record.tokenHash !== 'string') {
                throw fail('control_store_corrupt', 'Control store contains an invalid enrollment token', 500);
            }
            state.enrollmentTokens.push({
                id: String(record.id || `inv_${randomHex(8)}`),
                label: String(record.label || ''),
                tokenHash: record.tokenHash,
                pbxId: record.pbxId || null,
                extension: record.extension || null,
                maxUses: positiveInt(record.maxUses, 1, { min: 1, max: 100 }),
                usedCount: positiveInt(record.usedCount, 0, { min: 0, max: 100000 }),
                expiresAt: isoOrNull(record.expiresAt),
                revokedAt: isoOrNull(record.revokedAt),
                createdAt: isoOrNull(record.createdAt) || now,
                createdBy: sanitizeActor(record.createdBy),
                lastUsedAt: isoOrNull(record.lastUsedAt),
                lastUsedIp: record.lastUsedIp || null
            });
        }

        const seenDevices = new Set();
        for (const record of parsed.devices || []) {
            if (!record || typeof record !== 'object') {
                throw fail('control_store_corrupt', 'Control store contains an invalid device record', 500);
            }
            const id = requireString(record.id, 'id', { max: 64, label: 'device id' });
            if (seenDevices.has(id)) {
                throw fail('control_store_corrupt', `Control store contains duplicate device ids (${id})`, 500);
            }
            seenDevices.add(id);
            const status = String(record.status || '');
            if (!DEVICE_STATUSES.has(status)) {
                throw fail('control_store_corrupt', `Control store device ${id} has an unknown status`, 500);
            }
            const claimHash = typeof record.claimHash === 'string' ? record.claimHash : null;
            const enrollmentMode = ENROLLMENT_MODES.has(record.enrollmentMode)
                ? record.enrollmentMode
                : claimHash
                    ? 'claim'
                    : 'invite';
            state.devices.push({
                id,
                status,
                enrollmentMode,
                platform: normalizePlatform(record.platform),
                deviceUuid: String(record.deviceUuid || ''),
                instanceId: record.instanceId || null,
                deviceName: record.deviceName || null,
                appVersion: record.appVersion || null,
                model: record.model || null,
                osVersion: record.osVersion || null,
                requestIp: record.requestIp || null,
                enrollmentTokenId: record.enrollmentTokenId || null,
                suggestedPbxId: record.suggestedPbxId || null,
                suggestedExtension: record.suggestedExtension || null,
                claimHash,
                claimExpiresAt: isoOrNull(record.claimExpiresAt),
                claimRedeemedAt: isoOrNull(record.claimRedeemedAt),
                requestedAt: isoOrNull(record.requestedAt) || now,
                reviewedAt: isoOrNull(record.reviewedAt),
                reviewedBy: record.reviewedBy ? sanitizeActor(record.reviewedBy) : null,
                reviewReason: record.reviewReason || null,
                pbxId: record.pbxId || null,
                extension: record.extension || null,
                authorizationRevision: Number.isSafeInteger(record.authorizationRevision) && record.authorizationRevision >= 0
                    ? record.authorizationRevision : 0,
                secretHash: typeof record.secretHash === 'string' ? record.secretHash : null,
                secretIssuedAt: isoOrNull(record.secretIssuedAt),
                lastSeenAt: isoOrNull(record.lastSeenAt)
            });
        }

        for (const entry of parsed.audit || []) {
            if (!entry || typeof entry !== 'object' || typeof entry.action !== 'string') continue;
            state.audit.push({
                at: isoOrNull(entry.at) || now,
                actor: sanitizeActor(entry.actor),
                action: entry.action.slice(0, 64),
                target: entry.target ? String(entry.target).slice(0, 64) : null,
                detail: entry.detail ? String(entry.detail).slice(0, 200) : null
            });
        }
        if (state.audit.length > this.limits.auditEntries) {
            state.audit.splice(0, state.audit.length - this.limits.auditEntries);
        }

        return state;
    }

    // --- atomic persistence ------------------------------------------------

    async _flush(state) {
        const directory = path.dirname(this.filePath);
        const payload = `${JSON.stringify(state, null, 2)}\n`;
        const tmpPath = path.join(
            directory,
            `.${path.basename(this.filePath)}.${process.pid}.${randomHex(8)}.tmp`
        );

        let handle = null;
        try {
            handle = await fsp.open(tmpPath, 'wx', 0o600);
            await handle.writeFile(payload, 'utf8');
            await handle.sync();
        } catch (error) {
            if (handle) await handle.close().catch(() => {});
            handle = null;
            await fsp.unlink(tmpPath).catch(() => {});
            throw error;
        } finally {
            if (handle) await handle.close().catch(() => {});
        }

        try {
            await fsp.rename(tmpPath, this.filePath);
        } catch (error) {
            await fsp.unlink(tmpPath).catch(() => {});
            throw error;
        }
        await this._tightenMode(this.filePath, 0o600);
        await this._syncDirectory(directory);
    }

    async _syncDirectory(directory) {
        let handle = null;
        try {
            handle = await fsp.open(directory, 'r');
            await handle.sync();
        } catch {
            // Directory fsync is unavailable on some platforms (notably Windows).
        } finally {
            if (handle) await handle.close().catch(() => {});
        }
    }

    _mutate(mutator) {
        return this._mutateLazy(async (draft) => ({ commit: true, value: await mutator(draft) }));
    }

    /**
     * Like `_mutate`, but the mutator decides whether anything changed. Polling
     * a pending claim must not rewrite the document on every request, while a
     * redemption that activates a device has to be persisted. The mutator
     * returns `{ commit, value }`; when `commit` is false the draft is dropped.
     */
    _mutateLazy(mutator) {
        const task = this._chain.then(async () => {
            this._assertReady();
            const draft = clone(this.state);
            const outcome = await mutator(draft);
            if (!outcome || outcome.commit !== true) {
                return outcome ? outcome.value : undefined;
            }
            draft.updatedAt = isoAt(this._now());
            await this._flush(draft);
            this.state = draft;
            return outcome.value;
        });
        this._chain = task.then(
            () => undefined,
            () => undefined
        );
        return task;
    }

    // --- claim helpers -----------------------------------------------------

    _claimExpired(device, now = this._now()) {
        if (!device || device.enrollmentMode !== 'claim') return false;
        if (device.status !== 'pending' || !device.claimExpiresAt) return false;
        return Date.parse(device.claimExpiresAt) <= now;
    }

    /** Expired claim requests are kept on disk but hidden from the operator. */
    _visibleDevice(device) {
        return !this._claimExpired(device);
    }

    _findByClaimHash(devices, digest) {
        for (const device of devices) {
            if (device.claimHash && timingSafeEqualHex(device.claimHash, digest)) return device;
        }
        return null;
    }

    _claimAssignment(state, device) {
        const pbx = state.pbx.find((record) => record.id === device.pbxId);
        if (!pbx) {
            throw fail('pbx_not_found', 'The assigned PBX no longer exists', 409);
        }
        if (!pbx.enabled) {
            throw fail('pbx_disabled', 'The assigned PBX is disabled; contact the administrator', 409);
        }
        this._assertManagedAccess(state, device, pbx);
        return {
            deviceId: device.id,
            deviceUuid: device.deviceUuid,
            platform: device.platform,
            pbxId: pbx.id,
            pbxName: pbx.name,
            extension: device.extension,
            wsURL: pbx.wsURL,
            apiURL: pbx.apiURL,
            mediaIps: [...pbx.mediaIps]
        };
    }

    // --- reads -------------------------------------------------------------

    snapshot() {
        this._assertReady();
        return {
            schemaVersion: this.state.schemaVersion,
            pbx: this.state.pbx.map(publicPbx),
            extensions: this.state.extensions.map(clone),
            devices: this.state.devices.filter((d) => this._visibleDevice(d)).map(publicDevice),
            enrollmentTokens: this.state.enrollmentTokens.map(publicEnrollment),
            audit: this.state.audit.slice(-50),
            limits: { ...this.limits },
            stats: this.stats(),
            updatedAt: this.state.updatedAt
        };
    }

    stats() {
        this._assertReady();
        const count = (status) => this.state.devices.filter((d) => d.status === status).length;
        const pending = this.state.devices.filter(
            (d) => d.status === 'pending' && this._visibleDevice(d)
        );
        return {
            pbx: this.state.pbx.length,
            enabledPbx: this.state.pbx.filter((p) => p.enabled).length,
            maxEnabledPbx: this.limits.maxEnabledPbx,
            pendingDevices: pending.length,
            pendingClaimDevices: pending.filter((d) => d.enrollmentMode === 'claim').length,
            approvedDevices: count('approved'),
            rejectedDevices: count('rejected'),
            revokedDevices: count('revoked'),
            activeEnrollmentTokens: this.state.enrollmentTokens.filter(
                (t) => !t.revokedAt && (!t.expiresAt || Date.parse(t.expiresAt) > this._now()) && t.usedCount < t.maxUses
            ).length
        };
    }

    listPbx() {
        this._assertReady();
        return this.state.pbx.map(publicPbx);
    }

    getPbx(id) {
        this._assertReady();
        const record = this.state.pbx.find((p) => p.id === id);
        return record ? publicPbx(record) : null;
    }

    listDevices(status) {
        this._assertReady();
        const devices = status
            ? this.state.devices.filter((d) => d.status === status)
            : this.state.devices;
        return devices
            .filter((device) => this._visibleDevice(device))
            .slice()
            .sort((a, b) => Date.parse(b.requestedAt) - Date.parse(a.requestedAt))
            .map(publicDevice);
    }

    listEnrollmentTokens() {
        this._assertReady();
        return this.state.enrollmentTokens
            .slice()
            .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
            .map(publicEnrollment);
    }

    auditLog(limit = 50) {
        this._assertReady();
        const size = Math.min(Math.max(Number(limit) || 50, 1), this.limits.auditEntries);
        return this.state.audit.slice(-size).map(clone);
    }

    // --- PBX lifecycle -----------------------------------------------------

    _normalizeManagement(input, existing) {
        if (!input || typeof input !== 'object' || Array.isArray(input)
            || Object.keys(input).some(k => !['customer', 'loginHostname', 'extensionPolicyRequired', 'approvalStatus', 'reviewedInstallationId'].includes(k))) {
            throw fail('invalid_management', 'Unsupported PBX management payload');
        }
        try { return managementPolicy.normalizeManagement(input, existing); }
        catch (error) { throw fail(error.code || 'invalid_management', error.message, 400); }
    }

    _normalizeExtensionPolicy(input, existing) {
        try {
            const next = managementPolicy.normalizeExtensionPolicy(input, existing);
            next.extension = normalizeExtension(next.extension);
            return next;
        } catch (error) { throw fail(error.code || 'invalid_extension_policy', error.message, 400); }
    }

    _assertHostnameFree(state, management, excludeId) {
        if (!management?.loginHostname) return;
        if (state.pbx.some(p => p.id !== excludeId && p.management?.loginHostname === management.loginHostname)) {
            throw fail('gateway_hostname_conflict', 'Gateway login hostname is already assigned', 409);
        }
    }

    _assertManagedAccess(state, device, pbx) {
        if (!pbx?.management) return;
        if (pbx.management.approvalStatus !== 'approved') {
            throw fail('pbx_not_approved', 'PBX management approval is required', 403);
        }
        const policy = state.extensions.find(e => e.pbxId === pbx.id && e.extension === device.extension);
        if (!policy && !pbx.management.extensionPolicyRequired) return;
        if (!policy || policy.status !== 'enabled') {
            throw fail('extension_not_approved', 'Extension gateway access is not enabled', 403);
        }
        if (!policy.allowedPlatforms.includes(device.platform)) {
            throw fail('platform_not_allowed', 'Platform is not enabled for this extension', 403);
        }
    }

    listExtensions(pbxId) {
        this._assertReady();
        return this.state.extensions.filter(e => !pbxId || e.pbxId === pbxId).map(clone);
    }

    addExtension(input, meta = {}) {
        return this._mutate(draft => {
            if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('invalid_extension_policy', 'Policy must be an object');
            if (Object.keys(input).some(k => !['pbxId', 'extension', 'name', 'status', 'maxDevices', 'allowedPlatforms'].includes(k))) {
                throw fail('invalid_extension_policy', 'Unsupported extension policy field');
            }
            const pbx = draft.pbx.find(p => p.id === input.pbxId);
            if (!pbx) throw fail('pbx_not_found', 'PBX not found', 404);
            if (!pbx.management) throw fail('pbx_management_required', 'Opt this PBX into management before adding policies', 409);
            const normalized = this._normalizeExtensionPolicy(input);
            if (draft.extensions.some(e => e.pbxId === pbx.id && e.extension === normalized.extension)) {
                throw fail('extension_conflict', 'Extension policy already exists for this PBX', 409);
            }
            if (draft.extensions.length >= this.limits.maxExtensions) throw fail('extension_limit_reached', 'Extension policy limit reached', 409);
            const approved = draft.devices.filter(d => d.status === 'approved' && d.pbxId === pbx.id && d.extension === normalized.extension).length;
            if (normalized.maxDevices < approved) throw fail('device_cap_below_usage', 'Revoke devices before setting a limit below usage', 409);
            const at = isoAt(this._now());
            const record = { id: `ext_${randomHex(8)}`, pbxId: pbx.id, ...normalized, createdAt: at, updatedAt: at };
            draft.extensions.push(record);
            pushAudit(draft, { at, actor: meta.actor, action: 'extension.added', target: record.id,
                detail: `${pbx.name} / ${record.extension} (${record.status})` }, this.limits.auditEntries);
            return clone(record);
        });
    }

    updateExtension(id, patch, meta = {}) {
        return this._mutate(draft => {
            const record = draft.extensions.find(e => e.id === id);
            if (!record) throw fail('extension_not_found', 'Extension policy not found', 404);
            if (!patch || typeof patch !== 'object' || Array.isArray(patch)
                || Object.keys(patch).some(k => !['name', 'status', 'maxDevices', 'allowedPlatforms'].includes(k))) {
                throw fail('invalid_extension_policy', 'Only policy fields may be updated; extension identity is immutable');
            }
            const next = this._normalizeExtensionPolicy(patch, record);
            const approved = draft.devices.filter(d => d.status === 'approved' && d.pbxId === record.pbxId && d.extension === record.extension).length;
            if (next.maxDevices < approved) throw fail('device_cap_below_usage', 'Revoke devices before lowering the limit below usage', 409);
            const at = isoAt(this._now());
            Object.assign(record, next, { updatedAt: at });
            pushAudit(draft, { at, actor: meta.actor, action: 'extension.updated', target: id,
                detail: `${record.extension} (${record.status})` }, this.limits.auditEntries);
            return clone(record);
        });
    }

    _assertEnabledCapacity(draft, excludeId) {
        const enabled = draft.pbx.filter((p) => p.enabled && p.id !== excludeId).length;
        if (enabled >= this.limits.maxEnabledPbx) {
            throw fail(
                'pbx_cap_reached',
                `Maximum of ${this.limits.maxEnabledPbx} enabled PBX connections reached`,
                409
            );
        }
    }

    _assertPbxNameFree(draft, name, excludeId) {
        const wanted = name.toLowerCase();
        const clash = draft.pbx.find((p) => p.id !== excludeId && p.name.toLowerCase() === wanted);
        if (clash) throw fail('pbx_name_conflict', `A PBX named "${name}" already exists`, 409);
    }

    manageAllPbx() {
        return this._mutateLazy(draft => {
            let changed = false;
            for (const record of draft.pbx) {
                if (record.management) continue;
                // Migration never invents ownership approval for an old server.
                record.management = this._normalizeManagement({ approvalStatus: 'pending', extensionPolicyRequired: true });
                record.updatedAt = isoAt(this._now());
                changed = true;
            }
            return { commit: changed };
        });
    }

    addPbx(input, meta = {}) {
        return this._mutate((draft) => {
            const normalized = normalizePbxInput(input);
            if (draft.pbx.length >= this.limits.maxPbx) {
                throw fail('pbx_limit_reached', `Maximum of ${this.limits.maxPbx} PBX records reached`, 409);
            }
            this._assertPbxNameFree(draft, normalized.name, null);
            if (Object.hasOwn(input, 'management')) normalized.management = this._normalizeManagement(input.management);
            this._assertHostnameFree(draft, normalized.management, null);
            if (normalized.enabled) this._assertEnabledCapacity(draft, null);

            const at = isoAt(this._now());
            const record = {
                id: `pbx_${randomHex(8)}`,
                ...normalized,
                createdAt: at,
                updatedAt: at
            };
            draft.pbx.push(record);
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'pbx.added',
                    target: record.id,
                    detail: `${record.name}${record.enabled ? '' : ' (disabled)'}`
                },
                this.limits.auditEntries
            );
            return publicPbx(record);
        });
    }

    updatePbx(id, patch, meta = {}) {
        return this._mutate((draft) => {
            const record = draft.pbx.find((p) => p.id === id);
            if (!record) throw fail('pbx_not_found', 'PBX not found', 404);
            if (meta.expectedPbx && JSON.stringify(publicPbx(record)) !== JSON.stringify(meta.expectedPbx)) {
                throw fail('pbx_changed_during_setup', 'PBX changed during SSH setup', 409);
            }
            if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
                throw fail('invalid_pbx', 'PBX payload must be an object');
            }
            const allowed = ['name', 'wsURL', 'apiURL', 'mediaIps', 'enabled', 'management'];
            const unknown = Object.keys(patch).filter((key) => !allowed.includes(key));
            if (unknown.length) {
                throw fail('invalid_pbx', `Unsupported PBX field(s): ${unknown.join(', ')}`);
            }

            const next = {};
            if (Object.hasOwn(patch, 'management')) {
                next.management = this._normalizeManagement(patch.management, record.management);
                this._assertHostnameFree(draft, next.management, record.id);
            }
            if (patch.name !== undefined) {
                next.name = requireString(patch.name, 'name', { max: 64, label: 'PBX name' });
            }
            if (patch.wsURL !== undefined) {
                next.wsURL = normalizeUrl(patch.wsURL, 'wsURL', WS_PROTOCOLS);
            }
            if (patch.apiURL !== undefined) {
                next.apiURL = normalizeUrl(patch.apiURL, 'apiURL', API_PROTOCOLS);
            }
            if (patch.mediaIps !== undefined) {
                next.mediaIps = normalizeMediaIps(patch.mediaIps);
            }
            if (patch.enabled !== undefined) {
                next.enabled = toBoolean(patch.enabled, 'enabled', record.enabled);
            }

            // A changed route/identity needs a separate review action. Compare
            // normalized values so merely re-saving an equivalent form is safe.
            if (next.management || record.management) {
                const endpointChanged = ['wsURL', 'apiURL'].some(key => next[key] !== undefined && next[key] !== record[key]);
                const mediaChanged = next.mediaIps !== undefined
                    && JSON.stringify([...next.mediaIps].sort()) !== JSON.stringify([...record.mediaIps].sort());
                const identityChanged = record.management && next.management
                    && ['loginHostname', 'reviewedInstallationId'].some(key => next.management[key] !== record.management[key]);
                if (endpointChanged || mediaChanged || identityChanged) {
                    next.management = { ...(next.management || record.management), approvalStatus: 'pending' };
                }
            }

            if (next.name && next.name.toLowerCase() !== record.name.toLowerCase()) {
                this._assertPbxNameFree(draft, next.name, record.id);
            }
            if (next.enabled === true && record.enabled !== true) {
                this._assertEnabledCapacity(draft, record.id);
            }

            const at = isoAt(this._now());
            Object.assign(record, next, { updatedAt: at });
            if (next.management?.approvalStatus === 'retired') {
                this._retirePbxAccess(draft, id, at, meta, 'pbx-retired');
            }
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'pbx.updated',
                    target: record.id,
                    detail:
                        Object.keys(next).join(', ') +
                        (next.enabled === false ? ' (disabled)' : '')
                },
                this.limits.auditEntries
            );
            return publicPbx(record);
        });
    }

    _retirePbxAccess(draft, id, at, meta, reason) {
        let revokedDevices = 0;
        for (const device of draft.devices) {
            if (device.pbxId !== id && !(device.status === 'pending' && device.suggestedPbxId === id)) continue;
            if (device.status !== 'approved' && device.status !== 'pending') continue;
            Object.assign(device, { status: 'revoked', secretHash: null,
                reviewedAt: at, reviewedBy: sanitizeActor(meta.actor), reviewReason: reason });
            revokedDevices += 1;
        }
        let revokedInvites = 0;
        for (const token of draft.enrollmentTokens) {
            if (token.pbxId !== id || token.revokedAt) continue;
            token.revokedAt = at;
            revokedInvites += 1;
        }
        return { revokedDevices, revokedInvites };
    }

    removePbx(id, meta = {}) {
        return this._mutate((draft) => {
            const index = draft.pbx.findIndex((p) => p.id === id);
            if (index === -1) throw fail('pbx_not_found', 'PBX not found', 404);
            const [removed] = draft.pbx.splice(index, 1);
            draft.extensions = draft.extensions.filter(e => e.pbxId !== id);
            const at = isoAt(this._now());

            const { revokedDevices, revokedInvites } = this._retirePbxAccess(draft, id, at, meta, 'pbx-removed');

            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'pbx.removed',
                    target: removed.id,
                    detail: `${removed.name} (devices revoked: ${revokedDevices}, invites revoked: ${revokedInvites})`
                },
                this.limits.auditEntries
            );
            return { pbx: publicPbx(removed), revokedDevices, revokedInvites };
        });
    }

    // --- enrollment invitations -------------------------------------------

    createEnrollmentToken(input = {}, meta = {}) {
        return this._mutate((draft) => {
            const label = requireString(input.label || 'Device invite', 'label', {
                max: 64,
                label: 'Label'
            });
            const pbxId = input.pbxId ? String(input.pbxId) : null;
            if (pbxId && !draft.pbx.some((p) => p.id === pbxId)) {
                throw fail('pbx_not_found', 'PBX not found', 404);
            }
            const extension = input.extension ? normalizeExtension(input.extension) : null;
            const maxUses = positiveInt(input.maxUses, 1, { min: 1, max: 100 });
            const ttlMs = positiveInt(input.ttlMs, 24 * 60 * 60 * 1000, {
                min: 60 * 1000,
                max: 30 * 24 * 60 * 60 * 1000
            });

            const active = draft.enrollmentTokens.filter((t) => !t.revokedAt).length;
            if (active >= this.limits.maxEnrollmentTokens) {
                throw fail(
                    'enrollment_token_limit_reached',
                    `Maximum of ${this.limits.maxEnrollmentTokens} enrollment invites reached`,
                    409
                );
            }

            const token = createOpaqueToken(ENROLLMENT_TOKEN_PREFIX);
            const at = isoAt(this._now());
            const record = {
                id: `inv_${randomHex(8)}`,
                label,
                tokenHash: hashSecret(token),
                pbxId,
                extension,
                maxUses,
                usedCount: 0,
                expiresAt: isoAt(this._now() + ttlMs),
                revokedAt: null,
                createdAt: at,
                createdBy: sanitizeActor(meta.actor),
                lastUsedAt: null,
                lastUsedIp: null
            };
            draft.enrollmentTokens.push(record);
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'enrollment.created',
                    target: record.id,
                    detail: `${label} (uses: ${maxUses}, expires: ${record.expiresAt})`
                },
                this.limits.auditEntries
            );
            return { token, record: publicEnrollment(record) };
        });
    }

    revokeEnrollmentToken(id, meta = {}) {
        return this._mutate((draft) => {
            const record = draft.enrollmentTokens.find((t) => t.id === id);
            if (!record) throw fail('enrollment_token_not_found', 'Enrollment invite not found', 404);
            if (record.revokedAt) return publicEnrollment(record);
            const at = isoAt(this._now());
            record.revokedAt = at;
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'enrollment.revoked',
                    target: record.id,
                    detail: record.label
                },
                this.limits.auditEntries
            );
            return publicEnrollment(record);
        });
    }

    _findEnrollmentToken(draft, token) {
        const digest = hashSecret(token);
        let match = null;
        for (const record of draft.enrollmentTokens) {
            if (timingSafeEqualHex(record.tokenHash, digest) && !match) match = record;
        }
        return match;
    }

    // --- device enrollment / approvals ------------------------------------

    enrollDevice(input = {}, meta = {}) {
        return this._mutate((draft) => {
            const token = requireString(input.token, 'token', { max: 256, min: 16, label: 'Enrollment token' });
            const platform = normalizePlatform(input.platform);
            const deviceUuid = normalizeDeviceUuid(input.deviceUuid);

            // UUID and instance hints are recorded for the operator; they never
            // authenticate anything on their own.
            const instanceId = optionalText(input.instanceId, 'instanceId', 128);
            const appVersion = optionalText(input.appVersion, 'appVersion', 40);
            const deviceName = optionalText(input.deviceName, 'deviceName', 80);
            const model = optionalText(input.model, 'model', 64);
            const osVersion = optionalText(input.osVersion, 'osVersion', 40);
            const requestIp = optionalText(meta.requestIp, 'requestIp', 64);

            const record = this._findEnrollmentToken(draft, token);
            if (!record) {
                throw fail('invalid_enrollment_token', 'Enrollment token is not valid', 401);
            }
            if (record.revokedAt) {
                throw fail('enrollment_token_revoked', 'Enrollment token has been revoked', 401);
            }
            if (record.expiresAt && Date.parse(record.expiresAt) <= this._now()) {
                throw fail('enrollment_token_expired', 'Enrollment token has expired', 401);
            }

            const at = isoAt(this._now());
            const sameDevice = draft.devices.filter(
                (d) => d.deviceUuid === deviceUuid && d.platform === platform
            );
            const alreadyApproved = sameDevice.find((d) => d.status === 'approved');
            if (alreadyApproved) {
                throw fail(
                    'device_already_approved',
                    'This device already has an approved enrollment; revoke it before enrolling again',
                    409
                );
            }
            const existingPending = sameDevice.find((d) => d.status === 'pending');
            if (existingPending) {
                if (existingPending.enrollmentTokenId !== record.id) {
                    throw fail(
                        'device_uuid_conflict',
                        'A pending device with this UUID already exists under a different invite',
                        409
                    );
                }
                Object.assign(existingPending, {
                    instanceId,
                    appVersion,
                    deviceName,
                    model,
                    osVersion,
                    requestIp,
                    enrollmentTokenId: record.id,
                    suggestedPbxId: record.pbxId,
                    suggestedExtension: record.extension
                });
                return { device: publicDevice(existingPending), tokenId: record.id, reused: true };
            }

            if (record.usedCount >= record.maxUses) {
                throw fail('enrollment_token_exhausted', 'Enrollment token has no remaining uses', 401);
            }
            const pendingCount = draft.devices.filter((d) => d.status === 'pending').length;
            if (pendingCount >= this.limits.maxPendingDevices) {
                throw fail(
                    'pending_cap_reached',
                    `Maximum of ${this.limits.maxPendingDevices} pending devices reached`,
                    409
                );
            }
            if (draft.devices.length >= this.limits.maxDevices) {
                throw fail('device_limit_reached', 'Device limit reached', 409);
            }

            record.usedCount += 1;
            record.lastUsedAt = at;
            record.lastUsedIp = requestIp;

            const device = {
                id: `dev_${randomHex(10)}`,
                status: 'pending',
                enrollmentMode: 'invite',
                platform,
                deviceUuid,
                instanceId,
                deviceName,
                appVersion,
                model,
                osVersion,
                requestIp,
                enrollmentTokenId: record.id,
                suggestedPbxId: record.pbxId,
                suggestedExtension: record.extension,
                claimHash: null,
                claimExpiresAt: null,
                claimRedeemedAt: null,
                requestedAt: at,
                reviewedAt: null,
                reviewedBy: null,
                reviewReason: null,
                pbxId: null,
                extension: null,
                secretHash: null,
                secretIssuedAt: null,
                lastSeenAt: null
            };
            draft.devices.push(device);
            pushAudit(
                draft,
                {
                    at,
                    actor: `device:${platform}`,
                    action: 'device.enrolled',
                    target: device.id,
                    detail: deviceName || deviceUuid.slice(0, 8)
                },
                this.limits.auditEntries
            );
            return { device: publicDevice(device), tokenId: record.id, reused: false };
        });
    }

    // --- automatic (claim) enrollment --------------------------------------

    /**
     * Anonymous enrollment for a device that only knows its gateway extension
     * and SIP password. Identity is the client-generated claim secret: the
     * pending row is upserted by the digest of that secret, never by UUID, so a
     * forged UUID can neither read nor replace another device's claim. The
     * secret itself is never stored, returned or logged.
     */
    enrollClaim(input = {}, meta = {}) {
        return this._mutate((draft) => {
            const claimSecret = normalizeClaimSecret(input.claimSecret);
            const digest = hashSecret(claimSecret);
            const platform = normalizePlatform(input.platform);
            const deviceUuid = normalizeDeviceUuid(input.deviceUuid);
            const extension = normalizeExtension(input.extension);
            const suggestedPbxId = optionalText(input.pbxId, 'pbxId', 64);
            if (suggestedPbxId && !draft.pbx.some(p => p.id === suggestedPbxId)) {
                throw fail('pbx_not_found', 'PBX not found', 404);
            }
            const instanceId = optionalText(input.instanceId, 'instanceId', 128);
            const appVersion = optionalText(input.appVersion, 'appVersion', 40);
            const deviceName = optionalText(input.deviceName, 'deviceName', 80);
            const model = optionalText(input.model, 'model', 64);
            const osVersion = optionalText(input.osVersion, 'osVersion', 40);
            const requestIp = optionalText(meta.requestIp, 'requestIp', 64);

            const now = this._now();
            const at = isoAt(now);
            this._pruneExpiredClaims(draft, now);

            const existing = this._findByClaimHash(draft.devices, digest);
            if (existing) {
                if (existing.status === 'rejected') {
                    throw fail(
                        'device_rejected',
                        'This enrollment request was rejected; enroll again with a new claim secret',
                        403
                    );
                }
                if (existing.status === 'revoked') {
                    throw fail(
                        'device_revoked',
                        'This enrollment was revoked; enroll again with a new claim secret',
                        403
                    );
                }
                // A claim belongs to one installation identity. Possession of it
                // must not transfer an existing approval to another platform/UUID.
                if (existing.platform !== platform || existing.deviceUuid !== deviceUuid) {
                    throw fail('claim_identity_mismatch', 'Claim belongs to a different device identity', 409);
                }
                const assignmentChanged = existing.suggestedExtension !== extension
                    || (suggestedPbxId && suggestedPbxId !== (existing.suggestedPbxId || existing.pbxId));
                if (existing.status === 'approved' && assignmentChanged) {
                    const pendingCount = draft.devices.filter(d => d.status === 'pending' && this._visibleDevice(d)).length;
                    if (pendingCount >= this.limits.maxPendingDevices) {
                        throw fail('pending_cap_reached', 'Pending device limit reached', 409);
                    }
                    // Account changes are new requests, never implicit approval.
                    // Keep the claim for retry-safe polling but retire the old
                    // credential and all tickets/sockets from its authorization.
                    Object.assign(existing, {
                        suggestedPbxId: suggestedPbxId || existing.suggestedPbxId || existing.pbxId,
                        status: 'pending', pbxId: null, extension: null,
                        secretHash: null, secretIssuedAt: null, claimRedeemedAt: null,
                        reviewedAt: null, reviewedBy: null, reviewReason: null,
                        authorizationRevision: (existing.authorizationRevision || 0) + 1
                    });
                    pushAudit(draft, { at, actor: `device:${platform}`, action: 'claim.reapproval_requested',
                        target: existing.id, detail: `extension ${extension}` }, this.limits.auditEntries);
                }
                // Metadata-only retries preserve approval. Request identity
                // changes above must pass through administrator review again.
                Object.assign(existing, {
                    platform,
                    deviceUuid,
                    instanceId,
                    appVersion,
                    deviceName,
                    model,
                    osVersion,
                    requestIp,
                    suggestedExtension: extension,
                    ...(Object.hasOwn(input, 'pbxId') ? { suggestedPbxId } : {}),
                    lastSeenAt: at
                });
                if (existing.status === 'pending') {
                    existing.requestedAt = at;
                    existing.claimExpiresAt = isoAt(now + this.limits.claimTtlMs);
                }
                return {
                    device: publicDevice(existing),
                    status: existing.status,
                    reused: true,
                    created: false
                };
            }

            // A different claim presenting the same install identity must not
            // inherit the first claim's fate. Establishing a brand-new request
            // is allowed only when no live request or approval holds the UUID.
            const sameDevice = draft.devices.filter(
                (d) =>
                    d.deviceUuid === deviceUuid &&
                    d.platform === platform &&
                    this._visibleDevice(d)
            );
            if (sameDevice.some((d) => d.status === 'approved')) {
                throw fail(
                    'device_already_approved',
                    'This device already has an approved enrollment; revoke it before enrolling again',
                    409
                );
            }
            if (sameDevice.some((d) => d.status === 'pending')) {
                throw fail(
                    'device_uuid_conflict',
                    'A pending device with this UUID already exists under a different claim',
                    409
                );
            }

            const pendingCount = draft.devices.filter(
                (d) => d.status === 'pending' && this._visibleDevice(d)
            ).length;
            if (pendingCount >= this.limits.maxPendingDevices) {
                throw fail(
                    'pending_cap_reached',
                    `Maximum of ${this.limits.maxPendingDevices} pending devices reached`,
                    409
                );
            }
            if (draft.devices.length >= this.limits.maxDevices) {
                throw fail('device_limit_reached', 'Device limit reached', 409);
            }

            const device = {
                id: `dev_${randomHex(10)}`,
                status: 'pending',
                enrollmentMode: 'claim',
                platform,
                deviceUuid,
                instanceId,
                deviceName,
                appVersion,
                model,
                osVersion,
                requestIp,
                enrollmentTokenId: null,
                suggestedPbxId,
                suggestedExtension: extension,
                claimHash: digest,
                claimExpiresAt: isoAt(now + this.limits.claimTtlMs),
                claimRedeemedAt: null,
                requestedAt: at,
                reviewedAt: null,
                reviewedBy: null,
                reviewReason: null,
                pbxId: null,
                extension: null,
                secretHash: null,
                secretIssuedAt: null,
                lastSeenAt: at
            };
            draft.devices.push(device);
            pushAudit(
                draft,
                {
                    at,
                    actor: `device:${platform}`,
                    action: 'claim.requested',
                    target: device.id,
                    detail: `extension ${extension}${deviceName ? ` — ${deviceName}` : ''}`
                },
                this.limits.auditEntries
            );
            return { device: publicDevice(device), status: 'pending', reused: false, created: true };
        });
    }

    /**
     * Status + redemption for an automatic enrollment. Safe to retry: while the
     * request is pending it answers `pending` without touching the document,
     * and once approved it activates the client-held credential idempotently
     * and returns the assignment. A rejected or revoked claim stays dead until
     * the device enrolls again with a fresh claim secret.
     */
    redeemClaim(input = {}) {
        const claimSecret = normalizeClaimSecret(input.claimSecret);
        const deviceId = normalizeDeviceId(input.deviceId);
        const digest = hashSecret(claimSecret);

        return this._mutateLazy((draft) => {
            const device = draft.devices.find((d) => d.id === deviceId);
            if (!device || !device.claimHash || !timingSafeEqualHex(device.claimHash, digest)) {
                throw fail('invalid_claim', 'Claim credentials are not valid', 401);
            }
            const now = this._now();

            if (device.status === 'pending') {
                if (this._claimExpired(device, now)) {
                    throw fail(
                        'claim_expired',
                        'This enrollment request expired; enroll again to retry',
                        410
                    );
                }
                return {
                    commit: false,
                    value: {
                        status: 'pending',
                        device: publicDevice(device),
                        assignment: null,
                        retryAfterMs: CLAIM_RETRY_HINT_MS
                    }
                };
            }
            if (device.status === 'rejected') {
                throw fail('device_rejected', 'This enrollment was rejected by the administrator', 403);
            }
            if (device.status === 'revoked') {
                throw fail('device_revoked', 'This enrollment was revoked; contact the administrator', 403);
            }

            const assignment = this._claimAssignment(draft, device);
            const at = isoAt(now);
            const firstRedemption = !device.claimRedeemedAt;
            if (!device.secretHash) {
                // Activate the credential the device already holds; nothing is
                // minted here, so a retry can never lose a response secret.
                device.secretHash = device.claimHash;
                device.secretIssuedAt = at;
            }
            device.claimRedeemedAt = device.claimRedeemedAt || at;
            device.lastSeenAt = at;
            if (firstRedemption) {
                pushAudit(
                    draft,
                    {
                        at,
                        actor: `device:${device.platform}`,
                        action: 'claim.redeemed',
                        target: device.id,
                        detail: `${assignment.pbxName} / ${device.extension}`
                    },
                    this.limits.auditEntries
                );
            }
            return {
                commit: true,
                value: {
                    status: 'approved',
                    device: publicDevice(device),
                    assignment,
                    redeemedNow: firstRedemption
                }
            };
        });
    }

    /** Drops abandoned claim requests that expired more than one TTL ago. */
    _pruneExpiredClaims(draft, now) {
        const retention = this.limits.claimTtlMs;
        const kept = draft.devices.filter((device) => {
            if (device.enrollmentMode !== 'claim' || device.status !== 'pending' || !device.claimExpiresAt) {
                return true;
            }
            return Date.parse(device.claimExpiresAt) + retention > now;
        });
        if (kept.length === draft.devices.length) return 0;
        const removed = draft.devices.length - kept.length;
        draft.devices = kept;
        pushAudit(
            draft,
            {
                at: isoAt(now),
                actor: 'system',
                action: 'claim.expired',
                target: null,
                detail: `${removed} abandoned request(s) pruned`
            },
            this.limits.auditEntries
        );
        return removed;
    }

    approveDevice(id, input = {}, meta = {}) {
        return this._mutate((draft) => {
            const device = draft.devices.find((d) => d.id === id);
            if (!device) throw fail('device_not_found', 'Device not found', 404);
            if (device.status !== 'pending') {
                throw fail('invalid_device_state', `Device is ${device.status}`, 409);
            }
            const pbxId = requireString(input.pbxId, 'pbxId', { max: 64, label: 'PBX' });
            const pbx = draft.pbx.find((p) => p.id === pbxId);
            if (!pbx) throw fail('pbx_not_found', 'PBX not found', 404);
            if (!pbx.enabled) {
                throw fail('pbx_disabled', 'PBX is disabled; enable it before approving devices', 409);
            }
            const extension = normalizeExtension(input.extension);
            const at = isoAt(this._now());
            let policy = draft.extensions.find(e => e.pbxId === pbx.id && e.extension === extension);
            if (!policy && pbx.management && !pbx.management.extensionPolicyRequired) {
                policy = {
                    id: `ext_${randomHex(8)}`,
                    pbxId: pbx.id,
                    extension,
                    name: `Extension ${extension}`,
                    status: 'enabled',
                    maxDevices: 5,
                    allowedPlatforms: ['android', 'desktop', 'chrome', 'ios'],
                    createdAt: at,
                    updatedAt: at,
                };
                draft.extensions.push(policy);
                pushAudit(
                    draft,
                    {
                        at,
                        actor: meta.actor,
                        action: 'extension.added',
                        target: policy.id,
                        detail: `${pbx.name} / ${extension} (auto-created on device approval)`
                    },
                    this.limits.auditEntries
                );
            }
            this._assertManagedAccess(draft, { ...device, extension }, pbx);
            if (policy && draft.devices.filter(d => d.status === 'approved' && d.pbxId === pbx.id && d.extension === extension).length >= policy.maxDevices) {
                throw fail('extension_device_limit', 'Extension device limit reached', 409);
            }

            if (device.enrollmentMode === 'claim') {
                if (this._claimExpired(device, this._now())) {
                    throw fail(
                        'claim_expired',
                        'This automatic enrollment request expired; the device has to enroll again',
                        409
                    );
                }
                // The claim is preserved. Approval assigns the tenant route; the
                // device activates the credential it already generated by
                // redeeming its claim. Nothing is minted here, so the operator
                // has no secret to copy or leak.
                device.status = 'approved';
                device.pbxId = pbx.id;
                device.extension = extension;
                device.secretHash = null;
                device.secretIssuedAt = null;
                device.reviewedAt = at;
                device.reviewedBy = sanitizeActor(meta.actor);
                device.reviewReason = null;
                pushAudit(
                    draft,
                    {
                        at,
                        actor: meta.actor,
                        action: 'device.approved',
                        target: device.id,
                        detail: `${pbx.name} / ${extension} (automatic)`
                    },
                    this.limits.auditEntries
                );
                return { device: publicDevice(device), secret: null, enrollmentMode: 'claim' };
            }

            const secret = createOpaqueToken(DEVICE_SECRET_PREFIX);

            device.status = 'approved';
            device.pbxId = pbx.id;
            device.extension = extension;
            device.secretHash = hashSecret(secret);
            device.secretIssuedAt = at;
            device.reviewedAt = at;
            device.reviewedBy = sanitizeActor(meta.actor);
            device.reviewReason = null;

            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'device.approved',
                    target: device.id,
                    detail: `${pbx.name} / ${extension}`
                },
                this.limits.auditEntries
            );
            // The plaintext secret is returned once and never persisted.
            return { device: publicDevice(device), secret, enrollmentMode: 'invite' };
        });
    }

    rejectDevice(id, input = {}, meta = {}) {
        return this._mutate((draft) => {
            const device = draft.devices.find((d) => d.id === id);
            if (!device) throw fail('device_not_found', 'Device not found', 404);
            if (device.status !== 'pending') {
                throw fail('invalid_device_state', `Device is ${device.status}`, 409);
            }
            const reason = optionalText(input.reason, 'reason', 120) || 'rejected';
            const at = isoAt(this._now());
            device.status = 'rejected';
            device.secretHash = null;
            device.reviewedAt = at;
            device.reviewedBy = sanitizeActor(meta.actor);
            device.reviewReason = reason;
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'device.rejected',
                    target: device.id,
                    detail: reason
                },
                this.limits.auditEntries
            );
            return publicDevice(device);
        });
    }

    revokeDevice(id, input = {}, meta = {}) {
        return this._mutate((draft) => {
            const device = draft.devices.find((d) => d.id === id);
            if (!device) throw fail('device_not_found', 'Device not found', 404);
            if (device.status !== 'approved') {
                throw fail('invalid_device_state', `Device is ${device.status}`, 409);
            }
            const reason = optionalText(input.reason, 'reason', 120) || 'revoked';
            const at = isoAt(this._now());
            device.status = 'revoked';
            device.secretHash = null;
            device.reviewedAt = at;
            device.reviewedBy = sanitizeActor(meta.actor);
            device.reviewReason = reason;
            pushAudit(
                draft,
                {
                    at,
                    actor: meta.actor,
                    action: 'device.revoked',
                    target: device.id,
                    detail: reason
                },
                this.limits.auditEntries
            );
            return publicDevice(device);
        });
    }

    /**
     * Verify the opaque secret issued at approval time.
     * Returns `{ ok: false }` for unknown, unapproved, revoked or wrong-secret
     * devices — never distinguishing the cases to the caller.
     */
    verifyDeviceSecret(deviceId, secret) {
        this._assertReady();
        const device = this.state.devices.find((d) => d.id === deviceId);
        if (!device || device.status !== 'approved' || !device.secretHash) {
            return { ok: false };
        }
        if (typeof secret !== 'string' || secret.length < 16 || secret.length > 256) {
            return { ok: false };
        }
        if (!timingSafeEqualHex(device.secretHash, hashSecret(secret))) {
            return { ok: false };
        }
        const pbx = this.state.pbx.find(p => p.id === device.pbxId);
        if (!pbx?.enabled) return { ok: false };
        try { this._assertManagedAccess(this.state, device, pbx); }
        catch { return { ok: false }; }
        return { ok: true, device: publicDevice(device) };
    }

    getApprovedDevice(deviceId) {
        this._assertReady();
        const device = this.state.devices.find(
            (d) => d.id === deviceId && d.status === 'approved'
        );
        if (!device) return null;
        const pbx = this.state.pbx.find(p => p.id === device.pbxId);
        if (!pbx?.enabled) return null;
        try { this._assertManagedAccess(this.state, device, pbx); }
        catch { return null; }
        return publicDevice(device);
    }

    touchDevice(deviceId) {
        return this._mutate((draft) => {
            const device = draft.devices.find((d) => d.id === deviceId);
            if (!device) return null;
            device.lastSeenAt = isoAt(this._now());
            return publicDevice(device);
        });
    }
}

module.exports = {
    ControlStore,
    ControlStoreError,
    SCHEMA_VERSION,
    DEFAULT_LIMITS,
    ENROLLMENT_TOKEN_PREFIX,
    DEVICE_SECRET_PREFIX,
    CLAIM_SECRET_MIN_LENGTH,
    CLAIM_SECRET_MAX_LENGTH,
    CLAIM_RETRY_HINT_MS,
    // exported for tests / profiling integrations
    createOpaqueToken,
    hashSecret,
    timingSafeEqualHex,
    normalizeMediaIps,
    normalizeUrl,
    normalizeExtension,
    normalizeClaimSecret,
    publicDevice,
    publicPbx,
    publicEnrollment
};
