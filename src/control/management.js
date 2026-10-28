'use strict';

/**
 * Opt-in PBX management metadata + per-extension policy — **pure validation**.
 *
 * This module is intentionally dependency-free (Node built-ins only) and does
 * no I/O, no persistence and no routing. It answers exactly one question:
 * "is this admin input shaped correctly, and what is its canonical form?".
 *
 * Scope note (read before trusting it):
 * - This is management **foundation** only. It does not authenticate an
 *   operator, does not verify that a PBX approved anything, and does not
 *   prove ownership of a hostname or installation. Approval is a recorded
 *   administrative claim (`approvalStatus`), never an automatic proof.
 * - Nothing here enables tenant routing, pushes, tickets or ICE. Callers must
 *   still enforce authorization, audit and storage semantics elsewhere.
 * - It never returns or accepts credentials, tokens, URLs or IP addresses.
 *
 * Contract
 * --------
 * normalizeLoginHostname(value) -> string | null
 *   - `undefined` / `null` / `''` / whitespace-only  -> `null`
 *     (documented: "no login hostname configured", not an error).
 *   - Accepts a bare DNS hostname only; returns lower-case canonical form.
 *   - One trailing dot (absolute form) is stripped, so `PBX.Example.COM.`
 *     canonicalises to `pbx.example.com`.
 *   - Rejects: schemes/URLs, ports, credentials, paths, wildcards, IPv4/IPv6
 *     literals, numeric TLDs, single-label names, `localhost` and
 *     `*.localhost`, empty labels, labels > 63 chars, names > 253 chars,
 *     non-`[a-z0-9-]` characters, and leading/trailing hyphens in a label.
 *   - Throws `ManagementPolicyError` (code `invalid_loginHostname`,
 *     status 400) for anything that is a non-empty invalid hostname.
 *
 * normalizeManagement(input, existing = null) -> {
 *     customer, loginHostname, extensionPolicyRequired,
 *     approvalStatus, reviewedInstallationId
 * }
 *   - `customer`               optional string, trimmed, max 64, `''` -> null.
 *   - `loginHostname`          optional, canonicalised by the helper above.
 *   - `extensionPolicyRequired` boolean, default `false`.
 *   - `approvalStatus`         'pending' | 'approved' | 'suspended' | 'retired',
 *                              default 'pending' for new managed data.
 *   - `reviewedInstallationId` optional string, trimmed, max 128, `''` -> null.
 *   - Strict types: no string/number coercion for booleans or numbers.
 *   - Fields **omitted** (`undefined` or absent) are copied from `existing`;
 *     an explicit `null` clears an optional field. This pure helper can repair
 *     invalid fallback values supplied as `existing`; the ControlStore loader
 *     instead validates persisted records as fresh input and fails closed on
 *     corruption without rewriting the file. It never auto-repairs policies.
 *
 * normalizeExtensionPolicy(input, existing = null) -> {
 *     extension, name, status, maxDevices, allowedPlatforms
 * }
 *   - `extension`  required, `[0-9A-Za-z*#._-]`, 1..32 chars, case preserved.
 *   - `name`       optional string, trimmed, max 128, `''` -> null.
 *   - `status`     'enabled' | 'suspended' | 'disabled', default 'disabled'
 *                  (an extension is never enabled by omission).
 *   - `maxDevices` integer 1..20, default 5.
 *   - `allowedPlatforms` non-empty subset of
 *                  'android' | 'ios' | 'desktop' | 'chrome'; default all four.
 *                  Duplicates are dropped and the result is returned in
 *                  canonical order, so callers can compare arrays directly.
 *   - Same omit/preserve and strict-type rules as above.
 *
 * Every failure is a `ManagementPolicyError` (an `Error`) carrying a stable
 * `code` and `status === 400`, so an HTTP layer can map it directly.
 */

const net = require('node:net');

const HOSTNAME_MAX_LENGTH = 253;
const LABEL_MAX_LENGTH = 63;
const LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const NUMERIC_LABEL_PATTERN = /^\d+$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const WHITESPACE = /\s/;

const CUSTOMER_MAX_LENGTH = 64;
const INSTALLATION_ID_MAX_LENGTH = 128;
const EXTENSION_MAX_LENGTH = 32;
const POLICY_NAME_MAX_LENGTH = 128;

const EXTENSION_PATTERN = /^[0-9A-Za-z*#._-]{1,32}$/;

const APPROVAL_STATUSES = Object.freeze([
    'pending',
    'approved',
    'suspended',
    'retired'
]);

const POLICY_STATUSES = Object.freeze([
    'enabled',
    'suspended',
    'disabled'
]);

/** Canonical platform order; also the default for a new policy. */
const PLATFORMS = Object.freeze([
    'android',
    'ios',
    'desktop',
    'chrome'
]);

const APPROVAL_STATUS_SET = new Set(APPROVAL_STATUSES);
const POLICY_STATUS_SET = new Set(POLICY_STATUSES);
const PLATFORM_SET = new Set(PLATFORMS);

const MANAGEMENT_DEFAULTS = Object.freeze({
    customer: null,
    loginHostname: null,
    extensionPolicyRequired: false,
    approvalStatus: 'pending',
    reviewedInstallationId: null
});

const EXTENSION_POLICY_DEFAULTS = Object.freeze({
    name: null,
    status: 'disabled',
    maxDevices: 5,
    allowedPlatforms: PLATFORMS
});

class ManagementPolicyError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.name = 'ManagementPolicyError';
        this.code = code;
        this.status = status;
    }
}

function fail(code, message) {
    return new ManagementPolicyError(code, message, 400);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function assertPlainObject(value, field) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw fail(`invalid_${field}`, `${field} must be an object`);
    }
    return value;
}

function hasOwn(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
}

/**
 * `undefined` (or absent) means "keep whatever is stored". An explicit `null`
 * means "clear this optional field".
 */
function provided(input, key) {
    return hasOwn(input, key) && input[key] !== undefined;
}

function optionalText(value, field, max, label) {
    if (value === null) return null;
    if (typeof value !== 'string') {
        throw fail(`invalid_${field}`, `${label} must be a string`);
    }
    const text = value.trim();
    if (!text) return null;
    if (text.length > max) {
        throw fail(`invalid_${field}`, `${label} must be at most ${max} characters`);
    }
    if (CONTROL_CHARS.test(text)) {
        throw fail(`invalid_${field}`, `${label} must not contain control characters`);
    }
    return text;
}

/**
 * Reuse a persisted value, but never let corrupt legacy data break an update:
 * if the stored value no longer validates it is replaced by the default.
 */
function reuseExisting(existing, key, normalize, fallback) {
    if (!existing || !hasOwn(existing, key)) return fallback;
    try {
        return normalize(existing[key]);
    } catch {
        return fallback;
    }
}

// ---------------------------------------------------------------------------
// normalizeLoginHostname
// ---------------------------------------------------------------------------

function normalizeLoginHostname(value) {
    if (value === undefined || value === null) return null;
    if (typeof value !== 'string') {
        throw fail('invalid_loginHostname', 'loginHostname must be a string');
    }

    let text = value.trim();
    if (!text) return null;

    if (WHITESPACE.test(text)) {
        throw fail('invalid_loginHostname', 'loginHostname must not contain whitespace');
    }
    if (CONTROL_CHARS.test(text)) {
        throw fail('invalid_loginHostname', 'loginHostname must not contain control characters');
    }
    if (text.includes('*')) {
        throw fail('invalid_loginHostname', 'loginHostname must not contain wildcards');
    }
    if (text.includes('/')) {
        throw fail('invalid_loginHostname', 'loginHostname must be a bare hostname without a scheme or path');
    }
    if (text.includes('@')) {
        throw fail('invalid_loginHostname', 'loginHostname must not contain credentials');
    }
    if (text.includes(':')) {
        throw fail('invalid_loginHostname', 'loginHostname must not include a port or scheme');
    }
    if (text.includes('?') || text.includes('#') || text.includes('[') || text.includes(']')) {
        throw fail('invalid_loginHostname', 'loginHostname must be a bare DNS hostname');
    }

    // Absolute (trailing-dot) form is accepted and canonicalised away.
    if (text.endsWith('.')) text = text.slice(0, -1);
    if (!text) {
        throw fail('invalid_loginHostname', 'loginHostname must not be empty');
    }

    const canonical = text.toLowerCase();

    if (net.isIP(canonical) !== 0) {
        throw fail('invalid_loginHostname', 'loginHostname must be a DNS hostname, not an IP address');
    }
    if (canonical.length > HOSTNAME_MAX_LENGTH) {
        throw fail(
            'invalid_loginHostname',
            `loginHostname must be at most ${HOSTNAME_MAX_LENGTH} characters`
        );
    }
    if (canonical === 'localhost' || canonical.endsWith('.localhost')) {
        throw fail('invalid_loginHostname', 'loginHostname must not be localhost');
    }

    const labels = canonical.split('.');
    if (labels.length < 2) {
        throw fail('invalid_loginHostname', 'loginHostname must be a fully qualified DNS hostname');
    }
    for (const label of labels) {
        if (!label) {
            throw fail('invalid_loginHostname', 'loginHostname must not contain empty labels');
        }
        if (label.length > LABEL_MAX_LENGTH) {
            throw fail(
                'invalid_loginHostname',
                `loginHostname labels must be at most ${LABEL_MAX_LENGTH} characters`
            );
        }
        if (!LABEL_PATTERN.test(label)) {
            throw fail(
                'invalid_loginHostname',
                'loginHostname labels may only contain a-z, 0-9 and inner hyphens'
            );
        }
    }
    if (labels.every((label) => NUMERIC_LABEL_PATTERN.test(label))) {
        throw fail('invalid_loginHostname', 'loginHostname must be a DNS hostname, not an IP address');
    }
    if (NUMERIC_LABEL_PATTERN.test(labels[labels.length - 1])) {
        throw fail('invalid_loginHostname', 'loginHostname must not end in a numeric TLD');
    }

    return canonical;
}

// ---------------------------------------------------------------------------
// normalizeManagement
// ---------------------------------------------------------------------------

function normalizeApprovalStatus(value) {
    if (typeof value !== 'string' || !APPROVAL_STATUS_SET.has(value)) {
        throw fail(
            'invalid_approvalStatus',
            `approvalStatus must be one of: ${APPROVAL_STATUSES.join(', ')}`
        );
    }
    return value;
}

function normalizeCustomer(value) {
    return optionalText(value, 'customer', CUSTOMER_MAX_LENGTH, 'customer');
}

function normalizeInstallationId(value) {
    return optionalText(
        value,
        'reviewedInstallationId',
        INSTALLATION_ID_MAX_LENGTH,
        'reviewedInstallationId'
    );
}

function normalizeBoolean(value, field) {
    if (typeof value !== 'boolean') {
        throw fail(`invalid_${field}`, `${field} must be a boolean`);
    }
    return value;
}

function normalizeManagement(input, existing = null) {
    assertPlainObject(input, 'input');
    if (existing !== null && existing !== undefined) {
        assertPlainObject(existing, 'existing');
    }

    const customer = provided(input, 'customer')
        ? normalizeCustomer(input.customer)
        : reuseExisting(existing, 'customer', normalizeCustomer, MANAGEMENT_DEFAULTS.customer);

    const loginHostname = provided(input, 'loginHostname')
        ? normalizeLoginHostname(input.loginHostname)
        : reuseExisting(
            existing,
            'loginHostname',
            normalizeLoginHostname,
            MANAGEMENT_DEFAULTS.loginHostname
        );

    const extensionPolicyRequired = provided(input, 'extensionPolicyRequired')
        ? normalizeBoolean(input.extensionPolicyRequired, 'extensionPolicyRequired')
        : reuseExisting(
            existing,
            'extensionPolicyRequired',
            (value) => normalizeBoolean(value, 'extensionPolicyRequired'),
            MANAGEMENT_DEFAULTS.extensionPolicyRequired
        );

    const approvalStatus = provided(input, 'approvalStatus')
        ? normalizeApprovalStatus(input.approvalStatus)
        : reuseExisting(
            existing,
            'approvalStatus',
            normalizeApprovalStatus,
            MANAGEMENT_DEFAULTS.approvalStatus
        );

    const reviewedInstallationId = provided(input, 'reviewedInstallationId')
        ? normalizeInstallationId(input.reviewedInstallationId)
        : reuseExisting(
            existing,
            'reviewedInstallationId',
            normalizeInstallationId,
            MANAGEMENT_DEFAULTS.reviewedInstallationId
        );

    return {
        customer,
        loginHostname,
        extensionPolicyRequired,
        approvalStatus,
        reviewedInstallationId
    };
}

// ---------------------------------------------------------------------------
// normalizeExtensionPolicy
// ---------------------------------------------------------------------------

function normalizeExtension(value) {
    if (typeof value !== 'string') {
        throw fail('invalid_extension', 'extension is required and must be a string');
    }
    const text = value.trim();
    if (!text) {
        throw fail('invalid_extension', 'extension is required');
    }
    if (text.length > EXTENSION_MAX_LENGTH) {
        throw fail(
            'invalid_extension',
            `extension must be at most ${EXTENSION_MAX_LENGTH} characters`
        );
    }
    if (!EXTENSION_PATTERN.test(text)) {
        throw fail(
            'invalid_extension',
            'extension may only contain letters, digits and * # . _ -'
        );
    }
    return text;
}

function normalizePolicyName(value) {
    return optionalText(value, 'name', POLICY_NAME_MAX_LENGTH, 'name');
}

function normalizePolicyStatus(value) {
    if (typeof value !== 'string' || !POLICY_STATUS_SET.has(value)) {
        throw fail('invalid_status', `status must be one of: ${POLICY_STATUSES.join(', ')}`);
    }
    return value;
}

function normalizeMaxDevices(value) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 20) {
        throw fail('invalid_maxDevices', 'maxDevices must be an integer between 1 and 20');
    }
    return value;
}

function normalizeAllowedPlatforms(value) {
    if (!Array.isArray(value)) {
        throw fail('invalid_allowedPlatforms', 'allowedPlatforms must be an array');
    }
    if (value.length === 0) {
        throw fail('invalid_allowedPlatforms', 'allowedPlatforms must not be empty');
    }
    const selected = new Set();
    for (const entry of value) {
        if (typeof entry !== 'string') {
            throw fail('invalid_allowedPlatforms', 'allowedPlatforms entries must be strings');
        }
        const platform = entry.trim().toLowerCase();
        if (!PLATFORM_SET.has(platform)) {
            throw fail(
                'invalid_allowedPlatforms',
                `allowedPlatforms entries must be one of: ${PLATFORMS.join(', ')}`
            );
        }
        selected.add(platform);
    }
    // Duplicates collapse; canonical order keeps comparisons deterministic.
    return PLATFORMS.filter((platform) => selected.has(platform));
}

function normalizeExtensionPolicy(input, existing = null) {
    assertPlainObject(input, 'input');
    if (existing !== null && existing !== undefined) {
        assertPlainObject(existing, 'existing');
    }

    let extension;
    if (provided(input, 'extension')) {
        extension = normalizeExtension(input.extension);
    } else if (existing && existing.extension !== undefined && existing.extension !== null) {
        extension = normalizeExtension(existing.extension);
    } else {
        throw fail('invalid_extension', 'extension is required');
    }

    const name = provided(input, 'name')
        ? normalizePolicyName(input.name)
        : reuseExisting(existing, 'name', normalizePolicyName, EXTENSION_POLICY_DEFAULTS.name);

    const status = provided(input, 'status')
        ? normalizePolicyStatus(input.status)
        : reuseExisting(existing, 'status', normalizePolicyStatus, EXTENSION_POLICY_DEFAULTS.status);

    const maxDevices = provided(input, 'maxDevices')
        ? normalizeMaxDevices(input.maxDevices)
        : reuseExisting(
            existing,
            'maxDevices',
            normalizeMaxDevices,
            EXTENSION_POLICY_DEFAULTS.maxDevices
        );

    // Fresh array per call: callers may sort/splice the result safely.
    const allowedPlatforms = provided(input, 'allowedPlatforms')
        ? normalizeAllowedPlatforms(input.allowedPlatforms)
        : reuseExisting(
            existing,
            'allowedPlatforms',
            normalizeAllowedPlatforms,
            [...PLATFORMS]
        );

    return {
        extension,
        name,
        status,
        maxDevices,
        allowedPlatforms
    };
}

module.exports = {
    ManagementPolicyError,
    normalizeLoginHostname,
    normalizeManagement,
    normalizeExtensionPolicy,
    APPROVAL_STATUSES,
    POLICY_STATUSES,
    PLATFORMS,
    MANAGEMENT_DEFAULTS,
    EXTENSION_POLICY_DEFAULTS,
    CUSTOMER_MAX_LENGTH,
    INSTALLATION_ID_MAX_LENGTH,
    EXTENSION_MAX_LENGTH,
    POLICY_NAME_MAX_LENGTH
};
