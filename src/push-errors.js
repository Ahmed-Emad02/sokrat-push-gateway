'use strict';
const crypto = require('node:crypto');

/**
 * Stable, non-reversible fingerprint for a push token. Raw tokens are never
 * written to logs or error fields.
 */
function fingerprintToken(token) {
    if (typeof token !== 'string' || !token) return '';
    return crypto.createHash('sha256').update(token).digest('hex');
}

// Firebase Admin and APNs use different spellings; keep this list explicit.
// Do not add generic "invalid" matches: payload errors must remain retryable.
const PERMANENT_TOKEN_ERRORS = new Set([
    'messaging/registration-token-not-registered',
    'messaging/invalid-registration-token',
    'messaging/unregistered',
    'baddevicetoken',
    'unregistered',
    'notregistered',
    'invalid device token',
    'registration token is not registered',
]);

function normalizeErrorCode(error) {
    return String(error?.code || error?.message || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ');
}

function isPermanentTokenError(error) {
    const code = normalizeErrorCode(error);
    if (!code) return false;
    if (PERMANENT_TOKEN_ERRORS.has(code)) return true;
    // Firebase sometimes wraps the code in a longer message. Match only the
    // known permanent suffixes, never the generic word "invalid".
    return /(?:^|\s)(?:messaging\/)?(?:registration-token-not-registered|invalid-registration-token|unregistered|baddevicetoken|notregistered)(?:$|\s|:)/i.test(code);
}

module.exports = { fingerprintToken, isPermanentTokenError, PERMANENT_TOKEN_ERRORS };
