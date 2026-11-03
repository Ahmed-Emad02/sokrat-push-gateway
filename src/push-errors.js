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
    'registration token is not a valid fcm registration token',
    'registration token is not a valid registration token',
]);

function normalizeErrorCode(error) {
    return String(error?.code || error?.message || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ');
}

function isPermanentTokenError(error) {
    const code = normalizeErrorCode(error);
    const message = String(error?.message || '').trim().toLowerCase().replace(/\s+/g, ' ');
    if (message && /registration token is not a valid(?: fcm)? registration token/.test(message)) return true;
    if (!code) return false;
    if (PERMANENT_TOKEN_ERRORS.has(code)) return true;
    // Firebase Admin sometimes wraps a malformed token as invalid-argument
    // while keeping a specific token message in error.message.
    if (/registration token is not a valid(?: fcm)? registration token/i.test(code)) return true;
    // Firebase sometimes wraps the code in a longer message. Match only the
    // known permanent suffixes, never the generic word "invalid".
    return /(?:^|\s)(?:messaging\/)?(?:registration-token-not-registered|invalid-registration-token|unregistered|baddevicetoken|notregistered)(?:$|\s|:)/i.test(code);
}

module.exports = { fingerprintToken, isPermanentTokenError, PERMANENT_TOKEN_ERRORS };
