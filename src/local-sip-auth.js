'use strict';
const crypto = require('node:crypto');

/**
 * Verify an extension HMAC proof with the PBX's existing whoami verifier.
 * The request headers are a short-lived proof, not a reusable SIP password.
 */
async function verifyLocalExtensionHeaders(extension, headers) {
    if (process.env.LOCAL_SIP_AUTH !== 'true') { console.warn('[local-auth] disabled'); return false; }
    if (!/^[0-9]{1,12}$/.test(String(extension || ''))) { console.warn('[local-auth] invalid extension'); return false; }
    const base = String(process.env.PBX_AUTH_URL || '').replace(/\/$/, '');
    if (!/^http:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(base)) { console.warn('[local-auth] invalid PBX_AUTH_URL'); return false; }
    const required = ['X-Sokrat-Extension', 'X-Sokrat-Timestamp', 'X-Sokrat-Signature'];
    if (required.some(name => typeof headers?.[name] !== 'string' || !headers[name])) { console.warn('[local-auth] missing extension proof'); return false; }
    try {
        const response = await fetch(`${base}/api/extension/v1/whoami`, {
            headers: {
                'X-Sokrat-Extension': headers['X-Sokrat-Extension'],
                'X-Sokrat-Timestamp': headers['X-Sokrat-Timestamp'],
                'X-Sokrat-Signature': headers['X-Sokrat-Signature'],
            },
            signal: AbortSignal.timeout(5000),
            redirect: 'error',
        });
        if (!response.ok) { console.warn('[local-auth] PBX proof rejected HTTP', response.status); return false; }
        const identity = await response.json();
        const ok = identity.success === true && identity.extension === headers['X-Sokrat-Extension'] && identity.extension === String(extension);
        if (!ok) console.warn('[local-auth] PBX identity mismatch');
        return ok;
    } catch (error) {
        console.warn('[local-auth] extension proof verification failed:', error?.code || 'unknown');
        return false;
    }
}

module.exports = { verifyLocalExtensionHeaders };
