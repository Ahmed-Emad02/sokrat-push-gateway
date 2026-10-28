'use strict';

/**
 * Authentication primitives for the Sokrat control dashboard.
 *
 * - Admin password: scrypt with per-install salt. The recommended source is
 *   `CONTROL_ADMIN_PASSWORD_HASH` (already-hashed). A plaintext
 *   `CONTROL_ADMIN_PASSWORD` may be supplied as a bootstrap secret; it is
 *   hashed in memory at first use and never written to disk. There is no
 *   built-in default credential anywhere in this module.
 * - Sessions: opaque 256-bit identifiers held in memory (a restart signs the
 *   operator out), HttpOnly + SameSite=Strict cookies, idle + absolute expiry.
 * - CSRF: per-session token, compared in constant time.
 * - Login throttling: per-address failure window with lockout.
 * - Exposure guard: the console is intended for loopback / private networks
 *   only and rejects other peers unless explicitly opted out.
 */

const crypto = require('node:crypto');
const net = require('node:net');

const SCRYPT_PARAMS = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 64 });
const SCRYPT_MAX = Object.freeze({ N: 1 << 16, r: 16, p: 4, keylen: 128 });
const SCRYPT_FORMAT = /^scrypt\$(\d+)\$(\d+)\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/;
const MIN_BOOTSTRAP_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 1024;

// ---------------------------------------------------------------------------
// scrypt password handling
// ---------------------------------------------------------------------------

function scryptKey(password, salt, params) {
    const { N, r, p, keylen } = params;
    const maxmem = 256 * N * r + 32 * 1024 * 1024;
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, keylen, { N, r, p, maxmem }, (error, key) => {
            if (error) reject(error);
            else resolve(key);
        });
    });
}

function assertPasswordInput(password) {
    if (typeof password !== 'string') {
        throw new TypeError('password must be a string');
    }
    if (password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
        throw new RangeError(`password must be between 1 and ${MAX_PASSWORD_LENGTH} characters`);
    }
}

async function hashPassword(password, params = SCRYPT_PARAMS) {
    assertPasswordInput(password);
    const salt = crypto.randomBytes(16);
    const key = await scryptKey(password, salt, params);
    return [
        'scrypt',
        params.N,
        params.r,
        params.p,
        salt.toString('base64'),
        key.toString('base64')
    ].join('$');
}

function parseScryptHash(stored) {
    const match = SCRYPT_FORMAT.exec(String(stored || ''));
    if (!match) return null;
    const N = Number(match[1]);
    const r = Number(match[2]);
    const p = Number(match[3]);
    const salt = Buffer.from(match[4], 'base64');
    const key = Buffer.from(match[5], 'base64');
    if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return null;
    if (N < 1024 || N > SCRYPT_MAX.N || (N & (N - 1)) !== 0) return null;
    if (r < 1 || r > SCRYPT_MAX.r) return null;
    if (p < 1 || p > SCRYPT_MAX.p) return null;
    if (salt.length < 8 || salt.length > 64) return null;
    if (key.length < 16 || key.length > SCRYPT_MAX.keylen) return null;
    return { N, r, p, salt, key, keylen: key.length };
}

async function verifyPasswordHash(password, stored) {
    const parsed = parseScryptHash(stored);
    if (!parsed || typeof password !== 'string' || password.length === 0) {
        // Burn a comparable amount of time so "not configured"/"malformed"
        // cannot be fingerprinted by latency.
        await scryptKey('sokrat-control-dummy', Buffer.alloc(16), SCRYPT_PARAMS).catch(() => {});
        return false;
    }
    if (password.length > MAX_PASSWORD_LENGTH) return false;
    let derived;
    try {
        derived = await scryptKey(password, parsed.salt, {
            N: parsed.N,
            r: parsed.r,
            p: parsed.p,
            keylen: parsed.keylen
        });
    } catch {
        return false;
    }
    if (derived.length !== parsed.key.length) return false;
    return crypto.timingSafeEqual(derived, parsed.key);
}

/**
 * Resolve the admin credential from the environment.
 *
 * Returns `{ source, configured, verify(password) }`. Never throws for the
 * "nothing configured" case — the router turns that into a 503 and the UI
 * explains how to bootstrap.
 */
function loadAdminCredential(options = {}) {
    const env = options.env || process.env;
    const logger = options.logger || console;
    const hash = typeof env.CONTROL_ADMIN_PASSWORD_HASH === 'string'
        ? env.CONTROL_ADMIN_PASSWORD_HASH.trim()
        : '';
    const bootstrap = typeof env.CONTROL_ADMIN_PASSWORD === 'string'
        ? env.CONTROL_ADMIN_PASSWORD
        : '';

    if (hash) {
        if (!parseScryptHash(hash)) {
            throw new Error(
                'CONTROL_ADMIN_PASSWORD_HASH must look like scrypt$N$r$p$saltBase64$hashBase64'
            );
        }
        return {
            source: 'hash',
            configured: true,
            verify: (password) => verifyPasswordHash(password, hash)
        };
    }

    if (bootstrap) {
        if (bootstrap.length < MIN_BOOTSTRAP_PASSWORD_LENGTH) {
            throw new Error(
                `CONTROL_ADMIN_PASSWORD must be at least ${MIN_BOOTSTRAP_PASSWORD_LENGTH} characters`
            );
        }
        let derivedPromise = null;
        logger.warn(
            '[control] Using CONTROL_ADMIN_PASSWORD bootstrap. Set CONTROL_ADMIN_PASSWORD_HASH ' +
            '(scrypt) in .env for production.'
        );
        return {
            source: 'bootstrap',
            configured: true,
            verify: async (password) => {
                if (!derivedPromise) derivedPromise = hashPassword(bootstrap, SCRYPT_PARAMS);
                return verifyPasswordHash(password, await derivedPromise);
            }
        };
    }

    return {
        source: 'none',
        configured: false,
        verify: async () => false
    };
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

class SessionManager {
    constructor(options = {}) {
        this.ttlMs = clampInt(options.ttlMs, 30 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000);
        this.absoluteTtlMs = clampInt(
            options.absoluteTtlMs,
            12 * 60 * 60 * 1000,
            this.ttlMs,
            7 * 24 * 60 * 60 * 1000
        );
        this.maxSessions = clampInt(options.maxSessions, 32, 1, 512);
        this.now = typeof options.now === 'function' ? options.now : Date.now;
        this.sessions = new Map();
        this._sweepTimer = setInterval(() => this.sweep(), 60 * 1000);
        if (typeof this._sweepTimer.unref === 'function') this._sweepTimer.unref();
    }

    create(meta = {}) {
        this.sweep();
        while (this.sessions.size >= this.maxSessions) {
            let oldest = null;
            for (const session of this.sessions.values()) {
                if (!oldest || session.lastSeenAt < oldest.lastSeenAt) oldest = session;
            }
            if (!oldest) break;
            this.sessions.delete(oldest.id);
        }
        const at = this.now();
        const session = {
            id: crypto.randomBytes(32).toString('base64url'),
            csrfToken: crypto.randomBytes(32).toString('base64url'),
            createdAt: at,
            lastSeenAt: at,
            expiresAt: at + this.ttlMs,
            absoluteExpiresAt: at + this.absoluteTtlMs,
            ip: meta.ip || null,
            userAgent: String(meta.userAgent || '').slice(0, 200)
        };
        this.sessions.set(session.id, session);
        return { ...session };
    }

    get(id) {
        if (typeof id !== 'string' || id.length < 20 || id.length > 128) return null;
        const session = this.sessions.get(id);
        if (!session) return null;
        const at = this.now();
        if (at >= session.expiresAt || at >= session.absoluteExpiresAt) {
            this.sessions.delete(id);
            return null;
        }
        session.lastSeenAt = at;
        session.expiresAt = Math.min(at + this.ttlMs, session.absoluteExpiresAt);
        return session;
    }

    destroy(id) {
        if (typeof id === 'string') this.sessions.delete(id);
    }

    destroyAll() {
        this.sessions.clear();
    }

    sweep() {
        const at = this.now();
        for (const [id, session] of this.sessions) {
            if (at >= session.expiresAt || at >= session.absoluteExpiresAt) {
                this.sessions.delete(id);
            }
        }
    }

    get size() {
        return this.sessions.size;
    }

    close() {
        clearInterval(this._sweepTimer);
        this.sessions.clear();
    }
}

function clampInt(value, fallback, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function validateCsrf(session, token) {
    if (!session || typeof session.csrfToken !== 'string') return false;
    if (typeof token !== 'string' || !token) return false;
    const expected = Buffer.from(session.csrfToken, 'utf8');
    const provided = Buffer.from(token, 'utf8');
    if (expected.length !== provided.length) return false;
    return crypto.timingSafeEqual(expected, provided);
}

// ---------------------------------------------------------------------------
// Login throttling
// ---------------------------------------------------------------------------

class LoginRateLimiter {
    constructor(options = {}) {
        this.maxFailures = clampInt(options.maxFailures, 5, 1, 1000);
        this.windowMs = clampInt(options.windowMs, 10 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
        this.lockoutMs = clampInt(options.lockoutMs, 5 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
        this.maxKeys = clampInt(options.maxKeys, 4096, 8, 100000);
        this.now = typeof options.now === 'function' ? options.now : Date.now;
        this.buckets = new Map();
    }

    _bucket(key, at) {
        let bucket = this.buckets.get(key);
        if (!bucket) {
            bucket = { failures: 0, windowStart: at, lockedUntil: 0 };
            this.buckets.set(key, bucket);
            if (this.buckets.size > this.maxKeys) this._prune(at);
        }
        return bucket;
    }

    /**
     * Rolls the window forward. An elapsed lockout grants a clean slate rather
     * than leaving the address blocked for the remainder of the old window.
     */
    _refresh(bucket, at) {
        if (bucket.lockedUntil && bucket.lockedUntil <= at) {
            bucket.failures = 0;
            bucket.windowStart = at;
            bucket.lockedUntil = 0;
            return;
        }
        if (at - bucket.windowStart > this.windowMs) {
            bucket.failures = 0;
            bucket.windowStart = at;
            bucket.lockedUntil = 0;
        }
    }

    _prune(at) {
        for (const [key, bucket] of this.buckets) {
            if (bucket.lockedUntil <= at && at - bucket.windowStart > this.windowMs) {
                this.buckets.delete(key);
            }
        }
        if (this.buckets.size <= this.maxKeys) return;
        const ordered = [...this.buckets.entries()].sort(
            (a, b) => a[1].windowStart - b[1].windowStart
        );
        const excess = this.buckets.size - this.maxKeys;
        for (let i = 0; i < excess; i += 1) {
            if (!ordered[i]) break;
            this.buckets.delete(ordered[i][0]);
        }
    }

    check(key) {
        const at = this.now();
        const bucket = this._bucket(key, at);
        this._refresh(bucket, at);
        if (bucket.lockedUntil > at) {
            return {
                allowed: false,
                retryAfterMs: bucket.lockedUntil - at,
                failures: bucket.failures
            };
        }
        const allowed = bucket.failures < this.maxFailures;
        return {
            allowed,
            retryAfterMs: allowed ? 0 : this.windowMs - (at - bucket.windowStart),
            failures: bucket.failures,
            remaining: Math.max(0, this.maxFailures - bucket.failures)
        };
    }

    fail(key) {
        const at = this.now();
        const bucket = this._bucket(key, at);
        this._refresh(bucket, at);
        bucket.failures += 1;
        if (bucket.failures >= this.maxFailures) {
            bucket.lockedUntil = at + this.lockoutMs;
        }
        return this.check(key);
    }

    reset(key) {
        this.buckets.delete(key);
    }
}

// ---------------------------------------------------------------------------
// Network exposure helpers
// ---------------------------------------------------------------------------

function normalizeIp(value) {
    if (!value) return '';
    let ip = String(value).trim();
    if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    const zone = ip.indexOf('%');
    if (zone !== -1) ip = ip.slice(0, zone);
    return ip;
}

function isPrivateIp(value) {
    const ip = normalizeIp(value);
    if (!ip) return false;
    if (net.isIPv4(ip)) {
        const parts = ip.split('.').map(Number);
        if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
        const [a, b] = parts;
        if (a === 10 || a === 127) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 169 && b === 254) return true;
        // 100.64.0.0/10 — carrier-grade NAT, used by Tailscale.
        if (a === 100 && b >= 64 && b <= 127) return true;
        return false;
    }
    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        if (lower === '::' || lower === '::1') return true;
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
        if (/^fe[89ab]/.test(lower)) return true;
        const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
        if (mapped) return isPrivateIp(mapped[1]);
        return false;
    }
    return false;
}

function clientIp(req, options = {}) {
    const trustProxy = options.trustProxy === true;
    if (trustProxy) {
        const forwarded = req.headers && req.headers['x-forwarded-for'];
        const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        if (first) return normalizeIp(String(first).split(',')[0]);
        const realIp = req.headers && req.headers['x-real-ip'];
        if (realIp) return normalizeIp(Array.isArray(realIp) ? realIp[0] : realIp);
    }
    const socket = req.socket || req.connection || {};
    return normalizeIp(socket.remoteAddress || '');
}

function requestHost(req, trustProxy) {
    const forwarded = trustProxy ? req.headers['x-forwarded-host'] : null;
    const raw = (Array.isArray(forwarded) ? forwarded[0] : forwarded) || req.headers.host || '';
    return String(raw).split(',')[0].trim().toLowerCase();
}

/**
 * Same-origin check for state-changing requests. Requests without an Origin
 * header (curl, same-origin form posts on older browsers) are allowed and are
 * still protected by the session cookie + CSRF token.
 */
function originAllowed(req, options = {}) {
    const origin = req.headers && req.headers.origin;
    if (origin === undefined || origin === null || origin === '') return true;
    if (origin === 'null') return false;
    let parsed;
    try {
        parsed = new URL(String(origin));
    } catch {
        return false;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const host = requestHost(req, options.trustProxy === true);
    if (!host) return false;
    return parsed.host.toLowerCase() === host;
}

function isSecureRequest(req, trustProxy) {
    if (req.secure) return true;
    if (!trustProxy) return false;
    const proto = req.headers && req.headers['x-forwarded-proto'];
    const value = Array.isArray(proto) ? proto[0] : proto;
    return String(value || '').split(',')[0].trim().toLowerCase() === 'https';
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

function parseCookies(header) {
    const result = {};
    if (typeof header !== 'string' || !header) return result;
    for (const part of header.split(';')) {
        const index = part.indexOf('=');
        if (index === -1) continue;
        const name = part.slice(0, index).trim();
        if (!name || Object.prototype.hasOwnProperty.call(result, name)) continue;
        let value = part.slice(index + 1).trim();
        if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
        try {
            result[name] = decodeURIComponent(value);
        } catch {
            result[name] = value;
        }
    }
    return result;
}

function serializeCookie(name, value, options = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    parts.push(`Path=${options.path || '/'}`);
    if (options.maxAge !== undefined) {
        parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
    }
    parts.push('HttpOnly');
    parts.push(`SameSite=${options.sameSite || 'Strict'}`);
    if (options.secure) parts.push('Secure');
    return parts.join('; ');
}

function clearCookie(name, options = {}) {
    return serializeCookie(name, '', {
        ...options,
        maxAge: 0
    });
}

module.exports = {
    SCRYPT_PARAMS,
    MIN_BOOTSTRAP_PASSWORD_LENGTH,
    hashPassword,
    parseScryptHash,
    verifyPasswordHash,
    loadAdminCredential,
    SessionManager,
    LoginRateLimiter,
    validateCsrf,
    normalizeIp,
    isPrivateIp,
    clientIp,
    requestHost,
    originAllowed,
    isSecureRequest,
    parseCookies,
    serializeCookie,
    clearCookie
};
