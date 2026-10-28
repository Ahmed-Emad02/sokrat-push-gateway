'use strict';

/**
 * Public, unauthenticated **automatic enrollment** endpoint.
 *
 * This router is deliberately separate from the operator console (`router.js`):
 *
 * - it exposes no admin session, no CSRF surface, no PBX list, no device list
 *   and no operator actions — only "enroll" and "claim";
 * - it is expected to sit on the internet-facing listener, because a device
 *   that has not been approved yet has to reach it from a mobile network;
 * - every response is secret-free: the device keeps the claim secret it
 *   generated itself, and the gateway only ever stores its digest.
 *
 * Mount it from the parent boot file (this module never edits `index.js`):
 *
 *   const { createControl } = require('./control');
 *   const control = createControl({ filePath: process.env.CONTROL_DATA_FILE });
 *   app.use('/control', control.router);          // operator console (private)
 *   app.use('/connect', control.enrollmentRouter); // device enrollment (public)
 *
 * Flow (mobile client):
 *   1. POST /connect/enroll  { deviceUuid, platform, extension, deviceName,
 *                              claimSecret }            → 201 pending
 *   2. poll POST /connect/claim { deviceId, claimSecret }
 *        → 202 pending | 200 approved + assignment   | 4xx terminal
 *   3. use (deviceId, claimSecret) as the gateway credential:
 *        X-Sokrat-Device: <deviceId>
 *        Authorization: Bearer <claimSecret>
 *      SIP REGISTER/INVITE keep using the extension + SIP password; the PBX
 *      still authenticates SIP itself. See README.md for the full contract.
 */

const express = require('express');
const { ControlStoreError, CLAIM_RETRY_HINT_MS } = require('./store');
const { LoginRateLimiter, clientIp, isPrivateIp } = require('./auth');

const BODY_LIMIT = '8kb';

const DEFAULTS = Object.freeze({
    // Enrollment is rare: a device does it once per install.
    enrollPerAddress: 30,
    enrollPerAddressWindowMs: 10 * 60 * 1000,
    enrollGlobal: 1000,
    enrollGlobalWindowMs: 10 * 60 * 1000,
    // Redemption/polling is periodic; the budget is generous but bounded.
    claimPerDevice: 120,
    claimPerAddress: 600,
    claimWindowMs: 60 * 1000,
    // Wrong claim secrets are throttled hard, per address.
    claimFailures: 20,
    claimFailureWindowMs: 10 * 60 * 1000,
    claimFailureLockoutMs: 10 * 60 * 1000
});

const CSP = [
    "default-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'"
].join('; ');

function clampInt(value, fallback, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, Math.floor(parsed)));
}

/**
 * Fixed-window request counter. Unlike `LoginRateLimiter` it counts successful
 * calls too: this is a budget for work performed (disk writes), not a lockout
 * for failed passwords.
 */
class WindowLimiter {
    constructor(options = {}) {
        this.limit = clampInt(options.limit, 60, 1, 1e6);
        this.windowMs = clampInt(options.windowMs, 60 * 1000, 1000, 24 * 60 * 60 * 1000);
        this.maxKeys = clampInt(options.maxKeys, 4096, 8, 100000);
        this.now = typeof options.now === 'function' ? options.now : Date.now;
        this.buckets = new Map();
    }

    hit(key) {
        const at = this.now();
        let bucket = this.buckets.get(key);
        if (!bucket || bucket.reset <= at) {
            if (!bucket && this.buckets.size >= this.maxKeys) this._prune(at);
            bucket = { count: 0, reset: at + this.windowMs };
            this.buckets.set(key, bucket);
        }
        bucket.count += 1;
        const allowed = bucket.count <= this.limit;
        return {
            allowed,
            remaining: Math.max(0, this.limit - bucket.count),
            retryAfterMs: allowed ? 0 : Math.max(1, bucket.reset - at)
        };
    }

    reset(key) {
        this.buckets.delete(key);
    }

    _prune(at) {
        for (const [key, bucket] of this.buckets) {
            if (bucket.reset <= at) this.buckets.delete(key);
        }
        if (this.buckets.size < this.maxKeys) return;
        const ordered = [...this.buckets.entries()].sort((a, b) => a[1].reset - b[1].reset);
        const excess = this.buckets.size - this.maxKeys + 1;
        for (let index = 0; index < excess; index += 1) {
            if (!ordered[index]) break;
            this.buckets.delete(ordered[index][0]);
        }
    }

    get size() {
        return this.buckets.size;
    }
}

function throttle(res, retryAfterMs) {
    res.set('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
}

function tooMany(res, retryAfterMs, message) {
    throttle(res, retryAfterMs);
    return res.status(429).json({
        success: false,
        error: 'too_many_requests',
        message,
        retryAfterMs
    });
}

/**
 * @param {object} options
 * @param {import('./store').ControlStore} options.store   required
 * @param {boolean} [options.trustProxy]     honour X-Forwarded-For (behind nginx)
 * @param {boolean} [options.privateOnly]    keep the endpoint on a private network
 * @param {WindowLimiter} [options.enrollLimiter]
 * @param {WindowLimiter} [options.enrollGlobalLimiter]
 * @param {WindowLimiter} [options.claimLimiter]
 * @param {WindowLimiter} [options.claimAddressLimiter]
 * @param {LoginRateLimiter} [options.claimFailureLimiter]
 * @param {number} [options.retryAfterMs]     hint returned while pending
 * @returns {import('express').Router}
 */
function createEnrollmentRouter(options = {}) {
    const store = options.store;
    if (!store) throw new Error('createEnrollmentRouter requires a store option');

    const env = options.env || process.env;
    const trustProxy = options.trustProxy === true || env.CONTROL_TRUST_PROXY === 'true';
    const privateOnly = options.privateOnly === true || env.CONTROL_ENROLL_PRIVATE_ONLY === 'true';
    const now = typeof options.now === 'function' ? options.now : Date.now;
    const retryAfterMs = clampInt(options.retryAfterMs, CLAIM_RETRY_HINT_MS, 250, 60 * 1000);

    const enrollLimiter = options.enrollLimiter || new WindowLimiter({
        limit: DEFAULTS.enrollPerAddress,
        windowMs: DEFAULTS.enrollPerAddressWindowMs,
        now
    });
    const enrollGlobalLimiter = options.enrollGlobalLimiter || new WindowLimiter({
        limit: DEFAULTS.enrollGlobal,
        windowMs: DEFAULTS.enrollGlobalWindowMs,
        now
    });
    const claimLimiter = options.claimLimiter || new WindowLimiter({
        limit: DEFAULTS.claimPerDevice,
        windowMs: DEFAULTS.claimWindowMs,
        now
    });
    const claimAddressLimiter = options.claimAddressLimiter || new WindowLimiter({
        limit: DEFAULTS.claimPerAddress,
        windowMs: DEFAULTS.claimWindowMs,
        now
    });
    const claimFailureLimiter = options.claimFailureLimiter || new LoginRateLimiter({
        maxFailures: DEFAULTS.claimFailures,
        windowMs: DEFAULTS.claimFailureWindowMs,
        lockoutMs: DEFAULTS.claimFailureLockoutMs,
        now
    });

    const router = express.Router();

    router.use((req, res, next) => {
        res.set({
            'Content-Security-Policy': CSP,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            'Cache-Control': 'no-store',
            Pragma: 'no-cache'
        });
        req.enrollmentTrustProxy = trustProxy;
        next();
    });

    if (privateOnly) {
        router.use((req, res, next) => {
            if (isPrivateIp(clientIp(req, { trustProxy }))) return next();
            return res.status(403).json({ success: false, error: 'network_not_allowed' });
        });
    }

    router.use(express.json({ limit: BODY_LIMIT, strict: true }));

    router.use((req, res, next) => {
        Promise.resolve(store.init()).then(() => next(), next);
    });

    const wrap = (handler) => (req, res, next) => {
        Promise.resolve(handler(req, res, next)).catch(next);
    };

    const addressOf = (req) => clientIp(req, { trustProxy }) || 'unknown';

    // --- enrollment --------------------------------------------------------

    router.post('/enroll', wrap(async (req, res) => {
        const address = addressOf(req);
        const verdict = enrollLimiter.hit(address);
        if (!verdict.allowed) {
            return tooMany(res, verdict.retryAfterMs, 'Too many enrollment attempts from this address.');
        }
        const global = enrollGlobalLimiter.hit('__global__');
        if (!global.allowed) {
            return tooMany(res, global.retryAfterMs, 'Enrollment is temporarily saturated.');
        }

        let result;
        try {
            result = await store.enrollClaim(req.body || {}, { requestIp: address });
        } catch (error) {
            if (error instanceof ControlStoreError && error.status === 401) {
                claimFailureLimiter.fail(address);
            }
            throw error;
        }

        const device = result.device;
        res.status(result.created ? 201 : 200).json({
            success: true,
            status: result.status,
            device,
            claimExpiresAt: device.claimExpiresAt,
            retryAfterMs: result.status === 'pending' ? retryAfterMs : null,
            redeemsAutomatically: true,
            notice:
                result.status === 'approved'
                    ? 'This device is approved. Redeem the claim to receive its PBX assignment.'
                    : 'Request received. Poll POST /claim with the same deviceId and claimSecret.'
        });
    }));

    // --- claim status + redemption ----------------------------------------

    router.post('/claim', wrap(async (req, res) => {
        const address = addressOf(req);
        const body = req.body || {};

        const failure = claimFailureLimiter.check(address);
        if (!failure.allowed) {
            return tooMany(
                res,
                failure.retryAfterMs,
                'Too many invalid claim attempts. Try again later.'
            );
        }

        const addressVerdict = claimAddressLimiter.hit(address);
        if (!addressVerdict.allowed) {
            return tooMany(res, addressVerdict.retryAfterMs, 'Too many claim requests from this address.');
        }
        if (typeof body.deviceId === 'string' && body.deviceId.length <= 64) {
            const verdict = claimLimiter.hit(`device:${body.deviceId}`);
            if (!verdict.allowed) {
                return tooMany(res, verdict.retryAfterMs, 'Too many claim requests for this device.');
            }
        }

        let result;
        try {
            result = await store.redeemClaim(body);
        } catch (error) {
            if (error instanceof ControlStoreError && error.code === 'invalid_claim') {
                claimFailureLimiter.fail(address);
            }
            throw error;
        }

        if (result.status === 'approved') {
            claimFailureLimiter.reset(address);
            res.set('ETag', `"${result.device.id}:${result.device.secretIssuedAt || ''}"`);
            return res.json({
                success: true,
                status: 'approved',
                device: result.device,
                assignment: result.assignment,
                redeemed: result.redeemedNow,
                // The device authenticates with the claim secret it generated.
                // Nothing is transmitted or minted here, so retries are safe.
                credential: {
                    deviceHeader: 'X-Sokrat-Device',
                    authorization: 'Bearer',
                    note: 'Send the same deviceId and claimSecret you enrolled with.'
                }
            });
        }

        throttle(res, result.retryAfterMs || retryAfterMs);
        return res.status(202).json({
            success: true,
            status: 'pending',
            device: result.device,
            assignment: null,
            retryAfterMs: result.retryAfterMs || retryAfterMs,
            notice: 'Waiting for administrator approval.'
        });
    }));

    // --- fallbacks ---------------------------------------------------------

    router.use((req, res) => {
        res.status(404).json({ success: false, error: 'not_found' });
    });

    // eslint-disable-next-line no-unused-vars
    router.use((error, req, res, next) => {
        if (res.headersSent) return next(error);
        if (error && error.type === 'entity.parse.failed') {
            return res.status(400).json({ success: false, error: 'invalid_json' });
        }
        if (error && error.type === 'entity.too.large') {
            return res.status(413).json({ success: false, error: 'payload_too_large' });
        }
        if (error instanceof ControlStoreError) {
            return res.status(error.status || 400).json({
                success: false,
                error: error.code,
                message: error.message
            });
        }
        console.error('[enrollment] unhandled error:', error && error.stack ? error.stack : error);
        return res.status(500).json({ success: false, error: 'internal_error' });
    });

    router.enrollment = {
        store,
        trustProxy,
        privateOnly,
        retryAfterMs,
        enrollLimiter,
        enrollGlobalLimiter,
        claimLimiter,
        claimAddressLimiter,
        claimFailureLimiter
    };

    return router;
}

module.exports = {
    createEnrollmentRouter,
    WindowLimiter,
    DEFAULTS,
    CSP
};
