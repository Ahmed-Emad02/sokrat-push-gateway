'use strict';

/**
 * Sokrat control-plane dashboard — public surface for the gateway process.
 *
 *   const { createControl } = require('./control');
 *
 *   const control = createControl({
 *       filePath: process.env.CONTROL_DATA_FILE,   // required, mode 0600
 *       maxEnabledPbx: process.env.CONTROL_MAX_ENABLED_PBX
 *   });
 *   await control.init();                          // optional, router self-inits
 *   app.use('/control', control.router);           // operator console (private)
 *   app.use('/connect', control.enrollmentRouter); // device enrollment (public)
 *
 * The parent process keeps ownership of the SIP/WebRTC proxy and of the
 * inbound-call push pipeline; this package only handles PBX records, device
 * enrollment/approval and the operator console.
 */

const { ControlStore, ControlStoreError } = require('./store');
const { createControlRouter } = require('./router');
const { createEnrollmentRouter } = require('./enrollment');
const auth = require('./auth');

function createControl(options = {}) {
    const env = options.env || process.env;
    const filePath = options.filePath || env.CONTROL_DATA_FILE;
    if (!filePath) {
        throw new Error(
            'createControl requires a filePath option (or CONTROL_DATA_FILE) for its durable JSON store'
        );
    }

    const store = options.store || new ControlStore({
        filePath,
        maxEnabledPbx: options.maxEnabledPbx,
        maxPbx: options.maxPbx,
        maxPendingDevices: options.maxPendingDevices,
        maxDevices: options.maxDevices,
        maxEnrollmentTokens: options.maxEnrollmentTokens,
        maxExtensions: options.maxExtensions,
        claimTtlMs: options.claimTtlMs,
        now: options.now
    });
    const credential = options.credential || auth.loadAdminCredential({ env });
    const sessions = options.sessions || new auth.SessionManager({
        ttlMs: (Number(env.CONTROL_SESSION_TTL_MINUTES) || 30) * 60 * 1000,
        absoluteTtlMs: (Number(env.CONTROL_SESSION_MAX_HOURS) || 12) * 60 * 60 * 1000,
        now: options.now
    });
    const loginLimiter = options.loginLimiter || new auth.LoginRateLimiter({ now: options.now });
    const globalLimiter = options.globalLimiter || new auth.LoginRateLimiter({
        maxFailures: 25,
        windowMs: 10 * 60 * 1000,
        lockoutMs: 10 * 60 * 1000,
        now: options.now
    });
    const enrollLimiter = options.enrollLimiter || new auth.LoginRateLimiter({
        maxFailures: 20,
        windowMs: 10 * 60 * 1000,
        lockoutMs: 10 * 60 * 1000,
        now: options.now
    });

    const router = createControlRouter({
        store,
        credential,
        sessions,
        loginLimiter,
        globalLimiter,
        enrollLimiter,
        allowPublic: options.allowPublic,
        trustProxy: options.trustProxy,
        cookieSecure: options.cookieSecure,
        loginFailureDelayMs: options.loginFailureDelayMs,
        env
    });

    // Device-facing automatic enrollment. Separate router on purpose: it shares
    // the store but none of the console's session/cookie/CSRF machinery, and it
    // is meant to be mounted on the public listener.
    const enrollmentRouter = createEnrollmentRouter({
        store,
        trustProxy: options.trustProxy,
        privateOnly: options.enrollmentPrivateOnly,
        retryAfterMs: options.claimRetryAfterMs,
        now: options.now,
        env
    });

    return {
        store,
        router,
        enrollmentRouter,
        credential,
        sessions,
        loginLimiter,
        globalLimiter,
        enrollLimiter,
        limits: store.limits,
        init: async () => { await store.init(); await store.manageAllPbx(); },
        close: () => sessions.close()
    };
}

module.exports = {
    createControl,
    createControlRouter,
    createEnrollmentRouter,
    ControlStore,
    ControlStoreError,
    ...auth
};
