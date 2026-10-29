'use strict';

/**
 * Express router for the Sokrat multi-PBX / device approval dashboard.
 *
 * Mount it from the gateway boot file (do not edit index.js from here):
 *
 *   const { createControl } = require('./control');
 *   const control = createControl();
 *   app.use('/control', control.router);   // after express.json()
 *
 * Everything is served from this module: JSON API, page shell and the two
 * local static assets. No CDN, font or script is loaded from a third party and
 * the CSP forbids it. The SIP proxy remains the parent's responsibility; this
 * router never proxies SIP.
 */

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { ControlStoreError } = require('./store');
const { getProvisioningStatus, resolveStatusFile } = require('./provisioning');
const {
    SessionManager,
    LoginRateLimiter,
    loadAdminCredential,
    isPrivateIp,
    clientIp,
    isSecureRequest,
    originAllowed,
    parseCookies,
    serializeCookie,
    clearCookie,
    validateCsrf
} = require('./auth');

const COOKIE_NAME = 'sokrat_control_sid';
const PUBLIC_DIR = path.join(__dirname, 'public');
const INDEX_FILE = path.join(PUBLIC_DIR, 'index.html');
const ASSETS = new Map([
    ['app.css', { file: path.join(PUBLIC_DIR, 'app.css'), type: 'text/css; charset=utf-8' }],
    ['app.js', { file: path.join(PUBLIC_DIR, 'app.js'), type: 'text/javascript; charset=utf-8' }]
]);
const BASE_PLACEHOLDER = '__CONTROL_BASE__';

const CSP = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
].join('; ');

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function throttleHeaders(res, retryAfterMs) {
    res.set('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
}

function actorFor(req) {
    const ip = clientIp(req, { trustProxy: req.controlTrustProxy === true });
    return ip ? `admin@${ip}` : 'admin';
}

function httpDelay(ms) {
    if (!ms) return Promise.resolve();
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function readStatic(file) {
    return fs.readFileSync(file, 'utf8');
}

function readIndex() {
    return readStatic(INDEX_FILE);
}

/**
 * @param {object} options
 * @param {import('./store').ControlStore} options.store  required
 * @param {object} [options.credential]                    from loadAdminCredential()
 * @param {SessionManager} [options.sessions]
 * @param {LoginRateLimiter} [options.loginLimiter]
 * @param {LoginRateLimiter} [options.enrollLimiter]
 * @param {boolean} [options.allowPublic]   default false: loopback/private peers only
 * @param {boolean} [options.trustProxy]    honour X-Forwarded-* headers
 * @param {boolean|'auto'} [options.cookieSecure]
 * @param {number} [options.loginFailureDelayMs]
 * @param {object} [options.provisioning]     read-only worker snapshot settings
 * @param {string} [options.provisioning.filePath]
 * @param {string[]} [options.provisioning.ownerUids]
 * @param {number} [options.provisioning.now]
 * @param {number} [options.provisioning.staleAfterMs]
 * @returns {import('express').Router}
 */
function createControlRouter(options = {}) {
    const store = options.store;
    if (!store) throw new Error('createControlRouter requires a store option');

    const credential = options.credential || loadAdminCredential({ env: options.env });
    const allowPublic = options.allowPublic === true || process.env.CONTROL_ALLOW_PUBLIC === 'true';
    const trustProxy = options.trustProxy === true || process.env.CONTROL_TRUST_PROXY === 'true';
    const cookieSecure = options.cookieSecure !== undefined
        ? options.cookieSecure
        : process.env.CONTROL_COOKIE_SECURE === 'true'
            ? true
            : 'auto';
    const loginFailureDelayMs = options.loginFailureDelayMs !== undefined
        ? Math.max(0, Number(options.loginFailureDelayMs) || 0)
        : 150;
    const provisioningOptions = options.provisioning || {};
    const provisioningFilePath = provisioningOptions.filePath ||
        resolveStatusFile(options.env || process.env);

    const sessions = options.sessions || new SessionManager({
        ttlMs: (Number(process.env.CONTROL_SESSION_TTL_MINUTES) || 30) * 60 * 1000,
        absoluteTtlMs: (Number(process.env.CONTROL_SESSION_MAX_HOURS) || 12) * 60 * 60 * 1000
    });
    const loginLimiter = options.loginLimiter || new LoginRateLimiter({
        maxFailures: 5,
        windowMs: 10 * 60 * 1000,
        lockoutMs: 5 * 60 * 1000
    });
    const globalLimiter = options.globalLimiter || new LoginRateLimiter({
        maxFailures: 25,
        windowMs: 10 * 60 * 1000,
        lockoutMs: 10 * 60 * 1000
    });
    const enrollLimiter = options.enrollLimiter || new LoginRateLimiter({
        maxFailures: 20,
        windowMs: 10 * 60 * 1000,
        lockoutMs: 10 * 60 * 1000
    });

    const indexTemplate = readIndex();
    const assetCache = new Map();
    for (const [name, asset] of ASSETS) {
        assetCache.set(name, { body: readStatic(asset.file), type: asset.type });
    }

    if (allowPublic) {
        console.warn(
            '[control] CONTROL_ALLOW_PUBLIC is enabled — the device approval dashboard is ' +
            'reachable from any network peer. Terminate TLS and restrict the port at the firewall.'
        );
    }

    const router = express.Router();

    // --- cross-cutting -----------------------------------------------------

    router.use((req, res, next) => {
        res.set({
            'Content-Security-Policy': CSP,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
            'Cache-Control': 'no-store'
        });
        if (isSecureRequest(req, trustProxy)) {
            res.set('Strict-Transport-Security', 'max-age=15552000');
        }
        req.controlTrustProxy = trustProxy;
        next();
    });

    // Local/private exposure guard. Override only for a deliberate, TLS-
    // terminated deployment: CONTROL_ALLOW_PUBLIC=true.
    router.use((req, res, next) => {
        if (allowPublic) return next();
        const ip = clientIp(req, { trustProxy });
        if (isPrivateIp(ip)) return next();
        return res
            .status(403)
            .type('text/plain; charset=utf-8')
            .send('The control dashboard is restricted to loopback and private networks.');
    });

    router.use(express.json({ limit: '64kb', strict: true }));

    router.use((req, res, next) => {
        Promise.resolve(store.init()).then(() => next(), next);
    });

    // --- helpers -----------------------------------------------------------

    const wrap = (handler) => (req, res, next) => {
        Promise.resolve(handler(req, res, next)).catch(next);
    };

    const requireSession = (req, res, next) => {
        const sid = parseCookies(req.headers.cookie)[COOKIE_NAME];
        const session = sid ? sessions.get(sid) : null;
        if (!session) {
            return res.status(401).json({ success: false, error: 'authentication_required' });
        }
        req.controlSession = session;
        next();
    };

    const requireCsrf = (req, res, next) => {
        if (!originAllowed(req, { trustProxy })) {
            return res.status(403).json({ success: false, error: 'origin_not_allowed' });
        }
        const token = req.get('x-csrf-token') || (req.body && req.body._csrf) || '';
        if (!validateCsrf(req.controlSession, token)) {
            return res.status(403).json({ success: false, error: 'csrf_token_invalid' });
        }
        next();
    };

    const secureCookie = (req) => cookieSecure === true ||
        (cookieSecure === 'auto' && isSecureRequest(req, trustProxy));

    const sessionCookieHeader = (req, session, options = {}) => {
        if (options.clear) {
            return clearCookie(COOKIE_NAME, {
                path: '/',
                sameSite: 'Strict',
                secure: secureCookie(req)
            });
        }
        return serializeCookie(COOKIE_NAME, session.id, {
            path: '/',
            maxAge: Math.max(0, Math.floor((session.absoluteExpiresAt - Date.now()) / 1000)),
            sameSite: 'Strict',
            secure: secureCookie(req)
        });
    };

    // --- page + assets -----------------------------------------------------

    router.get('/', (req, res) => {
        const base = String(req.baseUrl || '').replace(/\/+$/, '');
        res.type('text/html; charset=utf-8').send(
            indexTemplate.replaceAll(BASE_PLACEHOLDER, escapeHtml(base))
        );
    });

    router.get('/asset/:name', (req, res) => {
        const asset = assetCache.get(String(req.params.name));
        if (!asset) return res.status(404).type('text/plain; charset=utf-8').send('Not found');
        res.type(asset.type).send(asset.body);
    });

    router.get('/favicon.ico', (req, res) => res.status(204).end());

    // --- session -----------------------------------------------------------

    router.get('/api/session', (req, res) => {
        const sid = parseCookies(req.headers.cookie)[COOKIE_NAME];
        const session = sid ? sessions.get(sid) : null;
        if (!session) {
            return res.json({
                success: true,
                authenticated: false,
                configured: credential.configured
            });
        }
        return res.json({
            success: true,
            authenticated: true,
            csrfToken: session.csrfToken,
            expiresAt: new Date(session.expiresAt).toISOString(),
            limits: { ...store.limits }
        });
    });

    router.post('/api/session', wrap(async (req, res) => {
        const ip = clientIp(req, { trustProxy }) || 'unknown';

        const gates = [
            { limiter: loginLimiter, key: ip },
            { limiter: globalLimiter, key: '__global__' }
        ];
        for (const gate of gates) {
            const verdict = gate.limiter.check(gate.key);
            if (!verdict.allowed) {
                throttleHeaders(res, verdict.retryAfterMs || 1000);
                return res.status(429).json({
                    success: false,
                    error: 'too_many_attempts',
                    message: 'Too many sign-in attempts. Try again later.',
                    retryAfterMs: verdict.retryAfterMs || 1000
                });
            }
        }

        if (!credential.configured) {
            return res.status(503).json({
                success: false,
                error: 'admin_not_configured',
                message:
                    'No administrator credential is configured. Set CONTROL_ADMIN_PASSWORD_HASH ' +
                    '(scrypt) or CONTROL_ADMIN_PASSWORD in the gateway environment.'
            });
        }

        if (!originAllowed(req, { trustProxy })) {
            return res.status(403).json({ success: false, error: 'origin_not_allowed' });
        }

        const password = req.body && req.body.password;
        if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
            loginLimiter.fail(ip);
            globalLimiter.fail('__global__');
            await httpDelay(loginFailureDelayMs);
            return res.status(400).json({
                success: false,
                error: 'password_required',
                message: 'Enter the administrator password.'
            });
        }

        const ok = await credential.verify(password);
        if (!ok) {
            loginLimiter.fail(ip);
            globalLimiter.fail('__global__');
            await httpDelay(loginFailureDelayMs);
            return res.status(401).json({
                success: false,
                error: 'invalid_credentials',
                message: 'Sign-in failed. Check the password and try again.'
            });
        }

        loginLimiter.reset(ip);
        globalLimiter.reset('__global__');
        const session = sessions.create({ ip, userAgent: req.get('user-agent') || '' });
        res.set('Set-Cookie', sessionCookieHeader(req, session));
        return res.json({
            success: true,
            authenticated: true,
            csrfToken: session.csrfToken,
            expiresAt: new Date(session.expiresAt).toISOString(),
            limits: { ...store.limits }
        });
    }));

    router.delete('/api/session', requireSession, requireCsrf, (req, res) => {
        sessions.destroy(req.controlSession.id);
        res.set('Set-Cookie', sessionCookieHeader(req, null, { clear: true }));
        res.json({ success: true, authenticated: false });
    });

    // --- dashboard state ---------------------------------------------------

    router.get('/api/state', requireSession, (req, res) => {
        const snapshot = store.snapshot();
        res.json({
            success: true,
            ...snapshot,
            session: {
                expiresAt: new Date(req.controlSession.expiresAt).toISOString()
            }
        });
    });

    router.get('/api/tunnel-token', requireSession, (req, res) => {
        const fs = require('node:fs');
        const tokenPath = '/etc/sokrat/gateway-tunnel.token';
        let token = '';
        try {
            if (fs.existsSync(tokenPath)) {
                token = fs.readFileSync(tokenPath, 'utf8').trim();
            } else if (process.env.GATEWAY_TUNNEL_TOKEN) {
                token = process.env.GATEWAY_TUNNEL_TOKEN.trim();
            } else if (fs.existsSync('/etc/frp/frps.toml')) {
                const frpConf = fs.readFileSync('/etc/frp/frps.toml', 'utf8');
                const m = frpConf.match(/auth\.token\s*=\s*["']([^"']+)["']/i);
                if (m) token = m[1].trim();
            }
        } catch (_) {}
        res.json({ success: true, token });
    });

    router.post('/api/tunnel/register', wrap(async (req, res) => {
        const fs = require('node:fs');
        const crypto = require('node:crypto');
        const token = String(req.body?.token || '').trim();
        const name = String(req.body?.name || '').trim();
        const hostname = String(req.body?.hostname || '').trim();
        const customer = String(req.body?.customer || '').trim();

        const tokenPath = '/etc/sokrat/gateway-tunnel.token';
        let expectedToken = '';
        try {
            if (fs.existsSync(tokenPath)) {
                expectedToken = fs.readFileSync(tokenPath, 'utf8').trim();
            } else if (process.env.GATEWAY_TUNNEL_TOKEN) {
                expectedToken = process.env.GATEWAY_TUNNEL_TOKEN.trim();
            } else if (fs.existsSync('/etc/frp/frps.toml')) {
                const frpConf = fs.readFileSync('/etc/frp/frps.toml', 'utf8');
                const m = frpConf.match(/auth\.token\s*=\s*["']([^"']+)["']/i);
                if (m) expectedToken = m[1].trim();
            }
        } catch (_) {}

        if (!token || !expectedToken || token !== expectedToken) {
            return res.status(401).json({ success: false, error: 'Invalid tunnel token' });
        }

        const publicHost = process.env.GATEWAY_PUBLIC_HOST || '89.117.54.235';

        const validHostname = (hostname && hostname.includes('.')) ? hostname : null;
        const pbxList = store.listPbx();
        let existingPbx = pbxList.find(p => (
            (validHostname && p.management?.loginHostname === validHostname) ||
            (name && p.name.toLowerCase() === name.toLowerCase())
        ));

        let wsPort = 18088;
        let apiPort = 18080;

        if (existingPbx) {
            const mWs = existingPbx.wsURL.match(/:(\d+)\//);
            const mApi = existingPbx.apiURL.match(/:(\d+)/);
            if (mWs) wsPort = parseInt(mWs[1], 10);
            if (mApi) apiPort = parseInt(mApi[1], 10);

            await store.updatePbx(existingPbx.id, {
                enabled: true,
                management: {
                    ...(existingPbx.management || {}),
                    approvalStatus: 'approved',
                    extensionPolicyRequired: false
                }
            }, { actor: 'auto-tunnel-registration' });
        } else {
            const usedPorts = new Set();
            for (const p of pbxList) {
                const m1 = p.wsURL.match(/:(\d+)\//);
                const m2 = p.apiURL.match(/:(\d+)/);
                if (m1) usedPorts.add(parseInt(m1[1], 10));
                if (m2) usedPorts.add(parseInt(m2[1], 10));
            }
            let slot = 0;
            while (usedPorts.has(18088 + slot * 2) || usedPorts.has(18080 + slot * 2)) {
                slot++;
            }
            wsPort = 18088 + slot * 2;
            apiPort = 18080 + slot * 2;

            existingPbx = await store.addPbx({
                name: name || hostname || `PBX ${slot + 1}`,
                wsURL: `ws://127.0.0.1:${wsPort}/ws`,
                apiURL: `http://127.0.0.1:${apiPort}`,
                mediaIps: [publicHost],
                enabled: true,
                management: {
                    customer: customer || name || hostname || `Customer ${slot + 1}`,
                    loginHostname: validHostname,
                    extensionPolicyRequired: false,
                    approvalStatus: 'approved'
                }
            }, { actor: 'auto-tunnel-registration' });
        }

        const provConfigPath = '/etc/sokrat/gateway-provisioning.json';
        try {
            if (fs.existsSync(provConfigPath)) {
                const provConfig = JSON.parse(fs.readFileSync(provConfigPath, 'utf8'));
                provConfig.pbx = provConfig.pbx || {};
                const canonWs = existingPbx.wsURL;
                const canonApi = existingPbx.apiURL.endsWith('/') ? existingPbx.apiURL : existingPbx.apiURL + '/';
                const mediaIps = [...(existingPbx.mediaIps || [publicHost])].sort();
                const doc = {
                    approval: 'approved',
                    apiURL: canonApi,
                    mediaIps,
                    wsURL: canonWs
                };
                const fp = crypto.createHash('sha256').update(JSON.stringify(doc)).digest('hex');
                provConfig.pbx[existingPbx.id] = {
                    wsURL: canonWs,
                    apiURL: canonApi,
                    mediaIps,
                    approval: 'approved',
                    fingerprint: fp,
                    hookAdapter: '/bin/true'
                };
                fs.writeFileSync(provConfigPath, JSON.stringify(provConfig, null, 2) + '\n', { mode: 0o600 });
            }
        } catch (provErr) {
            console.warn('[tunnel-register] Could not auto-pin in provisioning.json:', provErr.message);
        }

        res.json({
            success: true,
            pbxId: existingPbx.id,
            tunnelPort: 7000,
            remoteWsPort: wsPort,
            remoteApiPort: apiPort,
            publicHost,
            message: 'PBX automatically registered and approved on Gateway'
        });
    }));

    // --- provisioning status (read-only worker snapshot) --------------------

    // The provisioning worker publishes its reconciliation snapshot to a private
    // file and polls approved configuration itself; this route only sanitizes
    // and forwards that snapshot. It never writes the file and never issues
    // commands to the worker.
    router.get('/api/provisioning', requireSession, wrap(async (req, res) => {
        const current = store.snapshot();
        const provisioning = await getProvisioningStatus({
            filePath: provisioningFilePath,
            ownerUids: provisioningOptions.ownerUids,
            now: provisioningOptions.now,
            staleAfterMs: provisioningOptions.staleAfterMs,
            pbx: current.pbx.map((record) => ({ id: record.id, updatedAt: record.updatedAt }))
        });
        res.json({ success: true, provisioning });
    }));

    // --- PBX connections ---------------------------------------------------

    const onboard = options.onboardingRequest || require('./onboarding').requestOnboarding;
    let onboardingBusy = false;
    let lastOnboarding = 0;
    let lastResolution = 0;
    let lastProbe = 0;
    // Operator-facing reasons for a refused SSH setup. Only safe codes are
    // mapped; the raw broker error never reaches the dashboard.
    const ONBOARDING_MESSAGES = {
        pbx_not_approved_or_mismatched: 'The server record does not match the SSH target. Check the address and retry setup.',
        pbx_endpoints_mismatched: 'The saved WS/API hosts and media IP must match the SSH address. Resolve the PBX address and save its connection settings again.',
        pbx_approval_blocked: 'This PBX is suspended or retired. Restore it to Pending or Approved before running SSH setup.',
        pbx_changed_during_setup: 'SSH setup completed, but the PBX record changed during setup. Review its settings and retry before approval.',
        password_auth_failed: 'The PBX rejected the root SSH password. Check the password and try again.',
        host_key_changed: 'The server SSH host key no longer matches its saved key. No password was sent. Verify the server identity before resetting its saved SSH trust.',
        ssh_unreachable: 'The gateway could not reach the PBX on SSH port 22.',
        pbx_bootstrap_failed: 'The PBX refused the gateway key. Check that the shared push context exists and that root SSH is permitted.',
        key_login_failed: 'The gateway key was installed but key-only login failed on the PBX.',
        config_write_failed: 'The gateway could not save its own provisioning configuration.',
        onboarding_busy: 'Another SSH setup is already running. Wait a moment and try again.',
    };
    const onboardingMessage = code => ONBOARDING_MESSAGES[code] || 'Automatic setup could not complete. Check the server address and root SSH access, then retry.';
    router.post('/api/pbx-ssh/:action', requireSession, requireCsrf, wrap(async (req, res) => {
        // Sensitive credentials are only accepted over TLS or a local SSH tunnel.
        const peer = req.socket.remoteAddress;
        if (!isSecureRequest(req, trustProxy) && !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer)) {
            return res.status(403).json({ success: false, error: 'secure_transport_required' });
        }
        const action = String(req.params.action);
        if (!['resolve', 'probe', 'enroll'].includes(action)) return res.status(400).json({ success: false, error: 'invalid_action' });
        const input = req.body || {};
        const capturedPbx = action === 'enroll' ? store.getPbx(input.pbxId) : null;
        if (action === 'enroll' && !capturedPbx) return res.status(404).json({ success: false, error: 'pbx_not_found' });
        if (onboardingBusy || Date.now() - (action === 'resolve' ? lastResolution : action === 'probe' ? lastProbe : lastOnboarding) < 2000) return res.status(429).json({ success: false, error: 'onboarding_busy' });
        onboardingBusy = true;
        if (action === 'resolve') lastResolution = Date.now();
        else if (action === 'probe') lastProbe = Date.now();
        else lastOnboarding = Date.now();
        try {
            if (action === 'resolve') {
                const result = await require('./onboarding').resolvePbxAddress(input.address, options.pbxAddressLookup);
                return res.json({ success: true, ...result });
            }
            const payload = { action, host: input.host, username: input.username };
            if (action === 'enroll') Object.assign(payload, { pbxId: input.pbxId, fingerprint: input.fingerprint, password: input.password });
            const result = await onboard(payload);
            // Approval follows successful host-key/password/key-only verification,
            // not the browser's requested approval value. Never approve a record
            // edited or deleted while the root broker was working.
            if (action === 'enroll') {
                const current = store.getPbx(input.pbxId);
                if (JSON.stringify(current) !== JSON.stringify(capturedPbx)) {
                    return res.status(409).json({ success: false, error: 'pbx_changed_during_setup',
                        message: onboardingMessage('pbx_changed_during_setup') });
                }
                if (current.management && current.management.approvalStatus === 'pending') {
                    await store.updatePbx(current.id, {
                        management: { ...current.management, approvalStatus: 'approved' },
                    }, { actor: actorFor(req), expectedPbx: capturedPbx });
                }
            }
            res.json({ success: true, ...result });
        } catch (error) {
            if (action === 'resolve') return res.status(400).json({ success: false, error: 'invalid_pbx_address', message: error.message });
            res.status(error.code === 'pbx_changed_during_setup' ? 409 : 503).json({ success: false, error: 'onboarding_refused', code: error.code || 'onboarding_refused',
                message: onboardingMessage(error.code) });
        } finally {
            delete input.password;
            onboardingBusy = false;
        }
    }));

    router.post('/api/pbx', requireSession, requireCsrf, wrap(async (req, res) => {
        const extensionPolicyRequired = req.body.management?.extensionPolicyRequired === true;
        const input = { ...req.body, management: { ...(req.body.management || {}), approvalStatus: 'pending', extensionPolicyRequired } };
        const pbx = await store.addPbx(input, { actor: actorFor(req) });
        res.status(201).json({ success: true, pbx, limits: { ...store.limits } });
    }));

    router.patch('/api/pbx/:id', requireSession, requireCsrf, wrap(async (req, res) => {
        if (Object.hasOwn(req.body, 'management')) {
            if (!req.body.management || typeof req.body.management !== 'object' || Array.isArray(req.body.management)) {
                return res.status(400).json({ success: false, error: 'managed_pbx_required' });
            }
            const current = store.getPbx(String(req.params.id));
            if (req.body.management.approvalStatus === 'approved' && current?.management?.approvalStatus !== 'approved') {
                return res.status(400).json({ success: false, error: 'ssh_setup_required', message: 'Complete automatic SSH setup to approve this server.' });
            }
            if (Object.hasOwn(req.body.management, 'extensionPolicyRequired')) {
                req.body.management.extensionPolicyRequired = Boolean(req.body.management.extensionPolicyRequired);
            }
        }
        const pbx = await store.updatePbx(String(req.params.id), req.body, {
            actor: actorFor(req)
        });
        res.json({ success: true, pbx, limits: { ...store.limits } });
    }));

    router.delete('/api/pbx/:id', requireSession, requireCsrf, wrap(async (req, res) => {
        const result = await store.removePbx(String(req.params.id), { actor: actorFor(req) });
        res.json({ success: true, ...result, limits: { ...store.limits } });
    }));

    // --- extension gateway access -----------------------------------------

    router.get('/api/extensions', requireSession, (req, res) => {
        if (req.query.pbxId !== undefined && typeof req.query.pbxId !== 'string') {
            return res.status(400).json({ success: false, error: 'invalid_pbxId' });
        }
        res.json({ success: true, extensions: store.listExtensions(req.query.pbxId) });
    });

    router.post('/api/extensions', requireSession, requireCsrf, wrap(async (req, res) => {
        const extension = await store.addExtension(req.body, { actor: actorFor(req) });
        res.status(201).json({ success: true, extension });
    }));

    router.patch('/api/extensions/:id', requireSession, requireCsrf, wrap(async (req, res) => {
        const extension = await store.updateExtension(req.params.id, req.body, { actor: actorFor(req) });
        res.json({ success: true, extension });
    }));

    // --- enrollment invitations -------------------------------------------

    router.post('/api/enrollment-tokens', requireSession, requireCsrf, wrap(async (req, res) => {
        const result = await store.createEnrollmentToken(req.body || {}, {
            actor: actorFor(req)
        });
        res.status(201).json({
            success: true,
            token: result.token,
            enrollment: result.record,
            // The plaintext token is returned exactly once.
            notice: 'Copy this token now. Only its hash is stored.'
        });
    }));

    router.delete('/api/enrollment-tokens/:id', requireSession, requireCsrf, wrap(async (req, res) => {
        const enrollment = await store.revokeEnrollmentToken(String(req.params.id), {
            actor: actorFor(req)
        });
        res.json({ success: true, enrollment });
    }));

    // --- device enrollment (public endpoint, token-authenticated) ----------

    router.post('/api/devices/enroll', wrap(async (req, res) => {
        const ip = clientIp(req, { trustProxy }) || 'unknown';
        const verdict = enrollLimiter.check(ip);
        if (!verdict.allowed) {
            throttleHeaders(res, verdict.retryAfterMs || 1000);
            return res.status(429).json({
                success: false,
                error: 'too_many_attempts',
                message: 'Too many enrollment attempts. Try again later.',
                retryAfterMs: verdict.retryAfterMs || 1000
            });
        }

        try {
            const result = await store.enrollDevice(req.body || {}, { requestIp: ip });
            return res.status(result.reused ? 200 : 201).json({
                success: true,
                device: result.device,
                status: result.device.status,
                reused: result.reused,
                notice: 'Enrollment is pending administrator approval.'
            });
        } catch (error) {
            if (error instanceof ControlStoreError && error.status === 401) {
                enrollLimiter.fail(ip);
            }
            throw error;
        }
    }));

    // --- device decisions --------------------------------------------------

    router.post('/api/devices/:id/approve', requireSession, requireCsrf, wrap(async (req, res) => {
        const result = await store.approveDevice(String(req.params.id), req.body || {}, {
            actor: actorFor(req)
        });
        if (!result.secret) {
            // Automatic enrollment: the device keeps the claim secret it
            // generated, so there is no secret for the operator to copy.
            return res.json({
                success: true,
                device: result.device,
                enrollmentMode: result.enrollmentMode || 'claim',
                notice:
                    'No secret is issued for automatic enrollment. The device redeems its ' +
                    'claim and receives its assignment automatically.'
            });
        }
        return res.json({
            success: true,
            device: result.device,
            enrollmentMode: result.enrollmentMode || 'invite',
            // Plaintext device secret: returned once, stored as a hash only.
            secret: result.secret,
            notice: 'Store this device secret now. It is shown once.'
        });
    }));

    router.post('/api/devices/:id/reject', requireSession, requireCsrf, wrap(async (req, res) => {
        const device = await store.rejectDevice(String(req.params.id), req.body || {}, {
            actor: actorFor(req)
        });
        res.json({ success: true, device });
    }));

    router.post('/api/devices/:id/revoke', requireSession, requireCsrf, wrap(async (req, res) => {
        const device = await store.revokeDevice(String(req.params.id), req.body || {}, {
            actor: actorFor(req)
        });
        res.json({ success: true, device });
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
        console.error('[control] unhandled error:', error && error.stack ? error.stack : error);
        return res.status(500).json({ success: false, error: 'internal_error' });
    });

    router.control = {
        store,
        credential,
        sessions,
        loginLimiter,
        globalLimiter,
        enrollLimiter,
        cookieName: COOKIE_NAME,
        csp: CSP
    };

    return router;
}

module.exports = {
    createControlRouter,
    COOKIE_NAME,
    CSP,
    ASSETS
};
