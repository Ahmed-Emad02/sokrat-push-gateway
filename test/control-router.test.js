'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs').promises;
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const express = require('express');

const { createControlRouter } = require('../src/control/router');
const { ControlStore } = require('../src/control/store');
const { LoginRateLimiter } = require('../src/control/auth');

const PASSWORD = 'correct-horse-battery-staple';
const DEVICE_UUID = 'a9e89b44-cb09-4f7c-a9e5-4da631df95ed';

const PBX_BODY = {
    name: 'HQ PBX',
    wsURL: 'wss://pbx.example.com:8089/ws',
    apiURL: 'https://pbx.example.com:8080',
    mediaIps: '203.0.113.10, 198.51.100.0/24',
    enabled: true
};

function createClient(origin) {
    const jar = new Map();

    async function request(pathSuffix, options = {}) {
        const headers = { ...(options.headers || {}) };
        if (options.body !== undefined) headers['Content-Type'] = 'application/json';
        if (options.csrf) headers['X-CSRF-Token'] = options.csrf;
        const cookie = [...jar.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
        if (cookie && !options.noCookie) headers.Cookie = cookie;

        const response = await fetch(`${origin}${pathSuffix}`, {
            method: options.method || 'GET',
            headers,
            body: options.body === undefined ? undefined : JSON.stringify(options.body),
            redirect: 'manual'
        });

        for (const raw of response.headers.getSetCookie()) {
            const pair = raw.split(';')[0];
            const equals = pair.indexOf('=');
            const name = pair.slice(0, equals).trim();
            const value = pair.slice(equals + 1).trim();
            if (!value || /max-age=0/i.test(raw)) jar.delete(name);
            else jar.set(name, value);
        }

        const type = response.headers.get('content-type') || '';
        let body = null;
        let text = null;
        if (type.includes('application/json')) {
            try {
                body = await response.json();
            } catch {
                body = null;
            }
        } else {
            text = await response.text();
        }
        return {
            status: response.status,
            headers: response.headers,
            body,
            text,
            setCookie: response.headers.getSetCookie()
        };
    }

    return { request, jar };
}

async function createHarness(options = {}) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'sokrat-control-http-'));
    const filePath = path.join(dir, 'control.json');
    const store = new ControlStore({ filePath, ...(options.storeOptions || {}) });
    await store.init();

    const credential = options.credential || {
        source: 'test',
        configured: true,
        verify: async (password) => password === PASSWORD
    };

    const app = express();
    app.disable('x-powered-by');
    if (options.peerAddress) {
        app.use((req, res, next) => {
            Object.defineProperty(req.socket, 'remoteAddress', {
                value: options.peerAddress,
                configurable: true
            });
            next();
        });
    }
    app.use(
        options.mountPath || '/control',
        createControlRouter({
            store,
            credential,
            loginFailureDelayMs: 0,
            ...(options.routerOptions || {})
        })
    );

    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const client = createClient(origin);

    return {
        dir,
        filePath,
        store,
        server,
        origin,
        client,
        anonymous: createClient(origin),
        close: async () => {
            await new Promise((resolve) => {
                server.close(resolve);
                if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
            });
            await fsp.rm(dir, { recursive: true, force: true });
        },
        async login() {
            const response = await client.request('/control/api/session', {
                method: 'POST',
                body: { password: PASSWORD }
            });
            assert.equal(response.status, 200, 'test login should succeed');
            return response.body.csrfToken;
        }
    };
}

test('serves a self-contained login shell with a strict CSP', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    const page = await harness.client.request('/control/');
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    assert.match(page.text, /data-control-base="\/control"/);
    assert.doesNotMatch(page.text, /(?:src|href)="https?:\/\//i, 'no external resources');
    assert.doesNotMatch(page.text, /url\(https?:/i, 'no external CSS resources');
    assert.doesNotMatch(page.text, /<script(?![^>]*\bsrc=)/i, 'no inline scripts');
    assert.doesNotMatch(page.text, /style="/i, 'no inline styles');

    const csp = page.headers.get('content-security-policy');
    for (const directive of [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ]) {
        assert.ok(csp.includes(directive), `CSP should include ${directive}`);
    }
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(page.headers.get('x-frame-options'), 'DENY');
    assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(page.headers.get('cache-control'), 'no-store');

    const css = await harness.client.request('/control/asset/app.css');
    assert.equal(css.status, 200);
    assert.match(css.headers.get('content-type'), /text\/css/);
    assert.doesNotMatch(css.text, /@import/);
    assert.equal(/https?:\/\//.test(css.text), false);

    const js = await harness.client.request('/control/asset/app.js');
    assert.equal(js.status, 200);
    assert.match(js.headers.get('content-type'), /javascript/);
    assert.doesNotMatch(js.text, /\.(inner|outer)HTML\s*=/, 'frontend must not inject markup');
    assert.doesNotMatch(js.text, /document\.write/);

    const missing = await harness.client.request('/control/asset/unknown.js');
    assert.equal(missing.status, 404);
    const traversal = await harness.client.request('/control/asset/%2e%2e%2fstore.js');
    assert.equal(traversal.status, 404);

    const favicon = await harness.client.request('/control/favicon.ico');
    assert.equal(favicon.status, 204);
});

test('legacy enrollment and unauthenticated local bridge fail closed without throwing', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());
    const legacy = await harness.anonymous.request('/control/api/tunnel/register', { method: 'POST', body: {} });
    assert.ok([401, 426].includes(legacy.status));
    const bridge = await harness.anonymous.request('/control/api/tunnel/register-v2', { method: 'POST', body: {} });
    assert.equal(bridge.status, 401);
    assert.equal(harness.store.listPbx().length, 0);
});

test('unauthenticated callers cannot read state or mutate records', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    const state = await harness.client.request('/control/api/state');
    assert.equal(state.status, 401);
    assert.equal(state.body.error, 'authentication_required');

    const create = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY
    });
    assert.equal(create.status, 401);

    const session = await harness.client.request('/control/api/session');
    assert.equal(session.status, 200);
    assert.equal(session.body.authenticated, false);
    assert.equal(session.body.configured, true);
    assert.equal(session.body.csrfToken, undefined);
});

test('login sets a hardened cookie, rotates the session token and returns CSRF', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    const login = await harness.client.request('/control/api/session', {
        method: 'POST',
        body: { password: PASSWORD }
    });
    assert.equal(login.status, 200);
    assert.equal(login.body.authenticated, true);
    assert.match(login.body.csrfToken, /^[A-Za-z0-9_-]{43}$/);
    assert.ok(login.body.limits.maxEnabledPbx >= 1);

    const setCookie = login.setCookie.join(';');
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.match(setCookie, /Path=\//);
    assert.doesNotMatch(setCookie, /Secure/, 'plain HTTP test must not set Secure');
    assert.match(setCookie, /Max-Age=\d+/);
    assert.equal(harness.client.jar.size, 1);

    const state = await harness.client.request('/control/api/state');
    assert.equal(state.status, 200);
    assert.equal(state.body.success, true);
    assert.ok(Array.isArray(state.body.pbx));
    assert.ok(Array.isArray(state.body.devices));
});

test('repeated wrong passwords lock the address out', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    for (let attempt = 0; attempt < 5; attempt += 1) {
        const response = await harness.client.request('/control/api/session', {
            method: 'POST',
            body: { password: 'wrong-password' }
        });
        assert.equal(response.status, 401);
        assert.equal(response.body.error, 'invalid_credentials');
    }

    const locked = await harness.client.request('/control/api/session', {
        method: 'POST',
        body: { password: 'wrong-password' }
    });
    assert.equal(locked.status, 429);
    assert.equal(locked.body.error, 'too_many_attempts');
    assert.ok(Number(locked.headers.get('retry-after')) >= 1);

    const correctButLocked = await harness.client.request('/control/api/session', {
        method: 'POST',
        body: { password: PASSWORD }
    });
    assert.equal(correctButLocked.status, 429);
    assert.equal(harness.client.jar.size, 0);
});

test('mutations require the session CSRF token and a same-origin request', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());
    const csrf = await harness.login();

    const noToken = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY
    });
    assert.equal(noToken.status, 403);
    assert.equal(noToken.body.error, 'csrf_token_invalid');

    const badToken = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY,
        csrf: 'x'.repeat(43)
    });
    assert.equal(badToken.status, 403);

    const badOrigin = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY,
        csrf,
        headers: { Origin: 'https://evil.example' }
    });
    assert.equal(badOrigin.status, 403);
    assert.equal(badOrigin.body.error, 'origin_not_allowed');

    const created = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY,
        csrf,
        headers: { Origin: harness.origin }
    });
    assert.equal(created.status, 201);
    assert.equal(created.body.pbx.name, PBX_BODY.name);
    assert.equal(harness.store.listPbx().length, 1);
});

test('the enabled-PBX cap is enforced by the API, not just the UI', async (t) => {
    const harness = await createHarness({ storeOptions: { maxEnabledPbx: 1 } });
    t.after(() => harness.close());
    const csrf = await harness.login();

    const first = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY,
        csrf
    });
    assert.equal(first.status, 201);

    const second = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: { ...PBX_BODY, name: 'Second PBX' },
        csrf
    });
    assert.equal(second.status, 409);
    assert.equal(second.body.error, 'pbx_cap_reached');

    const state = await harness.client.request('/control/api/state');
    assert.equal(state.body.stats.pbx, 1);
    assert.equal(state.body.limits.maxEnabledPbx, 1);
});

test('enrollment → approval → revoke works end to end over HTTP', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());
    const csrf = await harness.login();

    const invite = await harness.client.request('/control/api/enrollment-tokens', {
        method: 'POST',
        body: { label: 'Reception', maxUses: 1, ttlMs: 60 * 60 * 1000 },
        csrf
    });
    assert.equal(invite.status, 201);
    assert.match(invite.body.token, /^sk_enroll_v1_/);
    assert.equal(invite.body.enrollment.tokenHash, undefined);

    const enrolled = await harness.anonymous.request('/control/api/devices/enroll', {
        method: 'POST',
        body: {
            token: invite.body.token,
            platform: 'android',
            deviceUuid: DEVICE_UUID,
            deviceName: 'Pixel 8',
            appVersion: '1.4.2',
            instanceId: 'install-abc'
        }
    });
    assert.equal(enrolled.status, 201);
    assert.equal(enrolled.body.status, 'pending');
    assert.equal(enrolled.body.device.hasSecret, false);
    assert.equal(enrolled.body.device.deviceUuid, DEVICE_UUID);
    assert.equal(enrolled.body.secret, undefined);
    const deviceId = enrolled.body.device.id;

    const pbx = await harness.client.request('/control/api/pbx', {
        method: 'POST',
        body: PBX_BODY,
        csrf
    });
    assert.equal(pbx.status, 201);

    const pendingState = await harness.client.request('/control/api/state');
    assert.equal(pendingState.body.stats.pendingDevices, 1);
    assert.equal(JSON.stringify(pendingState.body).includes(invite.body.token), false);
    assert.equal(JSON.stringify(pendingState.body).includes('tokenHash'), false);

    // PBX ownership and extension access precede device approval. SSH success
    // is tested independently by the onboarding API suite.
    assert.equal(pbx.body.pbx.management.approvalStatus, 'pending');
    await harness.store.updatePbx(pbx.body.pbx.id, { management: { approvalStatus: 'approved' } });
    await harness.store.addExtension({ pbxId: pbx.body.pbx.id, extension: '150',
        status: 'enabled', maxDevices: 5, allowedPlatforms: ['android'] });

    const approved = await harness.client.request(
        `/control/api/devices/${deviceId}/approve`,
        { method: 'POST', body: { pbxId: pbx.body.pbx.id, extension: '150' }, csrf }
    );
    assert.equal(approved.status, 200);
    assert.match(approved.body.secret, /^sk_device_v1_/);
    assert.equal(approved.body.device.status, 'approved');
    assert.equal(approved.body.device.extension, '150');
    assert.equal(harness.store.verifyDeviceSecret(deviceId, approved.body.secret).ok, true);

    const approvedState = await harness.client.request('/control/api/state');
    assert.equal(approvedState.body.stats.approvedDevices, 1);
    assert.equal(JSON.stringify(approvedState.body).includes(approved.body.secret), false);
    assert.equal(JSON.stringify(approvedState.body).includes('secretHash'), false);

    const revoked = await harness.client.request(
        `/control/api/devices/${deviceId}/revoke`,
        { method: 'POST', body: { reason: 'lost device' }, csrf }
    );
    assert.equal(revoked.status, 200);
    assert.equal(revoked.body.device.status, 'revoked');
    assert.equal(harness.store.verifyDeviceSecret(deviceId, approved.body.secret).ok, false);
});

test('enrollment rejects a missing or forged token; UUID alone is not auth', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    const noToken = await harness.anonymous.request('/control/api/devices/enroll', {
        method: 'POST',
        body: { platform: 'ios', deviceUuid: DEVICE_UUID, instanceId: 'install-abc' }
    });
    assert.equal(noToken.status, 400);
    assert.equal(noToken.body.error, 'invalid_token');

    const forged = await harness.anonymous.request('/control/api/devices/enroll', {
        method: 'POST',
        body: {
            token: `sk_enroll_v1_${'a'.repeat(43)}`,
            platform: 'ios',
            deviceUuid: DEVICE_UUID,
            instanceId: 'install-abc'
        }
    });
    assert.equal(forged.status, 401);
    assert.equal(forged.body.error, 'invalid_enrollment_token');
    assert.equal(harness.store.listDevices().length, 0);

    const invalidPlatform = await harness.anonymous.request('/control/api/devices/enroll', {
        method: 'POST',
        body: { token: `sk_enroll_v1_${'b'.repeat(43)}`, platform: 'windows', deviceUuid: DEVICE_UUID }
    });
    assert.equal(invalidPlatform.status, 400);
});

test('enrollment attempts are throttled per address', async (t) => {
    const harness = await createHarness({
        routerOptions: {
            enrollLimiter: new LoginRateLimiter({
                maxFailures: 3,
                windowMs: 60_000,
                lockoutMs: 60_000
            })
        }
    });
    t.after(() => harness.close());

    for (let attempt = 0; attempt < 3; attempt += 1) {
        const response = await harness.anonymous.request('/control/api/devices/enroll', {
            method: 'POST',
            body: {
                token: `sk_enroll_v1_${'c'.repeat(43)}`,
                platform: 'ios',
                deviceUuid: DEVICE_UUID
            }
        });
        assert.equal(response.status, 401);
    }
    const blocked = await harness.anonymous.request('/control/api/devices/enroll', {
        method: 'POST',
        body: {
            token: `sk_enroll_v1_${'d'.repeat(43)}`,
            platform: 'ios',
            deviceUuid: DEVICE_UUID
        }
    });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.body.error, 'too_many_attempts');
});

test('logout destroys the session and clears the cookie', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());
    const csrf = await harness.login();

    const logout = await harness.client.request('/control/api/session', {
        method: 'DELETE',
        csrf
    });
    assert.equal(logout.status, 200);
    assert.equal(logout.body.authenticated, false);
    assert.match(logout.setCookie.join(';'), /Max-Age=0/);
    assert.equal(harness.client.jar.size, 0);

    const state = await harness.client.request('/control/api/state');
    assert.equal(state.status, 401);

    const again = await harness.client.request('/control/api/session', {
        method: 'DELETE',
        csrf
    });
    assert.equal(again.status, 401);
});

test('missing administrator credential reports a locked console', async (t) => {
    const harness = await createHarness({
        credential: { source: 'none', configured: false, verify: async () => false }
    });
    t.after(() => harness.close());

    const session = await harness.client.request('/control/api/session');
    assert.equal(session.body.configured, false);

    const login = await harness.client.request('/control/api/session', {
        method: 'POST',
        body: { password: 'anything' }
    });
    assert.equal(login.status, 503);
    assert.equal(login.body.error, 'admin_not_configured');
});

test('non-private peers are refused unless explicitly allowed', async (t) => {
    const guarded = await createHarness({ peerAddress: '203.0.113.9' });
    t.after(() => guarded.close());
    const blocked = await guarded.client.request('/control/');
    assert.equal(blocked.status, 403);
    assert.match(blocked.text, /restricted to loopback and private networks/);
    assert.equal((await guarded.client.request('/control/api/session')).status, 403);

    const opened = await createHarness({
        peerAddress: '203.0.113.9',
        routerOptions: { allowPublic: true }
    });
    t.after(() => opened.close());
    const allowed = await opened.client.request('/control/');
    assert.equal(allowed.status, 200);
});

test('mounts at the site root without breaking relative asset paths', async (t) => {
    const harness = await createHarness({ mountPath: '/' });
    t.after(() => harness.close());

    const page = await harness.client.request('/');
    assert.equal(page.status, 200);
    assert.match(page.text, /data-control-base=""/);
    assert.match(page.text, /href="\/asset\/app.css"/);
    assert.equal((await harness.client.request('/asset/app.js')).status, 200);
    assert.equal((await harness.client.request('/api/session')).body.authenticated, false);
});

test('malformed JSON bodies are rejected with a JSON error', async (t) => {
    const harness = await createHarness();
    t.after(() => harness.close());

    const response = await fetch(`${harness.origin}/control/api/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"password":'
    });
    assert.equal(response.status, 400);
    const payload = await response.json();
    assert.equal(payload.error, 'invalid_json');
});
