'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
    SCRYPT_PARAMS,
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
    originAllowed,
    isSecureRequest,
    parseCookies,
    serializeCookie,
    clearCookie
} = require('../src/control/auth');

const PASSWORD = 'correct-horse-battery-staple';

test('scrypt hashes are salted, self-describing and verifiable', async () => {
    const first = await hashPassword(PASSWORD);
    const second = await hashPassword(PASSWORD);

    assert.match(first, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    assert.notEqual(first, second, 'each hash must use a fresh salt');
    assert.equal(await verifyPasswordHash(PASSWORD, first), true);
    assert.equal(await verifyPasswordHash(`${PASSWORD}x`, first), false);
    assert.equal(await verifyPasswordHash('', first), false);
    assert.equal(await verifyPasswordHash(PASSWORD, 'not-a-hash'), false);
    assert.equal(await verifyPasswordHash(PASSWORD, 'scrypt$1$8$1$aaaa$bbbb'), false);

    const parsed = parseScryptHash(first);
    assert.equal(parsed.N, SCRYPT_PARAMS.N);
    assert.equal(parsed.r, SCRYPT_PARAMS.r);
    assert.equal(parsed.p, SCRYPT_PARAMS.p);
    assert.equal(parsed.key.length, 64);
});

test('rejects scrypt parameters that would allow memory exhaustion', () => {
    assert.equal(parseScryptHash(`scrypt$1073741824$8$1$${'AAAA'}$${'AAAA'}`), null);
    assert.equal(parseScryptHash('scrypt$16384$99$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA'), null);
});

test('admin credential never defaults to a built-in password', async () => {
    const missing = loadAdminCredential({ env: {} });
    assert.equal(missing.configured, false);
    assert.equal(missing.source, 'none');
    assert.equal(await missing.verify('admin'), false);
    assert.equal(await missing.verify(''), false);

    const hash = await hashPassword(PASSWORD);
    const fromHash = loadAdminCredential({ env: { CONTROL_ADMIN_PASSWORD_HASH: hash } });
    assert.equal(fromHash.configured, true);
    assert.equal(fromHash.source, 'hash');
    assert.equal(await fromHash.verify(PASSWORD), true);
    assert.equal(await fromHash.verify('admin'), false);

    const bootstrap = loadAdminCredential({
        env: { CONTROL_ADMIN_PASSWORD: PASSWORD },
        logger: { warn() {} }
    });
    assert.equal(bootstrap.configured, true);
    assert.equal(bootstrap.source, 'bootstrap');
    assert.equal(await bootstrap.verify(PASSWORD), true);
    assert.equal(await bootstrap.verify('wrong'), false);

    assert.throws(
        () => loadAdminCredential({ env: { CONTROL_ADMIN_PASSWORD: 'short' }, logger: { warn() {} } }),
        /at least 8 characters/
    );
    assert.throws(
        () => loadAdminCredential({ env: { CONTROL_ADMIN_PASSWORD_HASH: 'bcrypt$whatever' } }),
        /scrypt\$N\$r\$p/
    );
});

test('sessions slide on activity but respect the absolute lifetime', () => {
    let now = 1_000_000;
    const sessions = new SessionManager({
        ttlMs: 60_000,
        absoluteTtlMs: 120_000,
        maxSessions: 2,
        now: () => now
    });
    try {
        const session = sessions.create({ ip: '127.0.0.1', userAgent: 'test' });
        assert.match(session.id, /^[A-Za-z0-9_-]{43}$/);
        assert.match(session.csrfToken, /^[A-Za-z0-9_-]{43}$/);

        now += 30_000;
        assert.ok(sessions.get(session.id), 'sliding window keeps the session alive');
        now += 30_000;
        assert.ok(sessions.get(session.id));
        now = 1_120_001; // absolute cap reached even though the idle window was refreshed
        assert.equal(sessions.get(session.id), null);

        const fresh = sessions.create({});
        now += 60_001;
        assert.equal(sessions.get(fresh.id), null, 'idle expiry applies');
        sessions.destroy(fresh.id);

        const a = sessions.create({});
        const b = sessions.create({});
        const c = sessions.create({});
        assert.ok(sessions.size <= 2);
        assert.ok(sessions.get(c.id));
        assert.equal(sessions.get(a.id) && sessions.get(b.id) ? 'both' : 'evicted', 'evicted');
    } finally {
        sessions.close();
    }
});

test('CSRF comparison is strict and length-safe', () => {
    const sessions = new SessionManager({ now: () => 0 });
    try {
        const session = sessions.create({});
        assert.equal(validateCsrf(session, session.csrfToken), true);
        assert.equal(validateCsrf(session, `${session.csrfToken}x`), false);
        assert.equal(validateCsrf(session, 'short'), false);
        assert.equal(validateCsrf(session, ''), false);
        assert.equal(validateCsrf(null, session.csrfToken), false);
    } finally {
        sessions.close();
    }
});

test('login throttling locks an address and then recovers', () => {
    let now = 0;
    const limiter = new LoginRateLimiter({
        maxFailures: 3,
        windowMs: 10_000,
        lockoutMs: 5_000,
        now: () => now
    });

    assert.equal(limiter.check('127.0.0.1').allowed, true);
    limiter.fail('127.0.0.1');
    limiter.fail('127.0.0.1');
    assert.equal(limiter.check('127.0.0.1').allowed, true);
    limiter.fail('127.0.0.1');

    const locked = limiter.check('127.0.0.1');
    assert.equal(locked.allowed, false);
    assert.ok(locked.retryAfterMs > 0);

    now += 5001;
    const recovered = limiter.check('127.0.0.1');
    assert.equal(recovered.allowed, true, 'an elapsed lockout grants a clean slate');

    limiter.fail('127.0.0.1');
    limiter.reset('127.0.0.1');
    assert.equal(limiter.check('127.0.0.1').allowed, true);
});

test('private-network detection covers loopback, RFC1918, CGNAT and ULA', () => {
    for (const address of [
        '127.0.0.1',
        '127.1.2.3',
        '10.1.2.3',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.1.5',
        '169.254.10.10',
        '100.98.185.86',
        '::1',
        '::',
        'fd7a:115c:a1e0::1',
        'fe80::1',
        '::ffff:10.0.0.7'
    ]) {
        assert.equal(isPrivateIp(address), true, `${address} should be private`);
    }
    for (const address of ['8.8.8.8', '203.0.113.9', '172.32.0.1', '2001:db8::1', '', 'example.com']) {
        assert.equal(isPrivateIp(address), false, `${address} should not be private`);
    }
    assert.equal(normalizeIp('[::1]'), '::1');
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(normalizeIp('fe80::1%eth0'), 'fe80::1');
});

test('client address honours proxy headers only when trusted', () => {
    const request = {
        headers: { 'x-forwarded-for': '203.0.113.7, 10.0.0.1' },
        socket: { remoteAddress: '127.0.0.1' }
    };
    assert.equal(clientIp(request, { trustProxy: false }), '127.0.0.1');
    assert.equal(clientIp(request, { trustProxy: true }), '203.0.113.7');
});

test('same-origin checks reject foreign origins and opaque origins', () => {
    const base = { headers: { host: 'pbx.internal:8095', origin: 'http://pbx.internal:8095' } };
    assert.equal(originAllowed(base), true);
    assert.equal(originAllowed({ headers: { host: 'pbx.internal:8095' } }), true);
    assert.equal(
        originAllowed({ headers: { host: 'pbx.internal:8095', origin: 'https://evil.example' } }),
        false
    );
    assert.equal(
        originAllowed({ headers: { host: 'pbx.internal:8095', origin: 'null' } }),
        false
    );
    assert.equal(
        originAllowed(
            {
                headers: {
                    host: '127.0.0.1:8095',
                    origin: 'https://pbx.example.com',
                    'x-forwarded-host': 'pbx.example.com'
                }
            },
            { trustProxy: true }
        ),
        true
    );
    assert.equal(
        originAllowed({ headers: { host: 'pbx.internal', origin: 'file:///tmp/x' } }),
        false
    );
});

test('HTTPS detection behind a trusted proxy', () => {
    assert.equal(isSecureRequest({ secure: false, headers: {} }, false), false);
    assert.equal(
        isSecureRequest({ secure: false, headers: { 'x-forwarded-proto': 'https' } }, true),
        true
    );
    assert.equal(
        isSecureRequest({ secure: false, headers: { 'x-forwarded-proto': 'https' } }, false),
        false
    );
});

test('cookie serialisation and parsing preserve flags and values', () => {
    const header = serializeCookie('sokrat_control_sid', 'abc-123_xyz', {
        path: '/',
        maxAge: 600,
        secure: true,
        sameSite: 'Strict'
    });
    assert.match(header, /^sokrat_control_sid=abc-123_xyz;/);
    assert.match(header, /Path=\//);
    assert.match(header, /Max-Age=600/);
    assert.match(header, /HttpOnly/);
    assert.match(header, /SameSite=Strict/);
    assert.match(header, /Secure/);

    const parsed = parseCookies(`other=1; sokrat_control_sid=abc-123_xyz; broken; encoded=a%20b`);
    assert.equal(parsed.sokrat_control_sid, 'abc-123_xyz');
    assert.equal(parsed.other, '1');
    assert.equal(parsed.encoded, 'a b');
    assert.equal(parsed.broken, undefined);

    const cleared = clearCookie('sokrat_control_sid', { secure: true });
    assert.match(cleared, /Max-Age=0/);
});
