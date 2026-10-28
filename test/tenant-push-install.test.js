'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const INSTALLER = path.join(ROOT, 'scripts', 'install-tenant-push-hook.py');
const RUNNER = path.join(ROOT, 'scripts', 'pbx-tenant-push-hook.py');
const PYTHON = process.env.PYTHON || 'python3';
const MARKER = '; sokrat-tenant-push-hook v1';

const LEGACY = ' same => n,System(nohup /usr/bin/curl -s --max-time 1 '
    + '"http://127.0.0.1:8095/api/push/incoming-call?callee=${CALLEE}&caller=${CALLER}" '
    + '>/dev/null 2>&1 &)';

const FIXTURE = [
    '; Sokrat test dialplan fixture',
    '',
    '[globals]',
    'SOKRAT_LEGACY_DISPATCH=1',
    '',
    '[sub-sokrat-push-send]',
    'exten => s,1,NoOp(Sokrat push send)',
    ' same => n,Set(SOKRAT_CALLEE=${CALLEE})',
    ' same => n,Set(SOKRAT_CALL_ID=${FILTER(0-9a-zA-Z,${UNIQUEID})})',
    LEGACY,
    ' same => n(done),Return()',
    '',
    '[from-internal-custom]',
    'exten => _9X.,1,NoOp(untouched legacy pattern)',
    ' same => n(done),Return()',
    '',
].join('\n');

function tempDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'sokrat-tenant-push-'));
}

function write(file, text, mode) {
    fs.writeFileSync(file, text);
    if (mode !== undefined) fs.chmodSync(file, mode);
    return file;
}

function sandbox(dialplan = FIXTURE) {
    const dir = tempDir();
    return {
        dir,
        dialplan: write(path.join(dir, 'extensions_custom.conf'), dialplan, 0o640),
        config: write(path.join(dir, 'gateway-hook.json'), '{"gatewayUrl":"http://127.0.0.1:1","pbxId":"pbx","token":"t"}', 0o600),
        hook: RUNNER,
    };
}

function run(box, extra = []) {
    return spawnSync(PYTHON, [INSTALLER,
        '--dialplan-file', box.dialplan,
        '--hook-script', box.hook,
        '--config', box.config,
        ...extra,
    ], { encoding: 'utf8' });
}

function systemLine(box, overrides = {}) {
    const vars = {
        callee: 'CALLEE', caller: 'CALLER', name: 'CALLER_NAME', callId: 'SOKRAT_CALL_ID',
        ...overrides,
    };
    return 'same=>n,System(nohup env SOKRAT_HOOK_CONFIG="' + box.config + '" '
        + '/usr/bin/python3 "' + box.hook + '" '
        + '"${URIENCODE(${' + vars.callee + '})}" '
        + '"${URIENCODE(${' + vars.caller + '})}" '
        + '"${URIENCODE(${' + vars.name + '})}" '
        + '"${' + vars.callId + '}" >/dev/null 2>&1 &)';
}

function contextOf(text) {
    const lines = text.split('\n');
    const start = lines.indexOf('[sub-sokrat-push-send]');
    assert.notEqual(start, -1, 'fixture context present');
    const rest = lines.slice(start + 1);
    const end = rest.findIndex(line => /^\s*\[[^\]\s]+\]\s*$/.test(line));
    return (end === -1 ? rest : rest.slice(0, end)).filter((line, index, all) => !(index === all.length - 1 && line === ''));
}

function backups(dir) {
    return fs.readdirSync(dir).filter(name => name.includes('.bak-tenant-push-'));
}

function assertRefused(result, needle) {
    assert.equal(result.status, 2, 'expected refusal exit 2, got ' + result.status + '\n' + result.stdout + result.stderr);
    assert.match(result.stderr, /refused:/);
    if (needle) assert.match(result.stderr, needle);
}

test('dry-run is the default, renders the exact context and writes nothing', () => {
    const box = sandbox();
    const before = fs.readFileSync(box.dialplan, 'utf8');
    const result = run(box);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Dry run: no files were written/);
    assert.match(result.stdout, /No Asterisk reload was performed/);
    assert.ok(result.stdout.includes(systemLine(box)), 'rendered System() action is printed');
    assert.ok(result.stdout.includes(LEGACY), 'legacy dispatcher shown untouched');
    assert.ok(result.stdout.includes(MARKER));
    assert.equal(fs.readFileSync(box.dialplan, 'utf8'), before);
    assert.deepEqual(backups(box.dir), []);
    assert.deepEqual(fs.readdirSync(box.dir).filter(name => name.includes('.tmp-')), []);
});

test('apply inserts exactly one System() action immediately before the context done/Return and keeps a timestamped backup', () => {
    const box = sandbox();
    const before = fs.readFileSync(box.dialplan, 'utf8');
    const result = run(box, ['--apply', '--allow-unprivileged']);
    assert.equal(result.status, 0, result.stderr);
    const after = fs.readFileSync(box.dialplan, 'utf8');

    assert.deepEqual(contextOf(after), [
        'exten => s,1,NoOp(Sokrat push send)',
        ' same => n,Set(SOKRAT_CALLEE=${CALLEE})',
        ' same => n,Set(SOKRAT_CALL_ID=${FILTER(0-9a-zA-Z,${UNIQUEID})})',
        LEGACY,
        MARKER,
        systemLine(box),
        ' same => n(done),Return()',
    ]);

    // Every original line is preserved and only the two additive lines appear.
    const added = after.split('\n').filter(line => !before.split('\n').includes(line));
    assert.deepEqual(added.sort(), [MARKER, systemLine(box)].sort());
    assert.equal((after.match(/System\(/g) || []).length, 2, 'one legacy + one tenant System() action');
    assert.equal((after.match(/n\(done\),Return\(\)/g) || []).length, 2, 'other context untouched');

    const files = backups(box.dir);
    assert.equal(files.length, 1);
    assert.match(files[0], /^extensions_custom\.conf\.bak-tenant-push-\d{8}T\d{6}Z$/);
    assert.equal(fs.readFileSync(path.join(box.dir, files[0]), 'utf8'), before);
    assert.equal(fs.statSync(box.dialplan).mode & 0o777, 0o640, 'mode preserved');
    assert.deepEqual(fs.readdirSync(box.dir).filter(name => name.includes('.tmp-')), []);
    assert.match(result.stdout, /No Asterisk reload was performed/);
});

test('apply is idempotent: a second run changes nothing and writes no new backup', () => {
    const box = sandbox();
    assert.equal(run(box, ['--apply', '--allow-unprivileged']).status, 0);
    const applied = fs.readFileSync(box.dialplan, 'utf8');
    const firstBackups = backups(box.dir);

    const second = run(box, ['--apply', '--allow-unprivileged']);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already installed/);
    assert.equal(fs.readFileSync(box.dialplan, 'utf8'), applied);
    assert.deepEqual(backups(box.dir), firstBackups);
});

test('apply without root is refused unless explicitly allowed', { skip: process.getuid?.() === 0 }, () => {
    const box = sandbox();
    const before = fs.readFileSync(box.dialplan, 'utf8');
    assertRefused(run(box, ['--apply']), /requires root/);
    assert.equal(fs.readFileSync(box.dialplan, 'utf8'), before);
    assert.deepEqual(backups(box.dir), []);
});

test('malformed dialplans are refused without writing', async t => {
    const cases = [
        ['missing context', FIXTURE.replace('[sub-sokrat-push-send]', '[sub-other]'), /no \[sub-sokrat-push-send\] context/],
        ['duplicate context', FIXTURE + '\n[sub-sokrat-push-send]\n same => n(done),Return()\n', /2 \[sub-sokrat-push-send\] contexts/],
        ['missing done/Return', FIXTURE.replace(' same => n(done),Return()\n', '', 1), /exactly one same=>n\(done\),Return\(\)/],
        ['duplicate done/Return', FIXTURE.replace(' same => n(done),Return()', ' same => n(done),Return()\n same => n(done),Return()'), /exactly one same=>n\(done\),Return\(\)/],
        ['missing legacy dispatcher', FIXTURE.replace(LEGACY, ' same => n,NoOp(no dispatcher)'), /legacy dispatcher line/],
        ['duplicate legacy dispatcher', FIXTURE.replace(LEGACY, LEGACY + '\n' + LEGACY), /legacy dispatcher line/],
        ['tenant endpoint already present', FIXTURE.replace(LEGACY, LEGACY + '\n same => n,System(nohup env /usr/bin/curl "http://127.0.0.1:8097/api/gateway/incoming-call" >/dev/null 2>&1 &)'), /already references \/api\/gateway\/incoming-call/],
        ['marker without action', FIXTURE.replace(LEGACY, LEGACY + '\n' + MARKER), /marker .* is present but the expected System\(\) line is missing/],
        ['hook referenced without marker', FIXTURE.replace(LEGACY, LEGACY + '\n same => n,System(/usr/bin/python3 /opt/x/pbx-tenant-push-hook.py)'), /already references pbx-tenant-push-hook\.py/],
    ];
    for (const [name, dialplan, needle] of cases) {
        await t.test(name, () => {
            const box = sandbox(dialplan);
            const before = fs.readFileSync(box.dialplan, 'utf8');
            assertRefused(run(box, ['--apply', '--allow-unprivileged']), needle);
            assert.equal(fs.readFileSync(box.dialplan, 'utf8'), before);
            assert.deepEqual(backups(box.dir), []);
        });
    }
});

test('unsafe or non-absolute paths are refused', async t => {
    const box = sandbox();
    const base = ['--hook-script', box.hook, '--config', box.config];
    const cases = [
        ['relative dialplan', ['--dialplan-file', 'extensions_custom.conf', ...base], /absolute path/],
        ['space in path', ['--dialplan-file', box.dialplan + ' copy', ...base], /whitespace or shell-active characters/],
        ['semicolon in path', ['--dialplan-file', box.dialplan + ';id', ...base], /whitespace or shell-active characters/],
        ['backtick in config', ['--dialplan-file', box.dialplan, '--hook-script', box.hook, '--config', box.config + '`id`'], /whitespace or shell-active characters/],
        ['dot-dot segment', ['--dialplan-file', box.dir + '/../' + path.basename(box.dir) + '/extensions_custom.conf', ...base], /"\.\." segments|empty, "\." or "\.\."/],
        ['directory path', ['--dialplan-file', box.dir + '/', ...base], /must name a file/],
        ['missing dialplan', ['--dialplan-file', path.join(box.dir, 'absent.conf'), ...base], /dialplan file not found/],
    ];
    for (const [name, argv, needle] of cases) {
        await t.test(name, () => {
            const result = spawnSync(PYTHON, [INSTALLER, ...argv], { encoding: 'utf8' });
            assertRefused(result, needle);
        });
    }
});

test('hook script must be the decoding tenant runner, not the legacy encoder', async t => {
    const box = sandbox();
    await t.test('missing hook', () => {
        const missing = { ...box, hook: path.join(box.dir, 'absent-hook.py') };
        assertRefused(run(missing), /hook script not found/);
    });
    await t.test('legacy hook without unquote', () => {
        const legacyHook = write(path.join(box.dir, 'legacy-hook.py'),
            '#!/usr/bin/env python3\nimport sys\nprint(sys.argv[1:4])\n', 0o755);
        assertRefused(run({ ...box, hook: legacyHook }), /does not decode URIENCODE\(\)d argv/);
    });
    await t.test('non-python hook', () => {
        const shellHook = write(path.join(box.dir, 'hook.sh'), '#!/bin/sh\necho unquote(\n', 0o755);
        assertRefused(run({ ...box, hook: shellHook }), /does not look like a Python entry point/);
    });
});

test('a world-readable hook config is refused before any write', () => {
    const box = sandbox();
    fs.chmodSync(box.config, 0o644);
    assertRefused(run(box, ['--apply', '--allow-unprivileged']), /must not be world-readable/);
    assert.deepEqual(backups(box.dir), []);
});

test('a missing hook config only warns (hook fails closed at call time)', () => {
    const box = sandbox();
    const missing = path.join(box.dir, 'not-created-yet.json');
    const result = spawnSync(PYTHON, [INSTALLER,
        '--dialplan-file', box.dialplan, '--hook-script', box.hook, '--config', missing,
    ], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /hook config does not exist yet/);
    assert.match(result.stdout, /Dry run: no files were written/);
});

test('custom variable names render exactly and are validated', () => {
    const box = sandbox();
    const result = run(box, ['--callee-var', 'DEXTEN', '--caller-var', 'CALLERID_NUM',
        '--name-var', 'CALLERID_NAME', '--call-id-var', 'SOKRAT_CID']);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.includes(systemLine(box, {
        callee: 'DEXTEN', caller: 'CALLERID_NUM', name: 'CALLERID_NAME', callId: 'SOKRAT_CID',
    })));
    assert.match(result.stderr, /warning: callee variable \$\{DEXTEN\} is not referenced/);

    const bad = run(box, ['--callee-var', 'CALLEE;id']);
    assertRefused(bad, /plain dialplan variable name/);
});

test('CRLF dialplans keep their line endings', () => {
    const box = sandbox(FIXTURE.replace(/\n/g, '\r\n'));
    assert.equal(run(box, ['--apply', '--allow-unprivileged']).status, 0);
    const after = fs.readFileSync(box.dialplan, 'utf8');
    assert.ok(!/[^\r]\n/.test(after), 'no bare LF introduced');
    assert.ok(after.includes(MARKER + '\r\n'));
    assert.ok(after.includes(systemLine(box) + '\r\n'));
});

test('the new runner decodes URIENCODE()d argv and posts the gateway contract', async () => {
    const received = [];
    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            received.push({ url: req.url, headers: req.headers, body: JSON.parse(body) });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end('{}');
        });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const dir = tempDir();
    const config = write(path.join(dir, 'gateway-hook.json'), JSON.stringify({
        gatewayUrl: 'http://127.0.0.1:' + port, pbxId: 'pbx_test', token: 'test-token',
    }), 0o600);
    try {
        const result = await new Promise(resolve => {
            const child = spawn(PYTHON, [RUNNER,
                '160', '%2B201234567890', 'John%20Doe%20%26%20Co', 'call-abc123',
            ], { env: { ...process.env, SOKRAT_HOOK_CONFIG: config } });
            let stdout = '';
            let stderr = '';
            child.stdout.on('data', chunk => { stdout += chunk; });
            child.stderr.on('data', chunk => { stderr += chunk; });
            child.on('close', status => resolve({ status, stdout, stderr }));
        });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(received.length, 1);
        assert.equal(received[0].url, '/api/gateway/incoming-call');
        assert.equal(received[0].headers['x-sokrat-pbx'], 'pbx_test');
        assert.equal(received[0].headers.authorization, 'Bearer test-token');
        assert.deepEqual(received[0].body, {
            callee: '160', caller: '+201234567890', callerName: 'John Doe & Co', callId: 'call-abc123',
        });
        assert.ok(!result.stdout.includes('test-token'), 'token never printed');
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});
