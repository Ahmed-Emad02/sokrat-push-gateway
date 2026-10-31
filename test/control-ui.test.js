'use strict';

/**
 * Static wiring checks for the dashboard shell. These catch the class of bug a
 * unit test on the server cannot see: a renamed element id, an inline handler
 * that the CSP would block, or an accidental external asset reference.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs').promises;
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'src', 'control', 'public');

async function read(name) {
    return fsp.readFile(path.join(PUBLIC_DIR, name), 'utf8');
}

test('every element id used by the script exists in the shell', async () => {
    const [html, script] = await Promise.all([read('index.html'), read('app.js')]);

    const htmlIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
    const scriptIds = new Set(
        [...script.matchAll(/getElementById\('([^']+)'\)/g)].map((match) => match[1])
    );

    assert.ok(scriptIds.size >= 30, 'the script should wire the dashboard controls');
    for (const id of scriptIds) {
        assert.ok(htmlIds.has(id), `app.js expects #${id} but index.html does not define it`);
    }

    // The reverse direction is allowed to lag (the shell can grow first), but a
    // orphaned structural section is worth flagging.
    for (const id of ['login-view', 'dashboard-view', 'pbx-form', 'secret-panel']) {
        assert.ok(scriptIds.has(id), `#${id} should be wired by app.js`);
    }
});

test('the shell has no inline handlers, inline styles or external resources', async () => {
    const [html, css, script] = await Promise.all([
        read('index.html'),
        read('app.css'),
        read('app.js')
    ]);

    assert.doesNotMatch(html, /\son[a-z]+\s*=\s*"/i, 'inline event handlers are blocked by CSP');
    assert.doesNotMatch(html, /\sstyle\s*=\s*"/i, 'inline styles are blocked by CSP');
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/i);
    assert.doesNotMatch(html, /(?:src|href)="https?:\/\//i);
    assert.doesNotMatch(css, /@import|url\(\s*['"]?https?:/i);
    assert.equal((html.match(/__CONTROL_BASE__/g) || []).length, 3);
    assert.doesNotMatch(script, /\.(inner|outer)HTML\s*=/);
    assert.doesNotMatch(script, /eval\(|new Function\(/);
});

test('the script only talks to same-origin control endpoints', async () => {
    const script = await read('app.js');
    const paths = [...script.matchAll(/(?:api|endpoint)\(\s*[`']([^`']+)[`']/g)].map(
        (match) => match[1]
    );
    assert.ok(paths.length > 0);
    for (const value of paths) {
        assert.ok(
            value.startsWith('/api/') || value.startsWith('/asset/') || value.startsWith('/'),
            `unexpected request target: ${value}`
        );
        assert.equal(/^https?:\/\//.test(value), false);
    }
});
