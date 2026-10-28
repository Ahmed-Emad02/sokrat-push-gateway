// Optional: node scripts/pbx-address-browser-smoke.cjs (requires sibling Playwright).
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || '../../sokrat-crm-main/app/node_modules/playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
(async () => {
    let saved;
    const server = http.createServer(async (req, res) => {
        let data = '';
        for await (const chunk of req) data += chunk;
        res.setHeader('Content-Type', 'application/json');
        if (req.url.includes('/api/session')) return res.end(JSON.stringify({ authenticated: true, csrfToken: 'fixture' }));
        if (req.url.includes('/api/pbx-ssh/resolve')) return res.end(JSON.stringify({ host: '100.64.0.12', wsURL: 'ws://100.64.0.12:8088/ws', apiURL: 'http://100.64.0.12:8080', mediaIps: '100.64.0.12' }));
        if (req.url.includes('/api/pbx') && req.method === 'POST') {
            saved = JSON.parse(data); return res.end(JSON.stringify({ pbx: { id: 'pbx_fixture' } }));
        }
        if (req.url.includes('/api/')) return res.end(JSON.stringify({ pbx: [], devices: [], invites: [], extensions: [], activity: [], limits: {} }));
        const name = req.url.endsWith('.js') ? 'app.js' : req.url.endsWith('.css') ? 'app.css' : 'index.html';
        res.setHeader('Content-Type', name.endsWith('.js') ? 'application/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
        res.end(fs.readFileSync(path.join(__dirname, '../src/control/public', name)));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({ headless: true });
    try {
        const page = await browser.newPage();
        const errors = []; page.on('pageerror', error => errors.push(error.message));
        await page.goto(`http://127.0.0.1:${server.address().port}/control/`);
        await page.locator('#pbx-name').fill('Fixture');
        await page.locator('#pbx-address').fill('pbx.example');
        assert.equal(await page.locator('#pbx-advanced').evaluate(el => el.open), false);
        await page.locator('#pbx-resolve').click();
        await page.waitForFunction(() => document.querySelector('#pbx-ssh-host').value === '100.64.0.12');
        assert.equal(await page.locator('#pbx-ws').inputValue(), 'ws://100.64.0.12:8088/ws');
        await page.locator('#pbx-submit').click();
        await page.waitForFunction(() => document.querySelector('#pbx-name').value === '');
        assert.equal(saved.mediaIps, '100.64.0.12');
        assert.equal(saved.apiURL, 'http://100.64.0.12:8080');
        await page.locator('#pbx-auto-address').uncheck();
        assert.equal(await page.locator('#pbx-advanced').evaluate(el => el.open), true);
        await page.locator('#pbx-ws').fill('wss://custom.example:8443/sip');
        assert.equal(await page.locator('#pbx-ws').inputValue(), 'wss://custom.example:8443/sip');
        assert.deepEqual(errors, []);
        console.log('PASS: single hostname derives settings, submits, resets and exposes custom overrides');
    } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });
