// Optional: node scripts/pbx-address-browser-smoke.cjs (requires sibling Playwright).
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || '../../sokrat-crm-main/app/node_modules/playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
(async () => {
    let saved;
    let enrolled;
    let approved = false;
    let edited;
    let createdCount = 0;
    let refuseEnrollment = true;
    const requests = [];
    const server = http.createServer(async (req, res) => {
        let data = '';
        for await (const chunk of req) data += chunk;
        requests.push({ url: req.url, method: req.method });
        res.setHeader('Content-Type', 'application/json');
        if (req.url.includes('/api/session')) return res.end(JSON.stringify({ authenticated: true, csrfToken: 'fixture' }));
        if (req.url.includes('/api/pbx-ssh/resolve')) return res.end(JSON.stringify({ host: '100.64.0.12', wsURL: 'ws://100.64.0.12:8088/ws', apiURL: 'http://100.64.0.12:8080', mediaIps: '100.64.0.12' }));
        if (req.url.includes('/api/pbx-ssh/enroll')) {
            enrolled = JSON.parse(data);
            if (refuseEnrollment) {
                refuseEnrollment = false;
                res.statusCode = 503;
                return res.end(JSON.stringify({ success: false, message: 'Fixture SSH password refused' }));
            }
            approved = true;
            return res.end(JSON.stringify({ success: true }));
        }
        if (req.url === '/control/api/pbx' && req.method === 'POST') {
            createdCount++;
            saved = JSON.parse(data);
            return res.end(JSON.stringify({ pbx: { id: 'pbx_fixture' } }));
        }
        if (req.url === '/control/api/pbx/pbx_fixture' && req.method === 'PATCH') {
            edited = JSON.parse(data);
            return res.end(JSON.stringify({ success: true }));
        }
        if (req.url.includes('/api/')) return res.end(JSON.stringify({ pbx: approved ? [{ ...saved, id: 'pbx_fixture',
            mediaIps: [saved.mediaIps], management: { ...saved.management, approvalStatus: 'approved' } }] : [],
            devices: [], invites: [], extensions: [], activity: [], limits: {} }));
        const name = req.url.endsWith('.js') ? 'app.js' : req.url.endsWith('.css') ? 'app.css' : 'index.html';
        res.setHeader('Content-Type', name.endsWith('.js') ? 'application/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
        const content = fs.readFileSync(path.join(__dirname, '../src/control/public', name), 'utf8');
        res.end(name === 'index.html' ? content.replaceAll('__CONTROL_BASE__', '/control') : content);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({ headless: true });
    try {
        const page = await browser.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(`http://127.0.0.1:${server.address().port}/control/`);
        // Only address + password are required. No mode, name, resolve, probe,
        // manual approval or fingerprint confirmation interaction is performed.
        for (const id of ['pbx-managed', 'pbx-ssh-enable', 'pbx-resolve', 'pbx-ssh-probe', 'pbx-ssh-confirm', 'pbx-approval']) {
            assert.equal(await page.locator('#' + id).isVisible(), false, id + ' must not complicate setup');
        }
        await page.locator('#pbx-address').fill('pbx.example');
        await page.locator('#pbx-ssh-password').fill('one-time-password');
        await page.locator('#pbx-submit').click();
        await page.waitForFunction(() => document.querySelector('#dashboard-alert').textContent.includes('Fixture SSH password refused'));
        assert.equal(await page.locator('#pbx-ssh-password').inputValue(), '', 'failed setup clears the password');
        assert.equal(createdCount, 1);
        assert.equal(saved.name, 'pbx.example');
        assert.equal(saved.management.approvalStatus, 'pending');
        assert.equal(saved.management.extensionPolicyRequired, true);
        assert.equal(saved.wsURL, 'ws://100.64.0.12:8088/ws');
        assert.equal(saved.apiURL, 'http://100.64.0.12:8080');
        assert.equal(saved.mediaIps, '100.64.0.12');
        assert.equal(saved.password, undefined);
        await page.locator('#pbx-ssh-password').fill('one-time-password');
        await page.locator('#pbx-submit').click();
        await page.waitForFunction(() => document.querySelector('#pbx-address').value === '');
        assert.equal(createdCount, 1, 'retry never duplicates the saved PBX');
        assert.equal(enrolled.host, '100.64.0.12');
        assert.equal(enrolled.username, 'root');
        assert.equal(enrolled.password, 'one-time-password');
        assert.equal(enrolled.fingerprint, undefined, 'broker automatically pins the first host key');
        assert.equal(requests.some(r => r.url.includes('/probe')), false, 'no separate fingerprint request');
        assert.equal(await page.locator('#pbx-ssh-password').inputValue(), '');
        await page.locator('#pbx-rows').getByRole('button', { name: 'Edit', exact: true }).click();
        assert.equal(await page.locator('#pbx-advanced').evaluate(el => el.open), false, 'editing keeps setup simple');
        assert.equal(await page.locator('#pbx-ssh-password').evaluate(el => el.required), false, 'approved server edits need no password');
        const enrollments = requests.filter(r => r.url.includes('/enroll')).length;
        await page.locator('#pbx-submit').click();
        await page.waitForFunction(() => document.querySelector('#pbx-address').value === '');
        assert.equal(edited.wsURL, saved.wsURL, 'editing preserves connection settings');
        assert.equal(requests.filter(r => r.url.includes('/enroll')).length, enrollments, 'no SSH bootstrap just to save an existing server');
        assert.deepEqual(errors, []);
        console.log('PASS: address + root password only; automatic managed SSH setup, failure/retry without duplicates, password-free existing edits');
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
