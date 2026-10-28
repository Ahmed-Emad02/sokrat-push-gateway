'use strict';

/**
 * Static checks for the management + extension policy console UI.
 *
 * These cover the parts a server test cannot see: the opt-in PBX management
 * payload, the immutable extension identity on PATCH, the platform checkbox
 * group, and the wording that must not imply verified PBX ownership or Chrome
 * tenant enrollment. No browser is required.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fsp = require('node:fs').promises;
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'src', 'control', 'public');

async function read(name) {
    return fsp.readFile(path.join(PUBLIC_DIR, name), 'utf8');
}

function attr(tag, name) {
    const match = tag.match(new RegExp(`\\b${name}="([^"]*)"`));
    return match ? match[1] : null;
}

test('PBX management controls exist with the store field names', async () => {
    const html = await read('index.html');
    const byId = new Map([...html.matchAll(/<input\b[^>]*>/g)].map((match) => {
        const tag = match[0];
        return [attr(tag, 'id'), tag];
    }));
    const selects = new Map([...html.matchAll(/<select\b[^>]*>/g)].map((match) => {
        const tag = match[0];
        return [attr(tag, 'id'), tag];
    }));

    const expected = [
        ['pbx-managed', 'managed'],
        ['pbx-customer', 'customer'],
        ['pbx-login-hostname', 'loginHostname'],
        ['pbx-policy-required', 'extensionPolicyRequired'],
        ['pbx-reviewed-installation-id', 'reviewedInstallationId']
    ];
    for (const [id, name] of expected) {
        assert.ok(byId.has(id), `#${id} should exist`);
        assert.equal(attr(byId.get(id), 'name'), name, `#${id} should post as ${name}`);
    }
    assert.equal(attr(selects.get('pbx-approval'), 'name'), 'approvalStatus');

    // customer is optional for the store, so the UI must not make it required.
    assert.equal(attr(byId.get('pbx-customer'), 'required'), null);
    assert.equal(attr(byId.get('pbx-customer'), 'maxlength'), '64');

    const approvalSelect = [...html.matchAll(/<select id="pbx-approval"[\s\S]*?<\/select>/g)][0][0];
    const approvalOptions = [...approvalSelect.matchAll(/<option value="([^"]+)"/g)]
        .map((match) => match[1]);
    assert.deepEqual(approvalOptions, ['pending', 'approved', 'suspended', 'retired']);
});

test('PBX management is opt-in and a new managed PBX starts pending', async () => {
    const script = await read('app.js');

    assert.match(
        script,
        /if \(refs\.pbxManaged\.checked\) \{\s*payload\.management = \{/,
        'management must only be added to the payload when the operator opts in'
    );
    assert.match(
        script,
        /approvalStatus: editingPbxId \? refs\.pbxApproval\.value : 'pending'/,
        'a new managed PBX must always be created as pending'
    );
    assert.match(script, /refs\.pbxApproval\.value = 'pending';\s*refs\.pbxApproval\.disabled = true;/);
    assert.match(script, /refs\.pbxApproval\.disabled = false;/);
    assert.match(script, /reviewedInstallationId: refs\.pbxReviewedInstallationId\.value\.trim\(\) \|\| null/);
    assert.doesNotMatch(script, /\binstallationId\b/, 'the store field is reviewedInstallationId');
});

test('management wording never claims verified ownership or Chrome enrollment', async () => {
    const html = await read('index.html');
    const approvalHint = html.slice(html.indexOf('id="pbx-approval-hint"'), html.indexOf('</span>', html.indexOf('id="pbx-approval-hint"')));
    assert.match(approvalHint, /does not verify ownership/i);
    assert.match(approvalHint, /still pending/i);

    const platformHint = html.slice(html.indexOf('id="ext-platforms-hint"'), html.indexOf('</span>', html.indexOf('id="ext-platforms-hint"')));
    assert.match(platformHint, /Chrome tenant enrollment is\s+not supported yet/i);
    assert.match(platformHint, /at least one/i);

    // "Approved (manual)" is the strongest label the UI may show.
    assert.match(html, /<option value="approved">Approved \(manual\)<\/option>/);
    assert.doesNotMatch(html, /verified ownership/i);
});

test('extension form exposes the policy fields and platform checkboxes', async () => {
    const html = await read('index.html');
    const inputTags = [...html.matchAll(/<input\b[^>]*>/g)].map((match) => match[0]);
    const fieldByName = (name) => inputTags.filter((tag) => attr(tag, 'name') === name);

    const selectTags = [...html.matchAll(/<select\b[^>]*>/g)].map((match) => match[0]);
    const extPbx = selectTags.find((tag) => attr(tag, 'id') === 'ext-pbx');
    assert.ok(extPbx, 'extension PBX select should exist');
    assert.equal(attr(extPbx, 'name'), 'pbxId');
    assert.match(extPbx, /\brequired\b/, 'the extension PBX is required');
    const number = fieldByName('extension')[0];
    assert.ok(number, 'extension number input should exist');
    assert.equal(attr(number, 'type'), 'text', 'extension numbers must stay text to keep leading zeros');
    assert.equal(attr(number, 'inputmode'), 'numeric');
    assert.equal(attr(number, 'autocomplete'), 'off');
    assert.equal(attr(number, 'autocorrect'), 'off');
    assert.equal(attr(number, 'spellcheck'), 'false');

    const name = inputTags.find((tag) => attr(tag, 'id') === 'ext-name');
    assert.ok(name, 'employee name input should exist');
    assert.equal(attr(name, 'maxlength'), '128');

    const maxDevices = fieldByName('maxDevices')[0];
    assert.equal(attr(maxDevices, 'type'), 'number');
    assert.equal(attr(maxDevices, 'min'), '1');
    assert.equal(attr(maxDevices, 'max'), '20');
    assert.equal(attr(maxDevices, 'step'), '1');

    const platforms = fieldByName('allowedPlatforms');
    assert.deepEqual(platforms.map((tag) => attr(tag, 'value')), ['android', 'ios', 'desktop', 'chrome']);
    for (const tag of platforms) {
        assert.equal(attr(tag, 'type'), 'checkbox');
        assert.equal(attr(tag, 'required'), null, 'the group is validated with setCustomValidity');
    }

    const statuses = [...html.matchAll(/<select id="ext-status"[\s\S]*?<\/select>/g)][0][0];
    for (const status of ['enabled', 'disabled', 'suspended']) {
        assert.match(statuses, new RegExp(`value="${status}"`));
    }
});

test('extension identity is disabled while editing and omitted from PATCH', async () => {
    const script = await read('app.js');

    const startEdit = script.slice(
        script.indexOf('function startEditExtension('),
        script.indexOf('function resetExtensionForm(')
    );
    assert.match(startEdit, /refs\.extPbx\.disabled = true;/, 'PBX must be locked while editing');
    assert.match(startEdit, /refs\.extNumber\.disabled = true;/, 'extension number must be locked while editing');

    const reset = script.slice(
        script.indexOf('function resetExtensionForm('),
        script.indexOf('function readExtensionForm(')
    );
    assert.match(reset, /refs\.extPbx\.disabled = false;/);
    assert.match(reset, /refs\.extNumber\.disabled = false;/);

    const readForm = script.slice(
        script.indexOf('function readExtensionForm('),
        script.indexOf('async function submitExtension(')
    );
    assert.doesNotMatch(readForm, /\bextension:/, 'readExtensionForm must not build identity fields');
    assert.doesNotMatch(readForm, /\bpbxId:/, 'readExtensionForm must not build identity fields');
    for (const field of ['name', 'status', 'maxDevices', 'allowedPlatforms']) {
        assert.match(readForm, new RegExp(`\\b${field}\\s*[:,]`), `${field} should be in the PATCH payload`);
    }

    const submit = script.slice(
        script.indexOf('async function submitExtension('),
        script.indexOf('// --------------------------------------------------------------- invites')
    );
    assert.match(submit, /method: 'PATCH',\s*body: payload/, 'PATCH must send only the mutable payload');
    assert.match(submit, /method: 'POST',\s*body: \{ pbxId, extension, \.\.\.payload \}/);
});

test('extension rows derive the approved count from the device snapshot', async () => {
    const script = await read('app.js');

    assert.match(script, /Array\.isArray\(snapshot\.extensions\) \? snapshot\.extensions : \[\]/);
    assert.match(script, /function approvedDeviceCount\(record\) \{/);
    const helper = script.slice(
        script.indexOf('function approvedDeviceCount('),
        script.indexOf('function selectedPlatforms(')
    );
    assert.match(helper, /device\.status === 'approved'/);
    assert.match(helper, /device\.pbxId === record\.pbxId/);
    assert.match(helper, /device\.extension/);

    // Extension policies only exist on managed PBX records.
    const options = script.slice(
        script.indexOf('function renderExtensionPbxOptions('),
        script.indexOf('function renderExtensions(')
    );
    assert.match(options, /filter\(\(record\) => record\.management\)/);
});

test('the console still uses only same-origin assets and safe DOM writes', async () => {
    const [html, css, script] = await Promise.all([read('index.html'), read('app.css'), read('app.js')]);

    assert.doesNotMatch(html, /\son[a-z]+\s*=\s*"/i);
    assert.doesNotMatch(html, /\sstyle\s*=\s*"/i);
    assert.doesNotMatch(html, /(?:src|href)="https?:\/\//i);
    assert.doesNotMatch(css, /@import|url\(\s*['"]?https?:/i);
    assert.doesNotMatch(script, /\.(inner|outer)HTML\s*=/);
    assert.doesNotMatch(script, /eval\(|new Function\(/);
    assert.doesNotMatch(script, /chrome\.(?:storage|runtime|identity|permissions)/);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/i);

    // Every request target stays on the control mount path.
    const paths = [...script.matchAll(/(?:api|endpoint)\(\s*[`']([^`']+)[`']/g)].map((match) => match[1]);
    assert.ok(paths.length > 0);
    for (const value of paths) {
        assert.match(value, /^\/(?:api|asset)?/);
        assert.equal(/^https?:\/\//.test(value), false);
    }
});
