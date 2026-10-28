'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
    ManagementPolicyError,
    normalizeLoginHostname,
    normalizeManagement,
    normalizeExtensionPolicy,
    APPROVAL_STATUSES,
    POLICY_STATUSES,
    PLATFORMS
} = require('../src/control/management');

const ALL_PLATFORMS = ['android', 'ios', 'desktop', 'chrome'];

function expectFailure(fn, code) {
    assert.throws(fn, (error) => {
        assert.ok(error instanceof Error, 'failure must be an Error');
        assert.ok(error instanceof ManagementPolicyError, 'failure must be a ManagementPolicyError');
        assert.equal(error.code, code);
        assert.equal(error.status, 400);
        assert.equal(typeof error.message, 'string');
        assert.ok(error.message.length > 0, 'failure must carry a message');
        return true;
    });
}

// ---------------------------------------------------------------------------
// normalizeLoginHostname
// ---------------------------------------------------------------------------

test('login hostname canonicalises case and the absolute trailing dot', () => {
    assert.equal(normalizeLoginHostname('PBX.Example.COM'), 'pbx.example.com');
    assert.equal(normalizeLoginHostname('  pbx.example.com  '), 'pbx.example.com');
    assert.equal(normalizeLoginHostname('PBX.Example.COM.'), 'pbx.example.com');
    assert.equal(normalizeLoginHostname('my-pbx.example.co.uk'), 'my-pbx.example.co.uk');
    // Idempotent: re-normalising a canonical value is a no-op.
    const once = normalizeLoginHostname('PBX.Example.COM.');
    assert.equal(normalizeLoginHostname(once), once);
});

test('login hostname treats empty input as "not configured"', () => {
    assert.equal(normalizeLoginHostname(undefined), null);
    assert.equal(normalizeLoginHostname(null), null);
    assert.equal(normalizeLoginHostname(''), null);
    assert.equal(normalizeLoginHostname('   '), null);
});

test('login hostname rejects schemes, ports, paths and credentials', () => {
    expectFailure(() => normalizeLoginHostname('https://pbx.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.example.com:8443'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.example.com/path'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('admin@pbx.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.example.com?x=1'), 'invalid_loginHostname');
});

test('login hostname rejects wildcards and IP literals', () => {
    expectFailure(() => normalizeLoginHostname('*.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('203.0.113.10'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('2001:db8::1'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('[2001:db8::1]'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.123'), 'invalid_loginHostname');
});

test('login hostname rejects localhost and single-label names', () => {
    expectFailure(() => normalizeLoginHostname('localhost'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('LOCALHOST.'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.localhost'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx'), 'invalid_loginHostname');
});

test('login hostname rejects malformed labels and over-long names', () => {
    expectFailure(() => normalizeLoginHostname('-pbx.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx-.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx_.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx..example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx.example.com..'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx ex.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname(`${'a'.repeat(64)}.example.com`), 'invalid_loginHostname');

    const longestValid = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(61)].join('.');
    assert.equal(longestValid.length, 253);
    assert.equal(normalizeLoginHostname(longestValid), longestValid);

    const tooLong = ['a'.repeat(63), 'a'.repeat(63), 'a'.repeat(63), 'a'.repeat(62)].join('.');
    assert.equal(tooLong.length, 254);
    expectFailure(() => normalizeLoginHostname(tooLong), 'invalid_loginHostname');
});

test('login hostname rejects non-string types and control characters', () => {
    for (const value of [42, true, {}, [], ['pbx.example.com']]) {
        expectFailure(() => normalizeLoginHostname(value), 'invalid_loginHostname');
    }
    expectFailure(() => normalizeLoginHostname('pbx\u0000.example.com'), 'invalid_loginHostname');
    expectFailure(() => normalizeLoginHostname('pbx\n.example.com'), 'invalid_loginHostname');
});

// ---------------------------------------------------------------------------
// normalizeManagement
// ---------------------------------------------------------------------------

test('management defaults describe a new, unapproved managed record', () => {
    assert.deepEqual(normalizeManagement({}), {
        customer: null,
        loginHostname: null,
        extensionPolicyRequired: false,
        approvalStatus: 'pending',
        reviewedInstallationId: null
    });
    // Existing records without an approval status stay pending.
    assert.equal(normalizeManagement({}, { customer: 'Acme' }).approvalStatus, 'pending');
});

test('management normalises a full input', () => {
    const result = normalizeManagement({
        customer: '  Acme Ltd  ',
        loginHostname: 'PBX.Example.COM',
        extensionPolicyRequired: true,
        approvalStatus: 'approved',
        reviewedInstallationId: '  inst_01HQ  '
    });
    assert.deepEqual(result, {
        customer: 'Acme Ltd',
        loginHostname: 'pbx.example.com',
        extensionPolicyRequired: true,
        approvalStatus: 'approved',
        reviewedInstallationId: 'inst_01HQ'
    });
});

test('management preserves omitted existing fields and clears on explicit null', () => {
    const existing = {
        customer: 'Acme',
        loginHostname: 'pbx.example.com',
        extensionPolicyRequired: true,
        approvalStatus: 'approved',
        reviewedInstallationId: 'inst_01'
    };

    assert.deepEqual(normalizeManagement({ customer: 'Other Co' }, existing), {
        ...existing,
        customer: 'Other Co'
    });

    assert.deepEqual(normalizeManagement({}, existing), existing);

    // Explicit false/undefined-free overrides must win over the stored value.
    assert.equal(
        normalizeManagement({ extensionPolicyRequired: false }, existing).extensionPolicyRequired,
        false
    );

    const cleared = normalizeManagement(
        { customer: null, loginHostname: null, reviewedInstallationId: null },
        existing
    );
    assert.equal(cleared.customer, null);
    assert.equal(cleared.loginHostname, null);
    assert.equal(cleared.reviewedInstallationId, null);
    assert.equal(cleared.approvalStatus, 'approved');
});

test('management ignores unknown keys and never mutates frozen input', () => {
    const input = Object.freeze({ customer: 'Acme', unexpected: 'ignored' });
    const existing = Object.freeze({ customer: 'Old', approvalStatus: 'suspended' });
    const result = normalizeManagement(input, existing);
    assert.equal(result.customer, 'Acme');
    assert.equal(result.approvalStatus, 'suspended');
    assert.equal(result.unexpected, undefined);
});

test('management validates the approval status enum strictly', () => {
    for (const status of APPROVAL_STATUSES) {
        assert.equal(normalizeManagement({ approvalStatus: status }).approvalStatus, status);
    }
    for (const status of ['Approved', 'active', 'enabled', 'pending ', 1, true, null, '']) {
        expectFailure(() => normalizeManagement({ approvalStatus: status }), 'invalid_approvalStatus');
    }
});

test('management enforces strict field types and lengths', () => {
    expectFailure(() => normalizeManagement({ customer: 42 }), 'invalid_customer');
    expectFailure(() => normalizeManagement({ customer: 'x'.repeat(65) }), 'invalid_customer');
    expectFailure(() => normalizeManagement({ customer: 'a\u0000b' }), 'invalid_customer');
    assert.equal(normalizeManagement({ customer: 'x'.repeat(64) }).customer, 'x'.repeat(64));
    assert.equal(normalizeManagement({ customer: '   ' }).customer, null);

    expectFailure(
        () => normalizeManagement({ extensionPolicyRequired: 'true' }),
        'invalid_extensionPolicyRequired'
    );
    expectFailure(
        () => normalizeManagement({ extensionPolicyRequired: 1 }),
        'invalid_extensionPolicyRequired'
    );

    expectFailure(
        () => normalizeManagement({ reviewedInstallationId: 'x'.repeat(129) }),
        'invalid_reviewedInstallationId'
    );
    expectFailure(
        () => normalizeManagement({ reviewedInstallationId: 7 }),
        'invalid_reviewedInstallationId'
    );
    assert.equal(
        normalizeManagement({ reviewedInstallationId: 'x'.repeat(128) }).reviewedInstallationId,
        'x'.repeat(128)
    );

    expectFailure(
        () => normalizeManagement({ loginHostname: 'https://pbx.example.com' }),
        'invalid_loginHostname'
    );
});

test('management rejects non-object input and non-object existing', () => {
    for (const value of [null, undefined, 'x', 42, [], [{}], true]) {
        expectFailure(() => normalizeManagement(value), 'invalid_input');
    }
    for (const existing of ['x', 42, [], [{}], true]) {
        expectFailure(() => normalizeManagement({}, existing), 'invalid_existing');
    }
    // null / undefined existing are the documented default, not an error.
    assert.equal(normalizeManagement({}, undefined).approvalStatus, 'pending');
    assert.equal(normalizeManagement({}, null).approvalStatus, 'pending');
});

test('management repairs corrupt persisted values with defaults', () => {
    const corrupt = {
        customer: 123,
        loginHostname: 'https://pbx.example.com',
        extensionPolicyRequired: 'yes',
        approvalStatus: 'bogus',
        reviewedInstallationId: {}
    };
    assert.deepEqual(normalizeManagement({}, corrupt), {
        customer: null,
        loginHostname: null,
        extensionPolicyRequired: false,
        approvalStatus: 'pending',
        reviewedInstallationId: null
    });
});

// ---------------------------------------------------------------------------
// normalizeExtensionPolicy
// ---------------------------------------------------------------------------

test('extension policy defaults are disabled, five devices, all platforms', () => {
    assert.deepEqual(normalizeExtensionPolicy({ extension: '160' }), {
        extension: '160',
        name: null,
        status: 'disabled',
        maxDevices: 5,
        allowedPlatforms: ALL_PLATFORMS
    });
    // A fresh array each call, so callers cannot corrupt the shared default.
    const first = normalizeExtensionPolicy({ extension: '160' });
    first.allowedPlatforms.push('mutated');
    assert.deepEqual(normalizeExtensionPolicy({ extension: '160' }).allowedPlatforms, ALL_PLATFORMS);
});

test('extension policy normalises a full input and canonical platform order', () => {
    assert.deepEqual(
        normalizeExtensionPolicy({
            extension: '00dc21c',
            name: '  Front Desk  ',
            status: 'enabled',
            maxDevices: 20,
            allowedPlatforms: ['chrome', 'android']
        }),
        {
            extension: '00dc21c',
            name: 'Front Desk',
            status: 'enabled',
            maxDevices: 20,
            allowedPlatforms: ['android', 'chrome']
        }
    );
});

test('extension policy requires a valid extension', () => {
    for (const extension of ['160', '00dc21c', '*97', '#100', 'ext.1_a-b', 'A1']) {
        assert.equal(normalizeExtensionPolicy({ extension }).extension, extension);
    }
    assert.equal(normalizeExtensionPolicy({ extension: '  160  ' }).extension, '160');

    for (const extension of [undefined, null, '', '   ', 'ext 1', 'ext/1', 'ext+1', 'ext@1', 'a'.repeat(33)]) {
        expectFailure(() => normalizeExtensionPolicy({ extension }), 'invalid_extension');
    }
    for (const extension of [160, true, {}, ['160']]) {
        expectFailure(() => normalizeExtensionPolicy({ extension }), 'invalid_extension');
    }
    // Other fields present does not excuse a missing extension on a new record.
    expectFailure(
        () => normalizeExtensionPolicy({ status: 'enabled', maxDevices: 3 }),
        'invalid_extension'
    );
});

test('extension policy validates status, device cap and name strictly', () => {
    for (const status of POLICY_STATUSES) {
        assert.equal(normalizeExtensionPolicy({ extension: '160', status }).status, status);
    }
    for (const status of ['active', 'ENABLED', 'Enabled', 1, null, '']) {
        expectFailure(
            () => normalizeExtensionPolicy({ extension: '160', status }),
            'invalid_status'
        );
    }

    assert.equal(normalizeExtensionPolicy({ extension: '160', maxDevices: 1 }).maxDevices, 1);
    assert.equal(normalizeExtensionPolicy({ extension: '160', maxDevices: 20 }).maxDevices, 20);
    for (const maxDevices of [0, 21, -1, 5.5, '5', null, true]) {
        expectFailure(
            () => normalizeExtensionPolicy({ extension: '160', maxDevices }),
            'invalid_maxDevices'
        );
    }

    assert.equal(normalizeExtensionPolicy({ extension: '160', name: 'x'.repeat(128) }).name, 'x'.repeat(128));
    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', name: 'x'.repeat(129) }),
        'invalid_name'
    );
    expectFailure(() => normalizeExtensionPolicy({ extension: '160', name: 5 }), 'invalid_name');
    assert.equal(normalizeExtensionPolicy({ extension: '160', name: '   ' }).name, null);
    assert.equal(normalizeExtensionPolicy({ extension: '160', name: '' }).name, null);
});

test('extension policy requires a non-empty unique platform subset', () => {
    assert.deepEqual(
        normalizeExtensionPolicy({
            extension: '160',
            allowedPlatforms: ['ios', 'ios', 'android', 'Android']
        }).allowedPlatforms,
        ['android', 'ios']
    );
    assert.deepEqual(
        normalizeExtensionPolicy({ extension: '160', allowedPlatforms: ['desktop'] }).allowedPlatforms,
        ['desktop']
    );

    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', allowedPlatforms: [] }),
        'invalid_allowedPlatforms'
    );
    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', allowedPlatforms: 'android' }),
        'invalid_allowedPlatforms'
    );
    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', allowedPlatforms: ['web'] }),
        'invalid_allowedPlatforms'
    );
    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', allowedPlatforms: ['android', 1] }),
        'invalid_allowedPlatforms'
    );
    expectFailure(
        () => normalizeExtensionPolicy({ extension: '160', allowedPlatforms: null }),
        'invalid_allowedPlatforms'
    );
});

test('extension policy preserves omitted existing fields and clears on null', () => {
    const existing = {
        extension: '160',
        name: 'Front Desk',
        status: 'enabled',
        maxDevices: 12,
        allowedPlatforms: ['android', 'ios']
    };

    assert.deepEqual(normalizeExtensionPolicy({ maxDevices: 7 }, existing), {
        ...existing,
        maxDevices: 7
    });

    // Existing-only lookup: extension is enough to rebuild the record.
    assert.deepEqual(normalizeExtensionPolicy({}, { extension: '160' }), {
        extension: '160',
        name: null,
        status: 'disabled',
        maxDevices: 5,
        allowedPlatforms: ALL_PLATFORMS
    });

    const cleared = normalizeExtensionPolicy({ name: null }, existing);
    assert.equal(cleared.name, null);
    assert.equal(cleared.status, 'enabled');
    assert.deepEqual(cleared.allowedPlatforms, ['android', 'ios']);
});

test('extension policy repairs corrupt persisted values with defaults', () => {
    assert.deepEqual(
        normalizeExtensionPolicy(
            {},
            {
                extension: '160',
                name: 5,
                status: 'bogus',
                maxDevices: 99,
                allowedPlatforms: []
            }
        ),
        {
            extension: '160',
            name: null,
            status: 'disabled',
            maxDevices: 5,
            allowedPlatforms: ALL_PLATFORMS
        }
    );
    // A corrupt stored extension is a hard error, not a silent default.
    expectFailure(
        () => normalizeExtensionPolicy({}, { extension: 'bad extension' }),
        'invalid_extension'
    );
});

test('extension policy ignores unknown keys and never mutates frozen input', () => {
    const input = Object.freeze({ extension: '160', allowedPlatforms: Object.freeze(['ios']) });
    const existing = Object.freeze({ extension: '160', status: 'enabled' });
    const result = normalizeExtensionPolicy(input, existing);
    assert.equal(result.status, 'enabled');
    assert.deepEqual(result.allowedPlatforms, ['ios']);
    assert.equal(result.unexpected, undefined);
    assert.equal(PLATFORMS.length, 4);
});

test('extension policy rejects non-object input and non-object existing', () => {
    for (const value of [null, undefined, 'x', 42, [], true]) {
        expectFailure(() => normalizeExtensionPolicy(value), 'invalid_input');
        if (value !== null && value !== undefined) {
            expectFailure(() => normalizeExtensionPolicy({ extension: '160' }, value), 'invalid_existing');
        }
    }
});

test('every failure is an Error with status 400', () => {
    const failures = [
        () => normalizeLoginHostname('https://pbx.example.com'),
        () => normalizeManagement(null),
        () => normalizeManagement({ approvalStatus: 'nope' }),
        () => normalizeExtensionPolicy({}),
        () => normalizeExtensionPolicy({ extension: '160', maxDevices: 0 })
    ];
    for (const fn of failures) {
        try {
            fn();
            assert.fail('expected a thrown validation error');
        } catch (error) {
            assert.ok(error instanceof Error);
            assert.equal(error.status, 400);
            assert.equal(typeof error.code, 'string');
        }
    }
});
