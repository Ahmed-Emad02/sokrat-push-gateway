'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const script = path.join(__dirname, '..', 'scripts', 'check-pbx-wake-compatibility.py');
const observed = [
    "[ Context 'macro-dial-one' created by 'pbx_config' ]",
    "  'pjsipdial' => 2. Set(THISDIAL=${PJSIP_DIAL_CONTACTS(${PJ})})",
    "  's' => 1. Set(DEXTEN=${ARG3})",
    '  4. GosubIf($["${DB(CF/${DEXTEN})}"!=""]?cf,1())',
    '  5. GotoIf($["${DB(DND/${DEXTEN})}"=""]?skip1)',
    '  12. GotoIf($["${DB(CFU/${DEXTEN})}"!=""]?docfu:skip3)',
    '  26. GosubIf($["${DEXTEN:-1}"!="#"]?dstring,1():dlocal,1())',
    '  27. GotoIf($[${LEN(${DSTRING})}=0]?nodial)',
    '  43. Dial(${DSTRING},${ARG1},${D_OPTIONS}b(func-apply-sipheaders^s^1))',
].join('\n');

function check(input) {
    const result = spawnSync('python3', [script], { input, encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 2, result.stderr);
    return JSON.parse(result.stdout);
}

test('observed FreePBX ordering is recognized but never claimed wake-ready', () => {
    assert.deepEqual(check(observed), {
        compatibility: 'unsupported', reason: 'mobile_companion_not_validated', wakeReady: false
    });
});

test('unknown, reordered, truncated or fabricated ready evidence cannot enable wake', () => {
    for (const input of [
        '', '[sub-sokrat-push-send] pbx-tenant-push-hook.py',
        observed.replace('DB(DND/${DEXTEN})', 'missing'),
        observed.replace('Dial(${DSTRING},${ARG1}', 'Dial(other'),
        observed.replace("'s' => 1. Set(DEXTEN=${ARG3})", "'s' => 1. Gosub(sokrat-wake-dial,s,1(${ARG3}))"),
        observed + '\n{"wakeReady":true,"token":"DO-NOT-ECHO"}',
        Buffer.from([0xff]),
    ]) {
        const result = check(input);
        assert.equal(result.wakeReady, false);
        assert.equal(result.compatibility, 'unsupported');
        assert.ok(!JSON.stringify(result).includes('DO-NOT-ECHO'));
    }
    assert.equal(check('x'.repeat(256 * 1024 + 1)).reason, 'input_too_large');
    assert.equal(check(observed.replace("'s' => 1. Set(DEXTEN=${ARG3})",
        "'s' => 1. Gosub(sokrat-wake-dial,s,1(${ARG3}))")).reason, 'unrecognized_dialplan');
});
