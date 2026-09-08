'use strict';

const assert = require('assert');
const { matchPjsipChannel, dbToAsteriskVolume } = require('../src/index');

console.log('=== Running Channel Matching & Float Volume Conversion Unit Tests ===');

// Test 1: dbToAsteriskVolume float factor conversion
assert.strictEqual(dbToAsteriskVolume(0), 0, '0 dB should be 0 (unity gain)');
assert.strictEqual(dbToAsteriskVolume('0'), 0, 'String "0" should be 0');
assert.strictEqual(dbToAsteriskVolume(3), 1.4125, '+3 dB should be precise factor ~1.4125 (10^(3/20))');
assert.strictEqual(dbToAsteriskVolume(6), 1.9953, '+6 dB should be precise factor ~1.9953 (10^(6/20))');
assert.strictEqual(dbToAsteriskVolume(-3), -1.4125, '-3 dB should be factor -1.4125 (-10^(3/20))');
assert.strictEqual(dbToAsteriskVolume(-6), -1.9953, '-6 dB should be factor -1.9953 (-10^(6/20))');
assert.strictEqual(dbToAsteriskVolume(-12), -3.9811, '-12 dB should be factor -3.9811 (-10^(12/20))');
assert.strictEqual(dbToAsteriskVolume(10), 1.9953, 'Capped at +6 dB max -> factor 1.9953');
assert.strictEqual(dbToAsteriskVolume(-20), -3.9811, 'Capped at -12 dB min -> factor -3.9811');
console.log('✓ dbToAsteriskVolume float conversion passed (+3dB=1.4125, -3dB=-1.4125, +6dB=1.9953, -12dB=-3.9811)');

// Test 2: Dongle row with CallerID 150 appears BEFORE PJSIP row
const rowsWithDongleFirst = [
    'Dongle/dongle1-0100000001!macro-dialout-trunk!s!1!Up!Dial!Dongle/dongle1/01281102350!150!!!14!c0356e9c-46ec-4c6e-b6a2-6323a63f848f!1788435876.12!1788435876.11',
    'PJSIP/150-0000002a!from-internal!01281102350!1!Up!AppDial!(Outgoing Line)!150!!!14!c0356e9c-46ec-4c6e-b6a2-6323a63f848f!1788435876.11!1788435876.11'
];
const matched1 = matchPjsipChannel(rowsWithDongleFirst, '150');
assert.strictEqual(matched1, 'PJSIP/150-0000002a', 'Pass 1 must strictly select PJSIP/150-xxxx and ignore preceding Dongle/ row');
console.log('✓ Dongle-first ordering test passed (PJSIP channel correctly prioritized over Dongle row)');

// Test 3: Dongle row appears AFTER PJSIP row
const rowsWithPjsipFirst = [
    'PJSIP/150-0000002b!from-internal!01281102350!1!Up!AppDial!(Outgoing Line)!150!!!14!c0356e9c-46ec-4c6e-b6a2-6323a63f848f!1788435876.11!1788435876.11',
    'Dongle/dongle0-0100000002!macro-dialout-trunk!s!1!Up!Dial!Dongle/dongle0/01281102350!150!!!14!c0356e9c-46ec-4c6e-b6a2-6323a63f848f!1788435876.12!1788435876.11'
];
const matched2 = matchPjsipChannel(rowsWithPjsipFirst, '150');
assert.strictEqual(matched2, 'PJSIP/150-0000002b', 'Must select PJSIP/150-xxxx');
console.log('✓ PJSIP-first ordering test passed');

// Test 4: Multiple calls from different extensions
const multiCallRows = [
    'Dongle/dongle1-0100000003!macro-dialout-trunk!s!1!Up!Dial!Dongle/dongle1/01000000000!151!!!5!!1788435880.1!1788435880.1',
    'PJSIP/151-00000030!from-internal!01000000000!1!Up!AppDial!(Outgoing Line)!151!!!5!!1788435880.1!1788435880.1',
    'PJSIP/150-00000031!from-internal!01281102350!1!Up!AppDial!(Outgoing Line)!150!!!8!!1788435885.1!1788435885.1',
    'Dongle/dongle0-0100000004!macro-dialout-trunk!s!1!Up!Dial!Dongle/dongle0/01281102350!150!!!8!!1788435885.1!1788435885.1'
];
assert.strictEqual(matchPjsipChannel(multiCallRows, '150'), 'PJSIP/150-00000031', 'Must isolate ext 150 in multi-call scenario');
assert.strictEqual(matchPjsipChannel(multiCallRows, '151'), 'PJSIP/151-00000030', 'Must isolate ext 151 in multi-call scenario');
console.log('✓ Multi-call isolation test passed');

// Test 5: No call active or invalid ext
assert.strictEqual(matchPjsipChannel([], '150'), null, 'Empty list must return null');
assert.strictEqual(matchPjsipChannel(multiCallRows, '999'), null, 'Non-existent ext must return null');
console.log('✓ Non-existent extension test passed');

console.log('=== ALL UNIT TESTS PASSED SUCCESSFULLY ===');
