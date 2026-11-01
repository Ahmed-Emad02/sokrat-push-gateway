'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createSystemMetrics, parseMemInfo } = require('../src/system-metrics');

function fakeFiles() {
    return new Map([
        [path.join('/sys/fs/cgroup', 'cpu.stat'), 'usage_usec 1000000\n'],
        [path.join('/sys/fs/cgroup', 'memory.stat'), 'anon 200000\nfile 100000\nkernel 50000\nsock 50000\n'],
        [path.join('/sys/fs/cgroup', 'memory.current'), '500000\n'],
        ['/proc/stat', 'cpu 100 0 100 800 0 0 0 0 0 0\n'],
        ['/proc/meminfo', 'MemTotal: 1000 kB\nMemAvailable: 400 kB\n'],
        ['/proc/net/dev', 'lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\neth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n'],
    ]);
}
let phase = 0;
async function fakeRead(filename) {
    const files = fakeFiles();
    if (filename.endsWith('cpu.stat')) return `usage_usec ${1000000 + phase * 500000}\n`;
    if (filename === '/proc/stat') return phase === 0
        ? 'cpu 100 0 100 800 0 0 0 0 0 0\n'
        : 'cpu 200 0 200 900 0 0 0 0 0 0\n';
    if (filename === '/proc/net/dev') return phase === 0
        ? 'eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n'
        : 'eth0: 126000 0 0 0 0 0 0 0 251000 0 0 0 0 0 0 0\n';
    return files.get(filename) ?? (() => { throw new Error('missing'); })();
}

test('samples CPU, memory, host load, SIP network and call counts', async () => {
    let now = 100000;
    let inBytes = 0;
    let outBytes = 0;
    const sampler = createSystemMetrics({
        readFile: fakeRead,
        now: () => now,
        getNetwork: () => ({ inBytes, outBytes, byPbx: [] }),
        getActiveCalls: () => [{ pbxId: 'pbx-a', active: 1, ringing: 1, total: 2 }],
        intervalMs: 2000,
    });
    await sampler.sample();
    phase = 1;
    now += 2000;
    // CPU +500000 usec / 2s => 25% of one core; host busy +100/200 => 50%.
    // 125000 bytes over 2s => 0.5 Mbps.
    inBytes = 125000;
    outBytes = 250000;
    const current = await sampler.sample();
    assert.equal(current.cpuPct, 25);
    assert.equal(current.hostCpuPct, 200 / 300 * 100);
    assert.equal(current.memoryBytes, 300000);
    assert.equal(current.sipInBps, 500000);
    assert.equal(current.sipOutBps, 1000000);
    assert.equal(current.activeCalls, 1);
    assert.equal(current.ringingCalls, 1);
    const snapshot = sampler.snapshot();
    assert.equal(snapshot.history.length, 2);
    assert.equal(snapshot.intervalMs, 2000);
});

test('parses MemTotal and MemAvailable with kB suffix', () => {
    assert.deepEqual(parseMemInfo('MemTotal: 1024 kB\nMemAvailable: 512 kB\n'), {
        totalBytes: 1048576,
        availableBytes: 524288,
    });
    assert.equal(parseMemInfo('garbage'), null);
});
