'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

const DEFAULT_INTERVAL_MS = 2000;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const DEFAULT_CGROUP_ROOT = '/sys/fs/cgroup';

function numberFrom(text, key) {
    if (!text) return null;
    const match = new RegExp(`^${key}\\s+(\\d+)\\s*$`, 'm').exec(text);
    return match ? Number(match[1]) : null;
}

function parseCpuStat(text) {
    return numberFrom(text, 'usage_usec');
}

function parseMemoryStat(text) {
    if (!text) return null;
    const values = {};
    for (const line of text.split('\n')) {
        const match = /^(\w+)\s+(\d+)\s*$/.exec(line);
        if (match) values[match[1]] = Number(match[2]);
    }
    const workingSet = (values.anon || 0) + (values.kernel || 0) + (values.sock || 0);
    return {
        workingSet: workingSet || null,
        anon: values.anon || null,
        file: values.file || null,
        kernel: values.kernel || null,
    };
}

function parseHostCpu(text) {
    if (!text) return null;
    const line = text.split('\n').find(value => value.startsWith('cpu '));
    if (!line) return null;
    const fields = line.trim().split(/\s+/).slice(1).map(Number);
    if (fields.length < 4 || fields.some(value => !Number.isFinite(value))) return null;
    const idle = fields[3] + (fields[4] || 0);
    return { total: fields.reduce((sum, value) => sum + value, 0), idle };
}

function parseMemInfo(text) {
    if (!text) return null;
    const read = (key) => {
        const match = new RegExp(`^${key}:\\s+(\\d+)(?:\\s+kB)?\\s*$`, 'm').exec(text);
        return match ? Number(match[1]) : null;
    };
    const total = read('MemTotal');
    const available = read('MemAvailable');
    if (total === null || available === null) return null;
    return { totalBytes: total * 1024, availableBytes: available * 1024 };
}

function parseHostNetwork(text) {
    if (!text) return null;
    let rx = 0;
    let tx = 0;
    for (const line of text.split('\n')) {
        const match = /^\s*([^:]+):\s*(.+)$/.exec(line);
        if (!match || match[1].trim() === 'lo') continue;
        const fields = match[2].trim().split(/\s+/).map(Number);
        if (fields.length < 9) continue;
        rx += fields[0] || 0;
        tx += fields[8] || 0;
    }
    return { rxBytes: rx, txBytes: tx };
}

async function readText(readFile, filename) {
    try {
        return await readFile(filename, 'utf8');
    } catch (_) {
        return null;
    }
}

function createSystemMetrics(options = {}) {
    const intervalMs = Math.max(500, Number(options.intervalMs) || DEFAULT_INTERVAL_MS);
    const windowMs = Math.max(intervalMs, Number(options.windowMs) || DEFAULT_WINDOW_MS);
    const cgroupRoot = options.cgroupRoot || DEFAULT_CGROUP_ROOT;
    const readFile = options.readFile || fs.readFile;
    const now = options.now || Date.now;
    const getNetwork = options.getNetwork || (() => ({ inBytes: 0, outBytes: 0, byPbx: [] }));
    const getActiveCalls = options.getActiveCalls || (() => []);
    const history = [];
    let current = null;
    let previous = null;
    let timer = null;
    let running = false;

    async function sample() {
        if (running) return current;
        running = true;
        const timestamp = now();
        try {
            const [cpuText, memoryText, memoryCurrent, hostCpuText, memInfoText, hostNetText] = await Promise.all([
                readText(readFile, path.join(cgroupRoot, 'cpu.stat')),
                readText(readFile, path.join(cgroupRoot, 'memory.stat')),
                readText(readFile, path.join(cgroupRoot, 'memory.current')),
                readText(readFile, '/proc/stat'),
                readText(readFile, '/proc/meminfo'),
                readText(readFile, '/proc/net/dev'),
            ]);
            const cpuUsage = parseCpuStat(cpuText);
            const memory = parseMemoryStat(memoryText);
            const memoryCurrentBytes = memoryCurrent ? Number(memoryCurrent.trim()) || null : null;
            const hostCpu = parseHostCpu(hostCpuText);
            const memoryInfo = parseMemInfo(memInfoText);
            const hostNet = parseHostNetwork(hostNetText);
            let network = { inBytes: 0, outBytes: 0, byPbx: [] };
            try { network = getNetwork() || network; } catch (_) { /* metrics must not break the dashboard */ }
            let calls = [];
            try { calls = getActiveCalls() || []; } catch (_) { /* metrics must not break the dashboard */ }

            const elapsed = previous ? timestamp - previous.timestamp : 0;
            const cpuPct = previous && previous.cpuUsage !== null && cpuUsage !== null && elapsed > 0
                ? Math.max(0, ((cpuUsage - previous.cpuUsage) / 1000 / elapsed) * 100)
                : null;
            const hostTotalDelta = hostCpu && previous?.hostCpu
                ? hostCpu.total - previous.hostCpu.total : 0;
            const hostCpuPct = previous && previous.hostCpu && hostCpu && hostTotalDelta > 0
                ? Math.max(0, ((hostTotalDelta - (hostCpu.idle - previous.hostCpu.idle)) /
                    hostTotalDelta) * 100)
                : null;
            const inBps = previous && previous.network && elapsed > 0
                ? Math.max(0, (network.inBytes - previous.network.inBytes) * 8 / elapsed * 1000)
                : 0;
            const outBps = previous && previous.network && elapsed > 0
                ? Math.max(0, (network.outBytes - previous.network.outBytes) * 8 / elapsed * 1000)
                : 0;
            const hostInBps = previous && previous.hostNet && hostNet && elapsed > 0
                ? Math.max(0, (hostNet.rxBytes - previous.hostNet.rxBytes) * 8 / elapsed * 1000)
                : 0;
            const hostOutBps = previous && previous.hostNet && hostNet && elapsed > 0
                ? Math.max(0, (hostNet.txBytes - previous.hostNet.txBytes) * 8 / elapsed * 1000)
                : 0;

            const active = calls.reduce((sum, row) => sum + (Number(row.active) || 0), 0);
            const ringing = calls.reduce((sum, row) => sum + (Number(row.ringing) || 0), 0);
            const sampleData = {
                timestamp,
                cpuPct,
                memoryBytes: memory?.workingSet || memoryCurrentBytes,
                memoryCurrentBytes,
                memoryAnonBytes: memory?.anon || null,
                hostCpuPct,
                hostMemoryBytes: memoryInfo ? memoryInfo.totalBytes - memoryInfo.availableBytes : null,
                hostMemoryTotalBytes: memoryInfo?.totalBytes || null,
                hostMemoryPct: memoryInfo ? (memoryInfo.totalBytes - memoryInfo.availableBytes) / memoryInfo.totalBytes * 100 : null,
                sipInBps: inBps,
                sipOutBps: outBps,
                hostInBps,
                hostOutBps,
                activeCalls: active,
                ringingCalls: ringing,
                calls,
            };
            current = sampleData;
            history.push(sampleData);
            while (history.length && timestamp - history[0].timestamp > windowMs) history.shift();
            previous = {
                timestamp,
                cpuUsage,
                hostCpu,
                network: { inBytes: network.inBytes || 0, outBytes: network.outBytes || 0 },
                hostNet,
            };
            return current;
        } finally {
            running = false;
        }
    }

    return {
        start() {
            if (timer) return;
            void sample();
            timer = setInterval(() => { void sample(); }, intervalMs);
            timer.unref?.();
        },
        stop() {
            if (timer) clearInterval(timer);
            timer = null;
        },
        sample,
        snapshot() {
            return {
                current,
                history: history.slice(),
                intervalMs,
                windowMs,
                source: {
                    cgroup: path.join(cgroupRoot, 'cpu.stat'),
                    host: '/proc',
                },
            };
        },
    };
}

module.exports = {
    createSystemMetrics,
    parseCpuStat,
    parseMemoryStat,
    parseHostCpu,
    parseMemInfo,
    parseHostNetwork,
    DEFAULT_INTERVAL_MS,
    DEFAULT_WINDOW_MS,
};
