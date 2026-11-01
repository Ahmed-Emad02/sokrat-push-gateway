'use strict';

const DEFAULT_TICK_MS = 30 * 1000;
const DEFAULT_STALE_MS = 3 * 60 * 1000;
const JITTER_MS = 250;

function positiveNumber(value, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Server-side liveness watchdog. It never sends a visible notification and
 * never sends to a device whose heartbeat is fresh. Sends are sequential so a
 * large tenant cannot create a burst at the same instant.
 */
function createHeartbeatScheduler({
    listDevices,
    sendToDevice,
    enabled = false,
    staleMs = DEFAULT_STALE_MS,
    tickMs = DEFAULT_TICK_MS,
    pbxIds = [],
    logger = console,
    now = Date.now,
    sleep = delay,
    jitterMs = JITTER_MS,
}) {
    if (typeof listDevices !== 'function' || typeof sendToDevice !== 'function') {
        throw new TypeError('Heartbeat scheduler requires listDevices and sendToDevice');
    }
    const stale = positiveNumber(staleMs, DEFAULT_STALE_MS);
    const tick = positiveNumber(tickMs, DEFAULT_TICK_MS);
    const allow = new Set(pbxIds);
    const states = new Map();
    let timer = null;
    let running = false;
    let stopped = false;

    function stateFor(deviceId) {
        if (!states.has(deviceId)) {
            states.set(deviceId, { lastSeenAt: 0, lastWakeAt: 0, nextWakeAt: 0, failures: 0 });
        }
        return states.get(deviceId);
    }

    function markSeen(deviceId, seenAt = now()) {
        const state = stateFor(String(deviceId));
        state.lastSeenAt = seenAt;
        state.nextWakeAt = seenAt + stale;
        state.failures = 0;
    }

    async function run() {
        if (!enabled || running || stopped) return { sent: 0, failed: 0, skipped: 0 };
        running = true;
        let sent = 0;
        let failed = 0;
        let skipped = 0;
        try {
            const devices = await listDevices();
            for (const device of Array.isArray(devices) ? devices : []) {
                if (device.platform !== 'android' || typeof device.token !== 'string' || !device.token) {
                    skipped++;
                    continue;
                }
                if (allow.size > 0 && !allow.has(device.pbxId)) {
                    skipped++;
                    continue;
                }
                const state = stateFor(device.deviceId);
                const current = now();
                if (current - state.lastSeenAt < stale) {
                    skipped++;
                    continue;
                }
                if (state.nextWakeAt && current < state.nextWakeAt) {
                    skipped++;
                    continue;
                }
                state.lastWakeAt = current;
                try {
                    await sendToDevice({
                        ...device,
                        device_uuid: device.deviceUuid,
                        voip_token: device.voipToken,
                    }, {
                        msg: 'wake',
                        type: 'keepalive',
                        timestamp: String(current),
                    });
                    sent++;
                    state.failures = 0;
                    state.nextWakeAt = current + stale;
                    logger.log(`[heartbeat] wake sent extension=${device.extension} pbx=${device.pbxId}`);
                } catch (error) {
                    failed++;
                    state.failures++;
                    const backoff = Math.min(stale, 60_000 * (2 ** Math.min(state.failures, 4)));
                    state.nextWakeAt = current + backoff;
                    logger.warn(`[heartbeat] wake failed extension=${device.extension} pbx=${device.pbxId} code=${String(error?.code || error?.message || 'unknown').slice(0, 96)}`);
                }
                if (jitterMs > 0) await sleep(jitterMs);
            }
        } catch (error) {
            logger.error(`[heartbeat] scheduler tick failed: ${String(error?.message || error).slice(0, 160)}`);
        } finally {
            running = false;
        }
        return { sent, failed, skipped };
    }

    function start() {
        if (!enabled || timer || stopped) return;
        timer = setInterval(() => { void run(); }, tick);
        timer.unref?.();
        void run();
    }

    function stop() {
        stopped = true;
        clearInterval(timer);
        timer = null;
    }

    return {
        start,
        stop,
        run,
        markSeen,
        staleMs: stale,
        tickMs: tick,
        getState: deviceId => (states.has(String(deviceId)) ? { ...states.get(String(deviceId)) } : null),
    };
}

module.exports = { createHeartbeatScheduler, DEFAULT_TICK_MS, DEFAULT_STALE_MS };
