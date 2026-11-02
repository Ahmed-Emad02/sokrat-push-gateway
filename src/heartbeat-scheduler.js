'use strict';
const { fingerprintToken, isPermanentTokenError } = require('./push-errors');

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
    markInvalid,
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
            states.set(deviceId, { lastSeenAt: 0, lastWakeAt: 0, nextWakeAt: 0, failures: 0, invalid: false, invalidLogged: false, tokenFingerprint: '' });
        }
        return states.get(deviceId);
    }

    function markSeen(deviceId, seenAt = now()) {
        const state = stateFor(String(deviceId));
        state.lastSeenAt = seenAt;
        state.nextWakeAt = seenAt + stale;
        state.failures = 0;
        state.invalid = false;
        state.invalidLogged = false;
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
                if (device.platform !== 'android' || typeof device.token !== 'string' || !device.token ||
                    device.pushState === 'invalid') {
                    skipped++;
                    continue;
                }
                if (allow.size > 0 && !allow.has(device.pbxId)) {
                    skipped++;
                    continue;
                }
                const state = stateFor(device.deviceId);
                const tokenFingerprint = fingerprintToken(device.token);
                if (state.tokenFingerprint !== tokenFingerprint) {
                    state.tokenFingerprint = tokenFingerprint;
                    state.invalid = false;
                    state.invalidLogged = false;
                    state.failures = 0;
                    state.nextWakeAt = 0;
                }
                if (state.invalid) {
                    skipped++;
                    continue;
                }
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
                    const code = String(error?.code || 'unknown').slice(0, 96);
                    if (isPermanentTokenError(error)) {
                        let quarantined = true;
                        if (typeof markInvalid === 'function') {
                            try {
                                quarantined = await markInvalid(device.deviceId, tokenFingerprint, code) !== false;
                            } catch (markError) {
                                logger.warn(`[heartbeat] invalid-token quarantine failed extension=${device.extension} pbx=${device.pbxId} code=${String(markError?.code || 'unknown').slice(0, 96)}`);
                            }
                        }
                        if (quarantined) {
                            state.invalid = true;
                            if (!state.invalidLogged) {
                                state.invalidLogged = true;
                                logger.warn(`[heartbeat] token invalid; re-registration required extension=${device.extension} pbx=${device.pbxId} code=${code}`);
                            }
                            continue;
                        }
                        // The token changed while this failure was in flight; do
                        // not suppress the newly registered token.
                        state.failures = 0;
                        state.nextWakeAt = 0;
                    }
                    state.failures++;
                    const backoff = Math.min(stale, 60_000 * (2 ** Math.min(state.failures, 4)));
                    state.nextWakeAt = current + backoff;
                    logger.warn(`[heartbeat] wake failed extension=${device.extension} pbx=${device.pbxId} code=${code}`);
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
