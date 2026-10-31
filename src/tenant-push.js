'use strict';
const { tenantCallId } = require('./tenant-call-id');

// Tenant registries are local to the gateway; never combine PBX-local rows by
// extension alone. The approved assignment supplies pbxId and extension.
function installTenantPush(router, { store, authorizeDevice, authorizePbx, sendToDevice, normalizeCallId }) {
    router.post('/register-device', async (req, res) => {
        try {
            const assignment = await authorizeDevice(req);
            if (!assignment) return res.status(403).json({ error: 'Device approval required' });
            const { platform, token, voipToken, deviceUuid, appVersion } = req.body || {};
            if (!['android', 'ios'].includes(platform) || typeof token !== 'string' || !token || token.length > 4096 ||
                (platform === 'ios' && (typeof voipToken !== 'string' || !voipToken || voipToken.length > 4096)) ||
                deviceUuid !== assignment.deviceUuid) return res.status(400).json({ error: 'Invalid device registration' });
            if (req.body.extension && req.body.extension !== assignment.extension) return res.status(403).json({ error: 'Extension does not match approval' });
            await store.savePush({ deviceId: assignment.deviceId, deviceUuid: assignment.deviceUuid, pbxId: assignment.pbxId,
                extension: assignment.extension, platform, token, voipToken: platform === 'ios' ? voipToken : '',
                authorizationRevision: assignment.authorizationRevision || 0,
                appVersion: String(appVersion || '').slice(0, 64), updatedAt: Date.now() });
            res.json({ success: true });
        } catch (error) { res.status(error.status === 409 ? 409 : 503).json({ error: error.status === 409 ? 'Push token already registered' : 'Device registry unavailable' }); }
    });
    router.post('/remove-device', async (req, res) => {
        try {
            const assignment = await authorizeDevice(req);
            if (!assignment) return res.status(403).json({ error: 'Device approval required' });
            await store.removePush(assignment.deviceId);
            res.json({ success: true });
        } catch (_) { res.status(503).json({ error: 'Device registry unavailable' }); }
    });
    router.post('/incoming-call', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const pbx = await authorizePbx(req);
            if (!pbx) return res.status(403).json({ error: 'PBX authentication required' });
            const { callee, caller, callerName, callId } = req.body || {};
            if (typeof callee !== 'string' || !/^[A-Za-z0-9*#._-]{1,64}$/.test(callee)) return res.status(400).json({ error: 'Invalid callee' });
            if (typeof callId !== 'string' || !callId || callId.length > 96) return res.status(400).json({ error: 'Invalid callId' });
            let id;
            try { id = tenantCallId(normalizeCallId, pbx.id, callId); }
            catch (_) { return res.status(400).json({ error: 'Invalid callId' }); }
            const devices = await store.listPush(pbx.id, callee);
            let count = 0;
            let failed = 0;
            let skipped = 0;
            if (!devices.length) {
                console.warn(`[tenant-push] no approved push devices extension=${callee} callId=${id}`);
            }
            for (const device of devices) {
                const assignment = await store.approvedAssignment(device.deviceId);
                if (!assignment || assignment.pbxId !== pbx.id || assignment.extension !== callee) {
                    skipped++;
                    continue;
                }
                try {
                    const messageId = await sendToDevice({ ...device, device_uuid: assignment.deviceUuid, voip_token: device.voipToken }, {
                        callerId: String(caller || '').slice(0, 128), callerName: String(callerName || caller || '').slice(0, 256),
                        extension: callee, callId: id, timestamp: Date.now(), sipWss: ''
                    });
                    count++;
                    // FCM accepts a message for delivery; this ID is not proof the
                    // phone woke. It is intentionally free of tokens/caller data.
                    if (messageId) {
                        console.log(`[tenant-push] dispatched extension=${callee} callId=${id} messageId=${String(messageId).slice(0, 96)}`);
                    }
                } catch (error) {
                    failed++;
                    console.warn(`[tenant-push] dispatch failed extension=${callee} callId=${id} code=${String(error.code || error.message || 'unknown').slice(0, 96)}`);
                    if (/registration-token-not-registered|unregistered|invalid-registration-token|baddevicetoken/i.test(String(error.code || error.message || ''))) {
                        await store.removePush(device.deviceId);
                    }
                }
            }
            console.log(`[tenant-push] incoming-call extension=${callee} callId=${id} devices=${devices.length} dispatched=${count} failed=${failed} skipped=${skipped}`);
            res.json({ status: failed ? 'partial' : 'dispatched', callId: id, count, failed });
        } catch (_) { res.status(503).json({ error: 'Push dispatch unavailable' }); }
    });
    router.post('/cancel-call', async (req, res) => {
        res.set('Cache-Control', 'no-store');
        try {
            const pbx = await authorizePbx(req);
            if (!pbx) return res.status(403).json({ error: 'PBX authentication required' });
            const { callee, callId } = req.body || {};
            if (typeof callee !== 'string' || !/^[A-Za-z0-9*#._-]{1,64}$/.test(callee)) return res.status(400).json({ error: 'Invalid callee' });
            if (typeof callId !== 'string' || !callId || callId.length > 96) return res.status(400).json({ error: 'Invalid callId' });
            let id;
            try { id = tenantCallId(normalizeCallId, pbx.id, callId); }
            catch (_) { return res.status(400).json({ error: 'Invalid callId' }); }
            const devices = await store.listPush(pbx.id, callee);
            let count = 0;
            for (const device of devices) {
                const assignment = await store.approvedAssignment(device.deviceId);
                if (!assignment || assignment.pbxId !== pbx.id || assignment.extension !== callee) continue;
                try {
                    await sendToDevice({ ...device, device_uuid: assignment.deviceUuid, voip_token: device.voipToken }, {
                        msg: 'cancel-call', callerId: '', callerName: '',
                        extension: callee, callId: id, timestamp: Date.now(), sipWss: ''
                    });
                    count++;
                } catch (_) {}
            }
            res.json({ status: 'cancelled', callId: id, count });
        } catch (_) { res.status(503).json({ error: 'Push dispatch unavailable' }); }
    });
}

module.exports = { installTenantPush };
