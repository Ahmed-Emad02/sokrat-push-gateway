'use strict';
const net = require('node:net');

// A fixed local broker, not a command runner. Passwords exist only in transit.
function requestOnboarding(payload, { socketPath = '/run/sokrat-tenant-onboarding/broker.sock' } = {}) {
    return new Promise((resolve, reject) => {
        const fail = () => reject(Object.assign(new Error('SSH onboarding unavailable or refused. Check the host key, credentials and PBX endpoints.'), { status: 503 }));
        const socket = net.createConnection(socketPath);
        let data = '';
        socket.setTimeout(90000);
        socket.on('connect', () => socket.end(JSON.stringify(payload)));
        socket.on('data', chunk => {
            data += chunk;
            if (Buffer.byteLength(data) > 8192) { socket.destroy(); fail(); }
        });
        socket.on('timeout', () => { socket.destroy(); fail(); });
        socket.on('error', fail);
        socket.on('end', () => {
            try {
                const result = JSON.parse(data);
                if (!result.ok) return fail();
                if (payload.action === 'probe') {
                    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(result.fingerprint)) return fail();
                    resolve({ fingerprint: result.fingerprint });
                } else resolve({ configured: true });
            } catch { fail(); }
        });
    });
}
module.exports = { requestOnboarding };
