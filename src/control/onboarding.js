'use strict';
const net = require('node:net');
const dns = require('node:dns').promises;

function isDisallowedIp(ipStr) {
    if (net.isIP(ipStr) !== 4) return true;
    const parts = ipStr.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 127) return true; // zero & loopback
    if (parts[0] === 169 && parts[1] === 254) return true; // link-local
    if (parts[0] >= 224) return true; // multicast & reserved
    return false;
}

async function resolvePbxAddress(value, lookup = dns.lookup) {
    const address = String(value || '').trim().toLowerCase().replace(/\.$/, '');
    const invalid = (msg) => Object.assign(new Error(msg || 'Enter a valid IP address or domain.'), { status: 400 });
    if (!address || address.length > 253 || !/^[a-z0-9.-]+$/.test(address) || address.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw invalid();
    let hosts;
    if (net.isIP(address) === 4) {
        if (isDisallowedIp(address)) throw invalid('Loopback, link-local, multicast and reserved IP addresses are not supported.');
        hosts = [address];
    } else {
        let timer;
        try {
            const answers = await Promise.race([lookup(address, { all: true }), new Promise((_, reject) => {
                timer = setTimeout(() => reject(invalid('DNS lookup timed out')), 3000);
            })]);
            hosts = [...new Set(answers.filter(a => a.family === 4).map(answer => answer.address))];
        } catch { throw invalid('Could not resolve domain name.'); }
        finally { clearTimeout(timer); }
    }
    if (hosts.length !== 1 || isDisallowedIp(hosts[0])) throw invalid('Enter a domain resolving to exactly one valid IPv4 address.');
    const host = hosts[0];
    return { host, wsURL: `ws://${host}:8088/ws`, apiURL: `http://${host}:8080`, mediaIps: host };
}

// A fixed local broker, not a command runner. Passwords exist only in transit.
function requestOnboarding(payload, { socketPath = '/run/sokrat-tenant-onboarding/broker.sock' } = {}) {
    return new Promise((resolve, reject) => {
        const fail = (code) => reject(Object.assign(
            new Error('SSH onboarding unavailable or refused. Check the host key, credentials and PBX endpoints.'),
            { status: 503, code: code || 'onboarding_refused' }
        ));
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
                if (!result.ok) return fail(result.code);
                if (payload.action === 'probe') {
                    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(result.fingerprint)) return fail();
                    resolve({ fingerprint: result.fingerprint });
                } else resolve({ configured: true });
            } catch { fail(); }
        });
    });
}
module.exports = { requestOnboarding, resolvePbxAddress };
