'use strict';

const fs = require('node:fs');

const DEFAULT_FILE = '/etc/sokrat/host-firewall.json';

function cleanText(value, max) {
    return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

/** Read only the installer-managed host firewall summary; never expose secrets. */
function readHostFirewall(filePath = DEFAULT_FILE) {
    let record;
    try {
        record = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (_) {
        return null;
    }
    if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
    const manager = cleanText(record.manager, 16).toLowerCase();
    if (record.configured !== true || !['ufw', 'firewalld'].includes(manager)) return null;
    const ports = Array.isArray(record.ports)
        ? record.ports
            .filter((value) => typeof value === 'string' && /^[0-9]{1,5}(?::[0-9]{1,5})?\/(?:tcp|udp)$/.test(value))
            .slice(0, 32)
        : [];
    const updatedAt = cleanText(record.updatedAt, 40);
    return {
        configured: true,
        manager,
        sshPort: Number.isInteger(record.sshPort) && record.sshPort > 0 && record.sshPort <= 65535
            ? record.sshPort
            : null,
        tls: record.tls === true,
        ports,
        updatedAt: updatedAt && !Number.isNaN(Date.parse(updatedAt)) ? updatedAt : null,
    };
}

module.exports = { DEFAULT_FILE, readHostFirewall };
