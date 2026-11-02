'use strict';

const crypto = require('node:crypto');

const TTL_MS = 60 * 1000;

function createChatTickets() {
    const tickets = new Map();
    function sweep(now = Date.now()) {
        for (const [key, entry] of tickets) if (entry.expiresAt <= now) tickets.delete(key);
    }
    return {
        issue(assignment) {
            sweep();
            const ticket = crypto.randomBytes(24).toString('base64url');
            tickets.set(ticket, { assignment, expiresAt: Date.now() + TTL_MS });
            return { ticket, expiresIn: 60 };
        },
        consume(ticket) {
            sweep();
            const entry = tickets.get(String(ticket || ''));
            if (!entry) return null;
            tickets.delete(String(ticket));
            return entry.assignment;
        },
    };
}

module.exports = { createChatTickets, TTL_MS };
