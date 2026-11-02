'use strict';

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

const PREFIX = '/api/gateway/chat/socket.io';

function reject(socket, status, text) {
    if (socket.writable) socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

/**
 * Raw WebSocket proxy for the PBX /chat Socket.IO namespace.
 *
 * The mobile client gets a short-lived gateway ticket after device approval.
 * PBX chat-token authentication still happens inside Socket.IO; this proxy
 * never sees the SIP password.
 */
function attachChatSocketProxy(server, { consume }) {
    const listener = (req, socket, head) => {
        if (!req.url || !req.url.startsWith(PREFIX)) return;
        const incoming = new URL(req.url, 'http://gateway.invalid');
        const ticket = incoming.searchParams.get('ticket');
        const assignment = consume(ticket);
        if (!assignment) return reject(socket, 401, 'Unauthorized');
        incoming.searchParams.delete('ticket');
        const upstream = new URL(assignment.apiUrl);
        const rest = incoming.pathname.slice(PREFIX.length) || '/';
        const path = `/socket.io${rest}${incoming.search ? `?${incoming.searchParams.toString()}` : ''}`;
        const transport = upstream.protocol === 'https:' ? https : http;
        const headers = { ...req.headers, host: upstream.host };
        delete headers['x-sokrat-device'];
        delete headers.authorization;
        const proxy = transport.request({
            hostname: upstream.hostname,
            port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
            path,
            method: req.method,
            headers,
            agent: false,
        });
        proxy.setTimeout(30000, () => proxy.destroy());
        proxy.on('upgrade', (response, upstreamSocket, upstreamHead) => {
            if (!socket.writable) { upstreamSocket.destroy(); return; }
            const lines = [`HTTP/1.1 101 Switching Protocols`];
            for (let i = 0; i < response.rawHeaders.length; i += 2) {
                lines.push(`${response.rawHeaders[i]}: ${response.rawHeaders[i + 1]}`);
            }
            socket.write(lines.join('\r\n') + '\r\n\r\n');
            if (upstreamHead && upstreamHead.length) upstreamSocket.write(upstreamHead);
            if (head && head.length) upstreamSocket.write(head);
            upstreamSocket.pipe(socket);
            socket.pipe(upstreamSocket);
            upstreamSocket.on('error', () => socket.destroy());
            socket.on('error', () => upstreamSocket.destroy());
        });
        proxy.on('response', (response) => {
            reject(socket, response.statusCode || 502, 'Bad Gateway');
            response.resume();
        });
        proxy.on('error', () => reject(socket, 502, 'Bad Gateway'));
        proxy.setTimeout(300000, () => proxy.destroy());
        proxy.end();
    };
    server.on('upgrade', listener);
    return () => server.removeListener('upgrade', listener);
}

module.exports = { attachChatSocketProxy, PREFIX };
