'use strict';
const { WebSocket, WebSocketServer } = require('ws');

// Device authorization belongs to the control store. SIP passwords continue to
// be checked upstream by the selected PBX; no password is parsed/stored here.
function attachSipProxy(server, { authorize, isAuthorized, consumeTicket }) {
    if (typeof authorize !== 'function' || typeof isAuthorized !== 'function') throw new Error('Authorization and revocation checks are required');
    const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024,
        perMessageDeflate: false, handleProtocols: protocols => protocols.has('sip') ? 'sip' : false });
    const sessions = new Set();
    let pending = 0;
    server.on('upgrade', async (req, socket, head) => {
        socket.on('error', () => {});
        if (sessions.size + pending >= 1000) {
            socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n'); return;
        }
        pending++;
        const deadline = setTimeout(() => socket.destroy(), 8000);
        try {
            const url = new URL(req.url, 'http://gateway.invalid');
            if (url.pathname !== '/ws' || req.headers['sec-websocket-protocol'] !== 'sip') {
                socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n'); return;
            }
            let device = url.searchParams.get('device');
            let token = url.searchParams.get('token');
            let route;
            if (consumeTicket) {
                const ticket = url.searchParams.get('ticket');
                const accepted = ticket && ticket.length <= 128 ? await consumeTicket(ticket) : null;
                if (!accepted) {
                    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
                }
                device = accepted.deviceId; token = accepted.token; route = accepted.route;
            }
            if (!device || !token || token.length > 256 || device.length > 128) {
                socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return;
            }
            route = route || await authorize(device, token);
            if (!route || !/^wss?:\/\//.test(route.wsUrl) || !route.extension) {
                socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
            }
            if (socket.destroyed) return;
            if ([...sessions].filter(session => session.device === device).length >= 3) {
                socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n'); return;
            }
            wss.handleUpgrade(req, socket, head, client => {
                const upstream = new WebSocket(route.wsUrl, 'sip', { maxPayload: 256 * 1024,
                    perMessageDeflate: false, handshakeTimeout: 8000, followRedirects: false });
                const session = { client, upstream, device, route, token };
                sessions.add(session);
                let alive = true;
                client.on('pong', () => { alive = true; });
                session.heartbeat = () => {
                    if (!alive) { client.terminate(); upstream.terminate(); return; }
                    alive = false; client.ping();
                };
                const close = () => {
                    sessions.delete(session);
                    client.terminate(); upstream.terminate();
                };
                const queue = [];
                const incomingDialogs = new Map();
                let queued = 0;
                const send = (target, data, binary) => {
                    if (target.bufferedAmount > 1024 * 1024) return close();
                    if (target.readyState === WebSocket.OPEN) target.send(data, { binary }, err => { if (err) close(); });
                };
                client.on('message', (data, binary) => {
                    // Bind all client-originated requests to the assigned
                    // extension. SIP responses to incoming calls are exempt.
                    const message = data.toString().replace(/^(?:\r\n)+/, '');
                    if (message === '') { send(upstream, data, binary); return; }
                    const split = message.indexOf('\r\n\r\n');
                    if (split < 0) return close();
                    const headerBlock = message.slice(0, split);
                    const lengths = [...headerBlock.matchAll(/^(?:Content-Length|l):\s*(\d+)\s*$/gmi)];
                    const bodyLength = Buffer.byteLength(message.slice(split + 4));
                    if (lengths.length > 1 || bodyLength !== (lengths.length ? Number(lengths[0][1]) : 0)) return close();
                    if (!/^(?:[A-Z]+\s+sips?:\S+\s+SIP\/2\.0|SIP\/2\.0\s+\d{3}[^\r\n]*)\r\n/.test(message)) return close();
                    if (/^[A-Z]+\s+sips?:\S+\s+SIP\/2\.0\r?\n/.test(message)) {
                        const headers = message.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
                        const fromHeaders = [...headers.matchAll(/^(?:From|f):[ \t]*(.*)$/gmi)];
                        const from = fromHeaders.length === 1 && /(?:<|^)sips?:([^@>\s]+)@/i.exec(fromHeaders[0][1]);
                        const callIds = [...headers.matchAll(/^(?:Call-ID|i):[ \t]*([^\r\n]+)$/gmi)];
                        const incoming = callIds.length === 1 && incomingDialogs.get(callIds[0][1].trim());
                        // In an incoming SIP dialog the caller remains From,
                        // even on BYE/re-INVITE originated by the called client.
                        // Only allow that identity for a dialog observed from
                        // the authenticated upstream; REGISTER is never exempt.
                        const incomingRequest = !/^REGISTER\s/.test(message) && incoming &&
                            /^To:[^\r\n]*;\s*tag=/mi.test(headers) && from && from[1] === incoming;
                        if (!from || (from[1] !== route.extension && !incomingRequest)) return close();
                        for (const auth of headers.matchAll(/^(?:Proxy-Authorization|Authorization):[ \t]*(.*)$/gmi)) {
                            const user = /\busername\s*=\s*"([^"]*)"/i.exec(auth[1]);
                            if (!user || user[1] !== route.extension) return close();
                        }
                    }
                    if (upstream.readyState === WebSocket.CONNECTING) {
                        queued += data.length;
                        if (queued > 256 * 1024) return close();
                        queue.push([data, binary]);
                    } else send(upstream, data, binary);
                });
                upstream.on('open', () => { for (const [data, binary] of queue) send(upstream, data, binary); queue.length = 0; });
                upstream.on('message', (data, binary) => {
                    const message = data.toString();
                    if (/^INVITE\s/.test(message)) {
                        const headers = message.split('\r\n\r\n', 1)[0].replace(/\r\n[ \t]+/g, ' ');
                        const id = /^(?:Call-ID|i):[ \t]*([^\r\n]+)$/mi.exec(headers);
                        const from = /^(?:From|f):[ \t]*.*?<sips?:([^@>\s]+)@/mi.exec(headers);
                        if (id && from && incomingDialogs.size < 128) incomingDialogs.set(id[1].trim(), from[1]);
                    }
                    send(client, data, binary);
                });
                client.on('close', close); upstream.on('close', close);
                client.on('error', close); upstream.on('error', close);
            });
        } catch (_) {
            if (!socket.destroyed) socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
        } finally { clearTimeout(deadline); pending--; }
    });
    const timer = setInterval(async () => {
        for (const session of sessions) {
            try {
                if (!await isAuthorized(session.device, session.route, session.token)) {
                    session.client.terminate(); session.upstream.terminate();
                } else session.heartbeat();
            } catch (_) { session.client.terminate(); session.upstream.terminate(); }
        }
    }, 10000);
    timer.unref();
    return { close() { clearInterval(timer); for (const s of sessions) { s.client.terminate(); s.upstream.terminate(); } wss.close(); } };
}
module.exports = { attachSipProxy };
