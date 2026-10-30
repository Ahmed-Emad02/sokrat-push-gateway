'use strict';
const { WebSocket, WebSocketServer } = require('ws');

// Device authorization belongs to the control store. SIP passwords continue to
// be checked upstream by the selected PBX; no password is parsed/stored here.
function attachSipProxy(server, { authorize, isAuthorized, consumeTicket, scopeIncomingCallId }) {
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
                const close = (why) => {
                    console.warn(`[sip-proxy][${route.extension}] close: ${why || 'unknown'}`);
                    sessions.delete(session);
                    client.terminate(); upstream.terminate();
                };
                const queue = [];
                const incomingDialogs = new Map();
                let queued = 0;
                const send = (target, data, binary) => {
                    if (target.bufferedAmount > 1024 * 1024) return close('buffer_overflow');
                    if (target.readyState === WebSocket.OPEN) target.send(data, { binary }, err => { if (err) close('send_error: ' + (err?.message || 'unknown')); });
                };
                client.on('message', (data, binary) => {
                    // Bind all client-originated requests to the assigned
                    // extension. SIP responses to incoming calls are exempt.
                    const message = data.toString().replace(/^(?:\r\n)+/, '');
                    if (message === '') { send(upstream, data, binary); return; }
                    const split = message.indexOf('\r\n\r\n');
                    if (split < 0) return close('no_crlfcrlf');
                    const headerBlock = message.slice(0, split);
                    const lengths = [...headerBlock.matchAll(/^(?:Content-Length|l):\s*(\d+)\s*$/gmi)];
                    const bodyLength = Buffer.byteLength(message.slice(split + 4));
                    if (lengths.length > 1 || bodyLength !== (lengths.length ? Number(lengths[0][1]) : 0)) return close(`content_length_mismatch: declared=${lengths[0]?.[1]} body=${bodyLength}`);
                    if (!/^(?:[A-Z]+\s+sips?:\S+\s+SIP\/2\.0|SIP\/2\.0\s+\d{3}[^\r\n]*)\r\n/.test(message)) return close('bad_sip_format: ' + message.slice(0, 40));
                    if (/^[A-Z]+\s+sips?:\S+\s+SIP\/2\.0\r?\n/.test(message)) {
                        const headers = message.split(/\r?\n\r?\n/, 1)[0].replace(/\r?\n[ \t]+/g, ' ');
                        const fromHeaders = [...headers.matchAll(/^(?:From|f):[ \t]*(.*)$/gmi)];
                        const from = fromHeaders.length === 1 && /(?:<|^)sips?:([^@>\s]+)@/i.exec(fromHeaders[0][1]);
                        const toHeaders = [...headers.matchAll(/^(?:To|t):[ \t]*(.*)$/gmi)];
                        const to = toHeaders.length === 1 && /(?:<|^)sips?:([^@>\s]+)@/i.exec(toHeaders[0][1]);
                        const callIds = [...headers.matchAll(/^(?:Call-ID|i):[ \t]*([^\r\n]+)$/gmi)];
                        const incoming = callIds.length === 1 && incomingDialogs.get(callIds[0][1].trim());
                        // In an incoming SIP dialog observed from the authenticated upstream,
                        // an in-dialog request (such as BYE or re-INVITE) originated by the
                        // called client has a To header with tag= pointing to the caller (incoming).
                        // The From header may contain the route extension OR the client's contact URI user.
                        // For any client-originated request outside an incoming dialog (like outgoing INVITE/REGISTER),
                        // From MUST match route.extension.
                        const incomingRequest = !/^REGISTER\s/.test(message) && incoming &&
                            /^(?:To|t):[^\r\n]*;\s*tag=/mi.test(headers) && to && to[1] === incoming;
                        const validFrom = from && (from[1] === route.extension || incomingRequest);
                        if (!validFrom) {
                            console.warn(`[sip-proxy][${route.extension}] rejected message: ${message.split('\r\n')[0]} | From: ${fromHeaders[0]?.[1]} | To: ${toHeaders[0]?.[1]}`);
                            return close(`from_mismatch: from=${from?.[1]} expected=${route.extension} incoming=${incoming}`);
                        }
                        for (const auth of headers.matchAll(/^(?:Proxy-Authorization|Authorization):[ \t]*(.*)$/gmi)) {
                            const user = /\busername\s*=\s*"([^"]*)"/i.exec(auth[1]);
                            if (!user || user[1] !== route.extension) return close('auth_username_mismatch');
                        }
                    }
                    if (upstream.readyState === WebSocket.CONNECTING) {
                        queued += data.length;
                        if (queued > 256 * 1024) return close('queue_overflow');
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
                    if (scopeIncomingCallId && /^INVITE\s/.test(message)) {
                        const split = message.indexOf('\r\n\r\n');
                        const headers = split >= 0 ? message.slice(0, split) : '';
                        const ids = [...headers.matchAll(/^X-Sokrat-Call-ID:[ \t]*([^\r\n]*)(?:\r\n[ \t]+[^\r\n]*)*/gmi)];
                        if (ids.length > 1) return close('ambiguous_application_call_id');
                        if (ids.length === 1) {
                            try {
                                const id = ids[0];
                                if (id[0].includes('\r\n')) throw new Error('Folded application call id');
                                const scoped = scopeIncomingCallId(id[1].trim(), route);
                                if (typeof scoped !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scoped)) throw new Error('Invalid scoped call id');
                                // Rewrite only this application header, retaining the body as
                                // bytes (including SDP) and the protocol's dialog identifiers.
                                const before = Buffer.byteLength(message.slice(0, id.index));
                                const after = before + Buffer.byteLength(id[0]);
                                data = Buffer.concat([data.subarray(0, before),
                                    Buffer.from(`X-Sokrat-Call-ID: ${scoped}`), data.subarray(after)]);
                            } catch (_) { return close('invalid_application_call_id'); }
                        }
                    }
                    send(client, data, binary);
                });
                client.on('close', (code, reason) => close(`client_close: code=${code} reason=${reason}`));
                upstream.on('close', (code, reason) => close(`upstream_close: code=${code} reason=${reason}`));
                client.on('error', err => close('client_error: ' + (err?.message || 'unknown')));
                upstream.on('error', err => close('upstream_error: ' + (err?.message || 'unknown')));
            });
        } catch (_) {
            if (!socket.destroyed) socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
        } finally { clearTimeout(deadline); pending--; }
    });
    const timer = setInterval(async () => {
        for (const session of sessions) {
            try {
                if (!await isAuthorized(session.device, session.route, session.token)) {
                    console.warn(`[sip-proxy][${session.route?.extension}] terminated: authorization_revoked`);
                    session.client.terminate(); session.upstream.terminate();
                } else session.heartbeat();
            } catch (err) {
                console.warn(`[sip-proxy][${session.route?.extension}] terminated: heartbeat_exception:`, err?.message);
                session.client.terminate(); session.upstream.terminate();
            }
        }
    }, 10000);
    timer.unref();
    return { close() { clearInterval(timer); for (const s of sessions) { s.client.terminate(); s.upstream.terminate(); } wss.close(); } };
}
module.exports = { attachSipProxy };
