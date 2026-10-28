'use strict';

/**
 * Sokrat device approval console (vanilla JS, no dependencies).
 *
 * Security notes:
 * - Every value coming from the API is written with `textContent` / text nodes.
 *   There is no `innerHTML` in this file, so PBX names, device names and error
 *   strings can never become markup.
 * - Mutations send the per-session CSRF token in `X-CSRF-Token`.
 * - Requests use `credentials: 'same-origin'` and relative URLs derived from
 *   the mount path injected into `<body data-control-base>`.
 */

(() => {
    const base = String(document.body.dataset.controlBase || '').replace(/\/+$/, '');
    const endpoint = (path) => `${base}${path}`;

    const refs = {
        main: document.getElementById('main'),
        signOut: document.getElementById('sign-out'),
        loginView: document.getElementById('login-view'),
        loginForm: document.getElementById('login-form'),
        loginSubmit: document.getElementById('login-submit'),
        loginMessage: document.getElementById('login-message'),
        loginNotConfigured: document.getElementById('login-not-configured'),
        password: document.getElementById('password'),
        dashboard: document.getElementById('dashboard-view'),
        alert: document.getElementById('dashboard-alert'),
        status: document.getElementById('status-message'),
        statEnabled: document.getElementById('stat-enabled'),
        statPending: document.getElementById('stat-pending'),
        statApproved: document.getElementById('stat-approved'),
        statCap: document.getElementById('stat-cap'),
        pbxForm: document.getElementById('pbx-form'),
        pbxId: document.getElementById('pbx-id'),
        pbxName: document.getElementById('pbx-name'),
        pbxWs: document.getElementById('pbx-ws'),
        pbxApi: document.getElementById('pbx-api'),
        pbxIps: document.getElementById('pbx-ips'),
        pbxEnabled: document.getElementById('pbx-enabled'),
        pbxSubmit: document.getElementById('pbx-submit'),
        pbxCancel: document.getElementById('pbx-cancel'),
        pbxRows: document.getElementById('pbx-rows'),
        pbxEmpty: document.getElementById('pbx-empty'),
        pbxCapHint: document.getElementById('pbx-cap-hint'),
        inviteForm: document.getElementById('invite-form'),
        inviteLabel: document.getElementById('invite-label'),
        invitePbx: document.getElementById('invite-pbx'),
        inviteExtension: document.getElementById('invite-extension'),
        inviteUses: document.getElementById('invite-uses'),
        inviteTtl: document.getElementById('invite-ttl'),
        inviteSubmit: document.getElementById('invite-submit'),
        inviteRows: document.getElementById('invite-rows'),
        inviteEmpty: document.getElementById('invite-empty'),
        tokenPanel: document.getElementById('token-panel'),
        tokenValue: document.getElementById('token-value'),
        tokenCopy: document.getElementById('token-copy'),
        tokenDismiss: document.getElementById('token-dismiss'),
        secretPanel: document.getElementById('secret-panel'),
        secretValue: document.getElementById('secret-value'),
        secretCopy: document.getElementById('secret-copy'),
        secretDismiss: document.getElementById('secret-dismiss'),
        pendingRows: document.getElementById('pending-rows'),
        pendingEmpty: document.getElementById('pending-empty'),
        approvedRows: document.getElementById('approved-rows'),
        approvedEmpty: document.getElementById('approved-empty'),
        activityList: document.getElementById('activity-list'),
        activityEmpty: document.getElementById('activity-empty')
    };

    if (!refs.main || !refs.loginForm || !refs.pbxRows) return;

    const dateFormatter = new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short'
    });

    let csrfToken = null;
    let snapshot = null;
    let editingPbxId = null;
    let statusTimer = null;

    // ------------------------------------------------------------- utilities

    function el(tag, props, ...children) {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(props || {})) {
            if (value === undefined || value === null || value === false) continue;
            if (key === 'class') node.className = value;
            else if (key === 'text') node.textContent = String(value);
            else if (key === 'dataset') Object.assign(node.dataset, value);
            else if (key === 'value') node.value = value;
            else if (key === 'checked') node.checked = Boolean(value);
            else if (key.startsWith('on') && typeof value === 'function') {
                node.addEventListener(key.slice(2).toLowerCase(), value);
            } else {
                node.setAttribute(key, value === true ? '' : String(value));
            }
        }
        for (const child of children.flat(Infinity)) {
            if (child === null || child === undefined || child === false) continue;
            node.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return node;
    }

    function formatTime(value) {
        const parsed = Date.parse(String(value || ''));
        return Number.isFinite(parsed) ? dateFormatter.format(parsed) : '—';
    }

    function shortId(value) {
        return String(value || '').slice(0, 12);
    }

    function deviceTitle(device) {
        if (device.deviceName) return device.deviceName;
        if (device.model) return device.model;
        return device.platform === 'ios' ? 'iOS device' : 'Android device';
    }

    function deviceSubtitle(device) {
        const parts = [device.platform];
        if (device.osVersion) parts.push(device.osVersion);
        if (device.appVersion) parts.push(`app ${device.appVersion}`);
        parts.push(shortId(device.deviceUuid));
        return parts.join(' · ');
    }

    /**
     * How the device arrived: automatic enrollment (client-held claim secret,
     * nothing to hand over) or an operator-issued invite token.
     */
    function enrollmentSource(device) {
        if (device.enrollmentMode === 'claim') {
            return device.claimRedeemedAt ? 'automatic · claimed' : 'automatic · awaiting claim';
        }
        return device.enrollmentTokenId
            ? `invite ${shortId(device.enrollmentTokenId)}`
            : 'invite';
    }

    function setBusy(button, busy, label) {
        if (!button) return;
        if (busy) {
            button.dataset.idleLabel = button.textContent;
            button.textContent = label || 'Working…';
            button.disabled = true;
        } else {
            if (button.dataset.idleLabel) button.textContent = button.dataset.idleLabel;
            delete button.dataset.idleLabel;
            button.disabled = false;
        }
    }

    function showError(message) {
        if (statusTimer) {
            clearTimeout(statusTimer);
            statusTimer = null;
        }
        refs.alert.textContent = message;
        refs.alert.hidden = false;
        refs.status.hidden = true;
    }

    function showStatus(message) {
        refs.alert.hidden = true;
        refs.alert.textContent = '';
        refs.status.textContent = message;
        refs.status.hidden = false;
        if (statusTimer) clearTimeout(statusTimer);
        statusTimer = setTimeout(() => {
            refs.status.hidden = true;
            statusTimer = null;
        }, 8000);
    }

    function clearMessages() {
        refs.alert.hidden = true;
        refs.alert.textContent = '';
        refs.status.hidden = true;
        refs.status.textContent = '';
    }

    function showLoginMessage(message) {
        refs.loginMessage.textContent = message;
        refs.loginMessage.hidden = !message;
    }

    // ------------------------------------------------------------------ API

    async function api(path, options = {}) {
        const method = options.method || 'GET';
        const headers = { Accept: 'application/json' };
        if (options.body !== undefined) headers['Content-Type'] = 'application/json';
        if (method !== 'GET' && method !== 'HEAD' && csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        let response;
        try {
            response = await fetch(endpoint(path), {
                method,
                headers,
                body: options.body === undefined ? undefined : JSON.stringify(options.body),
                credentials: 'same-origin',
                cache: 'no-store',
                redirect: 'error'
            });
        } catch (cause) {
            const error = new Error('Cannot reach the gateway. Check the connection and try again.');
            error.cause = cause;
            throw error;
        }

        let payload = null;
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            try {
                payload = await response.json();
            } catch {
                payload = null;
            }
        }

        if (!response.ok) {
            const error = new Error(
                (payload && (payload.message || payload.error)) ||
                `Request failed (${response.status})`
            );
            error.status = response.status;
            error.code = payload && payload.error;
            error.retryAfterMs = payload && payload.retryAfterMs;
            throw error;
        }
        return payload || {};
    }

    function handleError(error) {
        if (error && error.status === 401) {
            onUnauthenticated('Your session expired. Sign in again.');
            return;
        }
        if (error && error.status === 429 && error.retryAfterMs) {
            const seconds = Math.max(1, Math.ceil(error.retryAfterMs / 1000));
            showError(`${error.message} (retry in ${seconds}s)`);
            return;
        }
        showError(error && error.message ? error.message : 'Something went wrong.');
    }

    // --------------------------------------------------------------- session

    function showLogin() {
        refs.dashboard.hidden = true;
        refs.loginView.hidden = false;
        refs.signOut.hidden = true;
        refs.main.removeAttribute('aria-busy');
    }

    function onUnauthenticated(message) {
        csrfToken = null;
        snapshot = null;
        showLogin();
        showLoginMessage(message || 'Sign in to continue.');
    }

    async function enterDashboard() {
        refs.loginView.hidden = true;
        refs.dashboard.hidden = false;
        refs.signOut.hidden = false;
        await refresh();
    }

    async function refresh() {
        refs.main.setAttribute('aria-busy', 'true');
        try {
            snapshot = await api('/api/state');
            render();
        } finally {
            refs.main.removeAttribute('aria-busy');
        }
    }

    // -------------------------------------------------------------- render

    function render() {
        if (!snapshot) return;
        const stats = snapshot.stats || {};
        const limits = snapshot.limits || {};

        renderInvitePbxOptions();

        refs.statEnabled.textContent = String(stats.enabledPbx || 0);
        refs.statPending.textContent = String(stats.pendingDevices || 0);
        refs.statApproved.textContent = String(stats.approvedDevices || 0);
        refs.statCap.textContent = String(limits.maxEnabledPbx || 0);
        refs.pbxCapHint.textContent =
            `Enabled connections are capped at ${limits.maxEnabledPbx || 0} by the gateway; ` +
            `${stats.pbx || 0} of ${limits.maxPbx || 0} records used.`;

        renderPbx();
        renderInvites();
        renderPending();
        renderApproved();
        renderActivity();
    }

    function renderPbx() {
        const pbx = snapshot.pbx || [];
        refs.pbxEmpty.hidden = pbx.length > 0;
        refs.pbxRows.replaceChildren(...pbx.map((record) => el('tr', {},
            el('th', { scope: 'row', dataset: { label: 'Name' } },
                record.name,
                el('span', { class: 'cell-sub', text: record.id })),
            el('td', { dataset: { label: 'WebSocket' } },
                el('span', { class: 'url', text: record.wsURL })),
            el('td', { dataset: { label: 'API' } },
                el('span', { class: 'url', text: record.apiURL })),
            el('td', { dataset: { label: 'Media IPs' } },
                record.mediaIps && record.mediaIps.length
                    ? el('span', { class: 'url', text: record.mediaIps.join(', ') })
                    : el('span', { class: 'empty', text: 'None' })),
            el('td', { dataset: { label: 'State' } },
                el('span', {
                    class: record.enabled ? 'pill pill-on' : 'pill pill-off',
                    text: record.enabled ? 'Enabled' : 'Disabled'
                })),
            el('td', { dataset: { label: 'Actions' } },
                el('div', { class: 'row-actions' },
                    el('button', {
                        class: 'btn btn-sm',
                        type: 'button',
                        onclick: () => startEditPbx(record)
                    }, 'Edit'),
                    el('button', {
                        class: 'btn btn-danger btn-sm',
                        type: 'button',
                        onclick: () => removePbx(record)
                    }, 'Remove')))
        )));
    }

    function renderInvites() {
        const invites = snapshot.enrollmentTokens || [];
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));

        refs.inviteEmpty.hidden = invites.length > 0;
        refs.inviteRows.replaceChildren(...invites.map((invite) => {
            const presetPbx = invite.pbxId ? pbxById.get(invite.pbxId) : null;
            const preset = [
                presetPbx ? presetPbx.name : invite.pbxId ? 'Removed PBX' : 'Any PBX',
                invite.extension || null
            ].filter(Boolean).join(' / ');
            const expired = invite.expiresAt && Date.parse(invite.expiresAt) <= Date.now();
            const revoked = Boolean(invite.revokedAt);
            const state = revoked ? 'revoked' : expired ? 'expired' : 'active';

            return el('tr', {},
                el('th', { scope: 'row', dataset: { label: 'Label' } },
                    invite.label || 'Invite',
                    el('span', { class: 'cell-sub', text: invite.id })),
                el('td', { dataset: { label: 'Preset' }, text: preset }),
                el('td', { dataset: { label: 'Uses' }, text: `${invite.usedCount} / ${invite.maxUses}` }),
                el('td', { dataset: { label: 'Expires' } },
                    el('span', { text: formatTime(invite.expiresAt) }),
                    el('span', { class: 'cell-sub', text: state })),
                el('td', { dataset: { label: 'Actions' } },
                    el('button', {
                        class: 'btn btn-danger btn-sm',
                        type: 'button',
                        disabled: revoked,
                        onclick: () => revokeInvite(invite)
                    }, revoked ? 'Revoked' : 'Revoke'))
            );
        }));
    }

    function renderPending() {
        const pending = (snapshot.devices || []).filter((device) => device.status === 'pending');
        const enabledPbx = (snapshot.pbx || []).filter((record) => record.enabled);

        refs.pendingEmpty.hidden = pending.length > 0;
        refs.pendingRows.replaceChildren(...pending.map((device) => {
            const title = deviceTitle(device);
            const select = el('select', {
                'aria-label': `PBX for ${title}`,
                disabled: enabledPbx.length === 0
            }, enabledPbx.length
                ? enabledPbx.map((record) => el('option', { value: record.id, text: record.name }))
                : el('option', { value: '', text: 'Enable a PBX first' }));
            const preferred = enabledPbx.find((record) => record.id === device.suggestedPbxId);
            if (preferred) select.value = preferred.id;

            const extension = el('input', {
                type: 'text',
                maxlength: '32',
                inputmode: 'numeric',
                autocomplete: 'off',
                placeholder: 'Extension',
                'aria-label': `Extension for ${title}`,
                value: device.suggestedExtension || ''
            });

            const approve = el('button', {
                class: 'btn btn-primary btn-sm',
                type: 'button',
                disabled: enabledPbx.length === 0,
                onclick: () => approveDevice(device, select, extension)
            }, 'Approve');

            return el('tr', {},
                el('th', { scope: 'row', dataset: { label: 'Device' } },
                    title,
                    el('span', { class: 'cell-sub', text: deviceSubtitle(device) })),
                el('td', { dataset: { label: 'Platform' }, text: device.platform }),
                el('td', { dataset: { label: 'Version' }, text: device.appVersion || '—' }),
                el('td', { dataset: { label: 'Requested' } },
                    el('span', { text: formatTime(device.requestedAt) }),
                    el('span', {
                        class: 'cell-sub',
                        text: [
                            device.requestIp || 'unknown IP',
                            enrollmentSource(device),
                            device.claimExpiresAt ? `expires ${formatTime(device.claimExpiresAt)}` : null
                        ].filter(Boolean).join(' · ')
                    })),
                el('td', { dataset: { label: 'Decision' } },
                    el('div', { class: 'decision' }, select, extension, approve)),
                el('td', { dataset: { label: 'Reject' } },
                    el('button', {
                        class: 'btn btn-danger btn-sm',
                        type: 'button',
                        onclick: () => rejectDevice(device)
                    }, 'Reject'))
            );
        }));
    }

    function renderApproved() {
        const approved = (snapshot.devices || []).filter((device) => device.status === 'approved');
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));

        refs.approvedEmpty.hidden = approved.length > 0;
        refs.approvedRows.replaceChildren(...approved.map((device) => {
            const title = deviceTitle(device);
            const pbx = device.pbxId ? pbxById.get(device.pbxId) : null;
            return el('tr', {},
                el('th', { scope: 'row', dataset: { label: 'Device' } },
                    title,
                    el('span', { class: 'cell-sub', text: deviceSubtitle(device) })),
                el('td', { dataset: { label: 'Platform' }, text: device.platform }),
                el('td', { dataset: { label: 'PBX' }, text: pbx ? pbx.name : 'Removed PBX' }),
                el('td', { dataset: { label: 'Extension' }, text: device.extension || '—' }),
                el('td', { dataset: { label: 'Approved' }, text: formatTime(device.reviewedAt) }),
                el('td', { dataset: { label: 'Actions' } },
                    el('button', {
                        class: 'btn btn-danger btn-sm',
                        type: 'button',
                        onclick: () => revokeDevice(device)
                    }, 'Revoke'))
            );
        }));
    }

    function renderActivity() {
        const entries = (snapshot.audit || []).slice().reverse();
        refs.activityEmpty.hidden = entries.length > 0;
        refs.activityList.replaceChildren(...entries.map((entry) => el('li', {},
            el('time', { datetime: entry.at, text: formatTime(entry.at) }),
            el('span', { class: 'event', text: entry.action }),
            el('span', {
                class: 'detail',
                text: [entry.target ? shortId(entry.target) : '', entry.detail || ''].filter(Boolean).join(' · ')
            }),
            el('span', { class: 'detail', text: entry.actor || '' })
        )));
    }

    function renderInvitePbxOptions() {
        const current = refs.invitePbx.value;
        const options = [
            el('option', { value: '', text: 'No preset — choose at approval' }),
            ...(snapshot.pbx || []).map((record) => el('option', {
                value: record.id,
                text: record.name + (record.enabled ? '' : ' (disabled)')
            }))
        ];
        refs.invitePbx.replaceChildren(...options);
        refs.invitePbx.value = options.some((option) => option.value === current) ? current : '';
    }

    // ------------------------------------------------------------- PBX CRUD

    function readPbxForm() {
        return {
            name: refs.pbxName.value.trim(),
            wsURL: refs.pbxWs.value.trim(),
            apiURL: refs.pbxApi.value.trim(),
            mediaIps: refs.pbxIps.value.trim(),
            enabled: refs.pbxEnabled.checked
        };
    }

    function resetPbxForm() {
        editingPbxId = null;
        refs.pbxForm.reset();
        refs.pbxEnabled.checked = true;
        refs.pbxSubmit.textContent = 'Add PBX';
        refs.pbxCancel.hidden = true;
    }

    function startEditPbx(record) {
        editingPbxId = record.id;
        refs.pbxName.value = record.name;
        refs.pbxWs.value = record.wsURL;
        refs.pbxApi.value = record.apiURL;
        refs.pbxIps.value = (record.mediaIps || []).join(', ');
        refs.pbxEnabled.checked = Boolean(record.enabled);
        refs.pbxSubmit.textContent = 'Save changes';
        refs.pbxCancel.hidden = false;
        clearMessages();
        refs.pbxForm.scrollIntoView({ block: 'center', behavior: 'smooth' });
        refs.pbxName.focus({ preventScroll: true });
    }

    async function submitPbx(event) {
        event.preventDefault();
        clearMessages();
        const payload = readPbxForm();
        setBusy(refs.pbxSubmit, true, 'Saving…');
        try {
            if (editingPbxId) {
                await api(`/api/pbx/${encodeURIComponent(editingPbxId)}`, {
                    method: 'PATCH',
                    body: payload
                });
                showStatus(`Updated ${payload.name}.`);
            } else {
                await api('/api/pbx', { method: 'POST', body: payload });
                showStatus(`Added ${payload.name}.`);
            }
            resetPbxForm();
            await refresh();
        } catch (error) {
            handleError(error);
        } finally {
            setBusy(refs.pbxSubmit, false);
        }
    }

    async function removePbx(record) {
        const confirmed = window.confirm(
            `Remove "${record.name}"? Devices approved on it are revoked and its invites stop working.`
        );
        if (!confirmed) return;
        try {
            await api(`/api/pbx/${encodeURIComponent(record.id)}`, { method: 'DELETE' });
            if (editingPbxId === record.id) resetPbxForm();
            showStatus('PBX removed.');
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    // --------------------------------------------------------------- invites

    async function createInvite(event) {
        event.preventDefault();
        clearMessages();
        const hours = Math.min(720, Math.max(1, Number(refs.inviteTtl.value) || 24));
        const uses = Math.min(100, Math.max(1, Number(refs.inviteUses.value) || 1));
        const body = {
            label: refs.inviteLabel.value.trim() || 'Device invite',
            pbxId: refs.invitePbx.value || null,
            extension: refs.inviteExtension.value.trim() || null,
            maxUses: uses,
            ttlMs: hours * 60 * 60 * 1000
        };
        setBusy(refs.inviteSubmit, true, 'Creating…');
        try {
            const result = await api('/api/enrollment-tokens', { method: 'POST', body });
            refs.tokenValue.textContent = result.token || '';
            refs.tokenPanel.hidden = false;
            refs.inviteExtension.value = '';
            showStatus('Enrollment token created. Copy it now — it cannot be shown again.');
            refs.tokenPanel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            await refresh();
        } catch (error) {
            handleError(error);
        } finally {
            setBusy(refs.inviteSubmit, false);
        }
    }

    async function revokeInvite(invite) {
        const confirmed = window.confirm(`Revoke invite "${invite.label}"? Devices cannot use it afterwards.`);
        if (!confirmed) return;
        try {
            await api(`/api/enrollment-tokens/${encodeURIComponent(invite.id)}`, { method: 'DELETE' });
            showStatus('Invite revoked.');
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    // ---------------------------------------------------------- device review

    async function approveDevice(device, select, extensionInput) {
        clearMessages();
        const pbxId = select.value;
        const extension = extensionInput.value.trim();
        if (!pbxId) {
            showError('Enable a PBX connection before approving devices.');
            return;
        }
        if (!extension) {
            showError('Enter the extension to bind this device to.');
            extensionInput.focus();
            return;
        }
        try {
            const result = await api(`/api/devices/${encodeURIComponent(device.id)}/approve`, {
                method: 'POST',
                body: { pbxId, extension }
            });
            if (result.secret) {
                // Invite enrollment: the operator hands this secret over once.
                refs.secretValue.textContent = result.secret;
                refs.secretPanel.hidden = false;
                showStatus(`Approved ${deviceTitle(device)} for extension ${extension}. Copy the device secret now.`);
                refs.secretPanel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            } else {
                // Automatic enrollment: the device already holds its own secret.
                refs.secretValue.textContent = '';
                refs.secretPanel.hidden = true;
                showStatus(
                    `Approved ${deviceTitle(device)} for extension ${extension}. ` +
                    'The device collects its assignment automatically.'
                );
            }
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    async function rejectDevice(device) {
        const confirmed = window.confirm(
            `Reject "${deviceTitle(device)}"? The device stays blocked and cannot reuse this enrollment.`
        );
        if (!confirmed) return;
        try {
            await api(`/api/devices/${encodeURIComponent(device.id)}/reject`, {
                method: 'POST',
                body: { reason: 'rejected by operator' }
            });
            showStatus('Device rejected.');
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    async function revokeDevice(device) {
        const confirmed = window.confirm(
            `Revoke "${deviceTitle(device)}"? Its stored secret is deleted immediately.`
        );
        if (!confirmed) return;
        try {
            await api(`/api/devices/${encodeURIComponent(device.id)}/revoke`, {
                method: 'POST',
                body: { reason: 'revoked by operator' }
            });
            showStatus('Device revoked.');
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    // ----------------------------------------------------------------- login

    async function submitLogin(event) {
        event.preventDefault();
        showLoginMessage('');
        const password = refs.password.value;
        if (!password) {
            refs.password.focus();
            showLoginMessage('Enter the administrator password.');
            return;
        }
        setBusy(refs.loginSubmit, true, 'Signing in…');
        try {
            const session = await api('/api/session', { method: 'POST', body: { password } });
            csrfToken = session.csrfToken;
            refs.password.value = '';
            refs.loginNotConfigured.hidden = true;
            await enterDashboard();
        } catch (error) {
            if (error.status === 503) refs.loginNotConfigured.hidden = false;
            if (error.status === 429 && error.retryAfterMs) {
                const seconds = Math.max(1, Math.ceil(error.retryAfterMs / 1000));
                showLoginMessage(`Too many attempts. Try again in ${seconds}s.`);
            } else {
                showLoginMessage(error.message);
            }
        } finally {
            setBusy(refs.loginSubmit, false);
        }
    }

    async function signOut() {
        setBusy(refs.signOut, true, 'Signing out…');
        try {
            await api('/api/session', { method: 'DELETE' });
        } catch {
            // The local session is dropped either way.
        } finally {
            setBusy(refs.signOut, false);
            onUnauthenticated('Signed out.');
            refs.password.focus();
        }
    }

    // ------------------------------------------------------------------ copy

    async function copyFrom(element, button) {
        const value = (element.textContent || '').trim();
        if (!value) return;
        let copied = false;
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(value);
                copied = true;
            } catch {
                copied = false;
            }
        }
        if (!copied) {
            const range = document.createRange();
            range.selectNodeContents(element);
            const selection = window.getSelection();
            if (selection) {
                selection.removeAllRanges();
                selection.addRange(range);
                try {
                    copied = document.execCommand('copy');
                } catch {
                    copied = false;
                }
                selection.removeAllRanges();
            }
        }
        if (button) {
            const previous = button.textContent;
            button.textContent = copied ? 'Copied' : 'Select manually';
            setTimeout(() => {
                button.textContent = previous;
            }, 1600);
        }
    }

    // ------------------------------------------------------------ validation

    function syncValidity(event) {
        const target = event.target;
        if (!target || typeof target.matches !== 'function') return;
        if (!target.matches('input, select, textarea')) return;
        let invalid = false;
        try {
            invalid = target.matches(':user-invalid');
        } catch {
            invalid = false;
        }
        if (invalid) target.setAttribute('aria-invalid', 'true');
        else target.removeAttribute('aria-invalid');
    }

    // ------------------------------------------------------------------ wire

    function wireEvents() {
        refs.loginForm.addEventListener('submit', submitLogin);
        refs.pbxForm.addEventListener('submit', submitPbx);
        refs.inviteForm.addEventListener('submit', createInvite);
        refs.signOut.addEventListener('click', signOut);
        refs.pbxCancel.addEventListener('click', () => {
            resetPbxForm();
            clearMessages();
        });
        refs.tokenCopy.addEventListener('click', () => copyFrom(refs.tokenValue, refs.tokenCopy));
        refs.secretCopy.addEventListener('click', () => copyFrom(refs.secretValue, refs.secretCopy));
        refs.tokenDismiss.addEventListener('click', () => {
            refs.tokenPanel.hidden = true;
            refs.tokenValue.textContent = '';
        });
        refs.secretDismiss.addEventListener('click', () => {
            refs.secretPanel.hidden = true;
            refs.secretValue.textContent = '';
        });

        document.addEventListener('blur', syncValidity, true);
        document.addEventListener('input', syncValidity, true);
    }

    async function boot() {
        wireEvents();
        try {
            const session = await api('/api/session');
            if (session.authenticated) {
                csrfToken = session.csrfToken;
                await enterDashboard();
            } else {
                showLogin();
                refs.loginNotConfigured.hidden = session.configured !== false;
                refs.password.focus();
            }
        } catch (error) {
            showLogin();
            showLoginMessage(
                error.status === 401
                    ? 'Your session expired. Sign in again.'
                    : error.message
            );
        }
    }

    // `render` needs the invite <select> refreshed before invites paint.
    boot();
})();
