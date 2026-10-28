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
        pbxAddress: document.getElementById('pbx-address'),
        pbxAutoAddress: document.getElementById('pbx-auto-address'),
        pbxResolve: document.getElementById('pbx-resolve'),
        pbxAddressStatus: document.getElementById('pbx-address-status'),
        pbxAdvanced: document.getElementById('pbx-advanced'),
        pbxId: document.getElementById('pbx-id'),
        pbxName: document.getElementById('pbx-name'),
        pbxWs: document.getElementById('pbx-ws'),
        pbxApi: document.getElementById('pbx-api'),
        pbxIps: document.getElementById('pbx-ips'),
        pbxEnabled: document.getElementById('pbx-enabled'),
        pbxSubmit: document.getElementById('pbx-submit'),
        sshEnable: document.getElementById('pbx-ssh-enable'),
        sshHost: document.getElementById('pbx-ssh-host'),
        sshUser: document.getElementById('pbx-ssh-user'),
        sshPassword: document.getElementById('pbx-ssh-password'),
        sshProbe: document.getElementById('pbx-ssh-probe'),
        sshFingerprint: document.getElementById('pbx-ssh-fingerprint'),
        sshConfirm: document.getElementById('pbx-ssh-confirm'),
        pbxCancel: document.getElementById('pbx-cancel'),
        pbxRows: document.getElementById('pbx-rows'),
        pbxEmpty: document.getElementById('pbx-empty'),
        pbxCapHint: document.getElementById('pbx-cap-hint'),
        pbxProvisioningSummary: document.getElementById('pbx-provisioning-summary'),
        pbxManaged: document.getElementById('pbx-managed'),
        pbxCustomer: document.getElementById('pbx-customer'),
        pbxLoginHostname: document.getElementById('pbx-login-hostname'),
        pbxPolicyRequired: document.getElementById('pbx-policy-required'),
        pbxApproval: document.getElementById('pbx-approval'),
        pbxReviewedInstallationId: document.getElementById('pbx-reviewed-installation-id'),
        extForm: document.getElementById('ext-form'),
        extId: document.getElementById('ext-id'),
        extPbx: document.getElementById('ext-pbx'),
        extNumber: document.getElementById('ext-number'),
        extName: document.getElementById('ext-name'),
        extStatus: document.getElementById('ext-status'),
        extMaxDevices: document.getElementById('ext-max-devices'),
        extPlatformAndroid: document.getElementById('ext-platform-android'),
        extPlatformIos: document.getElementById('ext-platform-ios'),
        extPlatformDesktop: document.getElementById('ext-platform-desktop'),
        extPlatformChrome: document.getElementById('ext-platform-chrome'),
        extSubmit: document.getElementById('ext-submit'),
        extCancel: document.getElementById('ext-cancel'),
        extRows: document.getElementById('ext-rows'),
        extEmpty: document.getElementById('ext-empty'),
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

    if (!refs.main || !refs.loginForm || !refs.pbxRows || !refs.extForm || !refs.extRows) return;

    // PBX management fields stay out of the payload unless the operator opts in,
    // so legacy single-customer PBX records keep their original request shape.
    const MANAGEMENT_FIELDS = [
        refs.pbxCustomer,
        refs.pbxLoginHostname,
        refs.pbxPolicyRequired,
        refs.pbxApproval,
        refs.pbxReviewedInstallationId
    ];
    const PLATFORM_FIELDS = [
        refs.extPlatformAndroid,
        refs.extPlatformIos,
        refs.extPlatformDesktop,
        refs.extPlatformChrome
    ];

    const dateFormatter = new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short'
    });

    let csrfToken = null;
    let snapshot = null;
    let provisioning = null;
    let provisioningError = null;
    let editingPbxId = null;
    let editingExtensionId = null;
    let statusTimer = null;
    let sshVerifiedHost = null;
    let sshFingerprint = null;
    let resolvedAddress = null;
    let addressRevision = 0;

    function invalidateAddress() {
        addressRevision++;
        resolvedAddress = null;
        sshVerifiedHost = null; sshFingerprint = null;
        refs.sshFingerprint.textContent = ''; refs.sshConfirm.checked = false;
        refs.sshHost.value = '';
        refs.pbxAddressStatus.textContent = '';
    }
    function syncAddressMode() {
        const automatic = refs.pbxAutoAddress.checked;
        refs.pbxWs.required = !automatic;
        refs.pbxApi.required = !automatic;
        refs.pbxWs.readOnly = automatic;
        refs.pbxApi.readOnly = automatic;
        refs.pbxIps.readOnly = automatic;
        refs.pbxAddress.required = automatic;
        refs.pbxAdvanced.open = false;
    }
    refs.pbxAddress.addEventListener('input', () => {
        invalidateAddress();
        refs.pbxAutoAddress.checked = true;
        syncAddressMode();
    });
    refs.pbxAutoAddress.addEventListener('change', () => { invalidateAddress(); syncAddressMode(); });
    async function resolveAddress() {
        const address = refs.pbxAddress.value.trim();
        const revision = addressRevision;
        if (resolvedAddress?.address === address) return resolvedAddress;
        if (!address) throw new Error('Enter the PBX address first.');
        const result = await api('/api/pbx-ssh/resolve', { method: 'POST', body: { address } });
        if (addressRevision !== revision || refs.pbxAddress.value.trim() !== address) throw new Error('Address changed; resolve it again.');
        resolvedAddress = { ...result, address };
        refs.sshHost.value = result.host;
        if (refs.pbxAutoAddress.checked) {
            refs.pbxWs.value = result.wsURL; refs.pbxApi.value = result.apiURL; refs.pbxIps.value = result.mediaIps;
        }
        refs.pbxAddressStatus.textContent = `Server address: ${result.host}`;
        return resolvedAddress;
    }
    refs.pbxResolve.addEventListener('click', async () => {
        setBusy(refs.pbxResolve, true, 'Resolving…');
        try { await resolveAddress(); } catch (error) { handleError(error); }
        finally { setBusy(refs.pbxResolve, false); }
    });
    // Enabling SSH setup resolves the address on its own: the SSH target is
    // always the resolved Tailscale address, in automatic and in advanced mode.
    refs.sshEnable.addEventListener('change', async () => {
        if (!refs.sshEnable.checked || !refs.pbxAddress.value.trim()) return;
        try { await resolveAddress(); } catch (error) { handleError(error); }
    });
    syncAddressMode();

    refs.sshHost.addEventListener('input', () => {
        sshVerifiedHost = null; sshFingerprint = null;
        refs.sshFingerprint.textContent = ''; refs.sshConfirm.checked = false;
    });
    async function probeSshHost() {
        await resolveAddress();
        const revision = addressRevision;
        const host = refs.sshHost.value.trim();
        const result = await api('/api/pbx-ssh/probe', { method: 'POST', body: { host, username: refs.sshUser.value } });
        if (addressRevision !== revision || refs.sshHost.value.trim() !== host) throw new Error('Address changed; check the host key again.');
        sshVerifiedHost = host; sshFingerprint = result.fingerprint;
        refs.sshFingerprint.textContent = result.fingerprint;
        refs.sshConfirm.checked = false;
        return result.fingerprint;
    }
    refs.sshProbe.addEventListener('click', async () => {
        setBusy(refs.sshProbe, true, 'Checking…');
        try {
            await probeSshHost();
        } catch (error) { handleError(error); }
        finally { setBusy(refs.sshProbe, false); }
    });

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

    const APPROVAL_LABELS = {
        pending: 'Pending',
        approved: 'Approved',
        suspended: 'Suspended',
        retired: 'Retired'
    };
    const EXTENSION_STATUS_LABELS = {
        enabled: 'Enabled',
        disabled: 'Disabled',
        suspended: 'Suspended'
    };
    const PLATFORM_LABELS = {
        android: 'Android',
        ios: 'iOS',
        desktop: 'Desktop',
        chrome: 'Chrome'
    };

    // Provisioning values are sanitized server-side already; these maps are a
    // second allowlist so an unexpected value can only ever render as "Unknown".
    const PROVISIONING_FILE_STATUS = new Set(['ok', 'stale', 'not_configured', 'unavailable']);
    const PROVISIONING_STATE_LABELS = {
        ready: 'Ready',
        blocked: 'Blocked',
        error: 'Error',
        planned: 'Planned',
        not_configured: 'Not configured',
        pending: 'Pending reconciliation',
        stale: 'Stale snapshot',
        unavailable: 'Unavailable',
        unknown: 'Unknown'
    };
    const PROVISIONING_STAGE_LABELS = {
        pending: 'Pending',
        ready: 'Ready',
        blocked: 'Blocked',
        error: 'Error',
        planned: 'Planned',
        skipped: 'Skipped',
        unknown: 'Unknown'
    };
    const PROVISIONING_REASON_LABELS = {
        not_configured: 'Not configured',
        identity_mismatch: 'Identity mismatch',
        approval_required: 'Approval required',
        relay_failed: 'Relay failed',
        firewall_required: 'Firewall permit required',
        firewall_failed: 'Firewall permit failed',
        hook_required: 'PBX hook required',
        hook_failed: 'PBX hook failed',
        ready: 'Ready',
        planned: 'Planned',
        stale: 'Stale snapshot',
        worker_failed: 'Worker failed',
        configuration_invalid: 'Configuration invalid',
        unknown: 'Unknown'
    };
    const PROVISIONING_STAGE_NAMES = ['relay', 'firewall', 'hook'];

    function labelFrom(labels, value) {
        return Object.hasOwn(labels, value) ? labels[value] : labels.unknown;
    }

    function provisioningStatusOf(value) {
        return PROVISIONING_FILE_STATUS.has(value) ? value : 'unavailable';
    }

    function approvalLabel(status) {
        return APPROVAL_LABELS[status] || APPROVAL_LABELS.pending;
    }

    function extensionStatusLabel(status) {
        return EXTENSION_STATUS_LABELS[status] || EXTENSION_STATUS_LABELS.disabled;
    }

    function platformLabel(value) {
        return PLATFORM_LABELS[value] || String(value || '');
    }

    /** Approved devices whose PBX + extension match this extension record. */
    function approvedDeviceCount(record) {
        return (snapshot.devices || []).filter((device) =>
            device.status === 'approved' &&
            device.pbxId === record.pbxId &&
            String(device.extension || '') === String(record.extension || '')
        ).length;
    }

    function selectedPlatforms() {
        return PLATFORM_FIELDS.filter((field) => field.checked).map((field) => field.value);
    }

    function clearPlatformValidity() {
        for (const field of PLATFORM_FIELDS) field.setCustomValidity('');
    }

    /**
     * Validate the platform group through the constraint-validation API so the
     * browser shows its native message. A single `required` checkbox would force
     * one specific platform instead of "at least one of these".
     */
    function requirePlatformSelection() {
        if (selectedPlatforms().length > 0) {
            clearPlatformValidity();
            return true;
        }
        const first = PLATFORM_FIELDS[0];
        first.setCustomValidity('Select at least one allowed platform.');
        first.reportValidity();
        first.focus();
        return false;
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
        provisioning = null;
        provisioningError = null;
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
            // Read-only, separate fetch: a provisioning read failure must never
            // hide or block the approval workflow itself.
            provisioning = null;
            provisioningError = null;
            try {
                const result = await api('/api/provisioning');
                provisioning = result && result.provisioning ? result.provisioning : null;
            } catch (error) {
                provisioningError = error;
            }
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

        renderProvisioningSummary();
        renderPbx();
        renderExtensionPbxOptions();
        renderExtensions();
        renderInvites();
        renderPending();
        renderApproved();
        renderActivity();
    }

    function provisioningEntry(id) {
        if (!provisioning || !Array.isArray(provisioning.pbx)) return null;
        const wanted = String(id);
        return provisioning.pbx.find((item) => item && String(item.id) === wanted) || null;
    }

    function provisioningWhen() {
        if (!provisioning || !provisioning.updatedAt) return 'never';
        return formatTime(provisioning.updatedAt);
    }

    function renderProvisioningSummary() {
        const node = refs.pbxProvisioningSummary;
        if (!node) return;
        let message;
        if (!provisioning) {
            message = provisioningError
                ? 'Provisioning status is unavailable right now. Device approval still works; ' +
                  'relay, firewall and PBX hook readiness are unverified.'
                : 'Provisioning status has not been loaded yet.';
        } else {
            const status = provisioningStatusOf(provisioning.status);
            if (status === 'not_configured') {
                message =
                    'No provisioning snapshot has been published by the worker. Relay, firewall and ' +
                    'PBX hook readiness are unverified; this is not a failure report.';
            } else if (status === 'unavailable') {
                message =
                    'Provisioning snapshot unavailable: the status file did not pass its ownership, ' +
                    'permission, size or schema checks. Treat provisioning as unverified.';
            } else if (status === 'stale') {
                message =
                    `Provisioning snapshot is stale. Last reconciliation ${provisioningWhen()}; the ` +
                    'worker has not reported since, so the values below are historical, not current.';
            } else {
                message =
                    `Provisioning snapshot reported by the worker. Last reconciliation ${provisioningWhen()}.`;
            }
        }
        // Assigning the same text again would re-announce the polite live region
        // on every unrelated refresh, so only write when the wording changes.
        if (node.textContent !== message) node.textContent = message;
    }

    function provisioningCell(record) {
        const entry = provisioningEntry(record.id);
        if (!entry) {
            return el('td', { dataset: { label: 'Provisioning' } },
                el('span', {
                    class: 'pill pill-off',
                    text: provisioning ? 'Not reported' : 'Unknown'
                }),
                el('span', {
                    class: 'cell-sub',
                    text: provisioning
                        ? 'No provisioning status reported for this PBX.'
                        : 'Provisioning status not loaded.'
                }));
        }

        const state = labelFrom(PROVISIONING_STATE_LABELS, entry.effectiveState);
        const stages = PROVISIONING_STAGE_NAMES.map((name) => {
            const raw = entry.stages && typeof entry.stages === 'object' ? entry.stages[name] : undefined;
            const value = typeof raw === 'string' ? raw : 'unknown';
            return `${name.charAt(0).toUpperCase()}${name.slice(1)} ${labelFrom(PROVISIONING_STAGE_LABELS, value)}`;
        }).join(' · ');

        const reconciliation = typeof entry.reconciliation === 'string' ? entry.reconciliation : 'unknown';
        const when = provisioningWhen();
        const whenText = reconciliation === 'current'
            ? `Last reconciliation · ${when}`
            : reconciliation === 'pending'
                ? `Pending reconciliation · last reported ${when}`
                : reconciliation === 'stale'
                    ? `Stale · last reconciliation ${when}`
                    : 'No reconciliation timestamp';

        return el('td', { dataset: { label: 'Provisioning' } },
            el('span', {
                class: entry.effectiveState === 'ready' ? 'pill pill-on' : 'pill pill-off',
                text: state
            }),
            el('span', { class: 'cell-sub', text: whenText }),
            el('span', { class: 'cell-sub', text: stages }),
            el('span', {
                class: 'cell-sub',
                text: `Reason · ${labelFrom(PROVISIONING_REASON_LABELS, entry.reason)}`
            }));
    }

    function renderPbx() {
        const pbx = snapshot.pbx || [];
        refs.pbxEmpty.hidden = pbx.length > 0;
        refs.pbxRows.replaceChildren(...pbx.map((record) => {
            const management = record.management || null;
            return el('tr', {},
                el('th', { scope: 'row', dataset: { label: 'Name' } },
                    record.name,
                    el('span', { class: 'cell-sub', text: record.id }),
                    management && management.customer
                        ? el('span', { class: 'cell-sub', text: `Customer · ${management.customer}` })
                        : null,
                    management && management.loginHostname
                        ? el('span', { class: 'cell-sub', text: `Login · ${management.loginHostname}` })
                        : null),
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
                    }),
                    el('span', {
                        class: 'cell-sub',
                        text: management
                            ? `Approval · ${approvalLabel(management.approvalStatus)}`
                            : 'SSH setup required'
                    }),
                    management && management.reviewedInstallationId
                        ? el('span', {
                            class: 'cell-sub',
                            text: `Reviewed installation · ${management.reviewedInstallationId}`
                        })
                        : null),
                provisioningCell(record),
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
            );
        }));
    }

    function renderExtensionPbxOptions() {
        const wanted = refs.extPbx.value;
        // Only managed PBXs can hold extension policies (store rejects others).
        const managed = (snapshot.pbx || []).filter((record) => record.management);
        const options = managed.length
            ? managed.map((record) => el('option', {
                value: record.id,
                text: record.name + (record.enabled ? '' : ' (disabled)')
            }))
            : [el('option', { value: '', text: 'Add a managed PBX first' })];
        // Keep a selection whose PBX was removed visible while it is being edited.
        if (wanted && !options.some((option) => option.value === wanted)) {
            options.push(el('option', { value: wanted, text: 'Removed PBX' }));
        }
        refs.extPbx.replaceChildren(...options);
        refs.extPbx.value = wanted && options.some((option) => option.value === wanted)
            ? wanted
            : (options[0] ? options[0].value : '');
    }

    function renderExtensions() {
        // Legacy snapshots predate extension records; treat a missing array as empty.
        const extensions = Array.isArray(snapshot.extensions) ? snapshot.extensions : [];
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));

        refs.extEmpty.hidden = extensions.length > 0;
        refs.extRows.replaceChildren(...extensions.map((record) => {
            const pbx = record.pbxId ? pbxById.get(record.pbxId) : null;
            const status = record.status || 'disabled';
            const platforms = Array.isArray(record.allowedPlatforms) ? record.allowedPlatforms : [];
            return el('tr', {},
                el('td', { dataset: { label: 'PBX' }, text: pbx ? pbx.name : 'Removed PBX' }),
                el('th', { scope: 'row', dataset: { label: 'Extension' } },
                    record.extension || '—',
                    el('span', { class: 'cell-sub', text: record.name || '—' })),
                el('td', { dataset: { label: 'Status' } },
                    el('span', {
                        class: status === 'enabled' ? 'pill pill-on' : 'pill pill-off',
                        text: extensionStatusLabel(status)
                    }),
                    el('span', {
                        class: 'cell-sub',
                        text: platforms.length ? platforms.map(platformLabel).join(' · ') : 'No platforms'
                    })),
                el('td', {
                    dataset: { label: 'Approved devices' },
                    text: String(approvedDeviceCount(record))
                }),
                el('td', { dataset: { label: 'Limit' }, text: String(Number(record.maxDevices) || 0) }),
                el('td', { dataset: { label: 'Actions' } },
                    el('button', {
                        class: 'btn btn-sm',
                        type: 'button',
                        onclick: () => startEditExtension(record)
                    }, 'Edit'))
            );
        }));
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

    function syncManagementFields() {
        const managed = true;
        refs.pbxManaged.checked = true;
        for (const field of MANAGEMENT_FIELDS) {
            const wrapper = field.closest('.field');
            if (wrapper) wrapper.hidden = true;
            field.disabled = !managed;
        }
        if (!managed) return;
        if (editingPbxId) {
            refs.pbxApproval.disabled = false;
        } else {
            // SSH verification automatically approves a new server.
            refs.pbxApproval.value = 'pending';
            refs.pbxApproval.disabled = true;
        }
    }

    function readPbxForm() {
        const payload = {
            name: refs.pbxName.value.trim() || refs.pbxAddress.value.trim().slice(0, 64),
            wsURL: refs.pbxWs.value.trim(),
            apiURL: refs.pbxApi.value.trim(),
            mediaIps: refs.pbxIps.value.trim(),
            enabled: refs.pbxEnabled.checked
        };
        // Every server uses managed provisioning; no legacy setup mode.
        {
            payload.management = {
                customer: refs.pbxCustomer.value.trim() || null,
                loginHostname: refs.pbxLoginHostname.value.trim() || null,
                extensionPolicyRequired: refs.pbxPolicyRequired.checked,
                approvalStatus: editingPbxId ? refs.pbxApproval.value : 'pending',
                reviewedInstallationId: refs.pbxReviewedInstallationId.value.trim() || null
            };
        }
        return payload;
    }

    function resetPbxForm() {
        sshVerifiedHost = null; sshFingerprint = null; refs.sshFingerprint.textContent = '';
        editingPbxId = null;
        refs.pbxForm.reset();
        invalidateAddress(); syncAddressMode();
        refs.pbxEnabled.checked = true;
        refs.pbxPolicyRequired.checked = true;
        refs.sshEnable.checked = true;
        refs.sshPassword.required = true;
        refs.pbxSubmit.textContent = 'Add server';
        refs.pbxCancel.hidden = true;
        syncManagementFields();
    }

    function startEditPbx(record) {
        refs.sshPassword.value = ''; refs.sshEnable.checked = false;
        refs.sshPassword.required = record.management?.approvalStatus !== 'approved';
        refs.sshConfirm.checked = false; sshVerifiedHost = null; sshFingerprint = null;
        refs.sshFingerprint.textContent = '';
        editingPbxId = record.id;
        const management = record.management || null;
        refs.pbxName.value = record.name;
        refs.pbxWs.value = record.wsURL;
        refs.pbxApi.value = record.apiURL;
        refs.pbxIps.value = (record.mediaIps || []).join(', ');
        // Never rewrite existing/custom endpoints merely by opening Edit.
        refs.pbxAutoAddress.checked = false;
        refs.pbxAddress.value = (record.mediaIps || []).length === 1 ? record.mediaIps[0] : '';
        invalidateAddress(); syncAddressMode();
        refs.pbxEnabled.checked = Boolean(record.enabled);
        refs.pbxManaged.checked = Boolean(management);
        refs.pbxCustomer.value = management && management.customer ? management.customer : '';
        refs.pbxLoginHostname.value =
            management && management.loginHostname ? management.loginHostname : '';
        refs.pbxPolicyRequired.checked = management
            ? Boolean(management.extensionPolicyRequired)
            : true;
        refs.pbxApproval.value = management && management.approvalStatus
            ? management.approvalStatus
            : 'pending';
        refs.pbxReviewedInstallationId.value =
            management && management.reviewedInstallationId ? management.reviewedInstallationId : '';
        syncManagementFields();
        refs.pbxSubmit.textContent = 'Save changes';
        refs.pbxCancel.hidden = false;
        clearMessages();
        refs.pbxForm.scrollIntoView({ block: 'center', behavior: 'smooth' });
        refs.pbxAddress.focus({ preventScroll: true });
    }

    async function submitPbx(event) {
        event.preventDefault();
        clearMessages();
        const sshSetup = !editingPbxId || refs.sshPassword.required || Boolean(refs.sshPassword.value);
        // The derived endpoints and the SSH target come from the resolved
        // address, so it is resolved before the form is read.
        try {
            if (refs.pbxAutoAddress.checked || sshSetup) await resolveAddress();
        } catch (error) { handleError(error); refs.pbxAddress.focus(); return; }
        const payload = readPbxForm();
        if (sshSetup) {
            if (!refs.sshPassword.value) {
                showError('Enter the one-time root SSH password for this PBX.');
                refs.sshPassword.focus();
                return;
            }
        }
        setBusy(refs.pbxSubmit, true, 'Saving…');
        try {
            let pbxId = editingPbxId;
            if (editingPbxId) {
                await api(`/api/pbx/${encodeURIComponent(editingPbxId)}`, {
                    method: 'PATCH',
                    body: payload
                });
                showStatus(`Updated ${payload.name}.`);
            } else {
                const created = await api('/api/pbx', { method: 'POST', body: payload });
                pbxId = created.pbx.id;
                editingPbxId = pbxId; // Retry setup on this saved record, never duplicate it.
                showStatus(`Added ${payload.name}.`);
            }
            if (sshSetup) {
                const password = refs.sshPassword.value;
                refs.sshPassword.value = '';
                await api('/api/pbx-ssh/enroll', { method: 'POST', body: {
                    pbxId, host: refs.sshHost.value.trim(), username: 'root', password
                } });
                // The enrollment API approves pending managed PBXs only after
                // successful SSH verification, including non-browser clients.
                showStatus(`Server access verified for ${payload.name}. Automatic setup is finishing in the background.`);
            }
            resetPbxForm();
            await refresh();
        } catch (error) {
            handleError(error);
        } finally {
            refs.sshPassword.value = '';
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

    // ------------------------------------------------------------ extensions

    function startEditExtension(record) {
        editingExtensionId = record.id;
        refs.extId.value = record.id;
        refs.extPbx.value = record.pbxId || '';
        renderExtensionPbxOptions();
        // PBX and extension number are identity: fixed while editing.
        refs.extPbx.disabled = true;
        refs.extNumber.value = record.extension || '';
        refs.extNumber.disabled = true;
        refs.extName.value = record.name || '';
        refs.extStatus.value = record.status || 'enabled';
        refs.extMaxDevices.value = String(Number(record.maxDevices) || 1);
        const allowed = Array.isArray(record.allowedPlatforms) ? record.allowedPlatforms : [];
        for (const field of PLATFORM_FIELDS) field.checked = allowed.includes(field.value);
        clearPlatformValidity();
        refs.extSubmit.textContent = 'Save extension';
        refs.extCancel.hidden = false;
        clearMessages();
        refs.extForm.scrollIntoView({ block: 'center', behavior: 'smooth' });
        refs.extName.focus({ preventScroll: true });
    }

    function resetExtensionForm() {
        editingExtensionId = null;
        refs.extForm.reset();
        refs.extId.value = '';
        refs.extPbx.disabled = false;
        refs.extNumber.disabled = false;
        refs.extSubmit.textContent = 'Add extension';
        refs.extCancel.hidden = true;
        clearPlatformValidity();
    }

    function readExtensionForm() {
        const maxDevices = Math.min(20, Math.max(1, Math.trunc(Number(refs.extMaxDevices.value)) || 1));
        return {
            name: refs.extName.value.trim(),
            status: refs.extStatus.value,
            maxDevices,
            allowedPlatforms: selectedPlatforms()
        };
    }

    async function submitExtension(event) {
        event.preventDefault();
        clearMessages();
        if (!requirePlatformSelection()) return;

        const payload = readExtensionForm();
        const extension = refs.extNumber.value.trim();
        const pbxId = refs.extPbx.value;
        setBusy(refs.extSubmit, true, 'Saving…');

        let saved = false;
        try {
            if (editingExtensionId) {
                // Identity (pbxId, extension) is immutable: PATCH sends only the
                // mutable fields the store accepts.
                await api(`/api/extensions/${encodeURIComponent(editingExtensionId)}`, {
                    method: 'PATCH',
                    body: payload
                });
                showStatus(`Updated extension ${extension}.`);
            } else {
                await api('/api/extensions', {
                    method: 'POST',
                    body: { pbxId, extension, ...payload }
                });
                showStatus(`Added extension ${extension}.`);
            }
            saved = true;
        } catch (error) {
            handleError(error);
        }

        setBusy(refs.extSubmit, false);
        if (!saved) return;

        resetExtensionForm();
        try {
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
        refs.extForm.addEventListener('submit', submitExtension);
        refs.inviteForm.addEventListener('submit', createInvite);
        refs.signOut.addEventListener('click', signOut);
        refs.pbxManaged.addEventListener('change', syncManagementFields);
        refs.pbxCancel.addEventListener('click', () => {
            resetPbxForm();
            clearMessages();
        });
        refs.extCancel.addEventListener('click', () => {
            resetExtensionForm();
            clearMessages();
        });
        for (const field of PLATFORM_FIELDS) {
            field.addEventListener('change', clearPlatformValidity);
        }
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

        syncManagementFields();
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
