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
    const openDiagnostics = new Set();
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
        firewallState: document.getElementById('firewall-state'),
        firewallSummary: document.getElementById('firewall-summary'),
        pushCredentialsToggle: document.getElementById('push-credentials-toggle'),
        pushCredentialsPanel: document.getElementById('push-credentials-panel'),
        pushCredentialsStatus: document.getElementById('push-credentials-status'),
        pushFcmFile: document.getElementById('push-fcm-file'),
        pushFcmSave: document.getElementById('push-fcm-save'),
        pushApnsFile: document.getElementById('push-apns-file'),
        pushApnsKeyId: document.getElementById('push-apns-key-id'),
        pushApnsTeamId: document.getElementById('push-apns-team-id'),
        pushApnsTopic: document.getElementById('push-apns-topic'),
        pushApnsEnvironment: document.getElementById('push-apns-environment'),
        pushApnsSave: document.getElementById('push-apns-save'),
        activeCallsList: document.getElementById('active-calls-list'),
        activeCallsTotal: document.getElementById('active-calls-total'),
        activeCallsEmpty: document.getElementById('active-calls-empty'),
        loadCpu: document.getElementById('load-cpu'),
        loadMemory: document.getElementById('load-memory'),
        loadNetwork: document.getElementById('load-network'),
        loadCalls: document.getElementById('load-calls'),
        loadHost: document.getElementById('load-host'),
        loadSource: document.getElementById('load-source'),
        chartCpu: document.getElementById('chart-cpu'),
        chartMemory: document.getElementById('chart-memory'),
        chartNetwork: document.getElementById('chart-network'),
        chartCalls: document.getElementById('chart-calls'),
        pbxForm: document.getElementById('pbx-form'),
        pbxFormDetails: document.getElementById('pbx-form-details'),
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
        pbxSearch: document.getElementById('pbx-search'),
        pbxFilters: document.getElementById('pbx-filters'),
        pbxFilterClear: document.getElementById('pbx-filter-clear'),
        pbxFilterCount: document.getElementById('pbx-filter-count'),

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
        extSearch: document.getElementById('ext-search'),
        extFilters: document.getElementById('ext-filters'),
        extFilterClear: document.getElementById('ext-filter-clear'),
        extFilterCount: document.getElementById('ext-filter-count'),
        secretPanel: document.getElementById('secret-panel'),
        secretValue: document.getElementById('secret-value'),
        secretCopy: document.getElementById('secret-copy'),
        secretDismiss: document.getElementById('secret-dismiss'),
        pendingRows: document.getElementById('pending-rows'),
        pendingEmpty: document.getElementById('pending-empty'),
        pendingSearch: document.getElementById('pending-search'),
        pendingFilters: document.getElementById('pending-filters'),
        pendingFilterClear: document.getElementById('pending-filter-clear'),
        pendingFilterCount: document.getElementById('pending-filter-count'),
        approvedRows: document.getElementById('approved-rows'),
        approvedEmpty: document.getElementById('approved-empty'),
        approvedSearch: document.getElementById('approved-search'),
        approvedFilters: document.getElementById('approved-filters'),
        approvedFilterClear: document.getElementById('approved-filter-clear'),
        approvedFilterCount: document.getElementById('approved-filter-count'),
        approvedTokenWarning: document.getElementById('approved-token-warning'),
        approvedCleanup: document.getElementById('approved-cleanup'),
        activityList: document.getElementById('activity-list'),
        activityEmpty: document.getElementById('activity-empty'),
        showTunnelTokenBtn: document.getElementById('show-tunnel-token-btn'),
        tunnelTokenPanel: document.getElementById('tunnel-token-panel'),
        tunnelTokenValue: document.getElementById('tunnel-token-value'),
        copyTunnelTokenBtn: document.getElementById('copy-tunnel-token-btn')
    };

    if (!refs.main || !refs.loginForm || !refs.pbxRows || !refs.extForm || !refs.extRows) return;

    const tableFilters = {
        pbx: {
            search: refs.pbxSearch,
            menu: refs.pbxFilters,
            clear: refs.pbxFilterClear,
            count: refs.pbxFilterCount,
            empty: refs.pbxEmpty,
            selections: {},
            render: renderPbx
        },
        extensions: {
            search: refs.extSearch,
            menu: refs.extFilters,
            clear: refs.extFilterClear,
            count: refs.extFilterCount,
            empty: refs.extEmpty,
            selections: {},
            render: renderExtensions
        },
        pending: {
            search: refs.pendingSearch,
            menu: refs.pendingFilters,
            clear: refs.pendingFilterClear,
            count: refs.pendingFilterCount,
            empty: refs.pendingEmpty,
            selections: {},
            render: renderPending
        },
        approved: {
            search: refs.approvedSearch,
            menu: refs.approvedFilters,
            clear: refs.approvedFilterClear,
            count: refs.approvedFilterCount,
            empty: refs.approvedEmpty,
            selections: {},
            render: renderApproved
        }
    };

    for (const filter of Object.values(tableFilters)) {
        filter.search.addEventListener('input', () => {
            if (snapshot) filter.render();
        });
        filter.clear.addEventListener('click', () => {
            filter.search.value = '';
            for (const selection of Object.values(filter.selections)) selection.clear();
            syncFilterMenu(filter);
            if (snapshot) filter.render();
            filter.search.focus();
        });
    }

    document.addEventListener('click', (event) => {
        for (const details of document.querySelectorAll('.multi-select[open]')) {
            if (!details.contains(event.target)) details.open = false;
        }
    });
    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') return;
        const open = document.querySelector('.multi-select[open]');
        if (!open) return;
        open.open = false;
        const summary = open.querySelector('summary');
        if (summary instanceof HTMLElement) summary.focus();
    });

    refs.pendingRows.addEventListener('focusout', () => {
        setTimeout(() => {
            if (pendingHasFocus() || !pendingRenderDeferred || !snapshot) return;
            pendingRenderDeferred = false;
            renderPending();
        }, 0);
    });

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
    // Pending approval controls are edited while the dashboard polls every 3 s.
    // Keep per-device drafts and defer the table rebuild while a control has
    // focus so a refresh cannot reset the chosen PBX or the extension text.
    const pendingDrafts = new Map();
    let pendingRenderDeferred = false;
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

    /**
     * Multi-select filters are facets over columns, not free-form search. The
     * search box remains beside them for names, IDs and URLs. Within one facet
     * selections are ORed; different facets and search terms are ANDed.
     */
    function getFacetDefinitions(name) {
        const records = snapshot || {};
        const pbxRecords = records.pbx || [];
        const pbxById = new Map(pbxRecords.map((record) => [record.id, record]));
        const fixed = (values, labelFor = (value) => value) =>
            values.map((value) => ({ value, label: labelFor(value) }));

        if (name === 'pbx') {
            const provisioningValues = new Map();
            for (const record of pbxRecords) {
                const entry = provisioningEntry(record.id);
                const value = entry ? entry.effectiveState : (provisioning ? 'not_reported' : 'unknown');
                if (!provisioningValues.has(value)) {
                    provisioningValues.set(value, PROVISIONING_STATE_LABELS[value] || value);
                }
            }
            return [
                {
                    key: 'state',
                    label: 'State',
                    options: fixed(['enabled', 'disabled'], (value) =>
                        value.charAt(0).toUpperCase() + value.slice(1)),
                    value: (record) => (record.enabled ? 'enabled' : 'disabled')
                },
                {
                    key: 'approval',
                    label: 'Approval',
                    options: fixed(['approved', 'pending', 'suspended', 'retired', 'unmanaged'],
                        (value) => value === 'unmanaged' ? 'Unmanaged' : approvalLabel(value)),
                    value: (record) => record.management?.approvalStatus || 'unmanaged'
                },
                {
                    key: 'provisioning',
                    label: 'Provisioning',
                    options: [...provisioningValues].map(([value, label]) => ({ value, label })),
                    value: (record) => {
                        const entry = provisioningEntry(record.id);
                        return entry ? entry.effectiveState : (provisioning ? 'not_reported' : 'unknown');
                    }
                }
            ];
        }

        if (name === 'extensions') {
            const extensions = Array.isArray(records.extensions) ? records.extensions : [];
            const options = pbxRecords.map((record) => ({
                value: record.id,
                label: record.name + (record.enabled ? '' : ' (disabled)')
            }));
            if (extensions.some((record) => !record.pbxId || !pbxById.has(record.pbxId))) {
                options.push({ value: '__removed__', label: 'Removed PBX' });
            }
            return [
                {
                    key: 'pbx',
                    label: 'PBX',
                    options,
                    value: (record) => record.pbxId && pbxById.has(record.pbxId) ? record.pbxId : '__removed__'
                },
                {
                    key: 'status',
                    label: 'Status',
                    options: fixed(['enabled', 'disabled', 'suspended'],
                        (value) => extensionStatusLabel(value)),
                    value: (record) => record.status || 'disabled'
                }
            ];
        }

        if (name === 'pending') {
            const devices = (records.devices || []).filter((device) => device.status === 'pending');
            const seen = new Set();
            const options = [];
            for (const device of devices) {
                const value = device.platform || 'unknown';
                if (seen.has(value)) continue;
                seen.add(value);
                options.push({ value, label: platformLabel(value) });
            }
            return [{
                key: 'platform',
                label: 'Platform',
                options,
                value: (device) => device.platform || 'unknown'
            }];
        }

        if (name === 'approved') {
            const devices = (records.devices || []).filter((device) => device.status === 'approved');
            const options = pbxRecords.map((record) => ({
                value: record.id,
                label: record.name + (record.enabled ? '' : ' (disabled)')
            }));
            if (devices.some((device) => !device.pbxId || !pbxById.has(device.pbxId))) {
                options.push({ value: '__removed__', label: 'Removed PBX' });
            }
            const platforms = [];
            const seen = new Set();
            for (const device of devices) {
                const value = device.platform || 'unknown';
                if (seen.has(value)) continue;
                seen.add(value);
                platforms.push({ value, label: platformLabel(value) });
            }
            return [
                {
                    key: 'pbx',
                    label: 'PBX',
                    options,
                    value: (device) => device.pbxId && pbxById.has(device.pbxId) ? device.pbxId : '__removed__'
                },
                {
                    key: 'platform',
                    label: 'Platform',
                    options: platforms,
                    value: (device) => device.platform || 'unknown'
                },
                {
                    key: 'push',
                    label: 'Push',
                    options: fixed(['active', 'invalid', 'stale', 'missing'], (value) =>
                        value.charAt(0).toUpperCase() + value.slice(1)),
                    value: (device) => device.pushState || (device.pushRegistered === false ? 'missing' : 'active')
                }
            ];
        }

        return [];
    }

    function updateMultiSelectBadge(details, selected) {
        const badge = details.querySelector('.multi-select-badge');
        if (!badge) return;
        badge.textContent = selected.size ? String(selected.size) : '';
        badge.hidden = selected.size === 0;
    }

    function buildMultiSelect(filter, definition) {
        const selected = filter.selections[definition.key];
        const details = el('details', {
            class: 'multi-select',
            dataset: { filterKey: definition.key }
        });
        const badge = el('span', { class: 'multi-select-badge' });
        const summary = el('summary', {},
            el('span', { text: definition.label }),
            badge);
        const menu = el('div', {
            class: 'multi-select-menu',
            role: 'group',
            'aria-label': `${definition.label} filter`
        });

        if (definition.options.length === 0) {
            menu.append(el('p', { class: 'hint', text: 'No values available.' }));
        } else {
            for (const option of definition.options) {
                const checkbox = el('input', {
                    type: 'checkbox',
                    value: option.value,
                    checked: selected.has(option.value)
                });
                checkbox.addEventListener('change', () => {
                    if (checkbox.checked) selected.add(option.value);
                    else selected.delete(option.value);
                    updateMultiSelectBadge(details, selected);
                    filter.render();
                });
                menu.append(el('label', { class: 'multi-select-option' }, checkbox, option.label));
            }
        }

        details.append(summary, menu);
        updateMultiSelectBadge(details, selected);
        details.addEventListener('toggle', () => {
            if (!details.open) return;
            for (const other of filter.menu.querySelectorAll('details[open]')) {
                if (other !== details) other.open = false;
            }
        });
        return details;
    }

    function ensureFilterMenus(name) {
        const filter = tableFilters[name];
        const definitions = getFacetDefinitions(name);
        const signature = JSON.stringify(definitions.map((definition) => [
            definition.key,
            definition.label,
            definition.options
        ]));
        if (filter.signature === signature) {
            filter.definitions = definitions;
            return;
        }

        filter.definitions = definitions;
        for (const definition of definitions) {
            if (!filter.selections[definition.key]) filter.selections[definition.key] = new Set();
            const allowed = new Set(definition.options.map((option) => option.value));
            for (const value of [...filter.selections[definition.key]]) {
                if (!allowed.has(value)) filter.selections[definition.key].delete(value);
            }
        }
        filter.menu.replaceChildren(...definitions.map((definition) => buildMultiSelect(filter, definition)));
        filter.signature = signature;
    }

    function syncFilterMenu(filter) {
        for (const details of filter.menu.querySelectorAll('details.multi-select')) {
            const selected = filter.selections[details.dataset.filterKey] || new Set();
            for (const checkbox of details.querySelectorAll('input[type="checkbox"]')) {
                checkbox.checked = selected.has(checkbox.value);
            }
            updateMultiSelectBadge(details, selected);
        }
    }

    function filterRecords(name, records, textFor) {
        const filter = tableFilters[name];
        const terms = String(filter.search.value || '').trim().toLowerCase().split(/\s+/)
            .filter(Boolean);
        const definitions = filter.definitions || [];
        const facetValues = definitions.map((definition) => ({
            definition,
            selected: filter.selections[definition.key] || new Set()
        }));
        const visible = records.filter((record) => {
            const haystack = String(textFor(record) || '').toLowerCase();
            if (!terms.every((term) => haystack.includes(term))) return false;
            return facetValues.every(({ definition, selected }) =>
                selected.size === 0 || selected.has(definition.value(record)));
        });

        const selectedCount = facetValues.reduce((total, entry) => total + entry.selected.size, 0);
        const active = terms.length > 0 || selectedCount > 0;
        if (filter.clear) filter.clear.hidden = !active;
        const countText = records.length === 0
            ? '0 total'
            : active
                ? `${visible.length} of ${records.length}`
                : `${records.length} total`;
        if (filter.count && filter.count.textContent !== countText) {
            filter.count.textContent = countText;
        }
        return visible;
    }

    function updateFilterEmpty(name, visible, total) {
        const node = tableFilters[name].empty;
        if (!node) return;
        if (visible > 0) {
            node.hidden = true;
            return;
        }
        if (!node.dataset.emptyText) node.dataset.emptyText = node.textContent;
        node.textContent = total === 0 ? node.dataset.emptyText : 'No matching records.';
        node.hidden = false;
    }

    function deviceFilterText(device, pbxById) {
        const pbx = device.pbxId ? pbxById.get(device.pbxId) : null;
        const suggestedPbx = device.suggestedPbxId ? pbxById.get(device.suggestedPbxId) : null;
        return [
            deviceTitle(device),
            device.deviceName,
            device.model,
            device.deviceUuid,
            device.platform,
            platformLabel(device.platform),
            device.osVersion,
            device.appVersion,
            device.requestIp,
            enrollmentSource(device),
            formatTime(device.requestedAt),
            formatTime(device.reviewedAt),
            device.extension,
            device.suggestedExtension,
            pbx && pbx.name,
            pbx && pbx.id,
            suggestedPbx && suggestedPbx.name,
            device.status
        ].filter(Boolean).join(' ');
    }

    function pbxFilterText(record) {
        const management = record.management || {};
        const provisioningEntryForRecord = provisioningEntry(record.id);
        const provisionValues = provisioningEntryForRecord
            ? [
                provisioningEntryForRecord.effectiveState,
                provisioningEntryForRecord.reason,
                ...Object.values(provisioningEntryForRecord.stages || {})
            ]
            : [];
        return [
            record.name,
            record.id,
            record.wsURL,
            record.apiURL,
            ...(record.mediaIps || []),
            record.enabled ? 'enabled' : 'disabled',
            management.customer,
            management.loginHostname,
            management.reviewedInstallationId,
            approvalLabel(management.approvalStatus),
            ...provisionValues
        ].filter(Boolean).join(' ');
    }

    function extensionFilterText(record, pbxById) {
        const pbx = record.pbxId ? pbxById.get(record.pbxId) : null;
        const platforms = Array.isArray(record.allowedPlatforms) ? record.allowedPlatforms : [];
        return [
            pbx && pbx.name,
            pbx && pbx.id,
            record.extension,
            record.name,
            extensionStatusLabel(record.status),
            platforms.map(platformLabel).join(' '),
            approvedDeviceCount(record),
            record.maxDevices
        ].filter(Boolean).join(' ');
    }

    function deviceTitle(device) {
        if (device.deviceName) return device.deviceName;
        if (device.model) return device.model;
        return device.platform === 'ios' ? 'iOS device' : 'Android device';
    }

    function deviceSubtitle(device) {
        const parts = [device.platform];
        if (device.osVersion) parts.push(device.osVersion);
        const currentAppVersion = device.telemetry && device.telemetry.appVersion;
        if (currentAppVersion) parts.push(`app ${currentAppVersion}`);
        else if (device.appVersion) parts.push(`app ${device.appVersion}`);
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
        wake_unverified: 'Push-to-wake call path not verified',
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
        stopRealtimePolling();
        csrfToken = null;
        snapshot = null;
        provisioning = null;
        provisioningError = null;
        showLogin();
        showLoginMessage(message || 'Sign in to continue.');
    }

    let pollInterval = null;
    let activeCallsInterval = null;
    let metricsInterval = null;
    let firewallInterval = null;

    function formatMetric(value, digits = 1, suffix = '') {
        const number = Number(value);
        return Number.isFinite(number) ? `${number.toFixed(digits)}${suffix}` : '—';
    }

    function drawSpark(canvas, values, maximum, color) {
        if (!canvas || !canvas.getContext) return;
        const width = Math.max(1, Math.floor(canvas.clientWidth || canvas.width));
        const height = Math.max(1, Math.floor(canvas.clientHeight || 96));
        const ratio = window.devicePixelRatio || 1;
        canvas.width = Math.floor(width * ratio);
        canvas.height = Math.floor(height * ratio);
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        ctx.clearRect(0, 0, width, height);
        const points = values.map((value) => Number(value)).filter((value) => Number.isFinite(value));
        if (points.length === 0) return;
        const max = Math.max(1, Number(maximum) || 1);
        const step = points.length > 1 ? width / (points.length - 1) : width;
        const yFor = (value) => height - Math.max(0, Math.min(max, value)) / max * (height - 4) - 2;
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        ctx.beginPath();
        points.forEach((value, index) => {
            const x = points.length > 1 ? index * step : width / 2;
            const y = yFor(value);
            if (index === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
        ctx.globalAlpha = 0.12;
        ctx.lineTo(width, height);
        ctx.lineTo(0, height);
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.fill();
        ctx.globalAlpha = 1;
    }

    function renderMetrics(payload) {
        const metrics = payload && payload.metrics;
        const current = metrics && metrics.current;
        if (!current) {
            if (refs.loadCpu) refs.loadCpu.textContent = '—';
            if (refs.loadMemory) refs.loadMemory.textContent = '—';
            if (refs.loadNetwork) refs.loadNetwork.textContent = '—';
            if (refs.loadCalls) refs.loadCalls.textContent = '—';
            return;
        }
        if (refs.loadCpu) refs.loadCpu.textContent = formatMetric(current.cpuPct, 1, '%');
        if (refs.loadMemory) {
            refs.loadMemory.textContent = Number.isFinite(current.memoryBytes)
                ? `${formatMetric(current.memoryBytes / 1048576, 1)} MB`
                : '—';
        }
        if (refs.loadNetwork) {
            refs.loadNetwork.textContent =
                `${formatMetric(current.sipInBps / 1e6, 2)} / ${formatMetric(current.sipOutBps / 1e6, 2)} Mbps`;
        }
        if (refs.loadCalls) {
            refs.loadCalls.textContent = `${Number(current.activeCalls) || 0} / ${Number(current.ringingCalls) || 0}`;
        }
        if (refs.loadHost) {
            const hostCpu = formatMetric(current.hostCpuPct, 1, '%');
            const hostMemory = formatMetric(current.hostMemoryPct, 1, '%');
            refs.loadHost.textContent = `Host total (includes BT-Panel and other services): CPU ${hostCpu} · RAM ${hostMemory}.`;
        }
        if (refs.loadSource) {
            refs.loadSource.textContent = metrics.source && metrics.source.cgroup
                ? 'Gateway container · BT-Panel excluded · 5 min'
                : 'Gateway container · BT-Panel excluded';
        }
        const history = Array.isArray(metrics.history) ? metrics.history : [];
        const values = (key) => history.map((row) => row && row[key]);
        const style = getComputedStyle(document.documentElement);
        const accent = style.getPropertyValue('--accent').trim() || '#c0392b';
        const ok = style.getPropertyValue('--ok').trim() || '#1e6a45';
        const warn = style.getPropertyValue('--warn').trim() || '#8a5a00';
        const muted = style.getPropertyValue('--muted').trim() || '#5d6673';
        drawSpark(refs.chartCpu, values('cpuPct'), 100, accent);
        drawSpark(refs.chartMemory, values('memoryBytes').map((value) => value / 1048576), 64, ok);
        drawSpark(refs.chartNetwork, values('sipInBps').map((value, index) =>
            (Number(value) || 0) + (Number(values('sipOutBps')[index]) || 0)).map((value) => value / 1e6), 1, warn);
        drawSpark(refs.chartCalls, values('activeCalls'), Math.max(1, ...values('activeCalls').map(Number).filter(Number.isFinite)), muted);
    }

    async function refreshMetrics() {
        if (!refs.loadCpu) return;
        try {
            const payload = await api('/api/metrics');
            renderMetrics(payload);
        } catch (_) {}
    }

    function renderHostFirewall(firewall) {
        if (!refs.firewallState || !refs.firewallSummary) return;
        const configured = firewall && firewall.configured === true;
        if (!configured) {
            refs.firewallState.textContent = 'Not configured';
            refs.firewallState.style.color = 'var(--warn)';
            refs.firewallSummary.textContent =
                'No installer-managed host firewall record was found. Do not expose this gateway until the host firewall is configured.';
            return;
        }
        const manager = String(firewall.manager || 'firewall').toUpperCase();
        const ports = Array.isArray(firewall.ports) ? firewall.ports : [];
        refs.firewallState.textContent = `${manager} active`;
        refs.firewallState.style.color = 'var(--ok)';
        refs.firewallSummary.textContent =
            `SSH ${firewall.sshPort || '?'} / tcp · allowed: ${ports.join(', ') || 'none recorded'}`;
    }

    async function refreshHostFirewall() {
        if (!refs.firewallState) return;
        try {
            const payload = await api('/api/host-firewall');
            renderHostFirewall(payload && payload.firewall);
        } catch (_) {
            refs.firewallState.textContent = 'Unavailable';
            refs.firewallState.style.color = 'var(--warn)';
            refs.firewallSummary.textContent = 'The gateway could not read the host firewall status.';
        }
    }

    function renderPushCredentials(credentials) {
        if (!refs.pushCredentialsStatus) return;
        const fcm = credentials && credentials.fcm && credentials.fcm.configured === true;
        const apns = credentials && credentials.apns && credentials.apns.configured === true;
        const apnsDetail = apns && credentials.apns.keyId
            ? ` (${credentials.apns.keyId})`
            : '';
        refs.pushCredentialsStatus.textContent =
            `FCM: ${fcm ? 'configured' : 'not configured'} · APNs: ${apns ? `configured${apnsDetail}` : 'not configured'}`;
    }

    async function refreshPushCredentials() {
        if (!refs.pushCredentialsStatus) return;
        try {
            const payload = await api('/api/push-credentials');
            renderPushCredentials(payload && payload.credentials);
        } catch (_) {
            refs.pushCredentialsStatus.textContent = 'Push credential status is unavailable.';
        }
    }

    async function fileBase64(file) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = '';
        for (let index = 0; index < bytes.length; index += 1) {
            binary += String.fromCharCode(bytes[index]);
        }
        return btoa(binary);
    }

    async function saveFcmCredentials() {
        if (!refs.pushFcmFile || !refs.pushFcmSave) return;
        const file = refs.pushFcmFile.files && refs.pushFcmFile.files[0];
        if (!file) {
            showError('Choose an FCM service-account JSON file first.');
            return;
        }
        setBusy(refs.pushFcmSave, true, 'Saving…');
        try {
            const serviceAccount = await file.text();
            const payload = await api('/api/push-credentials/fcm', {
                method: 'POST',
                body: { serviceAccount }
            });
            renderPushCredentials(payload && payload.credentials);
            refs.pushFcmFile.value = '';
            showStatus('FCM credentials saved. The gateway will reload push providers automatically.');
        } catch (error) {
            showError(error.message || 'Could not save FCM credentials.');
        } finally {
            setBusy(refs.pushFcmSave, false);
        }
    }

    async function saveApnsCredentials() {
        if (!refs.pushApnsFile || !refs.pushApnsSave) return;
        const file = refs.pushApnsFile.files && refs.pushApnsFile.files[0];
        if (!file) {
            showError('Choose an APNs .p8 key file first.');
            return;
        }
        setBusy(refs.pushApnsSave, true, 'Saving…');
        try {
            const payload = await api('/api/push-credentials/apns', {
                method: 'POST',
                body: {
                    keyBase64: await fileBase64(file),
                    keyId: refs.pushApnsKeyId.value.trim(),
                    teamId: refs.pushApnsTeamId.value.trim(),
                    topic: refs.pushApnsTopic.value.trim(),
                    environment: refs.pushApnsEnvironment.value
                }
            });
            renderPushCredentials(payload && payload.credentials);
            refs.pushApnsFile.value = '';
            showStatus('APNs credentials saved. The gateway will reload push providers automatically.');
        } catch (error) {
            showError(error.message || 'Could not save APNs credentials.');
        } finally {
            setBusy(refs.pushApnsSave, false);
        }
    }

    async function refreshActiveCalls() {
        if (!refs.activeCallsList) return;
        try {
            const state = await api('/api/active-calls');
            renderActiveCalls(state);
        } catch (_) {}
    }

    function renderActiveCalls(state) {
        if (!refs.activeCallsList) return;
        const rows = Array.isArray(state && state.activeCalls) ? state.activeCalls : [];
        refs.activeCallsList.replaceChildren();
        for (const row of rows) {
            const li = document.createElement('li');
            const value = document.createElement('span');
            value.className = 'stat-value';
            value.textContent = String(row.active || 0);
            const label = document.createElement('span');
            label.className = 'stat-label';
            label.textContent = `${row.pbxName || row.pbxId}${row.ringing ? ` · ${row.ringing} ringing` : ''}`;
            li.append(value, label);
            refs.activeCallsList.append(li);
        }
        if (refs.activeCallsTotal) {
            refs.activeCallsTotal.textContent =
                `${Number(state && state.active) || 0} active · ${Number(state && state.ringing) || 0} ringing`;
        }
        if (refs.activeCallsEmpty) refs.activeCallsEmpty.hidden = rows.length > 0;
    }

    function startRealtimePolling() {
        if (pollInterval) return;
        pollInterval = setInterval(async () => {
            if (document.visibilityState === 'visible' && refs.dashboard && !refs.dashboard.hidden) {
                try {
                    await refresh(true);
                } catch (_) {}
            }
        }, 3000);
        if (!activeCallsInterval) {
            void refreshActiveCalls();
            activeCallsInterval = setInterval(() => {
                if (document.visibilityState === 'visible' && refs.dashboard && !refs.dashboard.hidden) {
                    void refreshActiveCalls();
                }
            }, 1000);
        }
        if (!metricsInterval) {
            void refreshMetrics();
            metricsInterval = setInterval(() => {
                if (document.visibilityState === 'visible' && refs.dashboard && !refs.dashboard.hidden) {
                    void refreshMetrics();
                }
            }, 2000);
        }
        if (!firewallInterval) {
            void refreshHostFirewall();
            firewallInterval = setInterval(() => {
                if (document.visibilityState === 'visible' && refs.dashboard && !refs.dashboard.hidden) {
                    void refreshHostFirewall();
                }
            }, 30_000);
        }
    }

    function stopRealtimePolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
        if (activeCallsInterval) {
            clearInterval(activeCallsInterval);
            activeCallsInterval = null;
        }
        if (metricsInterval) {
            clearInterval(metricsInterval);
            metricsInterval = null;
        }
        if (firewallInterval) {
            clearInterval(firewallInterval);
            firewallInterval = null;
        }
    }

    async function enterDashboard() {
        refs.loginView.hidden = true;
        refs.dashboard.hidden = false;
        refs.signOut.hidden = false;
        await refresh();
        void refreshPushCredentials();
        startRealtimePolling();
    }

    async function refresh(isBackground = false) {
        if (!isBackground) refs.main.setAttribute('aria-busy', 'true');
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
        void refreshActiveCalls();
        void refreshMetrics();
        } finally {
            if (!isBackground) refs.main.removeAttribute('aria-busy');
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
        if (refs.pbxCapHint) {
            refs.pbxCapHint.textContent =
                `Enabled connections are capped at ${limits.maxEnabledPbx || 0} by the gateway; ` +
                `${stats.pbx || 0} of ${limits.maxPbx || 0} records used.`;
        }

        renderProvisioningSummary();
        for (const name of Object.keys(tableFilters)) ensureFilterMenus(name);
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
            const label = name === 'hook' ? 'Push sender' : `${name.charAt(0).toUpperCase()}${name.slice(1)}`;
            return `${label} ${labelFrom(PROVISIONING_STAGE_LABELS, value)}`;
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

    function pbxDashboardUrl(record) {
        try {
            if (!record.enabled) return null;
            const api = new URL(record.apiURL);
            const apiPort = Number(api.port);
            if (api.hostname !== '127.0.0.1' || !Number.isInteger(apiPort) ||
                apiPort < 23000 || apiPort > 23099) return null;
            const publicPort = 39000 + (apiPort % 100);
            return `https://${location.hostname}:${publicPort}/`;
        } catch (_) {
            return null;
        }
    }

    function renderPbx() {
        const allPbx = snapshot.pbx || [];
        const pbx = filterRecords('pbx', allPbx, pbxFilterText);
        updateFilterEmpty('pbx', pbx.length, allPbx.length);
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
                el('td', { dataset: { label: 'Connection' } },
                    el('div', { class: 'connection' },
                        el('span', { class: 'conn-line' },
                            el('span', { class: 'conn-label', text: 'WS' }),
                            el('span', { class: 'url', text: record.wsURL })),
                        el('span', { class: 'conn-line' },
                            el('span', { class: 'conn-label', text: 'API' }),
                            el('span', { class: 'url', text: record.apiURL })),
                        record.mediaIps && record.mediaIps.length
                            ? el('span', { class: 'conn-line' },
                                el('span', { class: 'conn-label', text: 'Media' }),
                                el('span', { class: 'url', text: record.mediaIps.join(', ') }))
                            : null)),
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
                        pbxDashboardUrl(record)
                            ? el('a', {
                                class: 'btn btn-sm',
                                href: pbxDashboardUrl(record),
                                target: '_blank',
                                rel: 'noopener noreferrer',
                                title: 'Open this PBX dashboard through the gateway'
                            }, 'Open Sokrat VOIP')
                            : null,
                        el('button', {
                            class: 'btn btn-sm',
                            type: 'button',
                            onclick: () => startEditPbx(record)
                        }, 'Edit'),
                        el('button', {
                            class: 'btn btn-ghost btn-sm',
                            type: 'button',
                            onclick: () => setPbxSuspended(record, record.enabled)
                        }, record.enabled ? 'Suspend' : 'Resume'),
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
        const allExtensions = Array.isArray(snapshot.extensions) ? snapshot.extensions : [];
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));
        const extensions = filterRecords(
            'extensions',
            allExtensions,
            (record) => extensionFilterText(record, pbxById)
        );
        updateFilterEmpty('extensions', extensions.length, allExtensions.length);
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
                    el('div', { class: 'row-actions' },
                        el('button', {
                            class: 'btn btn-sm',
                            type: 'button',
                            onclick: () => startEditExtension(record)
                        }, 'Edit'),
                        el('button', {
                            class: 'btn btn-danger btn-sm',
                            type: 'button',
                            onclick: () => removeExtension(record)
                        }, 'Remove')))
            );
        }));
    }

    function renderInvites() {
        if (!refs.inviteRows || !refs.inviteEmpty) return;
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

    function pendingHasFocus() {
        const active = document.activeElement;
        return Boolean(active && refs.pendingRows.contains(active)
            && typeof active.matches === 'function'
            && active.matches('select, input, button'));
    }

    function renderPending() {
        const allPending = (snapshot.devices || []).filter((device) => device.status === 'pending');
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));
        const pending = filterRecords(
            'pending',
            allPending,
            (device) => deviceFilterText(device, pbxById)
        );
        const enabledPbx = (snapshot.pbx || []).filter((record) => record.enabled);

        // A 3-second poll must not replace the select/input under the operator.
        if (pendingHasFocus()) {
            pendingRenderDeferred = true;
            return;
        }
        pendingRenderDeferred = false;
        const pendingIds = new Set(allPending.map((device) => device.id));
        for (const id of pendingDrafts.keys()) {
            if (!pendingIds.has(id)) pendingDrafts.delete(id);
        }

        updateFilterEmpty('pending', pending.length, allPending.length);
        refs.pendingRows.replaceChildren(...pending.map((device) => {
            const title = deviceTitle(device);
            const draft = pendingDrafts.get(device.id) || {
                pbxId: device.suggestedPbxId || '',
                extension: device.suggestedExtension || ''
            };
            pendingDrafts.set(device.id, draft);

            const select = el('select', {
                'aria-label': `PBX for ${title}`,
                disabled: enabledPbx.length === 0
            }, enabledPbx.length
                ? enabledPbx.map((record) => el('option', { value: record.id, text: record.name }))
                : el('option', { value: '', text: 'Enable a PBX first' }));
            const preferred = enabledPbx.find((record) => record.id === device.suggestedPbxId);
            const chosen = enabledPbx.some((record) => record.id === draft.pbxId)
                ? draft.pbxId
                : (preferred ? preferred.id : (enabledPbx[0] ? enabledPbx[0].id : ''));
            if (chosen) select.value = chosen;
            if (!draft.pbxId || draft.pbxId !== select.value) draft.pbxId = select.value;
            select.addEventListener('change', () => { draft.pbxId = select.value; });

            const extension = el('input', {
                type: 'text',
                maxlength: '32',
                inputmode: 'numeric',
                autocomplete: 'off',
                placeholder: 'Extension',
                'aria-label': `Extension for ${title}`,
                value: draft.extension
            });
            extension.addEventListener('input', () => { draft.extension = extension.value; });

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


    function formatDiagnosticTime(value) {
        const number = Number(value);
        if (Number.isFinite(number) && number > 0) return dateFormatter.format(number);
        return formatTime(value);
    }

    function renderPushState(device) {
        if (device.legacyPushRegistered && !device.pushRegistered) {
            return el('span', {
                class: device.legacyPushError ? 'cell-sub push-missing' : 'cell-sub',
                text: `Legacy push token registered${device.legacyPushUpdatedAt ? ` · ${formatDiagnosticTime(device.legacyPushUpdatedAt)}` : ''}${device.legacyPushError ? ` · ${device.legacyPushError}` : ''}`
            });
        }
        if (device.pushRegistered) {
            return el('span', {
                class: 'cell-sub push-active',
                text: `Push token active${device.lastRegisteredAt ? ` · ${formatDiagnosticTime(device.lastRegisteredAt)}` : ''}`
            });
        }
        if (device.pushState === 'invalid') {
            return el('span', { class: 'cell-sub push-missing', text: 'Token invalid — re-register required' });
        }
        if (device.pushState === 'stale') {
            return el('span', { class: 'cell-sub push-missing', text: 'Push token stale — re-register required' });
        }
        if (device.pushRegistered === false) {
            return el('span', { class: 'cell-sub push-missing', text: 'No push token — notifications unavailable' });
        }
        return null;
    }

    function renderDeviceTelemetry(device) {
        const telemetry = device.telemetry && typeof device.telemetry === 'object' ? device.telemetry : null;
        const labels = {
            appVersion: 'App version',
            sipState: 'SIP',
            gatewayState: 'Gateway',
            appState: 'App state',
            networkConnected: 'Network connected',
            networkType: 'Network type',
            activeCall: 'Active call',
            fcmTokenPresent: 'FCM token',
            fcmLastTokenAt: 'FCM token refreshed',
            fcmLastError: 'FCM error',
            pushRegisteredAt: 'Push registered',
            pushLastError: 'Push error',
            reportedAt: 'Reported at',
        };
        const rows = telemetry ? Object.entries(telemetry)
            .filter(([key, value]) => !['fcmLastError', 'pushLastError'].includes(key) || String(value ?? '').trim())
            .map(([key, value]) => {
                let text = String(value ?? '—');
                if (key === 'fcmLastTokenAt' || key === 'pushRegisteredAt') text = formatDiagnosticTime(value);
                if (key === 'reportedAt') text = formatTime(value);
                if (key === 'networkConnected') text = value === 'true' || value === true ? 'Yes' : 'No';
                if (key === 'fcmTokenPresent') text = value === 'true' || value === true ? 'Present' : 'Missing';
                return el('div', { class: 'telemetry-pair' },
                    el('dt', { text: labels[key] || key }),
                    el('dd', { text: text || '—' }));
            }) : [];
        const details = el('details', { class: 'device-telemetry' },
            el('summary', {
                text: telemetry
                    ? `Device diagnostics · ${formatDiagnosticTime(device.telemetryAt)}`
                    : 'Device diagnostics · none received',
            }),
            telemetry
                ? el('dl', { class: 'telemetry-grid' }, ...rows)
                : el('p', { class: 'hint', text: 'This device has not sent a diagnostic heartbeat yet.' }));
        details.open = openDiagnostics.has(device.id);
        details.addEventListener('toggle', () => {
            if (details.open) openDiagnostics.add(device.id);
            else openDiagnostics.delete(device.id);
        });
        return details;
    }
    function renderApproved() {
        const allApproved = (snapshot.devices || []).filter((device) => device.status === 'approved')
            .sort((a, b) => (Date.parse(b.reviewedAt || '') || 0) - (Date.parse(a.reviewedAt || '') || 0));
        const pbxById = new Map((snapshot.pbx || []).map((record) => [record.id, record]));
        const approved = filterRecords(
            'approved',
            allApproved,
            (device) => deviceFilterText(device, pbxById)
        );

        updateFilterEmpty('approved', approved.length, allApproved.length);
        const noToken = allApproved.filter(device => !device.pushRegistered && !device.legacyPushRegistered);
        const noTokenExtensions = [...new Set(noToken.map(device => String(device.extension || 'unknown')))];
        if (refs.approvedTokenWarning) {
            refs.approvedTokenWarning.hidden = noToken.length === 0;
            refs.approvedTokenWarning.textContent = noToken.length
                ? `${noToken.length} approved device${noToken.length === 1 ? '' : 's'} have no active push token (${noTokenExtensions.join(', ')}).`
                : '';
        }
        refs.approvedRows.replaceChildren(...approved.flatMap((device) => {
            const title = deviceTitle(device);
            const pbx = device.pbxId ? pbxById.get(device.pbxId) : null;
            return [
                el('tr', {},
                    el('th', { scope: 'row', dataset: { label: 'Device' } },
                        title,
                        el('span', { class: 'cell-sub', text: deviceSubtitle(device) }),
                        renderPushState(device)),
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
                ),
                // Keep diagnostics out of the narrow Device cell and give the
                // grid the full width of the table on every viewport.
                el('tr', { class: 'approved-diagnostics' },
                    el('td', { colspan: '6' }, renderDeviceTelemetry(device)))
            ];
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
        if (!refs.invitePbx) return;
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
        refs.pbxPolicyRequired.checked = false;
        refs.sshEnable.checked = true;
        refs.sshPassword.required = true;
        refs.pbxSubmit.textContent = 'Add server';
        refs.pbxCancel.hidden = true;
        if (refs.pbxFormDetails) {
            refs.pbxFormDetails.open = false;
            refs.pbxFormDetails.hidden = true;
        }
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
        if (refs.pbxFormDetails) {
            refs.pbxFormDetails.hidden = false;
            refs.pbxFormDetails.open = true;
        }
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

    async function setPbxSuspended(record, suspend) {
        if (suspend) {
            const confirmed = window.confirm(
                `Suspend "${record.name}"? Its devices stop receiving pushes until resumed. ` +
                'The server record, device approvals and invites are kept.'
            );
            if (!confirmed) return;
        }
        try {
            await api(`/api/pbx/${encodeURIComponent(record.id)}`, {
                method: 'PATCH',
                body: { enabled: !suspend }
            });
            showStatus(suspend ? `Suspended ${record.name}.` : `Resumed ${record.name}.`);
            await refresh();
        } catch (error) {
            handleError(error);
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
        refs.extForm.hidden = false;
        refs.extSubmit.textContent = 'Save extension';
        refs.extCancel.hidden = false;
        clearMessages();
        refs.extForm.scrollIntoView({ block: 'center', behavior: 'smooth' });
        refs.extName.focus({ preventScroll: true });
    }

    function resetExtensionForm() {
        editingExtensionId = null;
        refs.extForm.reset();
        refs.extForm.hidden = true;
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

    async function removeExtension(record) {
        const pbx = (snapshot.pbx || []).find((item) => item.id === record.pbxId);
        const count = approvedDeviceCount(record);
        const where = pbx ? ` on ${pbx.name}` : '';
        const confirmed = window.confirm(
            `Remove extension ${record.extension}${where}? ` +
            `${count} approved device${count === 1 ? '' : 's'} will be revoked and matching invites will stop working.`
        );
        if (!confirmed) return;
        try {
            await api(`/api/extensions/${encodeURIComponent(record.id)}`, { method: 'DELETE' });
            if (editingExtensionId === record.id) resetExtensionForm();
            showStatus(`Removed extension ${record.extension}.`);
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
            pendingDrafts.delete(device.id);
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
            pendingDrafts.delete(device.id);
            showStatus('Device rejected.');
            await refresh();
        } catch (error) {
            handleError(error);
        }
    }

    async function pruneStaleApprovals() {
        const confirmed = window.confirm(
            'Revoke approved devices that have no active push token when another device on the same PBX and extension is active? Active devices are kept.'
        );
        if (!confirmed) return;
        setBusy(refs.approvedCleanup, true, 'Cleaning…');
        try {
            const result = await api('/api/devices/prune-stale', { method: 'POST', body: {} });
            showStatus(result.revoked
                ? `Removed ${result.revoked} stale approved device${result.revoked === 1 ? '' : 's'}.`
                : 'No stale duplicate approvals found.');
            await refresh();
        } catch (error) {
            handleError(error);
        } finally {
            setBusy(refs.approvedCleanup, false);
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
        if (refs.inviteForm) refs.inviteForm.addEventListener('submit', createInvite);
        refs.signOut.addEventListener('click', signOut);
        if (refs.approvedCleanup) refs.approvedCleanup.addEventListener('click', pruneStaleApprovals);
        if (refs.pushCredentialsToggle && refs.pushCredentialsPanel) {
            refs.pushCredentialsToggle.addEventListener('click', () => {
                refs.pushCredentialsPanel.hidden = !refs.pushCredentialsPanel.hidden;
                refs.pushCredentialsToggle.textContent = refs.pushCredentialsPanel.hidden
                    ? 'Add credentials'
                    : 'Hide credentials';
            });
        }
        if (refs.pushFcmSave) refs.pushFcmSave.addEventListener('click', saveFcmCredentials);
        if (refs.pushApnsSave) refs.pushApnsSave.addEventListener('click', saveApnsCredentials);
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
        if (refs.tokenCopy) refs.tokenCopy.addEventListener('click', () => copyFrom(refs.tokenValue, refs.tokenCopy));
        refs.secretCopy.addEventListener('click', () => copyFrom(refs.secretValue, refs.secretCopy));
        if (refs.tokenDismiss) refs.tokenDismiss.addEventListener('click', () => {
            refs.tokenPanel.hidden = true;
            refs.tokenValue.textContent = '';
        });
        refs.secretDismiss.addEventListener('click', () => {
            refs.secretPanel.hidden = true;
            refs.secretValue.textContent = '';
        });

        if (refs.showTunnelTokenBtn) {
            refs.showTunnelTokenBtn.addEventListener('click', async () => {
                if (!refs.tunnelTokenPanel.hidden) {
                    refs.tunnelTokenPanel.hidden = true;
                    refs.showTunnelTokenBtn.textContent = 'Show Pairing Code';
                    return;
                }
                try {
                    const res = await api('/api/tunnel-token');
                    if (res && res.token) {
                        refs.tunnelTokenValue.textContent = res.token;
                        refs.tunnelTokenPanel.hidden = false;
                        refs.showTunnelTokenBtn.textContent = 'Hide Pairing Code';
                    } else {
                        refs.tunnelTokenValue.textContent = 'No pairing code configured';
                        refs.tunnelTokenPanel.hidden = false;
                    }
                } catch (e) {
                    alert('Could not fetch tunnel token: ' + (e.message || e));
                }
            });
        }
        if (refs.copyTunnelTokenBtn) {
            refs.copyTunnelTokenBtn.addEventListener('click', () => {
                copyFrom(refs.tunnelTokenValue, refs.copyTunnelTokenBtn);
            });
        }

        document.addEventListener('blur', syncValidity, true);
        document.addEventListener('input', syncValidity, true);
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && refs.dashboard && !refs.dashboard.hidden) {
                refresh(true).catch(() => {});
            }
        });

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
