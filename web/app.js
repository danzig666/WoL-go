'use strict';

/* Wake-on-LAN control panel.
 *
 * All user-supplied text (device names, hostnames from the network scan) is
 * written with textContent rather than innerHTML, so a machine advertising a
 * hostile NetBIOS name cannot inject markup into this page. innerHTML is used
 * only for fixed skeleton markup defined in this file.
 */

const state = {
    token: localStorage.getItem('token') || '',
    username: localStorage.getItem('username') || '',
    // Anonymous visitors get a reduced view: names and online status only,
    // with a wake button. Everything else needs a session.
    signedIn: false,
    publicWake: true,
    // Identity as reported by the server: "admin", "cloudflare" or "local".
    identity: { kind: 'local', email: '' },
    people: [],
    devices: [],
    statuses: {},
    filter: '',
    editingId: null,
    scanTimer: null,
    scanSelection: new Set(),
    scanResults: [],
    statusTimer: null,
    wakeChecks: [],
};

const $ = (id) => document.getElementById(id);

/* ---------------- API ---------------- */

async function api(path, options = {}) {
    const opts = Object.assign({}, options);
    opts.headers = Object.assign({}, opts.headers);
    if (state.token) {
        opts.headers['Authorization'] = 'Bearer ' + state.token;
    }
    if (opts.body !== undefined && typeof opts.body !== 'string') {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(opts.body);
    }

    let response;
    try {
        response = await fetch(path, opts);
    } catch (err) {
        throw new Error('Cannot reach the server. Check that it is still running.');
    }

    if (response.status === 401 && state.token) {
        signOut();
        throw new Error('Your session has expired. Please sign in again.');
    }

    let data = null;
    if (response.status !== 204) {
        const text = await response.text();
        if (text) {
            try {
                data = JSON.parse(text);
            } catch (err) {
                data = null;
            }
        }
    }

    if (!response.ok) {
        const message = (data && data.error) || 'Something went wrong. Please try again.';
        const error = new Error(message);
        error.status = response.status;
        throw error;
    }
    return data;
}

/* ---------------- Views ---------------- */

function showView(name) {
    $('loginView').classList.toggle('active', name === 'login');
    $('mainView').classList.toggle('active', name === 'main');
}

function showLogin() {
    $('loginForm').style.display = 'block';
    $('changePasswordForm').style.display = 'none';
    hideError('loginError');
    hideError('changeError');
    // Only offer "back to the list" when there is a list to go back to.
    $('backRow').classList.toggle('hidden', !state.publicWake);
    showView('login');
}

function setSignedIn(signedIn) {
    state.signedIn = signedIn;
    document.body.classList.toggle('signed-in', signedIn);
}

// applyIdentity shows who the server thinks we are, and tailors the empty
// state: a Cloudflare visitor with nothing shared needs different wording
// from a local visitor looking at an empty list.
function applyIdentity(identity) {
    state.identity = identity || { kind: 'local', email: '' };
    const isCloudflare = state.identity.kind === 'cloudflare';

    document.body.classList.toggle('cf-user', isCloudflare);
    if (isCloudflare) {
        $('identityEmail').textContent = state.identity.email;
    }

    if (isCloudflare) {
        $('emptyTitle').textContent = 'Nothing shared with you yet';
        $('emptyMessage').textContent =
            'No computers have been shared with your account yet. Ask whoever runs this to give you access.';
    } else {
        $('emptyTitle').textContent = 'No computers yet';
        $('emptyMessage').textContent = 'Nobody has added any computers yet. Sign in to set them up.';
    }
}

async function refreshIdentity() {
    try {
        applyIdentity(await api('/api/me'));
    } catch (err) {
        applyIdentity(null);
    }
}

// Anonymous callers use a separate, read-reduced set of endpoints.
function endpoint(path) {
    return state.signedIn ? '/api' + path : '/api/public' + path;
}

function signOut() {
    state.token = '';
    state.username = '';
    state.devices = [];
    state.statuses = {};
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    stopScanPolling();
    if (state.statusTimer) {
        clearInterval(state.statusTimer);
        state.statusTimer = null;
    }
    closeAllModals();
    setSignedIn(false);

    if (state.publicWake) {
        showView('main');
        loadDevices();
        startStatusPolling();
    } else {
        showLogin();
    }
}

function startSession(token, username) {
    state.token = token;
    if (username) {
        state.username = username;
        localStorage.setItem('username', username);
    }
    localStorage.setItem('token', token);
    setSignedIn(true);
    showView('main');
    loadDevices();
    startStatusPolling();
}

function startStatusPolling() {
    if (!state.statusTimer) {
        state.statusTimer = setInterval(refreshStatus, 45000);
    }
}

/* ---------------- Errors & toasts ---------------- */

function showError(id, message) {
    const el = $(id);
    el.textContent = message;
    el.classList.add('visible');
}

function hideError(id) {
    const el = $(id);
    el.textContent = '';
    el.classList.remove('visible');
}

const TOAST_ICONS = {
    success: '#i-check',
    error: '#i-close',
    info: '#i-bolt',
};

function toast(message, kind = 'info') {
    const el = document.createElement('div');
    el.className = 'toast ' + kind;
    el.innerHTML = '<svg class="icon"><use href="' + TOAST_ICONS[kind] + '"/></svg><span></span>';
    el.querySelector('span').textContent = message;
    $('toasts').appendChild(el);

    setTimeout(() => {
        el.classList.add('hiding');
        setTimeout(() => el.remove(), 220);
    }, 3600);
}

function setLoading(button, loading, label) {
    if (loading) {
        button.dataset.label = button.innerHTML;
        button.classList.add('loading');
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span>';
        if (label) {
            const span = document.createElement('span');
            span.textContent = label;
            button.appendChild(span);
        }
    } else {
        button.classList.remove('loading');
        button.disabled = false;
        if (button.dataset.label) {
            button.innerHTML = button.dataset.label;
            delete button.dataset.label;
        }
    }
}

/* ---------------- Sign in ---------------- */

$('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('loginError');

    const username = $('usernameInput').value.trim();
    const password = $('passwordInput').value;
    if (!username || !password) {
        showError('loginError', 'Please enter your username and password.');
        return;
    }

    const button = $('loginButton');
    setLoading(button, true);
    try {
        const data = await api('/api/login', {
            method: 'POST',
            body: { username, password },
        });
        $('passwordInput').value = '';

        if (data.must_change_password) {
            state.token = data.token;
            state.username = data.username || username;
            $('loginForm').style.display = 'none';
            $('changePasswordForm').style.display = 'block';
            $('newPasswordInput').focus();
        } else {
            startSession(data.token, data.username || username);
        }
    } catch (err) {
        showError('loginError', err.message);
    } finally {
        setLoading(button, false);
    }
});

$('changePasswordForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('changeError');

    const password = $('newPasswordInput').value;
    const confirmation = $('confirmPasswordInput').value;
    const problem = passwordProblem(password, confirmation);
    if (problem) {
        showError('changeError', problem);
        return;
    }

    const button = $('changeButton');
    setLoading(button, true);
    try {
        const data = await api('/api/password', {
            method: 'POST',
            body: { new_password: password },
        });
        $('newPasswordInput').value = '';
        $('confirmPasswordInput').value = '';
        toast('Password saved', 'success');
        startSession(data.token, state.username);
    } catch (err) {
        showError('changeError', err.message);
    } finally {
        setLoading(button, false);
    }
});

function passwordProblem(password, confirmation) {
    if (password.length < 8) {
        return 'Use at least 8 characters.';
    }
    if (!/[a-z]/i.test(password) || !/[0-9]/.test(password)) {
        return 'Include at least one letter and one number.';
    }
    if (password !== confirmation) {
        return 'The two passwords do not match.';
    }
    return '';
}

/* ---------------- Devices ---------------- */

async function loadDevices() {
    try {
        state.devices = await api(endpoint('/devices'));
        renderDevices();
        refreshStatus();
    } catch (err) {
        toast(err.message, 'error');
    }
}

function matchesFilter(device) {
    if (!state.filter) {
        return true;
    }
    const needle = state.filter.toLowerCase();
    return [device.name, device.mac, device.ip, device.notes]
        .filter(Boolean)
        .some((value) => value.toLowerCase().includes(needle));
}

function renderDevices() {
    // Rebuilding the grid mid-drag would pull the card out from under the
    // pointer, so the redraw waits until the drag finishes.
    if (drag) {
        return;
    }
    const grid = $('deviceGrid');
    grid.textContent = '';

    const visible = state.devices.filter(matchesFilter);

    $('emptyState').classList.toggle('visible', state.devices.length === 0);
    $('noResults').classList.toggle('visible', state.devices.length > 0 && visible.length === 0);

    visible.forEach((device) => grid.appendChild(deviceCard(device)));
    updateStatusLine();
}

function updateStatusLine() {
    const total = state.devices.length;
    if (total === 0) {
        $('statusLine').textContent = '';
        return;
    }
    const online = state.devices.filter((d) => state.statuses[d.id] && state.statuses[d.id].online).length;
    const asleep = state.devices.filter((d) => state.statuses[d.id] && state.statuses[d.id].asleep).length;
    const noun = total === 1 ? 'computer' : 'computers';

    let line = `${total} ${noun} saved · ${online} online`;
    if (asleep > 0) {
        line += ` · ${asleep} asleep`;
    }
    $('statusLine').textContent = line;
}

function deviceCard(device) {
    const card = document.createElement('article');
    card.className = 'device-card';
    card.dataset.id = device.id;
    card.innerHTML = `
        <div class="device-head">
            <span class="dot"></span>
            <div class="device-title">
                <div class="device-name"></div>
                <div class="device-state"></div>
            </div>
            <button type="button" class="drag-handle manage-only" title="Drag to reorder" aria-label="Drag to reorder">
                <svg class="icon"><use href="#i-grip"/></svg>
            </button>
        </div>
        <div class="device-meta"></div>
        <div class="device-notes"></div>
        <div class="device-actions">
            <button type="button" class="btn btn-primary btn-wake" data-action="wake">
                <svg class="icon"><use href="#i-bolt"/></svg><span>Wake up</span>
            </button>
            <button type="button" class="btn btn-secondary btn-sleep" data-action="sleep" title="Put this computer to sleep">
                <svg class="icon"><use href="#i-moon"/></svg><span>Sleep</span>
            </button>
            <button type="button" class="btn btn-ghost btn-icon manage-only" data-action="edit" title="Edit" aria-label="Edit">
                <svg class="icon"><use href="#i-pencil"/></svg>
            </button>
            <button type="button" class="btn btn-ghost btn-icon manage-only" data-action="delete" title="Remove" aria-label="Remove">
                <svg class="icon"><use href="#i-trash"/></svg>
            </button>
        </div>`;

    card.querySelector('.device-name').textContent = device.name;

    // The anonymous view carries no MAC or IP, by design.
    const meta = card.querySelector('.device-meta');
    if (device.mac) {
        meta.appendChild(chip(device.mac));
    }
    if (device.ip) {
        meta.appendChild(chip(device.ip));
    }
    if (device.vendor) {
        meta.appendChild(chip(device.vendor, true));
    }
    // Only worth showing when it differs from the name the user chose.
    if (device.hostname && device.hostname !== device.name) {
        meta.appendChild(chip(device.hostname, true));
    }

    const notes = card.querySelector('.device-notes');
    if (device.notes) {
        notes.textContent = device.notes;
    } else {
        notes.remove();
    }

    // Sleeping needs the companion agent, so the button only appears where one
    // is installed, and is disabled while that machine is not reporting in.
    const sleepButton = card.querySelector('[data-action="sleep"]');
    if (!device.can_sleep) {
        sleepButton.remove();
    } else if (!device.agent_online) {
        sleepButton.disabled = true;
        sleepButton.title = 'That computer is not reporting in at the moment';
    }

    applyStatus(card, device);
    return card;
}

function chip(text, plain) {
    const el = document.createElement('span');
    el.className = plain ? 'chip plain' : 'chip';
    el.textContent = text;
    return el;
}

function applyStatus(card, device) {
    const dot = card.querySelector('.dot');
    const label = card.querySelector('.device-state');
    const status = state.statuses[device.id];

    dot.classList.remove('online', 'checking', 'asleep');
    label.classList.remove('online', 'asleep');

    if (status === 'checking') {
        dot.classList.add('checking');
        label.textContent = 'Checking…';
        return;
    }
    if (status && status.online) {
        dot.classList.add('online');
        label.classList.add('online');
        label.textContent = 'Online';
        return;
    }
    // Nothing answered, but the machine still holds its address on the
    // network: it is asleep with the network card listening, so it can be
    // woken. This is the normal state for a computer you are about to wake.
    if (status && status.asleep) {
        dot.classList.add('asleep');
        label.classList.add('asleep');
        label.textContent = device.last_woken
            ? 'Asleep · woken ' + relativeTime(device.last_woken)
            : 'Asleep · ready to wake';
        return;
    }
    // Anonymous callers are not told the IP address, so the "add an IP"
    // prompt would be meaningless to them.
    if (!device.ip && state.signedIn) {
        label.textContent = device.last_woken ? 'Woken ' + relativeTime(device.last_woken) : 'Add an IP to see if it is on';
        return;
    }
    // Once a machine has been seen at least once, when that was is more
    // useful than a bare "no reply".
    if (device.last_seen) {
        label.textContent = 'No reply · last seen ' + relativeTime(device.last_seen);
        return;
    }
    label.textContent = device.last_woken ? 'No reply · woken ' + relativeTime(device.last_woken) : 'No reply';
}

function refreshCardStatus(deviceId) {
    const card = document.querySelector(`.device-card[data-id="${deviceId}"]`);
    const device = state.devices.find((d) => String(d.id) === String(deviceId));
    if (card && device) {
        applyStatus(card, device);
    }
}

async function refreshStatus() {
    if (state.devices.length === 0) {
        return;
    }
    state.devices.forEach((d) => {
        // Without a session the IP is unknown here, so mark everything as
        // checking and let the server decide.
        if (d.ip || !state.signedIn) {
            state.statuses[d.id] = 'checking';
            refreshCardStatus(d.id);
        }
    });

    try {
        state.statuses = await api(endpoint('/status'));
    } catch (err) {
        state.statuses = {};
        return;
    }
    state.devices.forEach((d) => refreshCardStatus(d.id));
    updateStatusLine();
}

function relativeTime(unixSeconds) {
    if (!unixSeconds) {
        return 'never';
    }
    const seconds = Math.floor(Date.now() / 1000) - unixSeconds;
    if (seconds < 60) return 'just now';
    if (seconds < 3600) {
        const m = Math.floor(seconds / 60);
        return `${m} minute${m === 1 ? '' : 's'} ago`;
    }
    if (seconds < 86400) {
        const h = Math.floor(seconds / 3600);
        return `${h} hour${h === 1 ? '' : 's'} ago`;
    }
    const d = Math.floor(seconds / 86400);
    return `${d} day${d === 1 ? '' : 's'} ago`;
}

$('deviceGrid').addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) {
        return;
    }
    const card = button.closest('.device-card');
    const device = state.devices.find((d) => String(d.id) === card.dataset.id);
    if (!device) {
        return;
    }

    if (button.dataset.action === 'wake') {
        await wakeDevice(device, button);
    } else if (button.dataset.action === 'sleep') {
        await sleepDevice(device, button);
    } else if (button.dataset.action === 'edit') {
        openDeviceModal(device);
    } else if (button.dataset.action === 'delete') {
        const ok = await confirmDialog(`Remove "${device.name}" from your list? This does not affect the computer itself.`, 'Remove');
        if (!ok) {
            return;
        }
        try {
            await api('/api/devices/' + device.id, { method: 'DELETE' });
            toast('Removed', 'success');
            loadDevices();
        } catch (err) {
            toast(err.message, 'error');
        }
    }
});

async function wakeDevice(device, button) {
    setLoading(button, true, 'Sending');
    try {
        await api(endpoint(`/devices/${device.id}/wake`), { method: 'POST' });
        toast(`Wake-up signal sent to ${device.name}`, 'success');
        device.last_woken = Math.floor(Date.now() / 1000);
        // A machine takes a little while to boot, so look again shortly.
        scheduleWakeChecks();
    } catch (err) {
        toast(err.message, 'error');
    } finally {
        setLoading(button, false);
    }
}

async function sleepDevice(device, button) {
    const ok = await confirmDialog(
        `Put ${device.name} to sleep now?`, 'Sleep');
    if (!ok) {
        return;
    }

    setLoading(button, true);
    try {
        const result = await api(endpoint(`/devices/${device.id}/sleep`), {
            method: 'POST',
            body: { force: false },
        });
        if (result.agent_waiting) {
            toast(`${device.name} is going to sleep`, 'success');
        } else {
            // Queued instead of delivered: the agent will collect it within a
            // minute, or the command expires.
            toast(`Sleep sent to ${device.name}`, 'success');
        }
        // Watch it drop off, the mirror of the checks after a wake.
        scheduleWakeChecks();
    } catch (err) {
        toast(err.message, 'error');
    } finally {
        setLoading(button, false);
    }
}

function scheduleWakeChecks() {
    state.wakeChecks.forEach(clearTimeout);
    state.wakeChecks = [15000, 35000, 70000].map((delay) => setTimeout(refreshStatus, delay));
}

$('wakeAllButton').addEventListener('click', async (event) => {
    if (state.devices.length === 0) {
        toast('Add a computer first', 'error');
        return;
    }
    const ok = await confirmDialog(`Send a wake-up signal to all ${state.devices.length} computers?`, 'Wake all');
    if (!ok) {
        return;
    }
    const button = event.currentTarget;
    setLoading(button, true, 'Sending');
    try {
        const result = await api(endpoint('/devices/wake-all'), { method: 'POST' });
        toast(`Wake-up signal sent to ${result.woken} of ${result.total}`, 'success');
        scheduleWakeChecks();
    } catch (err) {
        toast(err.message, 'error');
    } finally {
        setLoading(button, false);
    }
});

$('refreshButton').addEventListener('click', () => {
    loadDevices();
});

$('searchInput').addEventListener('input', (event) => {
    state.filter = event.target.value.trim();
    renderDevices();
});

/* ---------------- Reordering by dragging ----------------
 *
 * Pointer events are used rather than the HTML5 drag-and-drop API, because
 * that API does not fire on touchscreens - and this page is meant to be used
 * from a phone. The dragged card is lifted out of the grid into fixed
 * positioning and a placeholder keeps its slot, which is what makes the other
 * cards flow around it.
 */

let drag = null;

$('deviceGrid').addEventListener('pointerdown', (event) => {
    const handle = event.target.closest('.drag-handle');
    if (!handle || !state.signedIn) {
        return;
    }
    // While a search is filtering the grid, "above" and "below" do not
    // describe the saved order, so reordering is held back.
    if (state.filter) {
        toast('Clear the search box before reordering', 'error');
        return;
    }

    const card = handle.closest('.device-card');
    const rect = card.getBoundingClientRect();
    event.preventDefault();

    const placeholder = document.createElement('div');
    placeholder.className = 'card-placeholder';
    placeholder.style.height = rect.height + 'px';
    card.parentNode.insertBefore(placeholder, card);

    drag = {
        card,
        placeholder,
        pointerId: event.pointerId,
        offsetX: event.clientX - rect.left,
        offsetY: event.clientY - rect.top,
        moved: false,
    };

    card.classList.add('dragging');
    card.style.width = rect.width + 'px';
    card.style.height = rect.height + 'px';
    card.style.left = rect.left + 'px';
    card.style.top = rect.top + 'px';
    document.body.classList.add('reordering');
    handle.setPointerCapture(event.pointerId);
});

$('deviceGrid').addEventListener('pointermove', (event) => {
    if (!drag || event.pointerId !== drag.pointerId) {
        return;
    }
    drag.moved = true;
    drag.card.style.left = (event.clientX - drag.offsetX) + 'px';
    drag.card.style.top = (event.clientY - drag.offsetY) + 'px';

    // The dragged card ignores pointer events while lifted, so this finds the
    // card underneath it.
    const under = document.elementFromPoint(event.clientX, event.clientY);
    const target = under && under.closest ? under.closest('.device-card') : null;
    if (!target || target === drag.card) {
        return;
    }

    const box = target.getBoundingClientRect();
    const after = event.clientX > box.left + box.width / 2;
    target.parentNode.insertBefore(drag.placeholder, after ? target.nextSibling : target);
});

function endDrag(event) {
    if (!drag || (event && event.pointerId !== drag.pointerId)) {
        return;
    }
    const { card, placeholder, moved } = drag;

    placeholder.parentNode.insertBefore(card, placeholder);
    placeholder.remove();
    card.classList.remove('dragging');
    card.style.width = '';
    card.style.height = '';
    card.style.left = '';
    card.style.top = '';
    document.body.classList.remove('reordering');
    drag = null;

    if (moved) {
        saveOrder();
    }
}

$('deviceGrid').addEventListener('pointerup', endDrag);
$('deviceGrid').addEventListener('pointercancel', endDrag);

async function saveOrder() {
    const ids = Array.from(document.querySelectorAll('.device-card'))
        .map((card) => parseInt(card.dataset.id, 10));

    // Keep the local list in step, so the next redraw does not undo the move.
    const byId = new Map(state.devices.map((device) => [device.id, device]));
    state.devices = ids.map((id) => byId.get(id)).filter(Boolean);

    try {
        await api('/api/devices/order', { method: 'PUT', body: { ids } });
    } catch (err) {
        toast(err.message, 'error');
        loadDevices();
    }
}

/* ---------------- Add / edit ---------------- */

// --- Sleep agent setup, inside the edit dialog ---

async function refreshAgentBlock(device) {
    const block = $('agentBlock');
    // Only meaningful for a saved device, since pairing needs its id.
    block.classList.toggle('visible', !!device);
    $('agentSteps').classList.remove('visible');
    if (!device) {
        return;
    }

    $('agentTargetName').textContent = device.name;

    let agents = [];
    try {
        agents = await api('/api/agents');
    } catch (err) {
        agents = [];
    }
    const agent = agents.find((a) => a.device_id === device.id);
    state.editingAgent = agent || null;

    const stateLabel = $('agentState');
    stateLabel.classList.toggle('on', !!(agent && agent.online));
    if (!agent) {
        stateLabel.textContent = 'Not set up';
        $('agentSetupButton').textContent = 'Set up';
        $('agentRemoveButton').style.display = 'none';
        return;
    }

    const warnings = [];
    if (agent.wake_armed === false) {
        warnings.push('nothing is allowed to wake it');
    }
    if (agent.fast_startup === true) {
        warnings.push('fast startup is on');
    }

    stateLabel.textContent = (agent.online ? 'Ready' : 'Installed, not reporting in') +
        (agent.hostname ? ' · ' + agent.hostname : '') +
        (agent.version ? ' · agent ' + agent.version : '') +
        (warnings.length ? ' · ' + warnings.join(', ') : '');
    $('agentSetupButton').textContent = 'Pair again';
    $('agentRemoveButton').style.display = '';
}

$('agentSetupButton').addEventListener('click', async (event) => {
    if (!state.editingId) {
        return;
    }
    const button = event.currentTarget;
    setLoading(button, true);
    try {
        const enrolment = await api(`/api/devices/${state.editingId}/enrol`, { method: 'POST' });
        $('agentCommand').textContent =
            `wol-agent.exe install --server ${location.origin} --code ${enrolment.code}`;
        $('agentSteps').classList.add('visible');
    } catch (err) {
        showError('deviceError', err.message);
    } finally {
        setLoading(button, false);
    }
});

$('agentRemoveButton').addEventListener('click', async () => {
    if (!state.editingAgent) {
        return;
    }
    const ok = await confirmDialog(
        'Remove the sleep agent for this computer? It will stop being able to sleep it.', 'Remove');
    if (!ok) {
        return;
    }
    try {
        await api('/api/agents/' + state.editingAgent.id, { method: 'DELETE' });
        toast('Agent removed', 'success');
        const device = state.devices.find((d) => d.id === state.editingId);
        await refreshAgentBlock(device);
        loadDevices();
    } catch (err) {
        showError('deviceError', err.message);
    }
});

function openDeviceModal(device) {
    state.editingId = device ? device.id : null;
    $('deviceModalTitle').textContent = device ? 'Edit computer' : 'Add a computer';
    $('deviceSaveButton').textContent = device ? 'Save changes' : 'Add computer';
    $('deviceName').value = device ? device.name : '';
    $('deviceMac').value = device ? device.mac : '';
    $('deviceIp').value = device ? device.ip : '';
    $('deviceNotes').value = device ? device.notes : '';
    $('deviceBroadcast').value = device ? device.broadcast : '';
    $('devicePort').value = device && device.port ? device.port : '';
    hideError('deviceError');
    openModal('deviceModal');
    refreshAgentBlock(device);
    setTimeout(() => $('deviceName').focus(), 50);
}

$('addButton').addEventListener('click', () => openDeviceModal(null));
$('emptyAddButton').addEventListener('click', () => openDeviceModal(null));

$('deviceForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('deviceError');

    const payload = {
        name: $('deviceName').value.trim(),
        mac: $('deviceMac').value.trim(),
        ip: $('deviceIp').value.trim(),
        notes: $('deviceNotes').value.trim(),
        broadcast: $('deviceBroadcast').value.trim(),
        port: parseInt($('devicePort').value, 10) || 0,
    };

    if (!payload.mac) {
        showError('deviceError', 'A MAC address is required. Use "Find computers" to look it up automatically.');
        return;
    }

    const button = $('deviceSaveButton');
    setLoading(button, true);
    try {
        if (state.editingId) {
            await api('/api/devices/' + state.editingId, { method: 'PUT', body: payload });
            toast('Changes saved', 'success');
        } else {
            await api('/api/devices', { method: 'POST', body: payload });
            toast('Computer added', 'success');
        }
        closeModal('deviceModal');
        loadDevices();
    } catch (err) {
        showError('deviceError', err.message);
    } finally {
        setLoading(button, false);
    }
});

/* ---------------- Network scan ---------------- */

$('scanButton').addEventListener('click', openScanModal);
$('emptyScanButton').addEventListener('click', openScanModal);

async function openScanModal() {
    hideError('scanError');
    state.scanSelection.clear();
    state.scanResults = [];
    $('scanResults').textContent = '';
    $('scanEmpty').classList.add('visible');
    $('scanProgress').classList.remove('visible');
    updateSelectionNote();
    openModal('scanModal');

    try {
        const data = await api('/api/networks');
        const select = $('scanNetwork');
        select.textContent = '';

        if (!data.networks || data.networks.length === 0) {
            const option = document.createElement('option');
            option.textContent = 'No network detected';
            option.value = '';
            select.appendChild(option);
            return;
        }

        data.networks.forEach((net) => {
            const option = document.createElement('option');
            option.value = net.cidr;
            option.textContent = net.scannable
                ? `${net.cidr} (${net.interface})`
                : `${net.cidr} (${net.interface}) — too large to scan`;
            option.disabled = !net.scannable;
            if (net.cidr === data.default) {
                option.selected = true;
            }
            select.appendChild(option);
        });
    } catch (err) {
        showError('scanError', err.message);
    }
}

$('startScanButton').addEventListener('click', async (event) => {
    const network = $('scanNetwork').value;
    if (!network) {
        showError('scanError', 'No network available to scan.');
        return;
    }

    hideError('scanError');
    state.scanSelection.clear();
    state.scanResults = [];
    $('scanResults').textContent = '';
    $('scanEmpty').classList.remove('visible');
    $('scanProgress').classList.add('visible');
    $('scanProgressBar').style.width = '0%';
    $('scanProgressText').textContent = 'Starting…';
    updateSelectionNote();

    const button = event.currentTarget;
    setLoading(button, true);
    try {
        await api('/api/scan', { method: 'POST', body: { network } });
        pollScan();
    } catch (err) {
        showError('scanError', err.message);
        $('scanProgress').classList.remove('visible');
    } finally {
        setLoading(button, false);
    }
});

function stopScanPolling() {
    if (state.scanTimer) {
        clearTimeout(state.scanTimer);
        state.scanTimer = null;
    }
}

async function pollScan() {
    stopScanPolling();
    let data;
    try {
        data = await api('/api/scan');
    } catch (err) {
        showError('scanError', err.message);
        $('scanProgress').classList.remove('visible');
        return;
    }

    const percent = data.total > 0 ? Math.round((data.done / data.total) * 100) : 0;
    $('scanProgressBar').style.width = percent + '%';

    if (data.running) {
        $('scanProgressText').textContent = `Checking address ${data.done} of ${data.total}…`;
        state.scanTimer = setTimeout(pollScan, 700);
        return;
    }

    const seconds = data.duration_ms ? (data.duration_ms / 1000).toFixed(1) : '0';
    const count = (data.results || []).length;
    $('scanProgressText').textContent = count === 0
        ? `Scan finished in ${seconds}s — nothing responded.`
        : `Found ${count} device${count === 1 ? '' : 's'} in ${seconds}s.`;

    if (data.error) {
        showError('scanError', data.error);
    }
    state.scanResults = data.results || [];
    renderScanResults();
}

function renderScanResults() {
    const container = $('scanResults');
    container.textContent = '';

    if (state.scanResults.length === 0) {
        $('scanEmpty').classList.add('visible');
        updateSelectionNote();
        return;
    }
    $('scanEmpty').classList.remove('visible');

    state.scanResults.forEach((result, index) => {
        const row = document.createElement('label');
        row.className = 'scan-row' + (result.known ? ' known' : '');
        row.innerHTML = `
            <input type="checkbox">
            <div class="scan-info">
                <div class="scan-name"></div>
                <div class="scan-sub"></div>
            </div>`;

        const checkbox = row.querySelector('input');
        checkbox.checked = state.scanSelection.has(index);
        checkbox.disabled = !!result.known;

        row.querySelector('.scan-name').textContent =
            result.known ? (result.known_name || result.hostname || result.ip)
                         : (result.hostname || result.vendor || result.ip);

        const parts = [result.ip, result.mac];
        if (result.vendor && result.hostname) {
            parts.push(result.vendor);
        }
        row.querySelector('.scan-sub').textContent = parts.filter(Boolean).join('  ·  ');

        if (result.known) {
            const badge = document.createElement('span');
            badge.className = 'badge added';
            badge.textContent = 'Already added';
            row.appendChild(badge);
        }

        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                state.scanSelection.add(index);
            } else {
                state.scanSelection.delete(index);
            }
            row.classList.toggle('selected', checkbox.checked);
            updateSelectionNote();
        });

        row.classList.toggle('selected', checkbox.checked);
        container.appendChild(row);
    });

    updateSelectionNote();
}

function updateSelectionNote() {
    const count = state.scanSelection.size;
    $('addSelectedButton').disabled = count === 0;
    $('scanSelectionNote').textContent = count === 0 ? '' : `${count} selected`;
}

$('addSelectedButton').addEventListener('click', async (event) => {
    const chosen = Array.from(state.scanSelection).map((index) => {
        const result = state.scanResults[index];
        return {
            name: result.hostname || result.vendor || result.ip,
            mac: result.mac,
            ip: result.ip,
            // Kept alongside the name, so renaming the entry does not lose
            // what the machine calls itself.
            hostname: result.hostname || '',
            notes: '',
            broadcast: '',
            port: 9,
        };
    });
    if (chosen.length === 0) {
        return;
    }

    const button = event.currentTarget;
    setLoading(button, true);
    try {
        const result = await api('/api/devices/bulk', { method: 'POST', body: { devices: chosen } });
        const noun = result.added === 1 ? 'computer' : 'computers';
        toast(`Added ${result.added} ${noun}`, 'success');
        closeModal('scanModal');
        loadDevices();
    } catch (err) {
        showError('scanError', err.message);
    } finally {
        setLoading(button, false);
    }
});

/* ---------------- Password change from the panel ---------------- */

$('passwordButton').addEventListener('click', () => {
    $('modalNewPassword').value = '';
    $('modalConfirmPassword').value = '';
    hideError('passwordError');
    openModal('passwordModal');
});

$('passwordForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    hideError('passwordError');

    const password = $('modalNewPassword').value;
    const problem = passwordProblem(password, $('modalConfirmPassword').value);
    if (problem) {
        showError('passwordError', problem);
        return;
    }

    try {
        const data = await api('/api/password', { method: 'POST', body: { new_password: password } });
        state.token = data.token;
        localStorage.setItem('token', data.token);
        closeModal('passwordModal');
        toast('Password changed', 'success');
    } catch (err) {
        showError('passwordError', err.message);
    }
});

/* ---------------- History & statistics ---------------- */

const insights = { range: 'day', selectedDevice: null };

$('insightsButton').addEventListener('click', async () => {
    openModal('insightsModal');
    await loadInsights();
    await loadWakes();
});

$('rangeButtons').addEventListener('click', (event) => {
    const button = event.target.closest('.range-btn');
    if (!button) {
        return;
    }
    document.querySelectorAll('.range-btn').forEach((b) => b.classList.remove('active'));
    button.classList.add('active');
    insights.range = button.dataset.range;
    loadInsights();
});

function formatDuration(seconds) {
    if (seconds < 90) {
        return Math.round(seconds) + 's';
    }
    if (seconds < 5400) {
        return Math.round(seconds / 60) + ' min';
    }
    if (seconds < 172800) {
        const h = seconds / 3600;
        return (h < 10 ? h.toFixed(1) : Math.round(h)) + ' h';
    }
    return (seconds / 86400).toFixed(1) + ' days';
}

function formatAxisTime(unix, spanSeconds) {
    const d = new Date(unix * 1000);
    if (spanSeconds <= 90000) {
        return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
    }
    return (d.getMonth() + 1) + '/' + d.getDate();
}

async function loadInsights() {
    let data;
    try {
        data = await api('/api/history?range=' + insights.range);
    } catch (err) {
        toast(err.message, 'error');
        return;
    }

    const devices = data.devices || [];
    const span = data.to - data.from;

    // ----- summary tiles -----
    const tiles = $('statTiles');
    tiles.textContent = '';
    const totalWakes = devices.reduce((sum, d) => sum + d.wake_count, 0);
    const tracked = devices.filter((d) => d.intervals.length > 0);
    const onNow = state.devices.filter((d) => state.statuses[d.id] && state.statuses[d.id].online).length;

    let busiest = null;
    for (const d of tracked) {
        if (!busiest || d.online_pct > busiest.online_pct) {
            busiest = d;
        }
    }
    const avgOn = tracked.length
        ? tracked.reduce((sum, d) => sum + d.online_pct, 0) / tracked.length
        : 0;
    const longest = tracked.reduce((best, d) => (d.longest_on > best ? d.longest_on : best), 0);

    const tileData = [
        { value: onNow + ' / ' + state.devices.length, label: 'on right now' },
        { value: avgOn.toFixed(0) + '%', label: 'average time on' },
        { value: totalWakes, label: 'wake-ups in this period' },
        { value: longest ? formatDuration(longest) : '—', label: 'longest stretch on' },
        { value: busiest ? busiest.name : '—', label: 'most used computer' },
    ];
    for (const t of tileData) {
        const el = document.createElement('div');
        el.className = 'stat-tile';
        el.innerHTML = '<div class="stat-value"></div><div class="stat-label"></div>';
        el.querySelector('.stat-value').textContent = t.value;
        el.querySelector('.stat-label').textContent = t.label;
        tiles.appendChild(el);
    }

    // ----- per-device timelines -----
    const container = $('timelines');
    container.textContent = '';
    const anyHistory = tracked.length > 0;
    $('insightsEmpty').classList.toggle('visible', !anyHistory);

    devices.forEach((d) => {
        const row = document.createElement('div');
        row.className = 'timeline-row';
        row.dataset.id = d.id;
        row.innerHTML = `
            <div class="tl-head">
                <span class="tl-name"></span>
                <span class="tl-stats"></span>
            </div>
            <div class="tl-track"></div>
            <div class="tl-axis"><span></span><span></span></div>`;

        row.querySelector('.tl-name').textContent = d.name;
        const stats = row.querySelector('.tl-stats');
        stats.innerHTML = 'on <strong></strong> · ' + d.wake_count + ' wake-up' + (d.wake_count === 1 ? '' : 's');
        stats.querySelector('strong').textContent = d.online_pct.toFixed(0) + '%';

        const track = row.querySelector('.tl-track');
        d.intervals.forEach((iv) => {
            const rect = document.createElement('span');
            rect.className = 'tl-rect ' + iv.state;
            const left = ((iv.from - data.from) / span) * 100;
            const width = ((iv.to - iv.from) / span) * 100;
            rect.style.left = left + '%';
            rect.style.width = Math.max(width, 0.15) + '%';
            const mins = Math.round((iv.to - iv.from) / 60);
            rect.title = `${iv.state} for ${formatDuration(mins * 60)} — ` +
                new Date(iv.from * 1000).toLocaleString();
            track.appendChild(rect);
        });

        const axes = row.querySelectorAll('.tl-axis span');
        axes[0].textContent = formatAxisTime(data.from, span);
        axes[1].textContent = 'now';

        row.addEventListener('click', () => selectHeatmapDevice(d.id, d.name));
        container.appendChild(row);
    });

    // Keep or initialise the heatmap selection.
    const stillThere = devices.find((d) => d.id === insights.selectedDevice);
    const pick = stillThere || devices[0];
    if (pick) {
        selectHeatmapDevice(pick.id, pick.name);
    }
}

async function selectHeatmapDevice(id, name) {
    insights.selectedDevice = id;
    document.querySelectorAll('.timeline-row').forEach((row) => {
        row.classList.toggle('selected', row.dataset.id === String(id));
    });
    $('heatmapTitle').textContent = 'Usage pattern — ' + name;

    let data;
    try {
        data = await api(`/api/history/${id}/heatmap`);
    } catch (err) {
        return;
    }

    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const grid = document.createElement('div');
    grid.className = 'heatmap-grid';

    // Header row: hour labels every three hours.
    grid.appendChild(document.createElement('span'));
    for (let hour = 0; hour < 24; hour++) {
        const label = document.createElement('span');
        label.className = 'hm-hour';
        label.textContent = hour % 3 === 0 ? hour : '';
        grid.appendChild(label);
    }

    // Monday-first reads more naturally than Sunday-first.
    for (const day of [1, 2, 3, 4, 5, 6, 0]) {
        const label = document.createElement('span');
        label.className = 'hm-label';
        label.textContent = dayNames[day];
        grid.appendChild(label);
        for (let hour = 0; hour < 24; hour++) {
            const cell = document.createElement('span');
            cell.className = 'hm-cell';
            const fraction = data.days[day][hour];
            cell.style.opacity = fraction === 0 ? 0.06 : (0.15 + fraction * 0.85);
            cell.title = `${dayNames[day]} ${hour}:00 — on ${(fraction * 100).toFixed(0)}% of the time`;
            grid.appendChild(cell);
        }
    }

    const host = $('heatmap');
    host.textContent = '';
    host.appendChild(grid);
}

async function loadWakes() {
    let events;
    try {
        events = await api('/api/wakes');
    } catch (err) {
        return;
    }
    const list = $('wakeList');
    list.textContent = '';
    if (events.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'No wake-ups recorded yet.';
        list.appendChild(empty);
        return;
    }
    events.forEach((event) => {
        const row = document.createElement('div');
        row.className = 'wake-row';
        row.innerHTML = '<svg class="icon"><use href="#i-bolt"/></svg><span class="wake-device"></span>' +
            '<span class="wake-who"></span><span class="wake-time"></span>';
        row.querySelector('.wake-device').textContent = event.device;
        row.querySelector('.wake-who').textContent = 'by ' + event.actor;
        row.querySelector('.wake-time').textContent = relativeTime(event.at);
        list.appendChild(row);
    });
}

/* ---------------- People (remote access) ---------------- */

$('peopleButton').addEventListener('click', openPeopleModal);

async function openPeopleModal() {
    hideError('peopleError');
    $('newPersonEmail').value = '';
    openModal('peopleModal');
    await loadCFSettings();
    await loadPeople();
}

// loadCFSettings shows how Cloudflare identities are configured, and what the
// server has actually received - which is what makes a misconfigured tunnel
// obvious instead of mysterious.
async function loadCFSettings() {
    hideError('cfError');
    let data;
    try {
        data = await api('/api/cf-settings');
    } catch (err) {
        return;
    }

    $('cfTrustInput').value = data.cf_trust || '';
    $('cfTrustInput').disabled = !!data.locked;
    $('cfSaveButton').disabled = !!data.locked;

    const badge = $('cfStatusBadge');
    badge.textContent = data.enabled ? 'on' : 'off';
    badge.className = 'badge ' + (data.enabled ? 'on' : 'off');

    // An unconfigured setup is the common case, so open the panel for it.
    if (!data.enabled) {
        $('cfSetup').open = true;
    }

    const list = $('cfSightings');
    list.textContent = '';

    if (!data.sightings || data.sightings.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'hint';
        empty.textContent = 'Nothing seen yet. Open the page through your tunnel, then look here again.';
        list.appendChild(empty);
        return;
    }

    data.sightings.forEach((s) => {
        const row = document.createElement('div');
        row.className = 'diag-row';
        row.innerHTML = '<span class="diag-dot"></span><span class="diag-peer"></span>' +
            '<span class="diag-note"></span><span class="diag-when"></span>';

        const viaCloudflare = (s.cf_headers || []).length > 0;
        let note;
        let kind = '';
        if (s.email) {
            note = 'signed in as ' + s.email;
            kind = 'good';
        } else if (s.header_found && !s.trusted) {
            note = data.enabled
                ? 'sent an identity, but this address is not trusted — add it above'
                : 'sent an identity, but Cloudflare identities are switched off';
            kind = 'bad';
        } else if (s.header_found) {
            note = 'sent an identity that could not be read';
            kind = 'bad';
        } else if (viaCloudflare) {
            // Came through Cloudflare, but Access added no identity.
            note = 'came through Cloudflare (' + s.cf_headers.join(', ') +
                ') but with no identity — Access is not enforcing on ' + (s.host || 'this hostname');
            kind = 'bad';
        } else {
            note = 'did not come through Cloudflare at all — a direct or local visitor';
        }

        row.querySelector('.diag-dot').className = 'diag-dot ' + kind;
        row.querySelector('.diag-peer').textContent = s.peer;
        row.querySelector('.diag-note').textContent = note;
        row.querySelector('.diag-when').textContent = relativeTime(s.at);

        // An identity did arrive from this address but is being ignored. That
        // is one click away from working, so offer the click rather than
        // asking the reader to retype an address.
        if (s.header_found && !s.trusted && !data.locked) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'btn btn-secondary btn-trust';
            button.textContent = 'Trust this';
            button.addEventListener('click', () => trustAddress(s.peer, button));
            row.appendChild(button);
        }

        list.appendChild(row);
    });
}

// trustAddress adds one address to the trust list and saves it.
async function trustAddress(peer, button) {
    // Loopback is written as "localhost", which covers both the IPv4 and IPv6
    // forms - a tunnel can arrive as either, and trusting only the one seen
    // today would break the first time it uses the other.
    const addition = (peer === '127.0.0.1' || peer === '::1') ? 'localhost' : peer;

    const current = $('cfTrustInput').value.trim();
    const parts = current ? current.split(',').map((s) => s.trim()).filter(Boolean) : [];
    if (!parts.includes(addition)) {
        parts.push(addition);
    }

    hideError('cfError');
    setLoading(button, true);
    try {
        await api('/api/cf-settings', { method: 'PUT', body: { cf_trust: parts.join(',') } });
        toast('Now trusting ' + addition, 'success');
        await loadCFSettings();
        await loadPeople();
    } catch (err) {
        showError('cfError', err.message);
        setLoading(button, false);
    }
}

$('cfSaveButton').addEventListener('click', async (event) => {
    hideError('cfError');
    const button = event.currentTarget;
    setLoading(button, true);
    try {
        const result = await api('/api/cf-settings', {
            method: 'PUT',
            body: { cf_trust: $('cfTrustInput').value.trim() },
        });
        toast(result.enabled ? 'Cloudflare identities are on' : 'Cloudflare identities are off', 'success');
        await loadCFSettings();
    } catch (err) {
        showError('cfError', err.message);
    } finally {
        setLoading(button, false);
    }
});

async function loadPeople() {
    try {
        state.people = await api('/api/users');
        // The checkbox list needs the full device list, which the admin has.
        if (state.devices.length === 0) {
            state.devices = await api('/api/devices');
        }
        renderPeople();
    } catch (err) {
        showError('peopleError', err.message);
    }
}

function renderPeople() {
    const container = $('peopleList');
    container.textContent = '';

    $('peopleEmpty').classList.toggle('visible', state.people.length === 0);

    state.people.forEach((person) => {
        const row = document.createElement('div');
        row.className = 'person';
        row.innerHTML = `
            <div class="person-head">
                <div class="person-info">
                    <div class="person-email"></div>
                    <div class="person-sub"></div>
                </div>
                <span class="badge"></span>
            </div>
            <div class="person-body">
                <div class="person-devices"></div>
                <div class="person-actions">
                    <button type="button" class="btn btn-ghost btn-danger-text" data-action="remove">Remove person</button>
                    <button type="button" class="btn btn-primary" data-action="save">Save access</button>
                </div>
            </div>`;

        row.querySelector('.person-email').textContent = person.email;
        row.querySelector('.person-sub').textContent = describePerson(person);
        row.querySelector('.badge').textContent =
            person.device_ids.length === 0
                ? 'no access'
                : `${person.device_ids.length} of ${state.devices.length}`;

        const list = row.querySelector('.person-devices');
        if (state.devices.length === 0) {
            const note = document.createElement('p');
            note.className = 'hint';
            note.textContent = 'Add some computers first, then you can share them.';
            list.appendChild(note);
        }
        state.devices.forEach((device) => {
            const label = document.createElement('label');
            label.className = 'person-device';
            label.innerHTML = '<input type="checkbox"><span></span>';
            const box = label.querySelector('input');
            box.checked = person.device_ids.includes(device.id);
            box.dataset.deviceId = device.id;
            label.querySelector('span').textContent = device.name;
            list.appendChild(label);
        });

        row.querySelector('.person-head').addEventListener('click', () => {
            row.classList.toggle('open');
        });

        row.querySelector('[data-action="save"]').addEventListener('click', async (event) => {
            const ids = Array.from(list.querySelectorAll('input:checked'))
                .map((box) => parseInt(box.dataset.deviceId, 10));
            const button = event.currentTarget;
            setLoading(button, true);
            try {
                await api(`/api/users/${person.id}/devices`, {
                    method: 'PUT',
                    body: { device_ids: ids },
                });
                toast(`Access updated for ${person.email}`, 'success');
                await loadPeople();
            } catch (err) {
                showError('peopleError', err.message);
            } finally {
                setLoading(button, false);
            }
        });

        row.querySelector('[data-action="remove"]').addEventListener('click', async () => {
            const ok = await confirmDialog(
                `Remove ${person.email}? They will lose access to every computer.`, 'Remove');
            if (!ok) {
                return;
            }
            try {
                await api('/api/users/' + person.id, { method: 'DELETE' });
                toast('Person removed', 'success');
                await loadPeople();
            } catch (err) {
                showError('peopleError', err.message);
            }
        });

        container.appendChild(row);
    });
}

function describePerson(person) {
    if (!person.last_seen) {
        return 'Added by you · has not connected yet';
    }
    return 'Last seen ' + relativeTime(person.last_seen);
}

$('addPersonButton').addEventListener('click', async (event) => {
    const email = $('newPersonEmail').value.trim();
    if (!email) {
        showError('peopleError', 'Enter an email address first.');
        return;
    }
    hideError('peopleError');

    const button = event.currentTarget;
    setLoading(button, true);
    try {
        await api('/api/users', { method: 'POST', body: { email } });
        $('newPersonEmail').value = '';
        toast('Person added', 'success');
        await loadPeople();
    } catch (err) {
        showError('peopleError', err.message);
    } finally {
        setLoading(button, false);
    }
});

/* ---------------- Help, sign out ---------------- */

$('helpButton').addEventListener('click', () => openModal('helpModal'));

$('logoutButton').addEventListener('click', async () => {
    const ok = await confirmDialog('Sign out of the control panel?', 'Sign out');
    if (ok) {
        signOut();
    }
});

/* ---------------- Modal plumbing ---------------- */

let lastFocused = null;

function openModal(id) {
    lastFocused = document.activeElement;
    $(id).classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closeModal(id) {
    $(id).classList.remove('open');
    if (!document.querySelector('.modal-backdrop.open')) {
        document.body.style.overflow = '';
    }
    if (id === 'scanModal') {
        stopScanPolling();
    }
    if (lastFocused && lastFocused.focus) {
        lastFocused.focus();
    }
}

function closeAllModals() {
    document.querySelectorAll('.modal-backdrop.open').forEach((el) => el.classList.remove('open'));
    document.body.style.overflow = '';
    stopScanPolling();
}

document.querySelectorAll('.modal-backdrop').forEach((backdrop) => {
    backdrop.addEventListener('click', (event) => {
        // Clicking the dimmed area closes; clicking inside the dialog does not.
        if (event.target !== backdrop) {
            return;
        }
        if (backdrop.id === 'confirmModal') {
            // Must go through resolveConfirm, or whoever is awaiting the
            // dialog would wait forever.
            resolveConfirm(false);
        } else {
            closeModal(backdrop.id);
        }
    });
});

document.querySelectorAll('.modal-close').forEach((button) => {
    button.addEventListener('click', () => {
        const backdrop = button.closest('.modal-backdrop');
        closeModal(backdrop.id);
    });
});

document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') {
        return;
    }
    const open = document.querySelector('.modal-backdrop.open');
    if (open) {
        if (open.id === 'confirmModal') {
            resolveConfirm(false);
        } else {
            closeModal(open.id);
        }
    }
});

/* ---------------- Confirm dialog ---------------- */

let confirmResolver = null;

function confirmDialog(message, okLabel) {
    $('confirmMessage').textContent = message;
    $('confirmOk').textContent = okLabel || 'Confirm';
    openModal('confirmModal');
    setTimeout(() => $('confirmOk').focus(), 50);
    return new Promise((resolve) => {
        confirmResolver = resolve;
    });
}

function resolveConfirm(value) {
    closeModal('confirmModal');
    if (confirmResolver) {
        confirmResolver(value);
        confirmResolver = null;
    }
}

$('confirmOk').addEventListener('click', () => resolveConfirm(true));
$('confirmCancel').addEventListener('click', () => resolveConfirm(false));

/* ---------------- Start ---------------- */

$('signInButton').addEventListener('click', showLogin);

$('backToListButton').addEventListener('click', () => {
    hideError('loginError');
    showView('main');
    if (state.devices.length === 0) {
        loadDevices();
    }
});

async function init() {
    // Whether anonymous waking is offered is the server's decision.
    try {
        const config = await api('/api/config');
        state.publicWake = !!config.public_wake;
        if (config.build) {
            // Shown in the help dialog, so "am I running the new version?"
            // can be answered from the phone that is showing the problem.
            $('buildStamp').textContent = 'Interface build ' + config.build;
        }
    } catch (err) {
        state.publicWake = false;
    }

    await refreshIdentity();
    // A Cloudflare visitor always has a list of their own, even when
    // anonymous waking is switched off.
    if (state.identity.kind === 'cloudflare') {
        state.publicWake = true;
    }

    if (state.token) {
        setSignedIn(true);
        showView('main');
        loadDevices();
        startStatusPolling();
        return;
    }

    setSignedIn(false);
    if (state.publicWake) {
        showView('main');
        loadDevices();
        startStatusPolling();
    } else {
        showLogin();
    }
}

init();
