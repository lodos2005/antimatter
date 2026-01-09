const API_BASE = window.location.origin;

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
}

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();

    document.getElementById('admin-login-btn').addEventListener('click', login);
    document.getElementById('admin-password').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });
    document.getElementById('captcha-answer').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });

    // Setup Filters
    document.getElementById('filter-model').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') loadAllSessions(1);
    });
    document.getElementById('filter-ip').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') loadAllSessions(1);
    });
});

async function checkAuth() {
    try {
        const res = await fetch(`${API_BASE}/api/admin/stats`);
        if (res.ok) {
            showDashboard();
            loadStats();
            loadModels();
            loadRecentLogs();
            loadAccounts(); // Load accounts on initial load
        }
    } catch (e) {
        console.log('Not authenticated');
    }
}

async function login() {
    const password = document.getElementById('admin-password').value;
    const msg = document.getElementById('login-msg');

    const captchaId = document.getElementById('captcha-id').value;
    const captchaAnswer = document.getElementById('captcha-answer').value;

    const payload = { password };
    if (captchaId) {
        payload.captcha_id = captchaId;
        payload.captcha_answer = captchaAnswer;
    }

    try {
        const res = await fetch(`${API_BASE}/api/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (res.ok) {
            showDashboard();
            loadStats();
            loadRecentLogs();
        } else {
            msg.textContent = data.error || 'Login failed';

            if (data.captcha_required) {
                document.getElementById('captcha-group').style.display = 'block';
                loadCaptcha();
                if (data.error === "Invalid password" || data.error === "Invalid Captcha") {
                    document.getElementById('captcha-answer').value = '';
                }
            }
        }
    } catch (e) {
        msg.textContent = 'Connection error';
    }
}

async function loadCaptcha() {
    try {
        const res = await fetch(`${API_BASE}/api/admin/captcha`);
        const data = await res.json();
        if (data.id) {
            document.getElementById('captcha-id').value = data.id;
            document.getElementById('captcha-image').src = `${API_BASE}/api/admin/captcha/image/${data.id}`;
        }
    } catch (e) {
        console.error("Failed to fetch captcha", e);
    }
}

function showDashboard() {
    document.getElementById('login-overlay').style.display = 'none';
    document.getElementById('admin-dashboard').style.display = 'flex'; // flex for sidebar layout
}

function switchView(viewName) {
    document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.view === viewName);
    });

    document.querySelectorAll('.view-section').forEach(el => {
        el.style.display = 'none';
        el.classList.remove('active');
    });

    const activeView = document.getElementById(`view-${viewName}`);
    activeView.style.display = 'block';
    setTimeout(() => activeView.classList.add('active'), 10);

    if (viewName === 'sessions') {
        loadAllSessions(1);
    } else if (viewName === 'settings') {
        loadSettings();
    } else if (viewName === 'keys') {
        loadKeys();
    } else {
        loadRecentLogs();
        loadAccounts(); // Load accounts on dashboard
    }
}

async function loadStats() {
    try {
        const res = await fetch(`${API_BASE}/api/admin/stats`);
        const stats = await res.json();

        const grid = document.getElementById('stats-grid');
        grid.innerHTML = `
            <div class="stat-card">
                <div class="stat-value">${stats.total_requests}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${formatNumber(stats.total_tokens)}</div>
                <div class="stat-label">Total Tokens</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.requests_last_24h}</div>
                <div class="stat-label">24h Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${formatNumber(stats.total_prompt)}</div>
                <div class="stat-label">Prompt Tokens</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${formatNumber(stats.total_completion)}</div>
                <div class="stat-label">Completion Tokens</div>
            </div>
        `;
    } catch (e) {
        console.error("Failed to load stats", e);
    }
}

async function loadModels() {
    try {
        const res = await fetch(`${API_BASE}/v1/models`);
        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }
        const data = await res.json();

        const container = document.getElementById('models-list-container');
        if (data.data && Array.isArray(data.data) && data.data.length > 0) {
            container.innerHTML = data.data.map(m => `
                <span style="
                    background: rgba(59, 130, 246, 0.1); 
                    color: #60a5fa; 
                    border: 1px solid rgba(59, 130, 246, 0.2); 
                    padding: 8px 12px; 
                    border-radius: 8px; 
                    font-size: 0.9em; 
                    font-family: monospace;">
                    ${m.id}
                </span>
            `).join('');
        } else {
            container.innerHTML = '<span style="color: #888;">No available models. Add a Google Account in Settings.</span>';
        }
    } catch (e) {
        console.error("Failed to load models", e);
        const container = document.getElementById('models-list-container');
        if (container) {
            container.innerHTML = `<span style="color: #fca5a5;">Failed to load models: ${e.message}</span>`;
        }
    }
}


async function loadRecentLogs() {
    try {
        const res = await fetch(`${API_BASE}/api/admin/logs?limit=10`);
        const data = await res.json();
        const container = document.getElementById('recent-logs-container');
        renderSessionList(container, data.data);
    } catch (e) {
        console.error("Failed to load logs", e);
    }
}

async function loadAllSessions(page) {
    const model = document.getElementById('filter-model').value;
    const ip = document.getElementById('filter-ip').value;

    const params = new URLSearchParams({
        page: page,
        limit: 10,
        model: model,
        ip: ip
    });

    const container = document.getElementById('all-sessions-container');
    container.innerHTML = '<p style="color: #888; text-align: center; padding: 20px;">Loading...</p>';

    try {
        const res = await fetch(`${API_BASE}/api/admin/sessions?${params.toString()}`);
        const result = await res.json();

        renderSessionList(container, result.data);
        renderPagination(result.pagination);
    } catch (e) {
        container.innerHTML = '<p style="color: #ef4444; text-align: center; padding: 20px;">Failed to load sessions.</p>';
        console.error(e);
    }
}

function renderSessionList(container, logs) {
    if (!logs || logs.length === 0) {
        container.innerHTML = '<p style="text-align:center; color:#666;">No sessions found.</p>';
        return;
    }

    // For /sessions endpoint, data is already grouped by backend
    // For /logs endpoint, we need to group by session_id
    // Detect which one we have by checking if we have multiple logs with same session_id

    const normalizedSessions = [];
    const sessionMap = {};

    logs.forEach(log => {
        const sid = log.session_id || `legacy-${log.id}`;
        if (!sessionMap[sid]) {
            sessionMap[sid] = {
                id: sid,
                model: log.model,
                user: log.user_id,
                startTime: log.timestamp,
                logs: [],
                tokenCount: log.total_tokens || 0
            };
            normalizedSessions.push(sessionMap[sid]);
        }
        // Always add to logs array
        sessionMap[sid].logs.push(log);
    });

    container.innerHTML = normalizedSessions.map(s => {
        const dateStr = new Date(s.startTime).toLocaleString();
        const safeId = CSS.escape(s.id); // Escape ID for CSS selector safety

        // Count unique models in this session
        const uniqueModels = [...new Set(s.logs.map(log => log.model))];
        const modelDisplay = uniqueModels.length === 1
            ? uniqueModels[0]
            : `${uniqueModels.length} models`;

        return `
        <div class="session-card" data-sid="${s.id}">
            <div class="session-header" data-session-id="${s.id}">
                <div class="session-info">
                    <span class="session-id">${s.id.substring(0, 12)}...</span>
                    <div class="session-meta">
                        <div><strong>User:</strong> ${s.user}</div>
                        <div style="font-size: 0.85em; color: #888;">${dateStr}</div>
                    </div>
                </div>
                <div class="session-info">
                    <span class="status-badge status-200">${modelDisplay}</span>
                    <span class="interaction-count" style="color: #666; font-size: 0.9em;">
                        ${s.logs.length > 0 ? s.logs.length + ' interactions' : 'Click to load'}
                    </span>
                    <span class="arrow-icon" style="font-size: 1.2em; margin-left: 10px;">›</span>
                </div>
            </div>
            <div class="session-details" data-session-id="${s.id}">
                ${s.logs.length > 0 ? renderLogs(s.logs) : '<p style="padding:20px; text-align:center; color:#666;">Loading details...</p>'}
            </div>
        </div>
       `;
    }).join('');

    // Add click event listeners to all session headers
    const headers = container.querySelectorAll('.session-header');
    console.log('Attaching click listeners to', headers.length, 'session headers');
    headers.forEach(header => {
        header.style.cursor = 'pointer'; // Make it visually clickable
        header.addEventListener('click', function (e) {
            const sid = this.getAttribute('data-session-id');
            console.log('Clicked session:', sid);
            toggleSession(sid, this);
            e.stopPropagation();
        });
    });
}

function renderLogs(logs) {
    if (!logs || logs.length === 0) return '';
    const sorted = [...logs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    return sorted.map(log => `
        <div class="chat-pair">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">
                <span class="status-badge status-200" style="font-size: 0.75em;">${log.model || 'unknown'}</span>
                <span style="font-size: 0.8em; color: #666;">
                    ${log.prompt_tokens || 0}p / ${log.completion_tokens || 0}c tokens • ${log.latency_ms || 0}ms
                </span>
            </div>
            <div class="message-row">
                <div class="role-label role-user">User</div>
                <div class="message-content">${escapeHtml(log.prompt || '(No prompt)')}</div>
            </div>
            <div class="message-row">
                <div class="role-label role-model">Model</div>
                <div class="message-content markdown-body" style="background: rgba(255, 255, 255, 0.03); padding: 12px; border-radius: 8px; font-size: 0.95em; line-height: 1.5; color: #eee;">
                    ${marked.parse(log.response || '(No response captured)')}
                </div>
            </div>
        </div>
    `).join('');
}

async function toggleSession(sid, header) {
    console.log('toggleSession called with sid:', sid);

    // Use data attribute selector instead of ID to avoid issues with special characters
    const card = header.closest('.session-card');
    const details = card ? card.querySelector('.session-details') : null;

    console.log('Found details element:', details);

    if (!details) {
        console.error('Details element not found for sid:', sid);
        return;
    }

    const isOpen = details.classList.contains('open');

    // If opening and only has placeholder, load full session
    if (!isOpen && (details.innerHTML.includes('Click to load') || details.innerHTML.includes('Loading'))) {
        try {
            details.innerHTML = '<p style="padding:20px; text-align:center; color:#666;">Loading...</p>';
            const res = await fetch(`${API_BASE}/api/admin/session/${encodeURIComponent(sid)}`);
            const data = await res.json();
            if (data.logs && data.logs.length > 0) {
                details.innerHTML = renderLogs(data.logs);
                const countEl = header.querySelector('.interaction-count');
                if (countEl) countEl.textContent = `${data.logs.length} interactions`;
            } else {
                details.innerHTML = '<p style="padding:20px; text-align:center; color:#666;">No interactions found.</p>';
            }
        } catch (e) {
            console.error('Failed to load session details:', e);
            details.innerHTML = '<p style="padding:20px; text-align:center; color:#f44;">Failed to load details.</p>';
        }
    }

    details.classList.toggle('open');
    const arrow = header.querySelector('.arrow-icon');
    if (arrow) {
        arrow.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(90deg)';
    }
}

function renderPagination(p) {
    const container = document.getElementById('pagination-controls');
    if (p.total_pages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = `
        <button class="page-btn" ${p.page === 1 ? 'disabled' : ''} onclick="loadAllSessions(${p.page - 1})">Previous</button>
        <span class="page-info">Page ${p.page} of ${p.total_pages}</span>
        <button class="page-btn" ${p.page === p.total_pages ? 'disabled' : ''} onclick="loadAllSessions(${p.page + 1})">Next</button>
    `;
    container.innerHTML = html;
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

async function logout() {
    try {
        await fetch(`${API_BASE}/api/admin/logout`, {
            method: 'POST',
            headers: {
                'X-CSRF-Token': getCookie('csrf_token')
            }
        });
        document.cookie = "admin_session=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;";
        document.cookie = "csrf_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;";
        location.reload();
    } catch (e) {
        console.error("Logout failed", e);
        location.reload();
    }
}

async function loadSettings() {
    try {
        const res = await fetch(`${API_BASE}/api/admin/config`);
        if (!res.ok) throw new Error("Failed to load settings");
        const cfg = await res.json();

        // Populate fields
        document.getElementById('set-port').value = cfg.server.port;
        document.getElementById('set-webui-port').value = cfg.server.webui_port || 8046;
        document.getElementById('set-host').value = cfg.server.host;

        document.getElementById('set-auth-mode').value = cfg.proxy.auth_mode;
        document.getElementById('set-fallback-model').value = cfg.models.fallback_model;
        document.getElementById('set-strategy').value = cfg.strategy.type;
        document.getElementById('set-session-limit').value = (cfg.session && cfg.session.webui_request_limit) ? cfg.session.webui_request_limit : 0;
        document.getElementById('set-token-limit').value = (cfg.session && cfg.session.webui_token_limit) ? cfg.session.webui_token_limit : 0;

        document.getElementById('set-debug').checked = cfg.proxy.debug;

        document.getElementById('set-admin-enabled').checked = cfg.admin.enabled;
        document.getElementById('set-admin-pass').value = ""; // Don't show current password

        loadAccounts(); // Load accounts when settings view is loaded
    } catch (e) {
        console.error(e);
        alert("Failed to load settings: " + e.message);
    }
}

async function saveSettings() {
    const payload = {
        server: {
            port: parseInt(document.getElementById('set-port').value) || 8045,
            webui_port: parseInt(document.getElementById('set-webui-port').value) || 8046,
            host: document.getElementById('set-host').value
        },
        proxy: {
            auth_mode: document.getElementById('set-auth-mode').value,
            debug: document.getElementById('set-debug').checked
        },
        models: {
            fallback_model: document.getElementById('set-fallback-model').value
        },
        strategy: {
            type: document.getElementById('set-strategy').value
        },
        session: {
            webui_request_limit: parseInt(document.getElementById('set-session-limit').value) || 0,
            webui_token_limit: parseInt(document.getElementById('set-token-limit').value) || 0
        },
        admin: {
            enabled: document.getElementById('set-admin-enabled').checked,
            password: document.getElementById('set-admin-pass').value
        }
    };

    // Remove password if empty (logic handled in backend too, but cleaner here if strict json bind)
    if (!payload.admin.password) delete payload.admin.password;

    const btn = document.querySelector('#view-settings .refresh-btn');
    const originalText = btn.textContent;
    btn.textContent = "Saving...";
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE}/api/admin/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token')
            },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            alert("Settings saved successfully!");
        } else {
            const data = await res.json();
            alert("Error saving settings: " + (data.error || "Unknown"));
        }
    } catch (e) {
        console.error(e);
        alert("Network error while saving settings");
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

// API Key Management
async function loadKeys() {
    const list = document.getElementById('keys-list');
    list.innerHTML = '<p style="color: #888; text-align: center;">Loading...</p>';

    try {
        const res = await fetch(`${API_BASE}/api/admin/keys`);
        const data = await res.json();

        // Populate Generator Dropdown
        const genSelect = document.getElementById('gen-key-select');
        if (genSelect) {
            // Keep default option
            genSelect.innerHTML = '<option value="YOUR_API_KEY">Select API Key...</option>';
            if (data.keys && data.keys.length > 0) {
                data.keys.forEach(k => {
                    const opt = document.createElement('option');
                    opt.value = k.key;
                    opt.textContent = `${k.name} (${k.key.substring(0, 8)}...)`;
                    genSelect.appendChild(opt);
                });
            }
        }

        await populateModelDropdown(); // Load models from API
        updateCurlExamples(); // Update examples

        if (!data.keys || data.keys.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No API Keys found (Config keys are not listed here).</p>';
            return;
        }

        list.innerHTML = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--admin-border); text-align: left;">
                        <th style="padding: 12px; color: #888;">Name</th>
                        <th style="padding: 12px; color: #888;">Key</th>
                        <th style="padding: 12px; color: #888;">Created</th>
                        <th style="padding: 12px; color: #888; text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.keys.map(k => `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 12px; color: #eee;">${escapeHtml(k.name || 'Unnamed')}</td>
                            <td style="padding: 12px; font-family: monospace; color: #a78bfa;">${escapeHtml(k.key)}</td>
                            <td style="padding: 12px; color: #666;">${new Date(k.created_at).toLocaleDateString()}</td>
                            <td style="padding: 12px; text-align: right;">
                                <button onclick="deleteKey('${k.key}')" style="background: rgba(220, 38, 38, 0.2); color: #f87171; border: 1px solid rgba(220, 38, 38, 0.3); padding: 6px 12px; border-radius: 6px; cursor: pointer;">Delete</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (e) {
        console.error(e);
        list.innerHTML = `<p style="color: #f87171;">Error loading keys: ${e.message}</p>`;
    }
}

function updateCurlExamples() {
    const key = document.getElementById('gen-key-select').value;
    const model = document.getElementById('gen-model-select').value;
    const chatEl = document.getElementById('code-chat');
    const modelsEl = document.getElementById('code-models');
    const anthropicEl = document.getElementById('code-anthropic');

    if (chatEl) {
        chatEl.textContent = `curl ${API_BASE}/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${key}" \\
  -d '{
    "model": "${model}",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "Hello!"}
    ]
  }'`;
    }

    if (modelsEl) {
        modelsEl.textContent = `curl ${API_BASE}/v1/models \\
  -H "Authorization: Bearer ${key}"`;
    }

    if (anthropicEl) {
        // Map model to something anthropic-like if desired, or keep generic
        // but user selected generic models. 
        anthropicEl.textContent = `curl ${API_BASE}/v1/messages \\
  -H "x-api-key: ${key}" \\
  -H "anthropic-version: 2023-06-01" \\
  -H "content-type: application/json" \\
  -d '{
    "model": "${model}", 
    "max_tokens": 1024,
    "messages": [
        {"role": "user", "content": "Hello, world"}
    ]
}'`;
    }
}

// Open the Create Key Modal
function createKey() {
    document.getElementById('new-key-name').value = ''; // Reset input
    document.getElementById('create-key-modal').showModal();
}

// Handle Modal Submission
async function submitCreateKey() {
    const name = document.getElementById('new-key-name').value || 'Unnamed Key';

    try {
        const res = await fetch(`${API_BASE}/api/admin/keys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token')
            },
            body: JSON.stringify({ name })
        });

        if (res.ok) {
            document.getElementById('create-key-modal').close();
            loadKeys();
            // Show success animation or toast if desired
        } else {
            const d = await res.json();
            alert("Error: " + (d.error || "Failed to create key"));
        }
    } catch (e) {
        alert("Network error");
    }
}

async function deleteKey(key) {
    if (!confirm("Are you sure you want to delete this API Key? This action cannot be undone.")) return;

    try {
        const res = await fetch(`${API_BASE}/api/admin/keys/${key}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': getCookie('csrf_token')
            }
        });

        if (res.ok) {
            loadKeys();
        } else {
            alert("Failed to delete key");
        }
    } catch (e) {
        alert("Network error");
    }
}

async function populateModelDropdown() {
    try {
        const res = await fetch(`${API_BASE}/v1/models`);
        const data = await res.json();
        const select = document.getElementById('gen-model-select');

        if (select && data.data && Array.isArray(data.data)) {
            // Store current selection if any
            const currentVal = select.value;
            select.innerHTML = '';

            data.data.forEach(m => {
                const opt = document.createElement('option');
                opt.value = m.id;
                opt.textContent = m.id;
                select.appendChild(opt);
            });

            // Try to restore selection or default to gemini-3-flash
            if (currentVal && data.data.some(m => m.id === currentVal)) {
                select.value = currentVal;
            } else if (data.data.some(m => m.id === 'gemini-3-flash')) {
                select.value = 'gemini-3-flash';
            }

            // Trigger update
            updateCurlExamples();
        }
    } catch (e) {
        console.error("Failed to populate gen-model-select", e);
    }
}

// Account Management
async function loadAccounts() {
    const list = document.getElementById('accounts-list-settings');
    if (!list) {
        console.error('accounts-list-settings element not found');
        return;
    }
    list.innerHTML = '<p style="color: #888; text-align: center;">Loading...</p>';

    try {
        console.log('Fetching accounts from:', `${API_BASE}/api/admin/accounts`);
        const res = await fetch(`${API_BASE}/api/admin/accounts`);

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const data = await res.json();
        console.log('Accounts data:', data);

        if (!data.accounts || data.accounts.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No accounts found. Add an account to get started.</p>';
            return;
        }

        list.innerHTML = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--admin-border); text-align: left;">
                        <th style="padding: 12px; color: #888;">Email</th>
                        <th style="padding: 12px; color: #888;">Status</th>
                        <th style="padding: 12px; color: #888;">Disabled Reason</th>
                        <th style="padding: 12px; color: #888; text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.accounts.map(acc => `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 12px; color: #eee;">${escapeHtml(acc.email)}</td>
                            <td style="padding: 12px;">
                                ${acc.disabled
                ? '<span style="color: #f87171;">Disabled</span>'
                : '<span style="color: #4ade80;">Active</span>'}
                            </td>
                            <td style="padding: 12px; color: #999; font-size: 0.9em;">
                                ${acc.disabled ? escapeHtml(acc.disabled_reason || 'Manual') : '-'}
                            </td>
                            <td style="padding: 12px; text-align: right;">
                                <button onclick="deleteAccount('${escapeHtml(acc.email)}')" 
                                    style="background: rgba(220, 38, 38, 0.2); color: #f87171; border: 1px solid rgba(220, 38, 38, 0.3); padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.9em;">
                                    Delete
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    } catch (e) {
        console.error('Error loading accounts:', e);
        list.innerHTML = `<p style="color: #f87171; text-align: center; padding: 20px;">Error loading accounts: ${e.message}</p>`;
    }
}

async function addAccount() {
    const email = document.getElementById('new-account-email').value;
    const token = document.getElementById('new-account-token').value;

    if (!email || !token) {
        alert("Email and Refresh Token are required");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/api/admin/accounts`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCookie('csrf_token')
            },
            body: JSON.stringify({ email: email, refresh_token: token })
        });

        if (res.ok) {
            document.getElementById('new-account-email').value = '';
            document.getElementById('new-account-token').value = '';
            document.getElementById('add-account-modal').close();
            loadAccounts();
        } else {
            const data = await res.json();
            alert("Error: " + (data.error || "Failed to add account"));
        }
    } catch (e) {
        alert("Network error");
    }
}

async function deleteAccount(email) {
    if (!confirm(`Are you sure you want to delete account ${email}? This action cannot be undone.`)) return;

    try {
        const res = await fetch(`${API_BASE}/api/admin/accounts/${encodeURIComponent(email)}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': getCookie('csrf_token')
            }
        });

        if (res.ok) {
            loadAccounts();
        } else {
            const data = await res.json();
            alert("Error: " + (data.error || "Failed to delete account"));
        }
    } catch (e) {
        alert("Network error");
    }
}

async function loginWithGoogle() {
    try {
        // Get current account count before login
        let initialCount = 0;
        try {
            const initialRes = await fetch(`${API_BASE}/api/admin/accounts`);
            if (initialRes.ok) {
                const initialData = await initialRes.json();
                initialCount = initialData.accounts ? initialData.accounts.length : 0;
            }
        } catch (e) {
            console.log('Could not get initial account count');
        }

        const res = await fetch(`${API_BASE}/api/antigravity_login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!res.ok) throw new Error('Failed to start login flow');
        const data = await res.json();

        if (data.url) {
            const width = 500, height = 600;
            const left = (screen.width / 2) - (width / 2);
            const top = (screen.height / 2) - (height / 2);

            const popup = window.open(data.url, 'Google Sign In', `width=${width},height=${height},left=${left},top=${top}`);

            let attempts = 0;
            const checkInterval = setInterval(async () => {
                attempts++;

                // Check if popup was closed without completing login
                if (popup && popup.closed) {
                    clearInterval(checkInterval);
                    console.log('Login popup closed by user');
                    return;
                }

                try {
                    const accountsRes = await fetch(`${API_BASE}/api/admin/accounts`);
                    if (accountsRes.ok) {
                        const accountsData = await accountsRes.json();
                        const currentCount = accountsData.accounts ? accountsData.accounts.length : 0;

                        // Only show success if a NEW account was added
                        if (currentCount > initialCount) {
                            clearInterval(checkInterval);
                            if (popup && !popup.closed) popup.close();
                            document.getElementById('add-account-modal').close();
                            loadAccounts();
                            alert('Account added successfully!');
                        }
                    }
                } catch (e) {
                    console.error('Error checking accounts:', e);
                }

                if (attempts >= 120) { // 2 minute timeout
                    clearInterval(checkInterval);
                    alert('Login timeout. Please try again.');
                }
            }, 1000);
        }
    } catch (e) {
        console.error('Error starting Google login:', e);
        alert('Failed to start Google login: ' + e.message);
    }
}