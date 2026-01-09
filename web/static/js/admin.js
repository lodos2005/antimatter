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
            loadRecentLogs();
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
    } else {
        loadRecentLogs();
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
                <div class="message-content">${escapeHtml(log.response || '(No response captured)')}</div>
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
