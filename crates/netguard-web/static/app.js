// NetGuard Web UI
(function () {
    'use strict';

    // ── State ──
    let ws = null;
    let currentPage = 'dashboard';
    let connections = [];
    let rules = [];
    let stats = { active_connections: 0, total_allowed: 0, total_denied: 0, connections_per_second: 0, top_apps: [] };
    let pendingPrompts = {};
    let connectionsOffset = 0;
    const CONNECTIONS_LIMIT = 50;

    // ── Auth ──
    // Token is stored in sessionStorage after user authenticates (never embedded in HTML)
    let API_TOKEN = sessionStorage.getItem('netguard_token') || '';

    // ── Security helpers ──
    function esc(str) {
        const div = document.createElement('div');
        div.textContent = String(str == null ? '' : str);
        return div.innerHTML;
    }

    function csvEsc(val) {
        const s = String(val == null ? '' : val);
        if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
        if (/[,"\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
        return s;
    }

    // ── DOM refs ──
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ── Navigation ──
    $$('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', () => {
            currentPage = item.dataset.page;
            $$('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            $$('.page').forEach(p => p.classList.add('hidden'));
            $(`#page-${currentPage}`).classList.remove('hidden');
            if (currentPage === 'connections') loadConnections(true);
            if (currentPage === 'rules') loadRules();
            if (currentPage === 'logs') loadLogs();
        });
    });

    // ── WebSocket ──
    async function connectWs() {
        // Obtain a one-time ticket via authenticated API call (token never in URL)
        let ticket;
        try {
            const res = await fetch('/ws-ticket', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${API_TOKEN}` },
            });
            if (!res.ok) { setTimeout(connectWs, 3000); return; }
            ticket = await res.text();
        } catch (e) { setTimeout(connectWs, 3000); return; }

        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/ws?ticket=${encodeURIComponent(ticket)}`);

        ws.onopen = () => {
            $('#ws-status').className = 'status-dot connected';
            $('#ws-status-text').textContent = 'Connected';
        };

        ws.onclose = () => {
            $('#ws-status').className = 'status-dot disconnected';
            $('#ws-status-text').textContent = 'Disconnected';
            setTimeout(connectWs, 3000);
        };

        ws.onerror = () => ws.close();

        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                handleWsEvent(msg);
            } catch (e) { /* ignore malformed messages */ }
        };
    }

    function handleWsEvent(msg) {
        switch (msg.type) {
            case 'new_connection':
                connections.unshift(msg.data);
                if (connections.length > 500) connections.pop();
                if (currentPage === 'dashboard') renderLiveStream();
                if (currentPage === 'connections') renderConnectionsTable();
                break;
            case 'prompt':
                pendingPrompts[msg.data.id] = msg.data;
                renderPrompts();
                break;
            case 'prompt_resolved':
                delete pendingPrompts[msg.data.prompt_id];
                renderPrompts();
                break;
            case 'rule_changed':
                const idx = rules.findIndex(r => r.id === msg.data.id);
                if (idx >= 0) rules[idx] = msg.data;
                else rules.push(msg.data);
                if (currentPage === 'rules') renderRulesTable();
                break;
            case 'stats':
                stats = msg.data;
                if (currentPage === 'dashboard') renderStats();
                break;
        }
    }

    // ── API helpers ──
    async function api(path, opts = {}) {
        const res = await fetch(`/api${path}`, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${API_TOKEN}`,
                ...opts.headers,
            },
            ...opts,
        });
        if (!res.ok) throw new Error(await res.text());
        if (res.status === 204) return null;
        return res.json();
    }

    // ── Dashboard ──
    function renderStats() {
        $('#stats-grid').innerHTML = `
            <div class="stat-card">
                <div class="label">Active Connections</div>
                <div class="value accent">${esc(stats.active_connections)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Allowed</div>
                <div class="value green">${esc(stats.total_allowed)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Denied</div>
                <div class="value red">${esc(stats.total_denied)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Conn/sec</div>
                <div class="value">${esc(Number(stats.connections_per_second).toFixed(1))}</div>
            </div>
        `;
    }

    function renderLiveStream() {
        const el = $('#live-stream');
        const recent = connections.slice(0, 50);
        if (recent.length === 0) {
            el.innerHTML = '<div class="empty-state"><div class="icon">&#128268;</div>No connections yet</div>';
            return;
        }
        el.innerHTML = recent.map(c => `
            <div class="stream-entry clickable" onclick="window.showPacketDetail('${esc(c.id)}')">
                <span class="badge ${esc(c.verdict)}">${esc(c.verdict)}</span>
                <span class="app-name truncate">${esc(appName(c))}</span>
                <span class="dest text-mono">${c.hostname ? esc(c.hostname) : esc(c.dst_ip)}:${esc(c.dst_port)}</span>
                <span class="badge ${esc(c.protocol)}">${esc(c.protocol)}</span>
                <span class="time">${esc(formatSize(c.packet_size))}</span>
                <span class="time">${esc(timeAgo(c.timestamp))}</span>
            </div>
        `).join('');
    }

    function renderTopApps() {
        const el = $('#top-apps');
        if (!stats.top_apps || stats.top_apps.length === 0) {
            el.innerHTML = '<div class="empty-state">No data yet</div>';
            return;
        }
        const max = Math.max(...stats.top_apps.map(a => a[1]));
        el.innerHTML = stats.top_apps.map(([name, count]) => `
            <div class="top-app">
                <span class="truncate" style="min-width:120px;font-size:13px">${esc(basename(name))}</span>
                <div class="bar-container">
                    <div class="bar" style="width:${(count/max*100).toFixed(0)}%"></div>
                </div>
                <span class="count">${esc(count)}</span>
            </div>
        `).join('');
    }

    async function refreshDashboard() {
        try {
            stats = await api('/stats');
            renderStats();
            renderTopApps();
        } catch (e) { /* ignore */ }
    }

    // ── Connections ──
    async function loadConnections(reset = false) {
        if (reset) connectionsOffset = 0;
        try {
            const data = await api(`/connections?limit=${CONNECTIONS_LIMIT}&offset=${connectionsOffset}`);
            if (reset) connections = data;
            else connections.push(...data);
            renderConnectionsTable();
        } catch (e) { /* ignore */ }
    }

    function renderConnectionsTable() {
        const appFilter = ($('#conn-filter-app')?.value || '').toLowerCase();
        const verdictFilter = $('#conn-filter-verdict')?.value || '';
        const protoFilter = $('#conn-filter-proto')?.value || '';

        const filtered = connections.filter(c => {
            if (appFilter && !appName(c).toLowerCase().includes(appFilter)) return false;
            if (verdictFilter && c.verdict !== verdictFilter) return false;
            if (protoFilter && c.protocol !== protoFilter) return false;
            return true;
        });

        $('#connections-table').innerHTML = filtered.map(c => `
            <tr class="clickable" onclick="window.showPacketDetail('${esc(c.id)}')">
                <td class="text-mono">${esc(formatTime(c.timestamp))}</td>
                <td class="truncate">${esc(appName(c))}</td>
                <td class="domain-label truncate">${esc(c.hostname || '-')}</td>
                <td class="text-mono">${esc(c.dst_ip)}</td>
                <td class="text-mono">${esc(c.dst_port)}</td>
                <td><span class="badge ${esc(c.protocol)}">${esc(c.protocol)}</span></td>
                <td>${esc(formatSize(c.packet_size))}</td>
                <td><span class="badge ${esc(c.verdict)}">${esc(c.verdict)}</span></td>
            </tr>
        `).join('');
    }

    $('#load-more-connections')?.addEventListener('click', () => {
        connectionsOffset += CONNECTIONS_LIMIT;
        loadConnections(false);
    });

    ['conn-filter-app', 'conn-filter-verdict', 'conn-filter-proto'].forEach(id => {
        $(`#${id}`)?.addEventListener('input', () => renderConnectionsTable());
        $(`#${id}`)?.addEventListener('change', () => renderConnectionsTable());
    });

    // ── Rules ──
    async function loadRules() {
        try {
            rules = await api('/rules');
            renderRulesTable();
        } catch (e) { /* ignore */ }
    }

    function renderRulesTable() {
        if (rules.length === 0) {
            $('#rules-table').innerHTML = '<tr><td colspan="9" class="empty-state">No rules defined. Click "Add Rule" to create one.</td></tr>';
            return;
        }
        $('#rules-table').innerHTML = rules.map(r => `
            <tr data-id="${esc(r.id)}">
                <td>
                    <label class="toggle">
                        <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="window.toggleRule('${esc(r.id)}')">
                        <span class="slider"></span>
                    </label>
                </td>
                <td class="text-mono truncate">${esc(r.app_path)}</td>
                <td class="text-mono">${esc(r.remote_host || '*')}</td>
                <td>${esc(r.remote_port || '*')}</td>
                <td>${r.protocol ? `<span class="badge ${esc(r.protocol)}">${esc(r.protocol)}</span>` : 'Any'}</td>
                <td>${esc(r.direction || 'Both')}</td>
                <td><span class="badge ${esc(r.verdict)}">${esc(r.verdict)}</span></td>
                <td>${esc(r.hit_count)}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="window.deleteRule('${esc(r.id)}')">Delete</button>
                </td>
            </tr>
        `).join('');
    }

    window.toggleRule = async (id) => {
        try {
            await api(`/rules/${id}/toggle`, { method: 'PATCH' });
            loadRules();
        } catch (e) { alert('Failed to toggle rule: ' + e.message); }
    };

    window.deleteRule = async (id) => {
        if (!confirm('Delete this rule?')) return;
        try {
            await api(`/rules/${id}`, { method: 'DELETE' });
            rules = rules.filter(r => r.id !== id);
            renderRulesTable();
        } catch (e) { alert('Failed to delete rule: ' + e.message); }
    };

    $('#add-rule-btn')?.addEventListener('click', () => {
        $('#rule-modal').classList.remove('hidden');
        $('#rule-modal-title').textContent = 'Add Rule';
    });

    $('#rule-modal-cancel')?.addEventListener('click', () => {
        $('#rule-modal').classList.add('hidden');
    });

    $('#rule-modal-save')?.addEventListener('click', async () => {
        const rule = {
            app_path: $('#rule-app-path').value || '*',
            remote_host: $('#rule-remote-host').value || null,
            remote_port: $('#rule-remote-port').value ? parseInt($('#rule-remote-port').value) : null,
            protocol: $('#rule-protocol').value || null,
            direction: $('#rule-direction').value || null,
            verdict: $('#rule-verdict').value,
            temporary: false,
            note: $('#rule-note').value || null,
        };
        try {
            await api('/rules', { method: 'POST', body: JSON.stringify(rule) });
            $('#rule-modal').classList.add('hidden');
            $('#rule-app-path').value = '';
            $('#rule-remote-host').value = '';
            $('#rule-remote-port').value = '';
            $('#rule-protocol').value = '';
            $('#rule-direction').value = '';
            $('#rule-verdict').value = 'allow';
            $('#rule-note').value = '';
            loadRules();
        } catch (e) { alert('Failed to create rule: ' + e.message); }
    });

    // ── Prompts ──
    function renderPrompts() {
        const overlay = $('#prompt-overlay');
        const prompts = Object.values(pendingPrompts);
        if (prompts.length === 0) {
            overlay.innerHTML = '';
            return;
        }
        overlay.innerHTML = prompts.map(p => `
            <div class="prompt-card" data-id="${esc(p.id)}">
                <div class="prompt-title">New Connection Detected</div>
                <div class="prompt-details">
                    <div><strong>App:</strong> ${esc(appName(p.connection))}</div>
                    <div><strong>Dest:</strong> ${esc(p.connection.dst_ip)}:${esc(p.connection.dst_port)}</div>
                    <div><strong>Protocol:</strong> ${esc(p.connection.protocol)}</div>
                    <div><strong>PID:</strong> ${esc(p.connection.process?.pid || 'unknown')}</div>
                </div>
                <div class="prompt-scope">
                    <select id="scope-${esc(p.id)}">
                        <option value="app_to_destination">This app to this destination</option>
                        <option value="app_anywhere">This app to anywhere</option>
                        <option value="app_to_port">This app to this port</option>
                        <option value="this_connection_only">This connection only</option>
                    </select>
                </div>
                <div class="prompt-actions" style="margin-top:8px">
                    <button class="btn btn-sm btn-success" onclick="window.respondPrompt('${esc(p.id)}', 'allow', true)">Allow & Remember</button>
                    <button class="btn btn-sm btn-deny" onclick="window.respondPrompt('${esc(p.id)}', 'deny', true)">Deny & Remember</button>
                    <button class="btn btn-sm" onclick="window.respondPrompt('${esc(p.id)}', 'allow', false)">Allow Once</button>
                    <button class="btn btn-sm" onclick="window.respondPrompt('${esc(p.id)}', 'deny', false)">Deny Once</button>
                </div>
            </div>
        `).join('');
    }

    window.respondPrompt = async (id, verdict, remember) => {
        const scopeEl = $(`#scope-${id}`);
        const scope = scopeEl ? scopeEl.value : 'app_to_destination';
        try {
            await api(`/prompts/${id}/respond`, {
                method: 'POST',
                body: JSON.stringify({ prompt_id: id, verdict, remember, scope }),
            });
            delete pendingPrompts[id];
            renderPrompts();
        } catch (e) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'respond_prompt',
                    prompt_id: id,
                    verdict,
                    remember,
                    scope,
                }));
                delete pendingPrompts[id];
                renderPrompts();
            }
        }
    };

    // ── Logs ──
    async function loadLogs() {
        try {
            const data = await api('/connections?limit=200&offset=0');
            renderLogsTable(data);
        } catch (e) { /* ignore */ }
    }

    function renderLogsTable(data) {
        const search = ($('#log-search')?.value || '').toLowerCase();
        const filtered = (data || connections).filter(c => {
            if (!search) return true;
            return appName(c).toLowerCase().includes(search)
                || String(c.dst_ip).includes(search)
                || String(c.dst_port).includes(search);
        });

        $('#logs-table').innerHTML = filtered.map(c => `
            <tr>
                <td class="text-mono">${esc(formatTime(c.timestamp))}</td>
                <td class="truncate">${esc(appName(c))}</td>
                <td class="text-mono">${esc(c.src_ip)}:${esc(c.src_port)}</td>
                <td class="text-mono">${esc(c.dst_ip)}:${esc(c.dst_port)}</td>
                <td><span class="badge ${esc(c.protocol)}">${esc(c.protocol)}</span></td>
                <td><span class="badge ${esc(c.verdict)}">${esc(c.verdict)}</span></td>
                <td class="text-mono" style="font-size:11px">${c.rule_id ? esc(c.rule_id.substring(0, 8)) + '...' : '-'}</td>
            </tr>
        `).join('');
    }

    $('#log-search')?.addEventListener('input', () => loadLogs());

    $('#export-csv')?.addEventListener('click', () => {
        const header = 'Time,Application,Source,Destination,Protocol,Verdict,Rule ID\n';
        const rows = connections.map(c =>
            [
                csvEsc(c.timestamp),
                csvEsc(appName(c)),
                csvEsc(c.src_ip + ':' + c.src_port),
                csvEsc(c.dst_ip + ':' + c.dst_port),
                csvEsc(c.protocol),
                csvEsc(c.verdict),
                csvEsc(c.rule_id || ''),
            ].join(',')
        ).join('\n');
        const blob = new Blob([header + rows], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `netguard-logs-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // ── Helpers ──
    function appName(conn) {
        if (conn.process) {
            return basename(conn.process.exe_path) || conn.process.exe_path;
        }
        return 'unknown';
    }

    function basename(path) {
        return path.split('/').pop() || path;
    }

    function formatTime(ts) {
        return new Date(ts).toLocaleTimeString();
    }

    function timeAgo(ts) {
        const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
        if (sec < 5) return 'just now';
        if (sec < 60) return sec + 's ago';
        if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
        return Math.floor(sec / 3600) + 'h ago';
    }

    function formatSize(bytes) {
        if (!bytes) return '-';
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function hexToAsciiLine(hexStr) {
        if (!hexStr) return '';
        const bytes = hexStr.split(' ');
        const lines = [];
        for (let i = 0; i < bytes.length; i += 16) {
            const chunk = bytes.slice(i, i + 16);
            const offset = i.toString(16).padStart(4, '0');
            const hex = chunk.join(' ').padEnd(47, ' ');
            const ascii = chunk.map(b => {
                const n = parseInt(b, 16);
                return (n >= 32 && n <= 126) ? String.fromCharCode(n) : '.';
            }).join('');
            lines.push(`${offset}  ${hex}  |${ascii}|`);
        }
        return lines.join('\n');
    }

    // ── Packet Detail Modal ──
    window.showPacketDetail = (id) => {
        const c = connections.find(x => x.id === id);
        if (!c) return;

        const el = $('#packet-detail');
        el.innerHTML = `
            <div class="pkt-row"><span class="pkt-label">Time</span><span class="pkt-value">${esc(new Date(c.timestamp).toLocaleString())}</span></div>
            <div class="pkt-row"><span class="pkt-label">Application</span><span class="pkt-value">${esc(c.process ? c.process.exe_path : 'unknown')}</span></div>
            <div class="pkt-row"><span class="pkt-label">Command</span><span class="pkt-value">${esc(c.process ? c.process.cmdline : '-')}</span></div>
            <div class="pkt-row"><span class="pkt-label">PID / UID</span><span class="pkt-value">${esc(c.process ? c.process.pid + ' / ' + c.process.username : '-')}</span></div>
            <div class="pkt-row"><span class="pkt-label">Domain</span><span class="pkt-value domain-label">${esc(c.hostname || 'not resolved')}</span></div>
            <div class="pkt-row"><span class="pkt-label">Direction</span><span class="pkt-value">${esc(c.direction)}</span></div>
            <div class="pkt-row"><span class="pkt-label">Source</span><span class="pkt-value text-mono">${esc(c.src_ip)}:${esc(c.src_port)}</span></div>
            <div class="pkt-row"><span class="pkt-label">Destination</span><span class="pkt-value text-mono">${esc(c.dst_ip)}:${esc(c.dst_port)}</span></div>
            <div class="pkt-row"><span class="pkt-label">Protocol</span><span class="pkt-value"><span class="badge ${esc(c.protocol)}">${esc(c.protocol)}</span></span></div>
            <div class="pkt-row"><span class="pkt-label">Packet Size</span><span class="pkt-value">${esc(formatSize(c.packet_size))}</span></div>
            <div class="pkt-row"><span class="pkt-label">Verdict</span><span class="pkt-value"><span class="badge ${esc(c.verdict)}">${esc(c.verdict)}</span></span></div>
            <div class="pkt-row"><span class="pkt-label">Rule ID</span><span class="pkt-value text-mono">${esc(c.rule_id || 'none')}</span></div>
            <div style="margin-top:12px">
                <div class="pkt-label" style="margin-bottom:6px">Payload (hex + ASCII)</div>
                <div class="hex-dump">${c.payload_hex ? esc(hexToAsciiLine(c.payload_hex)) : '<em>No payload data</em>'}</div>
            </div>
        `;
        $('#packet-modal').classList.remove('hidden');
    };

    $('#packet-modal-close')?.addEventListener('click', () => {
        $('#packet-modal').classList.add('hidden');
    });

    // Close modals on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
        backdrop.addEventListener('click', (e) => {
            if (e.target === backdrop) backdrop.classList.add('hidden');
        });
    });

    // ── Login ──
    function showLogin() {
        $('.main').innerHTML = `
            <div style="max-width:400px;margin:80px auto;text-align:center">
                <h1 style="color:var(--accent);margin-bottom:8px">NetGuard</h1>
                <p style="color:var(--text-muted);margin-bottom:24px">Enter API token to authenticate</p>
                <p style="color:var(--text-muted);font-size:12px;margin-bottom:16px">
                    Token is in: <code>/etc/netguard/api_token</code>
                </p>
                <input type="password" id="login-token" placeholder="Paste API token..."
                    style="width:100%;padding:10px 14px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-size:14px;margin-bottom:12px">
                <div id="login-error" style="color:var(--red);font-size:13px;margin-bottom:12px;display:none">Invalid token</div>
                <button class="btn btn-primary" id="login-btn" style="width:100%;padding:10px">Authenticate</button>
            </div>
        `;
        $('#login-btn').addEventListener('click', doLogin);
        $('#login-token').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
        $('#login-token').focus();
    }

    async function doLogin() {
        const token = $('#login-token').value.trim();
        if (!token) return;
        try {
            const res = await fetch('/auth/validate-token', { method: 'POST', body: token });
            if (res.ok) {
                API_TOKEN = token;
                sessionStorage.setItem('netguard_token', token);
                location.reload();
            } else {
                $('#login-error').style.display = 'block';
            }
        } catch (e) {
            $('#login-error').style.display = 'block';
        }
    }

    // ── Init ──
    async function init() {
        if (!API_TOKEN) {
            showLogin();
            return;
        }
        // Validate stored token still works
        try {
            const res = await fetch('/auth/validate-token', { method: 'POST', body: API_TOKEN });
            if (!res.ok) {
                sessionStorage.removeItem('netguard_token');
                API_TOKEN = '';
                showLogin();
                return;
            }
        } catch (e) {
            showLogin();
            return;
        }

        connectWs();
        refreshDashboard();
        setInterval(refreshDashboard, 5000);

        api('/prompts').then(data => {
            data.forEach(p => { pendingPrompts[p.id] = p; });
            renderPrompts();
        }).catch(() => {});

        renderStats();
        renderLiveStream();
        renderTopApps();
    }

    init();
})();
