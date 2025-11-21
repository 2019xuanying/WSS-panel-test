/**
 * WSS Panel Frontend (Axiom V5.0 - Full Feature Release)
 * * [架构说明]
 * 1. 混合模式: 
 * - 实时数据 (仪表盘、用户列表速度) -> WebSocket (Diff Push)
 * - 交互操作 (设置、生成载荷、保存配置) -> REST API
 * 2. 状态管理:
 * - globalState: 维护全量用户和系统状态。
 * - deepMerge: 处理后端推送的增量补丁。
 */

// --- 全局变量 ---
const API_BASE = '/api';
let currentView = 'dashboard';
let panelSocket = null;
let wsReconnectTimer = null;

// 本地状态镜像
let globalState = {
    users: {},
    system: { services: {}, ports: [] },
    live_ips: {}
};

// UI 状态
let selectedUsers = [];
let currentSortKey = 'username';
let currentSortDir = 'asc';

// 图表实例
let realtimeChartInstance = null;
let userStatsChartInstance = null;
let trafficChartInstance = null;

const TOKEN_PLACEHOLDER = "[*********]";

// --- 核心工具: 深度合并 (处理 Diff) ---
function deepMerge(target, source) {
    for (const key in source) {
        if (source[key] instanceof Object && key in target) {
            Object.assign(source[key], deepMerge(target[key], source[key]));
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// --- WebSocket 连接管理 ---
function connectWebSocket() {
    if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    if (panelSocket) panelSocket.close();

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/ui`;

    setWsStatusIcon('blue', '连接中...');
    panelSocket = new WebSocket(wsUrl);

    panelSocket.onopen = () => {
        console.log('[WS] Connected');
    };

    panelSocket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            switch (msg.type) {
                case 'status_connected':
                    setWsStatusIcon('green', '实时连接 (1s)');
                    // 连接成功后，立即拉取一次全量数据作为基准
                    fetchAllStaticData();
                    break;

                case 'live_update':
                    // 收到增量更新 (Diff)
                    if (msg.payload) {
                        // 1. 合并数据到本地状态
                        deepMerge(globalState, msg.payload);
                        
                        // 2. 触发局部 UI 更新 (不重绘 DOM)
                        if (currentView === 'dashboard') {
                            if (msg.payload.system) updateDashboardUI(msg.payload.system);
                            updateRealtimeChart(); // 更新流量图
                        } else if (currentView === 'users') {
                            if (msg.payload.users) updateUsersListUI(msg.payload.users);
                        }
                    }
                    break;

                case 'users_changed':
                    // 用户增删改，需要全量重绘列表
                    fetchAllUsers();
                    break;

                case 'hosts_changed':
                    if (currentView === 'hosts') fetchHosts();
                    break;
                
                case 'system_update':
                    // 低频全量更新 (3秒一次)
                    if (msg.payload) {
                        globalState.system = msg.payload; // 更新系统状态缓存
                        if (currentView === 'dashboard') {
                            // 刷新那些可能没覆盖到的静态字段
                            updateDashboardUI(msg.payload);
                            if (msg.payload.user_stats) renderUserQuickStats(msg.payload.user_stats);
                        }
                    }
                    break;

                case 'auth_failed':
                    setWsStatusIcon('red', '认证失败');
                    showStatus('WebSocket 认证失败，请重新登录', false);
                    break;
            }
        } catch (e) {
            console.error('[WS] Parse error:', e);
        }
    };

    panelSocket.onclose = () => {
        setWsStatusIcon('red', '连接断开');
        wsReconnectTimer = setTimeout(connectWebSocket, 3000);
    };

    panelSocket.onerror = () => setWsStatusIcon('red', '连接错误');
}

// --- UI 更新引擎 (Smart Render) ---

// 仅更新变动的 DOM 节点 (Dashboard)
function updateDashboardUI(sysData) {
    if (sysData.cpu_usage !== undefined) {
        setText('stat-cpu-value', `${sysData.cpu_usage.toFixed(1)}%`);
    }
    if (sysData.memory_used_gb !== undefined) {
        setText('stat-ram-value', `${sysData.memory_used_gb.toFixed(2)} / ${sysData.memory_total_gb.toFixed(2)} GB`);
    }
    if (sysData.active_connections_total !== undefined) {
        setText('stat-active-conns', sysData.active_connections_total); // 这个 ID 对应 index.html 中的实时连接数
    }
    if (sysData.user_stats) {
        setText('stat-active-users', sysData.user_stats.active); // 用户概览卡片中的数据
    }
}

// 仅更新变动的 DOM 节点 (User List)
function updateUsersListUI(usersDiff) {
    for (const [username, diff] of Object.entries(usersDiff)) {
        // 更新速度
        if (diff.speed_kbps) {
            const up = formatSpeed(diff.speed_kbps.upload);
            const down = formatSpeed(diff.speed_kbps.download);
            setHTML(`speed-up-${username}`, `↑ ${up}`);
            setHTML(`speed-down-${username}`, `↓ ${down}`);
            // 移动端
            setText(`speed-up-m-${username}`, `↑ ${up}`);
            setText(`speed-down-m-${username}`, `↓ ${down}`);
        }
        // 更新连接数
        if (diff.connections !== undefined) {
            setText(`conn-${username}`, diff.connections);
            setText(`conn-m-${username}`, diff.connections);
        }
        // 更新状态 (熔断等)
        if (diff.status) {
            const badgeClass = getStatusBadgeClass(diff.status);
            const badgeText = diff.status_text || diff.status;
            setClassAndText(`status-${username}`, `badge ${badgeClass} badge-sm`, badgeText);
            setClassAndText(`status-m-${username}`, `badge ${badgeClass} badge-sm`, badgeText);
        }
    }
}

// DOM 辅助
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}
function setHTML(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}
function setClassAndText(id, className, text) {
    const el = document.getElementById(id);
    if (el) {
        el.className = className;
        el.textContent = text;
    }
}

// --- 数据获取 ---

async function fetchAllStaticData() {
    // 1. 获取系统状态
    const sysData = await fetchData('/system/status');
    if (sysData) {
        globalState.system = sysData;
        if (currentView === 'dashboard') renderDashboard(sysData);
        // 初始化图表
        initRealtimeChart();
    }
    // 2. 获取用户列表
    await fetchAllUsers();
    
    // 3. 预加载其他数据 (按需)
    if (currentView === 'port-config') fetchGlobalConfig();
    if (currentView === 'hosts') fetchHosts();
}

async function fetchAllUsers() {
    const data = await fetchData('/users/list');
    if (data && data.users) {
        globalState.users = {};
        data.users.forEach(u => {
            globalState.users[u.username] = u;
            // 补全默认值，防止 diff 合并出错
            if (!u.speed_kbps) u.speed_kbps = { upload: 0, download: 0 };
            if (!u.connections) u.connections = 0;
        });
        
        if (currentView === 'users') renderUserList();
        if (currentView === 'dashboard' && globalState.system.user_stats) {
             // 如果在仪表盘，也要刷新用户统计
             renderUserQuickStats(globalState.system.user_stats);
        }
        if (currentView === 'payload-gen') populatePayloadUserSelect();
    }
}

// --- 渲染器 ---

function renderDashboard(sysData) {
    const grid = document.getElementById('system-status-grid');
    if (!grid) return;

    // 渲染静态结构，数据由 updateDashboardUI 填充
    grid.innerHTML = `
        <div class="stats stats-vertical lg:stats-horizontal shadow w-full bg-base-100 border border-base-200">
            <div class="stat">
                <div class="stat-figure text-primary"><i data-lucide="cpu" class="w-8 h-8"></i></div>
                <div class="stat-title">CPU 负载</div>
                <div class="stat-value text-2xl" id="stat-cpu-value">${(sysData.cpu_usage || 0).toFixed(1)}%</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-secondary"><i data-lucide="brain" class="w-8 h-8"></i></div>
                <div class="stat-title">内存使用</div>
                <div class="stat-value text-lg font-mono" id="stat-ram-value">${sysData.memory_used_gb.toFixed(2)} / ${sysData.memory_total_gb.toFixed(2)} GB</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-accent"><i data-lucide="activity" class="w-8 h-8"></i></div>
                <div class="stat-title">实时连接数</div>
                <div class="stat-value text-2xl" id="stat-active-conns">${sysData.user_stats?.active || 0}</div>
            </div>
        </div>
        
        <!-- 服务控制 -->
        <div class="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            ${Object.entries(sysData.services).map(([k, v]) => `
                <div class="flex justify-between items-center bg-base-100 p-3 rounded-lg shadow-sm border border-base-200">
                    <div class="flex items-center gap-2">
                        <span class="badge ${v.status === 'running' ? 'badge-success' : 'badge-error'} badge-xs"></span>
                        <span class="font-bold text-sm">${v.name}</span>
                    </div>
                    <button class="btn btn-xs btn-ghost" onclick="confirmAction('${k}', 'restart', null, 'serviceControl', '重启 ${v.name}')">
                        <i data-lucide="rotate-cw" class="w-3 h-3"></i>
                    </button>
                </div>
            `).join('')}
        </div>
    `;
    lucide.createIcons();
    
    renderUserQuickStats(sysData.user_stats);
    
    // 隐藏骨架屏
    document.getElementById('dashboard-skeleton').classList.add('hidden');
    document.getElementById('dashboard-content').classList.remove('hidden');
}

function renderUserQuickStats(stats) {
    const container = document.getElementById('user-quick-stats');
    if (!container || !stats) return;
    
    const active = stats.active || 0; // 注意：这里的 active 是活跃IP数
    const total = stats.total || 0;
    const problematic = (stats.paused || 0) + (stats.fused || 0) + (stats.expired || 0);
    
    container.innerHTML = `
        <div class="stats shadow w-full bg-base-100">
            <div class="stat place-items-center">
                <div class="stat-title">总用户</div>
                <div class="stat-value">${total}</div>
            </div>
            <div class="stat place-items-center">
                <div class="stat-title">活跃 IP</div>
                <div class="stat-value text-success" id="stat-active-users">${active}</div>
            </div>
            <div class="stat place-items-center">
                <div class="stat-title">异常/暂停</div>
                <div class="stat-value text-warning">${problematic}</div>
            </div>
        </div>
    `;
}

function renderUserList() {
    const tbody = document.getElementById('user-list-tbody');
    const mobile = document.getElementById('user-list-mobile');
    
    // 排序
    const users = Object.values(globalState.users).sort((a, b) => {
        let valA = a[currentSortKey];
        let valB = b[currentSortKey];
        
        if (currentSortKey === 'speed') {
             valA = (a.speed_kbps?.upload || 0) + (a.speed_kbps?.download || 0);
             valB = (b.speed_kbps?.upload || 0) + (b.speed_kbps?.download || 0);
        } else if (currentSortKey === 'expiration_date') {
             valA = valA ? new Date(valA).getTime() : 0;
             valB = valB ? new Date(valB).getTime() : 0;
        }
        
        if (valA < valB) return currentSortDir === 'asc' ? -1 : 1;
        if (valA > valB) return currentSortDir === 'asc' ? 1 : -1;
        return 0;
    });
    
    let html = '';
    let mobileHtml = '';
    
    // 更新表头箭头样式
    document.querySelectorAll('th.sortable .sort-arrow').forEach(arrow => {
        const th = arrow.parentElement;
        if (th.dataset.sortkey === currentSortKey) {
            arrow.innerHTML = currentSortDir === 'asc' ? '▲' : '▼';
            arrow.style.opacity = '1';
        } else {
            arrow.innerHTML = '▲';
            arrow.style.opacity = '0.3';
        }
    });

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center py-4 text-gray-500">无用户数据</td></tr>';
        mobile.innerHTML = '<div class="text-center py-4 text-gray-500">无用户数据</div>';
        return;
    }

    users.forEach(u => {
        const statusClass = getStatusBadgeClass(u.status);
        const quota = u.quota_gb > 0 ? `${u.usage_gb.toFixed(2)} / ${u.quota_gb}` : `${u.usage_gb.toFixed(2)} / ∞`;
        const progress = u.quota_gb > 0 ? Math.min(100, (u.usage_gb / u.quota_gb) * 100) : 0;
        const isChecked = selectedUsers.includes(u.username) ? 'checked' : '';
        const isLocked = u.status !== 'active';
        
        // PC Row - 注意 ID 的设置
        html += `
        <tr class="hover">
            <td class="px-4"><input type="checkbox" class="checkbox checkbox-primary checkbox-xs user-chk" data-user="${u.username}" ${isChecked}></td>
            <td class="font-mono font-bold text-sm">${u.username}</td>
            <td><span id="status-${u.username}" class="badge ${statusClass} badge-sm">${u.status_text}</span></td>
            <td class="text-gray-500 text-xs">${u.expiration_date || '永不'}</td>
            <td class="font-mono text-sm"><span id="conn-${u.username}" class="text-primary font-bold">${u.connections || 0}</span> / ${u.max_connections || '∞'}</td>
            <td class="text-xs">${u.rate_kbps ? u.rate_kbps + ' KB/s' : '无限制'}</td>
            <td>
                <div class="text-xs font-mono">${quota} GB</div>
                <progress class="progress progress-primary w-16 h-1" value="${progress}" max="100"></progress>
            </td>
            <td class="font-mono text-xs">
                <span id="speed-up-${u.username}" class="text-success block">↑ ${formatSpeed(u.speed_kbps?.upload)}</span>
                <span id="speed-down-${u.username}" class="text-warning block">↓ ${formatSpeed(u.speed_kbps?.download)}</span>
            </td>
            <td>
                <div class="flex gap-1">
                    <button class="btn btn-xs btn-square btn-ghost" title="流量图" onclick="openTrafficChart('${u.username}')"><i data-lucide="bar-chart-2" class="w-4 h-4 text-info"></i></button>
                    <button class="btn btn-xs btn-square btn-ghost" title="设置" onclick="openSettings('${u.username}')"><i data-lucide="settings" class="w-4 h-4 text-primary"></i></button>
                    <button class="btn btn-xs btn-square btn-ghost" title="${isLocked ? '启用' : '暂停'}" onclick="confirmAction('${u.username}', '${isLocked?'enable':'pause'}', null, 'toggleStatus', '${isLocked?'启用':'暂停'}')">
                        <i data-lucide="${isLocked ? 'play' : 'pause'}" class="w-4 h-4 ${isLocked ? 'text-success' : 'text-warning'}"></i>
                    </button>
                    <button class="btn btn-xs btn-square btn-ghost" title="删除" onclick="confirmAction('${u.username}', 'delete', null, 'deleteUser', '删除')"><i data-lucide="trash-2" class="w-4 h-4 text-error"></i></button>
                </div>
            </td>
        </tr>`;
        
        // Mobile Card
        mobileHtml += `
        <div class="card bg-base-100 shadow-sm border border-base-200 mb-2">
            <div class="card-body p-3">
                <div class="flex justify-between items-center">
                    <div class="flex items-center gap-2">
                        <input type="checkbox" class="checkbox checkbox-primary checkbox-xs user-chk" data-user="${u.username}" ${isChecked}>
                        <h3 class="font-bold text-sm">${u.username}</h3>
                    </div>
                    <span id="status-m-${u.username}" class="badge ${statusClass} badge-sm">${u.status_text}</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-xs mt-2">
                    <div>连接: <span id="conn-m-${u.username}" class="text-primary font-bold">${u.connections || 0}</span></div>
                    <div>用量: ${quota}</div>
                    <div id="speed-up-m-${u.username}" class="text-success">↑ ${formatSpeed(u.speed_kbps?.upload)}</div>
                    <div id="speed-down-m-${u.username}" class="text-warning">↓ ${formatSpeed(u.speed_kbps?.download)}</div>
                </div>
                <div class="flex justify-end gap-2 mt-2 pt-2 border-t border-base-200">
                    <button class="btn btn-xs btn-ghost" onclick="openTrafficChart('${u.username}')">流量</button>
                    <button class="btn btn-xs btn-outline" onclick="openSettings('${u.username}')">设置</button>
                </div>
            </div>
        </div>`;
    });
    
    tbody.innerHTML = html;
    mobile.innerHTML = mobileHtml;
    lucide.createIcons();
    bindCheckboxEvents();
}

// --- 图表逻辑 (Realtime + History) ---

function initRealtimeChart() {
    const ctx = document.getElementById('realtime-traffic-chart')?.getContext('2d');
    if (!ctx || realtimeChartInstance) return;
    
    realtimeChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [
                { label: '上传', data: Array(30).fill(0), borderColor: '#34d399', borderWidth: 2, fill: true, backgroundColor: 'rgba(52, 211, 153, 0.1)', tension: 0.3, pointRadius: 0 },
                { label: '下载', data: Array(30).fill(0), borderColor: '#3b82f6', borderWidth: 2, fill: true, backgroundColor: 'rgba(59, 130, 246, 0.1)', tension: 0.3, pointRadius: 0 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: { legend: { position: 'top' } },
            scales: { x: { display: false }, y: { beginAtZero: true } }
        }
    });
}

function updateRealtimeChart() {
    if (!realtimeChartInstance) return;
    
    let totalUp = 0, totalDown = 0;
    for (const u of Object.values(globalState.users)) {
        totalUp += u.speed_kbps?.upload || 0;
        totalDown += u.speed_kbps?.download || 0;
    }
    
    const data = realtimeChartInstance.data;
    data.labels.shift(); data.labels.push('');
    data.datasets[0].data.shift(); data.datasets[0].data.push(totalUp);
    data.datasets[1].data.shift(); data.datasets[1].data.push(totalDown);
    
    realtimeChartInstance.update();
}

async function openTrafficChart(username) {
    const modal = document.getElementById('traffic-chart-modal');
    const ctx = document.getElementById('trafficChartCanvas').getContext('2d');
    document.getElementById('traffic-chart-title').textContent = username;
    
    if (trafficChartInstance) trafficChartInstance.destroy();
    modal.showModal();
    
    const data = await fetchData(`/users/traffic-history?username=${username}`);
    if (!data || !data.history) return;
    
    const labels = data.history.map(h => h.date.substring(5));
    const values = data.history.map(h => h.usage_gb);
    
    trafficChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ label: 'GB', data: values, backgroundColor: '#3b82f6', borderRadius: 4 }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });
}

// --- 交互逻辑 (增删改查、批量) ---

async function handleAddUser(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    const body = Object.fromEntries(formData.entries());
    body.require_auth_header = form.require_auth_header.checked ? 1 : 0;
    body.allow_shell = form.allow_shell.checked ? 1 : 0;
    
    const res = await fetchData('/users/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res) {
        showStatus(res.message, true);
        form.reset();
        closeModal('add-user-modal');
    }
}

async function openSettings(username) {
    const user = globalState.users[username];
    if (!user) return;
    
    document.getElementById('modal-username-setting').value = username;
    document.getElementById('settings-title-user').textContent = username;
    
    document.getElementById('set-expiry').value = user.expiration_date || '';
    document.getElementById('set-quota').value = user.quota_gb;
    document.getElementById('set-rate').value = user.rate_kbps;
    document.getElementById('set-conns').value = user.max_connections;
    document.getElementById('set-auth').checked = user.require_auth_header === 1;
    document.getElementById('set-shell').checked = user.allow_shell === 1;
    document.getElementById('set-password').value = '';
    document.getElementById('set-token').value = TOKEN_PLACEHOLDER;
    
    document.getElementById('settings-modal').showModal();
}

async function saveSettings(e) {
    e.preventDefault();
    const username = document.getElementById('modal-username-setting').value;
    const body = {
        username,
        expiry_date: document.getElementById('set-expiry').value,
        quota_gb: document.getElementById('set-quota').value,
        rate_kbps: document.getElementById('set-rate').value,
        max_connections: document.getElementById('set-conns').value,
        new_password: document.getElementById('set-password').value,
        require_auth_header: document.getElementById('set-auth').checked ? 1 : 0,
        allow_shell: document.getElementById('set-shell').checked ? 1 : 0
    };
    const res = await fetchData('/users/set_settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res) { showStatus(res.message, true); closeModal('settings-modal'); }
}

async function executeConfirmAction() {
    const btn = document.getElementById('confirm-btn');
    const type = btn.dataset.type;
    const p1 = btn.dataset.p1;
    const p2 = btn.dataset.p2;
    
    closeModal('confirm-modal');
    
    let url = '', body = {};
    if (type === 'deleteUser') { url = '/users/delete'; body = { username: p1 }; }
    else if (type === 'toggleStatus') { url = '/users/status'; body = { username: p1, action: p2 }; }
    else if (type === 'serviceControl') { url = '/system/control'; body = { service: p1, action: p2 }; }
    else if (type === 'killAll') { url = '/users/kill_all'; body = { username: p1 }; }
    else if (type === 'resetTraffic') { url = '/users/reset_traffic'; body = { username: p1 }; }
    else if (type === 'banGlobal') { url = '/ips/ban_global'; body = { ip: p1, reason: 'Manual' }; }
    else if (type === 'unbanGlobal') { url = '/ips/unban_global'; body = { ip: p1 }; }
    else if (type === 'batchAction') {
        url = '/users/batch-action';
        body = { action: p1, usernames: JSON.parse(p2), days: document.getElementById('batch-days')?.value };
    }
    
    const res = await fetchData(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res) {
        showStatus(res.message, true);
        if (type === 'batchAction') { selectedUsers = []; updateBatchBar(); }
    }
}

// --- 业务工具函数 (完整保留) ---

function confirmAction(p1, p2, p3, type, text) {
    document.getElementById('confirm-title').textContent = text;
    document.getElementById('confirm-msg').textContent = "确定要执行此操作吗？";
    const btn = document.getElementById('confirm-btn');
    btn.dataset.type = type; btn.dataset.p1 = p1; btn.dataset.p2 = p2;
    btn.className = `btn ${type.includes('delete')||type.includes('kill') ? 'btn-error' : 'btn-primary'}`;
    openModal('confirm-modal');
}

function bindCheckboxEvents() {
    document.querySelectorAll('.user-chk').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const u = e.target.dataset.user;
            e.target.checked ? selectedUsers.push(u) : (selectedUsers = selectedUsers.filter(x => x !== u));
            updateBatchBar();
        });
    });
    document.getElementById('select-all')?.addEventListener('change', (e) => {
        const all = document.querySelectorAll('.user-chk');
        all.forEach(cb => {
            cb.checked = e.target.checked;
            if (e.target.checked && !selectedUsers.includes(cb.dataset.user)) selectedUsers.push(cb.dataset.user);
        });
        if (!e.target.checked) selectedUsers = [];
        updateBatchBar();
    });
}

function updateBatchBar() {
    const bar = document.getElementById('batch-bar');
    if (selectedUsers.length > 0) {
        bar.classList.remove('translate-y-full');
        document.getElementById('batch-count').textContent = selectedUsers.length;
    } else {
        bar.classList.add('translate-y-full');
    }
}

function handleBatch(action) {
    if (!selectedUsers.length) return;
    let msg = `对 ${selectedUsers.length} 个用户执行 ${action}?`;
    if (action === 'renew') msg += ' (需指定天数)';
    confirmAction(action, JSON.stringify(selectedUsers), null, 'batchAction', msg);
}

// --- 载荷生成器逻辑 (完整) ---
function generatePayload() {
    const host = document.getElementById('pl-host').value || '[host]';
    const method = document.getElementById('pl-method').value;
    const split = document.getElementById('pl-split').checked;
    const r1 = document.getElementById('pl-r1').value || 'GET';
    
    const CRLF = '[crlf]', SPLIT = '[split]';
    let res = '';
    
    if (split) {
        res += `${r1} / HTTP/1.1${CRLF}Host: ${host}${CRLF}Connection: close${CRLF}${CRLF}${SPLIT}${CRLF}`;
    }
    
    res += `${method} http://${host}/ HTTP/1.1${CRLF}Host: ${host}${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}User-Agent: [ua]${CRLF}${CRLF}`;
    document.getElementById('pl-output').value = res;
}

function populatePayloadUserSelect() {
    const sel = document.getElementById('payload-user-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- 选择用户 --</option>';
    Object.keys(globalState.users).forEach(u => {
        const opt = document.createElement('option');
        opt.value = u; opt.textContent = u;
        sel.appendChild(opt);
    });
    sel.onchange = (e) => {
        if(e.target.value) {
            document.getElementById('payload-username').value = e.target.value;
            document.getElementById('payload-password').focus();
        }
    };
}

function setupTokenListeners() {
    const u = document.getElementById('new-username'), p = document.getElementById('new-password'), t = document.getElementById('new-connect-token');
    if(u && p && t) {
        const upd = () => t.value = (u.value && p.value) ? btoa(`${u.value}:${p.value}`) : '...';
        u.addEventListener('input', upd); p.addEventListener('input', upd);
    }
    const u2 = document.getElementById('payload-username'), p2 = document.getElementById('payload-password'), t2 = document.getElementById('payload-auth-token');
    if(u2 && p2 && t2) {
        const upd2 = () => t2.value = (u2.value && p2.value) ? btoa(`${u2.value}:${p2.value}`) : '...';
        u2.addEventListener('input', upd2); p2.addEventListener('input', upd2);
    }
}

// --- 配置与日志 ---
async function fetchGlobalConfig() {
    const data = await fetchData('/settings/config');
    if(data?.config) {
        document.getElementById('cfg-panel').value = data.config.panel_port;
        document.getElementById('cfg-wss-http').value = data.config.wss_http_port;
        document.getElementById('cfg-wss-tls').value = data.config.wss_tls_port;
        document.getElementById('cfg-stunnel').value = data.config.stunnel_port;
        document.getElementById('cfg-udpgw').value = data.config.udpgw_port;
        document.getElementById('cfg-internal').value = data.config.internal_forward_port;
    }
}
async function saveGlobalConfig() {
    showStatus('保存配置中...', true);
    const body = {
        panel_port: parseInt(document.getElementById('cfg-panel').value),
        wss_http_port: parseInt(document.getElementById('cfg-wss-http').value),
        wss_tls_port: parseInt(document.getElementById('cfg-wss-tls').value),
        stunnel_port: parseInt(document.getElementById('cfg-stunnel').value),
        udpgw_port: parseInt(document.getElementById('cfg-udpgw').value),
        internal_forward_port: parseInt(document.getElementById('cfg-internal').value)
    };
    const res = await fetchData('/settings/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    if (res) showStatus(res.message, true);
}

async function fetchHosts() {
    const data = await fetchData('/settings/hosts');
    document.getElementById('host-input').value = data?.hosts?.join('\n') || '';
}
async function saveHosts() {
    const hosts = document.getElementById('host-input').value.split('\n').map(x=>x.trim()).filter(x=>x);
    const res = await fetchData('/settings/hosts', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hosts}) });
    if(res) showStatus(res.message, true);
}

async function runSniFinder() {
    const host = document.getElementById('sni-host').value;
    const btn = document.getElementById('sni-btn');
    const out = document.getElementById('sni-result');
    if (!host) return;
    btn.classList.add('loading');
    const res = await fetchData('/utils/find_sni', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({hostname:host}) });
    btn.classList.remove('loading');
    if(res) out.textContent = `IP: ${res.ip}\nHosts:\n${res.hosts.join('\n')}`;
}

// --- 基础辅助 ---
function openModal(id) { document.getElementById(id).showModal(); }
function closeModal(id) { document.getElementById(id).close(); }
function showStatus(msg, success) {
    const el = document.getElementById('status-toast');
    el.textContent = msg;
    el.className = `alert ${success ? 'alert-success' : 'alert-error'} fixed top-4 right-4 w-auto z-50 shadow-lg`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 3000);
}
async function fetchData(url, opts) {
    try {
        const res = await fetch(API_BASE + url, opts);
        if (res.status === 401) { window.location.href = '/login.html'; return null; }
        const json = await res.json();
        return json.success ? json : (showStatus(json.message, false), null);
    } catch(e) { showStatus(e.message, false); return null; }
}
function formatSpeed(kbps) {
    if (!kbps) return '0.0 KB/s';
    return kbps < 1024 ? `${kbps.toFixed(1)} KB/s` : `${(kbps/1024).toFixed(2)} MB/s`;
}
function getStatusBadgeClass(status) {
    return status === 'active' ? 'badge-success' : (status === 'expired' ? 'badge-error' : 'badge-warning');
}
function setWsStatusIcon(color, title) {
    const btn = document.getElementById('ws-status-btn');
    if (btn) {
        btn.className = `btn btn-ghost btn-circle text-${color}-500`;
        btn.title = title;
    }
}
function switchView(view) {
    currentView = view;
    document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
    document.getElementById(`view-${view}`).classList.remove('hidden');
    document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
    document.getElementById(`nav-${view}`)?.classList.add('active');
    
    if (view === 'users') renderUserList();
    if (view === 'hosts') fetchHosts();
    if (view === 'port-config') fetchGlobalConfig();
    if (view === 'settings') fetchData('/system/audit_logs').then(d => document.getElementById('audit-logs').textContent = d?.logs?.join('\n'));
    if (view === 'payload-gen') populatePayloadUserSelect();
    if (view === 'security') fetchData('/ips/global_list').then(d => {
        document.getElementById('global-ban-list').innerHTML = Object.keys(d.global_bans).map(ip => `
            <div class="flex justify-between bg-base-200 p-2 rounded mb-2">
                <span>${ip}</span><button class="btn btn-xs btn-success" onclick="confirmAction('${ip}',null,null,'unbanGlobal','解封')">解封</button>
            </div>`).join('');
    });
    if (view === 'live-ips') fetchData('/system/active_ips').then(d => {
        document.getElementById('live-ip-list').innerHTML = d.active_ips.map(i => `
            <div class="flex justify-between bg-base-200 p-2 rounded mb-2">
                <span>${i.ip} (${i.username||'未知'})</span>
                <button class="btn btn-xs ${i.is_banned?'btn-success':'btn-error'}" onclick="confirmAction('${i.ip}',null,null,'${i.is_banned?'unbanGlobal':'banGlobal'}','${i.is_banned?'解封':'封禁'}')">${i.is_banned?'解封':'封禁'}</button>
            </div>`).join('');
    });
}

// --- 启动 ---
window.onload = () => {
    document.documentElement.setAttribute('data-theme', localStorage.getItem('theme') || 'light');
    initializeApp();
};
async function initializeApp() {
    lucide.createIcons();
    setupTokenListeners();
    setupPayloadAuthListeners();
    connectWebSocket();
    switchView('dashboard');
}
