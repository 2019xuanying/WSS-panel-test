/**
 * WSS Panel Frontend (Axiom V5.0 - Smart Push & Silent Updates)
 *
 * [AXIOM V5.0 CHANGELOG]
 * - [协议适配] 适配后端 V5.0 的分级推送策略:
 * - `live_update` (1s): 仅包含用户速度、流量增量和总连接数。
 * - `system_update` (3s): 包含 CPU、内存等系统级负载数据。
 * - [渲染优化] 全局静默更新 (Zero-Flicker):
 * - 重构 `renderSystemStatus`: 分离为 `initSystemStatus` (构建 DOM) 和 `updateSystemStatusSilent` (更新数值)。
 * - 仪表盘不再因数据刷新而重绘 DOM，仅修改 textContent。
 * - [图表] 内存泄漏修复:
 * - 增强了 Chart.js 实例的销毁逻辑 (safeDestroy)。
 * - [UX] 移除所有遗留的轮询代码，完全依赖 WebSocket 驱动。
 */

// --- 全局配置 ---
const API_BASE = '/api';
let currentView = 'dashboard';
let FLASK_CONFIG = {
    WSS_HTTP_PORT: "...",
    WSS_TLS_PORT: "...",
    STUNNEL_PORT: "...",
    UDPGW_PORT: "...",
    INTERNAL_FORWARD_PORT: "...",
    PANEL_PORT: "..."
};

// --- 全局状态变量 ---
let selectedUsers = []; 
let trafficChartInstance = null; 
let userStatsChartInstance = null;
let realtimeChartInstance = null; 
let allUsersCache = []; 
let currentSortKey = 'username';
let currentSortDir = 'asc';

let panelSocket = null; 
let wsReconnectTimer = null; 
let wsReconnectDelay = 1000; // 指数退避起始值

const TOKEN_PLACEHOLDER = "[*********]";

// --- 主题切换逻辑 ---
const themeToggle = document.getElementById('theme-toggle');
const htmlTag = document.documentElement;
const savedTheme = localStorage.getItem('theme') || 'light';
htmlTag.setAttribute('data-theme', savedTheme);
if (themeToggle) {
    themeToggle.checked = (savedTheme === 'dark');
    themeToggle.addEventListener('change', (e) => {
        const newTheme = e.target.checked ? 'dark' : 'light';
        htmlTag.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        // 切换主题时重绘图表以适配颜色
        safeDestroyChart(userStatsChartInstance);
        safeDestroyChart(realtimeChartInstance);
        userStatsChartInstance = null;
        realtimeChartInstance = null;
        
        // 重新加载数据以触发图表重建
        fetchAllStaticData();
    });
}

// --- 辅助工具函数 ---

function safeDestroyChart(chartInstance) {
    if (chartInstance) {
        try {
            chartInstance.destroy();
        } catch (e) {
            console.warn("Chart destroy error:", e);
        }
    }
}

function showStatus(message, isSuccess) {
    const statusDiv = document.getElementById('status-message');
    statusDiv.innerHTML = ''; 
    const iconName = isSuccess ? 'check-circle' : 'alert-triangle';
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', iconName);
    icon.className = 'w-6 h-6 mr-2';
    const text = document.createElement('span');
    text.textContent = message;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = "flex items-center";
    contentDiv.appendChild(icon);
    contentDiv.appendChild(text);
    
    statusDiv.appendChild(contentDiv);
    const colorClass = isSuccess ? 'alert-success' : 'alert-error';
    statusDiv.className = 'alert shadow-lg flex mb-6 ' + colorClass;
    statusDiv.style.display = 'flex'; 
    
    if (typeof lucide !== 'undefined') lucide.createIcons({ root: statusDiv });
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
}

function openModal(id) {
    const modal = document.getElementById(id);
    if (modal && typeof modal.showModal === 'function') modal.showModal();
}

function closeModal(id) {
    if (id === 'traffic-chart-modal') {
        safeDestroyChart(trafficChartInstance);
        trafficChartInstance = null;
    }
    const modal = document.getElementById(id);
    if (modal && typeof modal.close === 'function') modal.close();
}

function logout() {
    window.location.assign('/logout'); 
}

function formatSpeedUnits(kbps) {
    const rate = parseFloat(kbps);
    if (isNaN(rate) || rate <= 0) return '0.0 KB/s';
    if (rate < 1024) return rate.toFixed(1) + ' KB/s';
    return (rate / 1024).toFixed(2) + ' MB/s';
}

function formatConnections(count) {
    const num = parseInt(count);
    return (num === 0) ? '∞' : num;
}

function copyToClipboard(elementId, message) {
     const copyTextEl = document.getElementById(elementId);
     const copyText = copyTextEl.value;
     if (!copyText || copyText === TOKEN_PLACEHOLDER || copyText.startsWith('[在此输入')) {
         if (elementId === 'modal-connect-token') showStatus('请先在下方输入新密码以生成令牌。', false);
         else if (elementId === 'new-connect-token') showStatus('请先在表单中输入用户名和密码。', false);
         else if (elementId === 'payload-output') showStatus('请先生成载荷。', false);
         return;
     }
     try {
        navigator.clipboard.writeText(copyText).then(() => showStatus(message || '已复制！', true))
        .catch(() => {
            copyTextEl.select(); document.execCommand('copy'); showStatus(message || '已复制！', true);
        });
     } catch (err) {
         copyTextEl.select(); document.execCommand('copy'); showStatus(message || '已复制！', true);
     }
}

// --- 视图切换逻辑 ---

function switchView(viewId) {
    const views = ['dashboard', 'users', 'settings', 'security', 'live-ips', 'hosts', 'payload-gen', 'port-config'];
    views.forEach(id => {
        const element = document.getElementById('view-' + id);
        if (element) element.style.display = (id === viewId) ? 'block' : 'none';
    });
    
    document.querySelectorAll('#sidebar-menu .nav-link').forEach(link => {
        link.classList.toggle('active', link.dataset.view === viewId);
    });

    currentView = viewId;
    
    if (viewId === 'users') {
        document.getElementById('user-search-input').value = '';
        renderFilteredUserList();
    } else {
        clearSelections();
    }
    
    // 按需加载
    if (viewId === 'payload-gen' && allUsersCache.length > 0) populatePayloadUserSelect();
    if (viewId === 'hosts') fetchHosts();
    if (viewId === 'settings') { fetchGlobalSettings(); fetchAuditLogs(); }
    if (viewId === 'security') fetchGlobalBans(); 
    if (viewId === 'port-config') fetchGlobalConfig();
    if (viewId === 'live-ips') fetchActiveIPs(); 
    
    if (window.innerWidth < 1024) { 
        const drawerToggle = document.getElementById('my-drawer-2');
        if (drawerToggle) drawerToggle.checked = false;
    }
}

// --- WebSocket & 实时推送核心 ---

function setWsStatusIcon(color, tip) {
    const button = document.getElementById('ws-status-button');
    const tooltip = document.getElementById('ws-status-tooltip');
    if (!button || !tooltip) return;

    tooltip.setAttribute('data-tip', tip);
    
    let iconName = 'wifi';
    let iconClass = 'w-5 h-5 transition-colors duration-300 ';

    switch (color) {
        case 'red': iconClass += 'text-error'; iconName = 'wifi-off'; break;
        case 'green': iconClass += 'text-success'; iconName = 'wifi'; break;
        case 'blue': iconClass += 'text-info animate-spin'; iconName = 'loader-2'; break;
        default: iconClass += 'text-base-content/30'; iconName = 'wifi-off'; break;
    }
    
    // 使用 innerHTML 重建以确保 lucide 能重新渲染
    button.innerHTML = `<i data-lucide="${iconName}" class="${iconClass}"></i>`;
    if (typeof lucide !== 'undefined') lucide.createIcons({ root: button });
}

function connectWebSocket() {
    if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
    if (panelSocket) { panelSocket.close(); panelSocket = null; }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/ui`;
    
    setWsStatusIcon('blue', '正在连接实时推送...');

    panelSocket = new WebSocket(wsUrl);

    panelSocket.onopen = () => {
        console.log('[Axiom V5.0] WS Connected.');
        wsReconnectDelay = 1000; // 重置退避
    };

    panelSocket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            switch (msg.type) {
                case 'status_connected':
                    setWsStatusIcon('green', '实时推送已连接 (Smart Push)');
                    fetchAllStaticData(); 
                    break;
                
                case 'live_update': // 1秒高频推送 (用户/流量)
                    if (msg.payload) {
                        if (msg.payload.users) handleSilentUpdate(msg.payload.users);
                        if (msg.payload.system) handleDashboardStatsSilent(msg.payload.system);
                        updateRealtimeTrafficChart(msg.payload);
                    }
                    break;
                
                case 'system_update': // 3秒低频推送 (CPU/Mem)
                    if (msg.payload) updateSystemStatusSilent(msg.payload);
                    break;
                
                case 'users_changed':
                    console.log('[Axiom] User list changed, refreshing...');
                    fetchAllUsersAndRender();
                    break;
                
                case 'hosts_changed':
                    if (currentView === 'hosts') fetchHosts();
                    break;
                
                case 'auth_failed':
                    setWsStatusIcon('red', '认证失败');
                    window.location.assign('/login.html');
                    break;
            }
        } catch (e) { console.error('WS Parse Error:', e); }
    };

    panelSocket.onclose = (e) => {
        setWsStatusIcon('red', `已断开 (${e.code})，${wsReconnectDelay/1000}s后重连...`);
        wsReconnectTimer = setTimeout(connectWebSocket, wsReconnectDelay);
        wsReconnectDelay = Math.min(wsReconnectDelay * 1.5, 10000); // 简单退避
    };

    panelSocket.onerror = () => setWsStatusIcon('red', '连接错误');
}

// --- 仪表盘逻辑 (Axiom V5.0 重构) ---

/**
 * [Init] 初始化系统状态卡片 DOM (仅一次)
 */
function initSystemStatus(data) {
    const grid = document.getElementById('system-status-grid');
    if (!grid) return;
    grid.innerHTML = ''; // 清空骨架

    // 1. 状态数值网格
    const statsHtml = `
        <div class="stats stats-vertical lg:stats-horizontal shadow w-full bg-base-100 mb-4">
            <div class="stat">
                <div class="stat-figure text-blue-500"><i data-lucide="cpu" class="w-6 h-6"></i></div>
                <div class="stat-title">CPU (Load)</div>
                <div class="stat-value text-xl text-blue-500" id="stat-cpu-val">...%</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-indigo-500"><i data-lucide="brain" class="w-6 h-6"></i></div>
                <div class="stat-title">内存 (Used/Total)</div>
                <div class="stat-value text-xl text-indigo-500" id="stat-mem-val">.../... GB</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-purple-500"><i data-lucide="hard-drive" class="w-6 h-6"></i></div>
                <div class="stat-title">磁盘使用率</div>
                <div class="stat-value text-xl text-purple-500" id="stat-disk-val">${data.disk_used_percent}%</div>
            </div>
        </div>
    `;
    
    // 2. 服务状态列表
    let servicesHtml = `<div class="space-y-2 border-t border-base-300 pt-4"><h3 class="text-sm font-bold text-base-content/70 mb-2">服务控制</h3>`;
    Object.keys(data.services).forEach(key => {
        const item = data.services[key];
        const isRun = item.status === 'running';
        servicesHtml += `
            <div class="flex justify-between items-center p-2 bg-base-200 rounded-lg">
                <div class="flex items-center gap-2">
                    <span id="svc-dot-${key}" class="badge ${isRun ? 'badge-success' : 'badge-error'} badge-xs"></span>
                    <span class="text-sm font-medium">${item.name}</span>
                </div>
                <button onclick="confirmAction('${key}', 'restart', null, 'serviceControl', '重启 ${item.name}')" 
                        class="btn btn-xs ${isRun ? 'btn-ghost' : 'btn-error'}">
                    <i data-lucide="refresh-cw" class="w-3 h-3"></i>
                </button>
            </div>`;
    });
    servicesHtml += `</div>`;

    // 3. 端口状态列表
    let portsHtml = `<div class="space-y-2 border-t border-base-300 pt-4"><h3 class="text-sm font-bold text-base-content/70 mb-2">端口监听</h3>`;
    data.ports.forEach(p => {
        portsHtml += `
            <div class="flex justify-between items-center p-2 bg-base-200 rounded-lg">
                <span class="text-sm font-mono text-base-content/80">${p.name} (${p.port}/${p.protocol})</span>
                <span class="badge ${p.status === 'LISTEN' ? 'badge-success' : 'badge-error'} badge-sm font-bold">${p.status}</span>
            </div>`;
    });
    portsHtml += `</div>`;

    grid.innerHTML = statsHtml + servicesHtml + portsHtml;
    if (typeof lucide !== 'undefined') lucide.createIcons({ root: grid });
}

/**
 * [Update] 静默更新系统数值 (3s 推送)
 */
function updateSystemStatusSilent(data) {
    const cpuEl = document.getElementById('stat-cpu-val');
    const memEl = document.getElementById('stat-mem-val');
    
    if (cpuEl && data.cpu_usage !== undefined) cpuEl.textContent = data.cpu_usage.toFixed(1) + '%';
    if (memEl && data.memory_used_gb !== undefined) {
        // 假设 total 变化不大，这里我们可能需要从某处获取 total，或者后端传过来
        // 简化：后端 V5.0 代码中 payload 只发了 used_gb。
        // 我们在 initSystemStatus 时最好把 total 存一下，或者后端加上 total。
        // 查看 wss_panel.js: payload 只有 cpu_usage, memory_used_gb.
        // 为了显示 total，我们需要保存它。
        if (!window._sysTotalMem) window._sysTotalMem = "?"; 
        memEl.textContent = data.memory_used_gb.toFixed(2) + '/' + window._sysTotalMem + ' GB';
    }
}

/**
 * [Init] 初始化用户统计卡片
 */
function renderUserQuickStats(stats) {
    if (!stats) return;
    const container = document.getElementById('user-quick-stats-text');
    if (!container) return;

    // 仅在第一次时渲染结构
    if (!container.innerHTML.trim()) {
        container.innerHTML = `
            <div class="stat">
                <div class="stat-figure text-primary"><i data-lucide="users" class="w-8 h-8"></i></div>
                <div class="stat-title">账户总数</div>
                <div class="stat-value" id="stat-total-users">${stats.total}</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-success"><i data-lucide="activity" class="w-8 h-8"></i></div>
                <div class="stat-title">活跃连接 (IPs)</div>
                <div class="stat-value text-success" id="stat-active-conns">${stats.active}</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-secondary"><i data-lucide="pie-chart" class="w-8 h-8"></i></div>
                <div class="stat-title">总用量</div>
                <div class="stat-value text-secondary" id="stat-total-traffic">${stats.total_traffic_gb.toFixed(2)} GB</div>
            </div>`;
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: container });
    }

    // 更新图表
    const nonActive = stats.paused + stats.expired + stats.exceeded + (stats.fused || 0);
    const active = stats.total - nonActive;
    const ctx = document.getElementById('user-stats-chart').getContext('2d');
    const isDark = htmlTag.getAttribute('data-theme') === 'dark';
    
    if (userStatsChartInstance) {
        userStatsChartInstance.data.datasets[0].data = [active, nonActive];
        userStatsChartInstance.update();
    } else {
        userStatsChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['可用', '不可用'],
                datasets: [{
                    data: [active, nonActive],
                    backgroundColor: ['#34d399', '#d1d5db'],
                    borderColor: isDark ? '#1d232a' : '#ffffff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: { legend: { position: 'bottom', labels: { color: isDark ? '#a6adbb' : '#1f2937' } } }
            }
        });
    }
}

/**
 * [Update] 仪表盘数字静默更新 (1s 推送)
 */
function handleDashboardStatsSilent(systemStats) {
    const activeEl = document.getElementById('stat-active-conns');
    if (activeEl && systemStats.active_connections_total !== undefined) {
        activeEl.textContent = systemStats.active_connections_total;
    }
}

// --- 实时流量图表 ---

function initRealtimeTrafficChart() {
    safeDestroyChart(realtimeChartInstance);
    const ctx = document.getElementById('realtime-traffic-chart');
    if (!ctx) return;
    
    const initialLabels = Array(30).fill('');
    const initialDataUp = Array(30).fill(0);
    const initialDataDown = Array(30).fill(0);

    realtimeChartInstance = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: initialLabels,
            datasets: [
                {
                    label: '上传 (KB/s)',
                    data: initialDataUp,
                    borderColor: '#34d399',
                    backgroundColor: 'rgba(52, 211, 153, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                    pointRadius: 0
                },
                {
                    label: '下载 (KB/s)',
                    data: initialDataDown,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    tension: 0.3,
                    fill: true,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                y: { beginAtZero: true, ticks: { callback: v => v + ' KB/s' } },
                x: { display: false }
            },
            plugins: { legend: { position: 'bottom' }, tooltip: { mode: 'index', intersect: false } },
            interaction: { mode: 'nearest', intersect: false }
        }
    });
}

function updateRealtimeTrafficChart(payload) {
    if (!realtimeChartInstance || !payload.users) return;
    
    let totalUp = 0, totalDown = 0;
    for (const u in payload.users) {
        totalUp += (payload.users[u].speed_kbps.upload || 0);
        totalDown += (payload.users[u].speed_kbps.download || 0);
    }
    
    const data = realtimeChartInstance.data;
    data.labels.shift(); data.labels.push('');
    data.datasets[0].data.shift(); data.datasets[0].data.push(totalUp);
    data.datasets[1].data.shift(); data.datasets[1].data.push(totalDown);
    
    realtimeChartInstance.update();
}

// --- 用户列表处理 ---

function handleSilentUpdate(userStats) {
    // 1. 更新列表行
    for (const username in userStats) {
        const s = userStats[username];
        const speedUp = formatSpeedUnits(s.speed_kbps.upload);
        const speedDown = formatSpeedUnits(s.speed_kbps.download);
        
        const speedEl = document.getElementById(`speed-cell-${username}`);
        const connEl = document.getElementById(`conn-cell-${username}`);
        const speedMobUp = document.getElementById(`speed-up-mobile-${username}`);
        const speedMobDown = document.getElementById(`speed-down-mobile-${username}`);
        const connMob = document.getElementById(`conn-mobile-${username}`);

        if (speedEl) speedEl.innerHTML = `<span class="speed-up">↑ ${speedUp}</span> / <span class="speed-down">↓ ${speedDown}</span>`;
        if (connEl) connEl.textContent = s.connections;
        
        if (speedMobUp) speedMobUp.textContent = `↑ ${speedUp}`;
        if (speedMobDown) speedMobDown.textContent = `↓ ${speedDown}`;
        if (connMob) connMob.textContent = s.connections;
    }
}

// --- 数据加载 ---

async function fetchData(url, options = {}) {
    try {
        const res = await fetch(API_BASE + url, options);
        if (res.status === 401 || res.redirected) {
            window.location.assign('/login.html');
            return null;
        }
        const data = await res.json();
        if (!res.ok) {
            showStatus(data.message || 'Request failed', false);
            return null;
        }
        return data;
    } catch (e) {
        showStatus('Network error: ' + e.message, false);
        return null;
    }
}

async function fetchAllStaticData() {
    const statusData = await fetchData('/system/status');
    if (statusData) {
        window._sysTotalMem = statusData.memory_total_gb.toFixed(2); // 缓存 Total Mem
        initSystemStatus(statusData);
        renderUserQuickStats(statusData.user_stats);
        initRealtimeTrafficChart();
        
        // 隐藏骨架屏
        const skel = document.getElementById('dashboard-skeleton-loader');
        if (skel) skel.style.display = 'none';
        document.getElementById('system-status-card').style.display = 'block';
        document.getElementById('user-stats-card').style.display = 'block';
        document.getElementById('realtime-traffic-card').style.display = 'block';
    }
    await fetchAllUsersAndRender();
}

async function fetchAllUsersAndRender() {
    const data = await fetchData('/users/list');
    if (data) {
        allUsersCache = data.users;
        if (currentView === 'users') renderFilteredUserList();
        if (currentView === 'payload-gen') populatePayloadUserSelect();
    }
}

// --- 渲染用户列表 (PC & Mobile) ---
function renderFilteredUserList() {
    const tbody = document.getElementById('user-list-tbody');
    const mobileContainer = document.getElementById('user-list-mobile');
    if (!tbody) return;

    let users = [...allUsersCache];
    const search = document.getElementById('user-search-input').value.toLowerCase();
    if (search) users = users.filter(u => u.username.toLowerCase().includes(search));
    
    // 排序
    users.sort((a, b) => {
        let va = a[currentSortKey], vb = b[currentSortKey];
        if (currentSortKey === 'usage_gb' || currentSortKey === 'active_connections') {
            va = parseFloat(va) || 0; vb = parseFloat(vb) || 0;
        }
        if (va > vb) return currentSortDir === 'asc' ? 1 : -1;
        if (va < vb) return currentSortDir === 'asc' ? -1 : 1;
        return 0;
    });

    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-gray-500">无数据</td></tr>`;
        mobileContainer.innerHTML = `<div class="text-center py-4 text-gray-500">无数据</div>`;
        return;
    }

    let htmlPC = '', htmlMobile = '';
    users.forEach(u => {
        const statusColor = u.status === 'active' ? 'badge-success' : (u.status === 'paused' || u.status === 'fused' ? 'badge-warning' : 'badge-error');
        const isChecked = selectedUsers.includes(u.username) ? 'checked' : '';
        const usagePct = u.quota_gb > 0 ? (u.usage_gb / u.quota_gb) * 100 : 0;
        const progress = u.quota_gb > 0 ? `<progress class="progress progress-primary w-full" value="${usagePct}" max="100"></progress>` : '';
        
        // PC Row
        htmlPC += `
            <tr class="hover">
                <td class="px-4"><input type="checkbox" data-username="${u.username}" ${isChecked} class="checkbox checkbox-primary user-checkbox"></td>
                <td class="font-mono">${u.username}</td>
                <td><span class="badge ${statusColor} badge-sm">${u.status_text}</span></td>
                <td class="text-sm">${u.expiration_date || '永不'}</td>
                <td class="text-primary font-bold" id="conn-cell-${u.username}">${u.active_connections || 0}</td>
                <td>${formatConnections(u.max_connections)}</td>
                <td>
                    <div class="text-xs">${u.usage_gb.toFixed(3)} / ${u.quota_gb || '∞'} GB</div>
                    ${progress}
                </td>
                <td class="font-mono text-xs speed-cell" id="speed-cell-${u.username}">
                    <span class="speed-up">↑ ...</span> / <span class="speed-down">↓ ...</span>
                </td>
                <td>
                    <div class="flex gap-1">
                        <button class="btn btn-xs btn-square btn-ghost" onclick="openSettingsModal('${u.username}', '${u.expiration_date||''}', ${u.quota_gb}, ${u.rate_kbps}, ${u.max_connections}, ${u.require_auth_header}, ${u.allow_shell})"><i data-lucide="settings" class="w-4 h-4"></i></button>
                        <button class="btn btn-xs btn-square btn-ghost text-error" onclick="confirmAction('${u.username}', 'delete', null, 'deleteUser', '删除')"><i data-lucide="trash-2" class="w-4 h-4"></i></button>
                    </div>
                </td>
            </tr>`;
            
        // Mobile Card
        htmlMobile += `
            <div class="card bg-base-100 shadow-sm border-l-4 ${statusColor.replace('badge', 'border')}">
                <div class="card-body p-4">
                    <div class="flex justify-between items-center border-b pb-2 mb-2">
                        <div class="flex items-center gap-2">
                            <input type="checkbox" data-username="${u.username}" ${isChecked} class="checkbox checkbox-xs checkbox-primary user-checkbox">
                            <span class="font-bold text-lg">${u.username}</span>
                        </div>
                        <span class="badge ${statusColor} badge-xs">${u.status_text}</span>
                    </div>
                    <div class="text-sm space-y-1">
                        <div class="flex justify-between"><span>流量:</span> <span>${u.usage_gb.toFixed(2)} / ${u.quota_gb || '∞'} GB</span></div>
                        ${progress}
                        <div class="flex justify-between"><span>连接:</span> <span><strong id="conn-mobile-${u.username}">${u.active_connections||0}</strong> / ${formatConnections(u.max_connections)}</span></div>
                        <div class="flex justify-between font-mono text-xs">
                            <span id="speed-up-mobile-${u.username}" class="text-success">↑ ...</span>
                            <span id="speed-down-mobile-${u.username}" class="text-warning">↓ ...</span>
                        </div>
                    </div>
                    <div class="grid grid-cols-4 gap-2 mt-3">
                        <button class="btn btn-xs btn-outline" onclick="openTrafficChartModal('${u.username}')">流量</button>
                        <button class="btn btn-xs btn-outline btn-error" onclick="confirmAction('${u.username}', null, null, 'killAll', '踢下线')">踢人</button>
                        <button class="btn btn-xs btn-primary col-span-2" onclick="openSettingsModal('${u.username}', '${u.expiration_date||''}', ${u.quota_gb}, ${u.rate_kbps}, ${u.max_connections}, ${u.require_auth_header}, ${u.allow_shell})">设置</button>
                    </div>
                </div>
            </div>`;
    });
    
    tbody.innerHTML = htmlPC;
    mobileContainer.innerHTML = htmlMobile;
    if (typeof lucide !== 'undefined') lucide.createIcons({ root: tbody });
    bindCheckboxEvents();
}

// --- 事件绑定与初始化 ---

function bindCheckboxEvents() {
    const selectAll = document.getElementById('select-all-users');
    const checkboxes = document.querySelectorAll('.user-checkbox');
    
    if (selectAll) {
        selectAll.onchange = (e) => {
            selectedUsers = e.target.checked ? Array.from(checkboxes).map(c => c.dataset.username) : [];
            checkboxes.forEach(c => c.checked = e.target.checked);
            updateBatchBar();
        };
    }
    
    checkboxes.forEach(c => {
        c.onchange = (e) => {
            const u = e.target.dataset.username;
            if (e.target.checked) { if (!selectedUsers.includes(u)) selectedUsers.push(u); }
            else selectedUsers = selectedUsers.filter(x => x !== u);
            updateBatchBar();
        };
    });
}

function updateBatchBar() {
    const bar = document.getElementById('batch-action-bar');
    document.getElementById('selected-user-count').textContent = selectedUsers.length;
    bar.classList.toggle('visible', selectedUsers.length > 0);
}

// 初始化启动
window.onload = async () => {
    if (typeof lucide === 'undefined') {
        console.error("Lucide icons library failed to load.");
    }
    
    // 加载基础配置 (Ports) - 仅用于展示，不影响核心逻辑
    const cfg = await fetchData('/settings/config');
    if (cfg && cfg.config) FLASK_CONFIG = cfg.config;

    switchView('dashboard');
    connectWebSocket(); // 启动核心
    
    // 绑定搜索和排序
    document.getElementById('user-search-input').addEventListener('input', renderFilteredUserList);
    document.querySelectorAll('th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sortkey;
            if (currentSortKey === key) currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
            else { currentSortKey = key; currentSortDir = 'asc'; }
            renderFilteredUserList();
        });
    });
    
    setupPayloadAuthListeners(); // 保留载荷生成器逻辑
};

// --- 保留的业务逻辑 (Modal Actions, Payload Gen etc.) ---
// 这些函数逻辑与 V4 保持一致，只是 UI 调用

async function confirmAction(p1, p2, p3, type, title) {
    document.getElementById('confirm-title').textContent = title;
    document.getElementById('confirm-message').textContent = '确定要执行此操作吗？';
    document.getElementById('confirm-param1').value = p1 || '';
    document.getElementById('confirm-param2').value = p2 || '';
    document.getElementById('confirm-param3').value = p3 || '';
    document.getElementById('confirm-type').value = type;
    
    const btn = document.getElementById('confirm-action-btn');
    btn.onclick = async () => {
        closeModal('confirm-modal');
        let url = '', body = {};
        if (type === 'deleteUser') { url = '/users/delete'; body = { username: p1 }; }
        else if (type === 'killAll') { url = '/users/kill_all'; body = { username: p1 }; }
        else if (type === 'serviceControl') { url = '/system/control'; body = { service: p1, action: p2 }; }
        else if (type === 'resetTraffic') { url = '/users/reset_traffic'; body = { username: p1 }; }
        
        if (url) {
            const res = await fetchData(url, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
            if (res && res.success) showStatus(res.message || '操作成功', true);
        }
    };
    openModal('confirm-modal');
}

// Payload Generator Logic (Simplified)
function setupPayloadAuthListeners() {
    const u = document.getElementById('payload-username');
    const p = document.getElementById('payload-password');
    const t = document.getElementById('payload-auth-token');
    const update = () => {
        if(u.value && p.value) t.value = btoa(u.value + ':' + p.value);
        else t.value = TOKEN_PLACEHOLDER;
    };
    if(u && p) { u.oninput = update; p.oninput = update; }
}

function populatePayloadUserSelect() {
    const sel = document.getElementById('payload-user-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">-- 手动输入 --</option>';
    allUsersCache.forEach(u => {
        const opt = document.createElement('option');
        opt.value = u.username; opt.textContent = u.username;
        sel.appendChild(opt);
    });
    sel.onchange = (e) => {
        if (e.target.value) {
            document.getElementById('payload-username').value = e.target.value;
            document.getElementById('payload-password').focus();
        }
    };
}

// User Settings Modal
function openSettingsModal(user, exp, quota, rate, maxConn, auth, shell) {
    document.getElementById('modal-username-title-settings').textContent = user;
    document.getElementById('modal-username-setting').value = user;
    document.getElementById('modal-expiry-date').value = exp;
    document.getElementById('modal-quota-gb').value = quota;
    document.getElementById('modal-rate-kbps').value = rate;
    document.getElementById('modal-max-connections').value = maxConn;
    document.getElementById('modal-require-auth').checked = (parseInt(auth) === 1);
    document.getElementById('modal-allow-shell').checked = (parseInt(shell) === 1);
    document.getElementById('modal-new-password').value = '';
    openModal('settings-modal');
}

async function saveUserSettings() {
    const body = {
        username: document.getElementById('modal-username-setting').value,
        expiry_date: document.getElementById('modal-expiry-date').value,
        quota_gb: document.getElementById('modal-quota-gb').value,
        rate_kbps: document.getElementById('modal-rate-kbps').value,
        max_connections: document.getElementById('modal-max-connections').value,
        require_auth_header: document.getElementById('modal-require-auth').checked,
        allow_shell: document.getElementById('modal-allow-shell').checked,
        new_password: document.getElementById('modal-new-password').value
    };
    closeModal('settings-modal');
    const res = await fetchData('/users/set_settings', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    if (res && res.success) showStatus('设置已保存', true);
}

// Port Config
async function saveGlobalConfig() {
    const body = {
        panel_port: document.getElementById('config-panel-port').value,
        wss_http_port: document.getElementById('config-wss-http-port').value,
        wss_tls_port: document.getElementById('config-wss-tls-port').value,
        stunnel_port: document.getElementById('config-stunnel-port').value,
        udpgw_port: document.getElementById('config-udpgw-port').value,
        internal_forward_port: document.getElementById('config-internal-forward-port').value
    };
    const res = await fetchData('/settings/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    if (res && res.success) showStatus(res.message, true);
}

// Hosts
async function fetchHosts() {
    const res = await fetchData('/settings/hosts');
    if (res) document.getElementById('host-list-textarea').value = res.hosts.join('\n');
}
async function saveHosts() {
    const hosts = document.getElementById('host-list-textarea').value.split('\n');
    const res = await fetchData('/settings/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ hosts }) });
    if (res && res.success) showStatus(res.message, true);
}

// Logs & Traffic History (Standard Fetch)
async function openTrafficChartModal(username) {
    openModal('traffic-chart-modal');
    const res = await fetchData(`/users/traffic-history?username=${username}`);
    if (res && res.history) {
        const ctx = document.getElementById('trafficChartCanvas');
        safeDestroyChart(trafficChartInstance);
        trafficChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: res.history.map(h => h.date.slice(5)),
                datasets: [{ label: 'GB', data: res.history.map(h => h.usage_gb), backgroundColor: '#3b82f6' }]
            }
        });
        document.getElementById('traffic-chart-loading').style.display = 'none';
    }
}
