/**
 * WSS Panel Frontend (Axiom Refactor V6.0 - Realtime Push Optimization)
 *
 * [AXIOM V6.0 CHANGELOG]
 * - OPTIMIZE: 强化 handleSilentUpdate，通过直接操作 DOM 元素（而不是重绘整个列表）来最小化 CPU 使用率。
 * - NEW: CORE_SERVICES_MAP 增加 'xray' 服务。
 * - PREP: 在配置中增加 internal_wss_port, xray_internal_port, nginx_enabled 字段，以支持后续的 Xray/Nginx 集成。
 */

// --- 全局配置 (将由 initializeApp 异步填充) ---
const API_BASE = '/api';
let currentView = 'dashboard';
let FLASK_CONFIG = {
    WSS_HTTP_PORT: "...",
    WSS_TLS_PORT: "...",
    STUNNEL_PORT: "...",
    UDPGW_PORT: "...",
    SSH_UDP_PORT: "...",
    INTERNAL_WSS_PORT: "...", // [NEW V6.0]
    XRAY_INTERNAL_PORT: "...", // [NEW V6.0]
    PANEL_PORT: "...",
    NGINX_ENABLED: 0 // [NEW V6.0]
};

// --- 全局变量 ---
let selectedUsers = []; 
let trafficChartInstance = null; 
let userStatsChartInstance = null;
let realtimeChartInstance = null; 
let allUsersCache = []; 
let currentSortKey = 'username';
let currentSortDir = 'asc';

let panelSocket = null; 
let wsReconnectTimer = null; 

let lastUserStats = { total: -1, total_traffic_gb: -1 };

const TOKEN_PLACEHOLDER = "[*********]";

// [AXIOM V6.0 FIX] 注册新的 Xray 服务
const CORE_SERVICES_MAP = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'BadVPN UDPGW', 
    'ssh_udp': 'SSH-UDP Auth',
    'xray': 'Xray Core', // [NEW] Xray Service
    'wss_panel': 'Web Panel'
};

// --- 主题切换逻辑 ---
const themeToggle = document.getElementById('theme-toggle');
const htmlTag = document.documentElement;
const savedTheme = localStorage.getItem('theme') || 'light';
htmlTag.setAttribute('data-theme', savedTheme);
if (themeToggle) {
    themeToggle.checked = (savedTheme === 'dark');
}
if (themeToggle) {
    themeToggle.addEventListener('change', (e) => {
        const newTheme = e.target.checked ? 'dark' : 'light';
        htmlTag.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        if (userStatsChartInstance) {
            userStatsChartInstance.destroy();
            userStatsChartInstance = null;
        }
        if (realtimeChartInstance) {
            realtimeChartInstance.destroy();
            realtimeChartInstance = null;
        }
        lastUserStats = {}; 
        
        fetchData('/system/status').then(data => {
            if (data) {
                renderSystemStatus(data); 
                renderUserQuickStats(data.user_stats);
                initRealtimeTrafficChart();
            }
        });
    });
}

// --- 辅助工具函数 ---

function showStatus(message, isSuccess) {
    const statusDiv = document.getElementById('status-message');
    statusDiv.innerHTML = ''; 
    const iconName = isSuccess ? 'check-circle' : 'alert-triangle';
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', iconName);
    icon.className = 'w-6 h-6';
    const text = document.createElement('span');
    text.textContent = message;
    statusDiv.appendChild(icon);
    statusDiv.appendChild(text);
    const colorClass = isSuccess ? 'alert-success' : 'alert-error';
    statusDiv.className = 'alert shadow-lg flex mb-6 ' + colorClass;
    statusDiv.style.display = 'flex'; 
    lucide.createIcons({ context: statusDiv });
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => { 
        statusDiv.style.display = 'none'; 
    }, 5000);
}

function openModal(id) {
    const modal = document.getElementById(id);
    if (modal && typeof modal.showModal === 'function') {
        modal.showModal();
    }
}

function closeModal(id) {
    if (id === 'traffic-chart-modal' && trafficChartInstance) {
        trafficChartInstance.destroy();
        trafficChartInstance = null;
    }
    const modal = document.getElementById(id);
    if (modal && typeof modal.close === 'function') {
        modal.close();
    }
}

function logout() {
    window.location.assign('/logout'); 
}

function formatSpeedUnits(kbps) {
    const rate = parseFloat(kbps);
    if (isNaN(rate) || rate <= 0) return '0.0 KB/s';
    
    if (rate < 1024) {
        return rate.toFixed(1) + ' KB/s';
    } else {
        const mbps = rate / 1024;
        return mbps.toFixed(2) + ' MB/s';
    }
}

function formatConnections(count) {
    const num = parseInt(count);
    return (num === 0) ? '∞' : num;
}

function copyToClipboard(elementId, message) {
     const copyTextEl = document.getElementById(elementId);
     const copyText = copyTextEl.value;
     if (!copyText || copyText === TOKEN_PLACEHOLDER || copyText.startsWith('[在此输入')) {
         if (elementId === 'modal-connect-token') {
             showStatus('请先在下方输入新密码以生成令牌。', false);
         } else if (elementId === 'new-connect-token') {
             showStatus('请先在表单中输入用户名和密码。', false);
         } else if (elementId === 'payload-output') {
             showStatus('请先生成载荷。', false);
         }
         return;
     }
     try {
        navigator.clipboard.writeText(copyText).then(() => {
            showStatus(message || '已复制到剪贴板！', true);
        }).catch(err => {
            // Fallback for non-secure contexts or older browsers
            copyTextEl.select();
            document.execCommand('copy');
            showStatus(message || '已复制到剪贴板！', true);
        });
     } catch (err) {
         copyTextEl.select();
         document.execCommand('copy');
         showStatus(message || '已复制到剪贴板！', true);
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
        if (link.dataset.view === viewId) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    currentView = viewId;
    
    if (viewId === 'users') {
        document.getElementById('user-search-input').value = '';
        currentSortKey = 'username';
        currentSortDir = 'asc';
        renderFilteredUserList();
    } else {
        clearSelections();
    }
    
    // 按需加载数据
    if (viewId === 'payload-gen') {
        if (allUsersCache.length > 0) {
            populatePayloadUserSelect();
        } else {
            fetchAllUsersAndRender(); 
        }
    }
    
    if (viewId === 'hosts') {
        fetchHosts();
    }
    
    if (viewId === 'settings') {
        fetchGlobalSettings();
        fetchAuditLogs(); 
    }
    
    if (viewId === 'security') {
        fetchGlobalBans(); 
    }
    
    if (viewId === 'port-config') {
        fetchGlobalConfig();
    }
    
    if (viewId === 'live-ips') {
        fetchActiveIPs(); 
    }
    
    if (window.innerWidth < 1024) { 
        const drawerToggle = document.getElementById('my-drawer-2');
        if (drawerToggle) {
            drawerToggle.checked = false;
        }
    }
}

// --- 数据渲染函数 ---

/**
 * [AXIOM V6.0 FIX] 核心服务列表已更新
 */
function renderSystemStatus(data) {
    const grid = document.getElementById('system-status-grid');
    grid.innerHTML = ''; 
    grid.className = "space-y-4"; 

    const fragment = document.createDocumentFragment();
    
    // --- 1. 渲染系统状态 (CPU/内存/磁盘) ---
    const systemItems = [
        { name: 'CPU 使用率 (LoadAvg)', value: data.cpu_usage.toFixed(1) + '%', color: 'text-blue-500', icon: 'cpu', id: 'stat-cpu' },
        { name: '内存 (用/总)', value: data.memory_used_gb.toFixed(2) + '/' + data.memory_total_gb.toFixed(2) + 'GB', color: 'text-indigo-500', icon: 'brain', id: 'stat-mem' },
        { name: '磁盘使用率', value: data.disk_used_percent.toFixed(1) + '%', color: 'text-purple-500', icon: 'database', id: 'stat-disk' },
    ];
    
    const statsGrid = document.createElement('div');
    statsGrid.className = "stats stats-vertical shadow w-full bg-base-100";
    
    systemItems.forEach(item => {
        const card = document.createElement('div');
        card.className = 'stat';
        card.innerHTML = 
            `<div class="stat-figure ${item.color}"><i data-lucide="${item.icon}" class="w-6 h-6"></i></div>` +
            `<div class="stat-title text-sm">${item.name}</div>` +
            `<div class="stat-value text-xl ${item.color} flex items-center" id="${item.id}">` + 
                 item.value +
            '</div>';
        statsGrid.appendChild(card);
    });
    fragment.appendChild(statsGrid);
    
    // --- 2. 渲染服务状态 (带按钮) ---
    const servicesTitle = document.createElement('h3');
    servicesTitle.className = "text-lg font-semibold pt-4 border-t border-base-300";
    servicesTitle.textContent = "服务控制";
    fragment.appendChild(servicesTitle);
    
    const servicesContainer = document.createElement('div');
    servicesContainer.className = "space-y-2";
    
    Object.keys(data.services).forEach(key => {
        const item = data.services[key];
        const status = item.status;
        let dotClass;
        if (status === 'running') {
            dotClass = 'badge-success';
        } else {
            dotClass = 'badge-error';
        }
        
        const div = document.createElement('div');
        div.id = `service-status-${key}`;
        div.className = 'flex justify-between items-center text-base-content p-2 bg-base-200 rounded-lg border border-base-300';
        div.innerHTML = 
            `<div class="flex items-center">
                <span id="service-dot-${key}" class="badge ${dotClass} badge-xs mr-2 p-1"></span>
                <span class="font-medium text-sm">${item.name}</span>
            </div>
            <button onclick="confirmAction('${key}', 'restart', null, 'serviceControl', '重启 ${item.name}')" 
                    class="btn ${status === 'running' ? 'btn-primary' : 'btn-error'} btn-xs">
                <i data-lucide="refresh-cw" class="w-3 h-3"></i> 重启
            </button>`;
        servicesContainer.appendChild(div);
    });
    fragment.appendChild(servicesContainer);

    // --- 3. 渲染端口状态 ---
    const portsTitle = document.createElement('h3');
    portsTitle.className = "text-lg font-semibold pt-4 border-t border-base-300";
    portsTitle.textContent = "端口状态";
    fragment.appendChild(portsTitle);
    
    const portsContainer = document.createElement('div');
    portsContainer.className = "space-y-2";
    
    data.ports.forEach(p => {
        const isListening = p.status === 'LISTEN';
        const badgeClass = isListening ? 'badge-success' : 'badge-error';
        const portNote = p.note ? `<span class="text-xs text-warning ml-2">(${p.note})</span>` : '';
        const div = document.createElement('div');
        div.id = `port-status-${p.name}`;
        div.className = 'flex justify-between items-center text-gray-700 p-2 bg-base-200 rounded-lg shadow-sm border border-base-300';
        div.innerHTML = 
            `<span class="font-medium text-sm">
                ${p.name} (${p.port}/${p.protocol}):
                ${portNote}
            </span>` +
            `<span class="badge ${badgeClass} badge-sm font-bold" id="port-badge-${p.name}">` + p.status +
            '</span>';
        portsContainer.appendChild(div);
    });
    fragment.appendChild(portsContainer);
    
    // --- 最终渲染 ---
    grid.appendChild(fragment);
    lucide.createIcons({ context: grid });
}

function handleSystemUpdateMessage(data) {
    if (currentView !== 'dashboard') return;
    
    // 1. 更新系统资源统计
    const statCpu = document.getElementById('stat-cpu');
    const statMem = document.getElementById('stat-mem');
    const statDisk = document.getElementById('stat-disk');

    if (statCpu) statCpu.textContent = data.cpu_usage.toFixed(1) + '%';
    if (statMem) statMem.textContent = data.memory_used_gb.toFixed(2) + '/' + data.memory_total_gb.toFixed(2) + 'GB';
    if (statDisk) statDisk.textContent = data.disk_used_percent.toFixed(1) + '%';
    
    // 2. 更新服务状态
    Object.keys(data.services).forEach(key => {
        const item = data.services[key];
        const dot = document.getElementById(`service-dot-${key}`);
        
        if (dot) {
            const isRunning = item.status === 'running';
            dot.className = `badge ${isRunning ? 'badge-success' : 'badge-error'} badge-xs mr-2 p-1`;
        }
    });

    // 3. 更新端口状态
    data.ports.forEach(p => {
        const badge = document.getElementById(`port-badge-${p.name}`);
        if (badge) {
            const isListening = p.status === 'LISTEN';
            badge.className = `badge ${isListening ? 'badge-success' : 'badge-error'} badge-sm font-bold`;
            badge.textContent = p.status;
        }
    });

    // 4. 更新用户快速统计卡片
    renderUserQuickStats(data.user_stats);
}


function renderUserQuickStats(stats) {
    if (!stats) return;
    
    const total = stats.total;
    const active = stats.active; 
    const nonActive = stats.paused + stats.expired + stats.exceeded + (stats.fused || 0);
    
    const container = document.getElementById('user-quick-stats-text');
    
    if (total !== lastUserStats.total || active !== lastUserStats.active || stats.total_traffic_gb !== lastUserStats.total_traffic_gb || lastUserStats.total === -1) {
         container.innerHTML = 
            `<div class="stat">
                <div class="stat-figure text-primary"><i data-lucide="users" class="w-8 h-8"></i></div>
                <div class="stat-title">账户总数</div>
                <div class="stat-value" id="stat-total-users">${total}</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-success"><i data-lucide="activity" class="w-8 h-8"></i></div>
                <div class="stat-title">活跃连接 (IPs)</div>
                <div class="stat-value text-success" id="stat-active-conns">${active}</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-warning"><i data-lucide="user-x" class="w-8 h-8"></i></div>
                <div class="stat-title">暂停/不可用账户</div>
                <div class="stat-value text-warning" id="stat-inactive-users">${nonActive}</div>
            </div>
            <div class="stat">
                <div class="stat-figure text-secondary"><i data-lucide="pie-chart" class="w-8 h-8"></i></div>
                <div class="stat-title">总用量</div>
                <div class="stat-value" id="stat-total-traffic">${stats.total_traffic_gb.toFixed(2)} GB</div>
            </div>`;
        lucide.createIcons({ context: container });
    } else {
         const activeConnsEl = document.getElementById('stat-active-conns');
         const totalTrafficEl = document.getElementById('stat-total-traffic');
         const inactiveUsersEl = document.getElementById('stat-inactive-users');

         if (activeConnsEl) activeConnsEl.textContent = active;
         if (totalTrafficEl) totalTrafficEl.textContent = stats.total_traffic_gb.toFixed(2) + ' GB';
         if (inactiveUsersEl) inactiveUsersEl.textContent = nonActive;
    }

    lastUserStats = stats;
    
    // 更新饼图
    const ctx = document.getElementById('user-stats-chart').getContext('2d');
    const activeAccounts = total - nonActive; 
    const chartDataValues = [(activeAccounts || 0), (nonActive || 0)];
    if (total === 0) {
        chartDataValues[0] = 1;
        chartDataValues[1] = 0;
    }
    const chartData = {
        labels: ['可连接账户', '不可用账户'], 
        datasets: [{
            data: chartDataValues,
            backgroundColor: [
                (total > 0) ? '#00a96e' : '#d1d5db', 
                (total > 0) ? '#fbbd23' : '#d1d5db'  
            ],
            borderColor: htmlTag.getAttribute('data-theme') === 'dark' ? '#1d232a' : '#ffffff', 
            borderWidth: 2,
            hoverOffset: 4
        }]
    };
    if (userStatsChartInstance) {
        userStatsChartInstance.data = chartData;
        userStatsChartInstance.options.plugins.legend.labels.color = htmlTag.getAttribute('data-theme') === 'dark' ? '#a6adbb' : '#4f5664';
        userStatsChartInstance.options.borderColor = htmlTag.getAttribute('data-theme') === 'dark' ? '#1d232a' : '#ffffff';
        userStatsChartInstance.update();
    } else {
        userStatsChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 10,
                            color: htmlTag.getAttribute('data-theme') === 'dark' ? '#a6adbb' : '#4f5664' 
                        }
                    }
                }
            }
        });
    }
}

function handleDashboardConnectionSilentUpdate(systemStats) {
    if (currentView !== 'dashboard') return; 
    const activeConnsWidget = document.getElementById('stat-active-conns');
    if (activeConnsWidget) {
        activeConnsWidget.textContent = systemStats.active_connections_total;
    }
}


/**
 * [AXIOM V6.0 FIX] 核心服务列表已更新
 */
async function fetchAllStaticData() {
    try {
        const data = await fetchData('/settings/config');
        if (data && data.config) {
            FLASK_CONFIG = {
                WSS_HTTP_PORT: data.config.wss_http_port,
                WSS_TLS_PORT: data.config.wss_tls_port,
                STUNNEL_PORT: data.config.stunnel_port,
                UDPGW_PORT: data.config.udpgw_port,
                SSH_UDP_PORT: data.config.ssh_udp_port,
                INTERNAL_WSS_PORT: data.config.internal_wss_port, // [NEW V6.0] Load new port
                XRAY_INTERNAL_PORT: data.config.xray_internal_port, // [NEW V6.0] Load new port
                PANEL_PORT: data.config.panel_port
            };
        }
        
        // 2. 加载仪表盘数据 (将触发全量渲染)
        const statusData = await fetchData('/system/status');
        if (statusData) {
            renderSystemStatus(statusData);
            renderUserQuickStats(statusData.user_stats); 
            FLASK_CONFIG.NGINX_ENABLED = statusData.nginx_enabled;
            initRealtimeTrafficChart();
        }

        // 3. 加载用户列表
        await fetchAllUsersAndRender();
        
        // 4. 更新日志按钮以匹配 CORE_SERVICES_MAP
        const btnGroup = document.querySelector('#view-settings .btn-group');
        if (btnGroup) {
            btnGroup.innerHTML = '';
            Object.keys(CORE_SERVICES_MAP).forEach(key => {
                const newButton = document.createElement('button');
                newButton.setAttribute('onclick', `fetchServiceLogs('${key}')`);
                newButton.className = 'btn btn-ghost btn-sm';
                newButton.textContent = CORE_SERVICES_MAP[key];
                btnGroup.appendChild(newButton);
            });
        }
        
        if (currentView === 'settings') { 
            fetchAuditLogs(); 
        }
        if (currentView === 'security') { fetchGlobalBans(); }
        
        // 5. 隐藏骨架屏, 显示真实卡片
        const skeleton = document.getElementById('dashboard-skeleton-loader');
        const card1 = document.getElementById('system-status-card');
        const card2 = document.getElementById('user-stats-card');
        const card3 = document.getElementById('realtime-traffic-card');

        if (skeleton) skeleton.style.display = 'none';
        if (card1) card1.style.display = 'block';
        if (card2) card2.style.display = 'block';
        if (card3) card3.style.display = 'block';
        
    } catch (error) {
        console.error("Error during fetchAllStaticData:", error);
    }
}

async function fetchGlobalConfig() {
     const data = await fetchData('/settings/config');
     if (data && data.config) {
        document.getElementById('config-panel-port').value = data.config.panel_port;
        document.getElementById('config-wss-http-port').value = data.config.wss_http_port;
        document.getElementById('config-wss-tls-port').value = data.config.wss_tls_port;
        document.getElementById('config-stunnel-port').value = data.config.stunnel_port;
        document.getElementById('config-udpgw-port').value = data.config.udpgw_port;
        document.getElementById('config-ssh-udp-port').value = data.config.ssh_udp_port;
        // [NEW V6.0] 端口
        document.getElementById('config-internal-wss-port').value = data.config.internal_wss_port || 44333;
        document.getElementById('config-xray-internal-port').value = data.config.xray_internal_port || 44444;
        document.getElementById('config-nginx-external-port').value = data.config.nginx_external_port || 443;
        // [NEW V6.0] 内部/转发端口
        document.getElementById('config-internal-forward-port').value = data.config.internal_forward_port;
        document.getElementById('config-internal-api-port').value = data.config.internal_api_port;
     }
     
     // 加载 Nginx 启用状态
     const globalData = await fetchData('/settings/global');
     if (globalData && globalData.settings) {
        document.getElementById('global-nginx-enable').checked = (globalData.settings.nginx_enabled === 1);
        FLASK_CONFIG.NGINX_ENABLED = globalData.settings.nginx_enabled;
     }
     
}

async function saveGlobalConfig() {
    showStatus('正在保存端口配置...', true);
    
    const configData = {
        panel_port: parseInt(document.getElementById('config-panel-port').value),
        wss_http_port: parseInt(document.getElementById('config-wss-http-port').value),
        wss_tls_port: parseInt(document.getElementById('config-wss-tls-port').value),
        stunnel_port: parseInt(document.getElementById('config-stunnel-port').value),
        udpgw_port: parseInt(document.getElementById('config-udpgw-port').value),
        ssh_udp_port: parseInt(document.getElementById('config-ssh-udp-port').value),
        // [NEW V6.0]
        internal_wss_port: parseInt(document.getElementById('config-internal-wss-port').value),
        xray_internal_port: parseInt(document.getElementById('config-xray-internal-port').value),
        nginx_external_port: parseInt(document.getElementById('config-nginx-external-port').value),
        // [END NEW V6.0]
        internal_forward_port: parseInt(document.getElementById('config-internal-forward-port').value)
    };
    
    const result = await fetchData('/settings/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configData)
    });
    
    if (result) {
        showStatus(result.message, true);
        if (configData.panel_port !== FLASK_CONFIG.PANEL_PORT) {
            showStatus('面板端口已更改！页面将在 3 秒后尝试使用新端口重新加载...', true);
            setTimeout(() => {
                window.location.port = configData.panel_port;
                window.location.reload();
            }, 3000);
        } else {
             // 端口未变，刷新系统状态以更新端口列表
             fetchAllStaticData(); 
        }
    }
}

function fetchServiceLogs(serviceId) {
    const logContainer = document.getElementById('service-log-content');
    logContainer.textContent = '正在加载 ' + CORE_SERVICES_MAP[serviceId] + ' 日志...';
    fetchData('/system/logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: serviceId })
    }).then(data => {
        if (data && data.logs) {
            const prefixedLogs = data.logs.split('\n').map(line => `~$ ${line}`).join('\n');
            logContainer.textContent = prefixedLogs;
        } else {
            logContainer.textContent = `~$ 无法加载 ${CORE_SERVICES_MAP[serviceId]} 日志。`;
        }
    });
}

async function fetchHosts() {
     const data = await fetchData('/settings/hosts');
     if (data && data.hosts) {
        renderHosts(data.hosts);
     } else {
        renderHosts([]);
     }
}

async function saveHosts() {
    const textarea = document.getElementById('host-list-textarea');
    const hostsArray = textarea.value.split('\n').map(h => h.trim()).filter(h => h.length > 0);
    showStatus('正在保存 Host 配置并通知 WSS 代理热重载...', true);
    const result = await fetchData('/settings/hosts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: hostsArray })
    });
    if (result) {
        showStatus(result.message, true);
    }
}

async function fetchGlobalSettings() {
     const data = await fetchData('/settings/global');
     if (data && data.settings) {
        document.getElementById('global-fuse-threshold').value = data.settings.fuse_threshold_kbps || 0;
        document.getElementById('global-nginx-enable').checked = (data.settings.nginx_enabled === 1);
     }
}

async function saveGlobalSettings() {
    const fuseThreshold = document.getElementById('global-fuse-threshold').value;
    const nginxEnabled = document.getElementById('global-nginx-enable').checked ? 1 : 0;
    
    showStatus('正在保存全局安全设置并实时通知所有代理...', true);
    
    const result = await fetchData('/settings/global', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            fuse_threshold_kbps: parseInt(fuseThreshold),
            nginx_enabled: nginxEnabled
        })
    });
    
    if (result) {
        showStatus(result.message, true);
        FLASK_CONFIG.NGINX_ENABLED = nginxEnabled;
        // 触发状态更新以显示端口变化
        fetchAllStaticData(); 
    }
}

async function fetchAuditLogs() {
    const auditData = await fetchData('/system/audit_logs');
    if (auditData) {
        renderAuditLogs(auditData.logs);
    }
}
async function fetchGlobalBans() {
    const globalData = await fetchData('/ips/global_list');
    if (globalData) {
        renderGlobalBans(globalData.global_bans);
    }
}

function renderHosts(hosts) {
    const textarea = document.getElementById('host-list-textarea');
    const countInfo = document.getElementById('host-count-info');
    textarea.value = hosts.join('\n');
    const validHosts = hosts.filter(h => h.trim() !== '');
    countInfo.textContent = `当前加载 ${validHosts.length} 个 Host。`;
}

function renderGlobalBans(bans) {
    const container = document.getElementById('global-ban-list');
    const banKeys = Object.keys(bans);
    if (banKeys.length === 0) {
        container.innerHTML = '<p class="text-success font-semibold p-2">目前没有全局封禁的 IP。</p>';
        return;
    }
    container.innerHTML = banKeys.map(ip => {
        const banInfo = bans[ip];
        return (
            '<div class="flex justify-between items-center p-3 bg-error/10 border border-error/20 rounded-lg shadow-sm">' +
                '<div class="font-mono text-sm text-error-content">' +
                    '<strong>' + ip + '</strong> ' +
                    '<span class="text-xs text-gray-500 ml-4">原因: ' + (banInfo.reason || 'N/A') + ' (添加于 ' + banInfo.timestamp + ')</span>' +
                '</div>' +
                '<button onclick="confirmAction(null, \'' + ip + '\', null, \'unbanGlobal\', \'解除全局封禁\')" ' +
                             'class="btn btn-success btn-xs font-semibold flex-shrink-0">解除封禁</button>' +
            '</div>'
        );
    }).join('');
}


function renderAuditLogs(logs) {
    const logContainer = document.getElementById('audit-log-content');
    const filteredLogs = logs.filter(log => log.trim() !== "" && log !== '读取日志失败或日志文件为空。' && log !== '日志文件不存在。');

    if (filteredLogs.length === 0) {
        logContainer.innerHTML = '<p class="text-gray-500">目前没有管理员审计活动日志。</p>';
        return;
    }
    logContainer.innerHTML = '';
    const fragment = document.createDocumentFragment();

    filteredLogs.forEach(log => {
        const parts = log.match(/^\[(.*?)\] \[USER:(.*?)\] \[IP:(.*?)\] ACTION:(.*?) DETAILS: (.*)$/);
        const div = document.createElement('div');
        if (parts) {
            const [_, timestamp, user, ip, action, details] = parts;
            const safeDetails = document.createElement('div');
            safeDetails.textContent = details;
            div.className = 'text-xs text-base-content font-mono space-y-1 p-1 hover:bg-base-300 rounded-md';
            div.innerHTML = 
                '<span class="text-primary">' + timestamp.split(' ')[1] + '</span> ' +
                '<span class="font-bold">[' + user + ']</span> ' +
                '<span class="text-sm font-semibold text-base-content">' + action + '</span> ' +
                '<span class="text-gray-500">' + safeDetails.innerHTML + '</span>'; 
        } else {
            div.className = 'text-xs text-base-content font-mono p-1';
            div.textContent = log;
        }
        fragment.appendChild(div);
    });
    logContainer.appendChild(fragment);
}


function renderActiveGlobalIPs(ipData) {
    const container = document.getElementById('live-ip-list');
    let htmlContent = '';
    
    if (ipData.length === 0) {
        container.innerHTML = '<p class="text-gray-500 p-2">目前没有活跃的外部连接。</p>';
        return;
    }

    ipData.forEach(ipInfo => {
        const isBanned = ipInfo.is_banned;
        const action = isBanned ? 'unban' : 'ban';
        const actionText = isBanned ? '解除封禁' : '全局封禁';
        const buttonColor = isBanned ? 'btn-success' : 'btn-error';
        const banTag = isBanned ? '<span class="badge badge-error badge-outline ml-2">已封禁</span>' : '';
        
        const usernameSpan = ipInfo.username && ipInfo.username !== 'N/A' ? 
            `<span class="badge badge-primary badge-outline ml-2 font-mono text-xs">${ipInfo.username}</span>` : 
            `<span class="badge badge-warning badge-outline ml-2 text-xs">未知用户/IP 统计</span>`;
            
        htmlContent += `
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 bg-base-100 border border-base-300 rounded-lg shadow-sm">
                <div class="min-w-0 flex-1 flex flex-col sm:flex-row sm:items-center">
                    <p class="font-mono text-sm text-base-content flex items-center">
                        <strong>${ipInfo.ip}</strong> ${usernameSpan} ${banTag}
                    </p>
                </div>
                <button onclick="confirmAction(null, '${ipInfo.ip}', null, '${action}Global', '${isBanned ? '解除全局封禁' : '全局封禁 IP'}')" 
                             class="mt-2 sm:mt-0 w-full sm:w-auto btn ${buttonColor} btn-xs font-semibold flex-shrink-0">
                    ${actionText}
                </button>
            </div>`;
    });
    container.innerHTML = htmlContent;
}

async function fetchActiveIPs() {
     const ipData = await fetchData('/system/active_ips');
     if (ipData) {
        renderActiveGlobalIPs(ipData.active_ips);
     }
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / (3600 * 24));
    seconds -= days * 3600 * 24;
    const hrs = Math.floor(seconds / 3600);
    seconds -= hrs * 3600;
    const mins = Math.floor(seconds / 60);
    seconds -= mins * 60;
    const secs = Math.floor(seconds);

    let parts = [];
    if (days > 0) parts.push(`${days}天`);
    if (hrs > 0) parts.push(`${hrs}时`);
    if (mins > 0) parts.push(`${mins}分`);
    if (secs > 0 && parts.length < 3) parts.push(`${secs}秒`);
    
    return parts.join(' ');
}

function renderConnectionList(connections) {
    const container = document.getElementById('connection-list-container');
    if (!container) return;

    if (connections.length === 0) {
        container.innerHTML = '<div class="text-center text-gray-500 py-4">该用户目前没有活跃的 WSS 连接。</div>';
        return;
    }

    let html = `
        <div class="grid grid-cols-5 gap-2 font-bold text-sm text-base-content/80 p-2 border-b border-base-300 bg-base-200 sticky top-0 rounded-t-lg">
            <div class="col-span-2">客户端 IP</div>
            <div class="col-span-1">Worker ID</div>
            <div class="col-span-2">连接开始时间 (UTC)</div>
        </div>
    `;

    connections.forEach(conn => {
        const startTime = new Date(conn.start);
        const duration = (Date.now() - startTime.getTime()) / 1000;
        const uptime = formatUptime(duration);

        html += `
            <div class="grid grid-cols-5 gap-2 text-xs p-2 bg-base-100 rounded-lg shadow-sm border border-base-300">
                <div class="col-span-2 font-mono text-primary">${conn.ip}</div>
                <div class="col-span-1 text-secondary">W-${conn.workerId}</div>
                <div class="col-span-2 text-gray-500">
                    ${startTime.toISOString().replace('T', ' ').substring(0, 19)}<br>
                    <span class="text-xs font-medium text-success">已连接: ${uptime}</span>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

async function openConnectionDetailsModal(username) {
    const titleEl = document.getElementById('modal-username-connection');
    const loadingEl = document.getElementById('connection-loading');
    const listContainer = document.getElementById('connection-list-container');
    
    titleEl.textContent = username;
    loadingEl.textContent = '正在查询活跃连接...';
    loadingEl.style.display = 'block';
    listContainer.innerHTML = '';
    
    openModal('connection-details-modal');

    const result = await fetchData(`/users/connections?username=${username}`);

    loadingEl.style.display = 'none';

    if (result && result.success) {
        renderConnectionList(result.connections);
        showStatus(result.message, true);
    } else {
        listContainer.innerHTML = `<div class="text-center text-error py-4">查询失败: ${result ? result.message : '网络或 API 错误'}</div>`;
        showStatus(`连接查询失败: ${result ? result.message : 'API 错误'}`, false);
    }
}

async function fetchAllUsersAndRender() {
    const usersData = await fetchData('/users/list');
    if (usersData) {
        allUsersCache = usersData.users; 
        if (currentView === 'users') {
            renderFilteredUserList(); 
        }
        if (currentView === 'payload-gen') { 
            populatePayloadUserSelect();
        }
    }
}

function renderFilteredUserList() {
    let usersToRender = [...allUsersCache];
    const searchTerm = document.getElementById('user-search-input').value.toLowerCase();
    if (searchTerm) {
        usersToRender = usersToRender.filter(user => 
            user.username.toLowerCase().includes(searchTerm)
        );
    }
    
    usersToRender.sort((a, b) => {
        let valA = a[currentSortKey];
        let valB = b[currentSortKey];
        
        if (currentSortKey === 'expiration_date') {
            valA = valA ? new Date(valA).getTime() : 0;
            valB = valB ? new Date(valB).getTime() : 0;
        } else if (currentSortKey === 'max_connections' || currentSortKey === 'active_connections' || currentSortKey === 'usage_gb' || 
                   currentSortKey === 'realtime_speed_down' || currentSortKey === 'realtime_speed_up') { 
            valA = parseFloat(valA) || 0;
            valB = parseFloat(valB) || 0;
            if (currentSortKey === 'max_connections') {
                 valA = valA === 0 ? Infinity : valA;
                 valB = valB === 0 ? Infinity : valB;
            }
        } else if (typeof valA === 'string') {
            valA = valA.toLowerCase();
            valB = valB.toLowerCase();
        }

        let comparison = 0;
        if (valA > valB) comparison = 1;
        else if (valA < valB) comparison = -1;
        
        return currentSortDir === 'asc' ? comparison : -comparison;
    });
    
    renderUserList(usersToRender);
}

function renderUserList(users) {
    const tbody = document.getElementById('user-list-tbody');
    const mobileContainer = document.getElementById('user-list-mobile');
    let tableHtml = [];
    let mobileHtml = [];
    
    document.querySelectorAll('th.sortable .sort-arrow').forEach(arrow => {
        const th = arrow.parentElement;
        if (th.dataset.sortkey === currentSortKey) {
            arrow.innerHTML = currentSortDir === 'asc' ? '▲' : '▼';
            arrow.style.opacity = '1';
        } else {
            arrow.innerHTML = '▲'; 
            arrow.style.opacity = '0.4';
        }
    });

    if (users.length === 0) {
        const emptyRow = '<tr><td colspan="9" class="px-6 py-4 text-center text-gray-500">没有找到匹配的用户</td></tr>';
        tbody.innerHTML = emptyRow;
        mobileContainer.innerHTML = `<div class="text-center text-gray-500 py-4">没有找到匹配的用户</div>`;
        return;
    }

    users.forEach(user => {
        let statusColor = 'badge-success';
        if (user.status === 'paused') { statusColor = 'badge-warning'; }
        if (user.status === 'fused') { statusColor = 'badge-warning'; }
        if (user.status === 'expired' || user.status === 'exceeded') { statusColor = 'badge-error'; }
        
        const statusText = user.status_text;
        const isLocked = (user.status !== 'active'); 
        const toggleAction = isLocked ? 'enable' : 'pause';
        const toggleText = isLocked ? '启用' : '暂停';
        const toggleColor = isLocked ? 'btn-success' : 'btn-warning';
        const isChecked = selectedUsers.includes(user.username) ? 'checked' : '';
        
        const maxConnections = user.max_connections !== undefined ? user.max_connections : 0; 
        const fuseThreshold = user.fuse_threshold_kbps !== undefined ? user.fuse_threshold_kbps : 0; 
        
        const speedUp = formatSpeedUnits(user.realtime_speed_up || 0);
        const speedDown = formatSpeedUnits(user.realtime_speed_down || 0);
        const activeConnections = user.active_connections !== undefined ? user.active_connections : 0;
        
        const allowShell = user.allow_shell || 0;

        const quotaLimit = user.quota_gb > 0 ? user.quota_gb : '∞';
        const usageText = user.usage_gb.toFixed(4) + ' / ' + quotaLimit;
        const quotaLimitValue = user.quota_gb > 0 ? user.quota_gb : 0;
        const usagePercent = (quotaLimitValue > 0) ? (user.usage_gb / quotaLimitValue) * 100 : 0;
        const progressHtml = (quotaLimitValue > 0) 
            ? `<progress class="progress progress-primary usage-progress" value="${usagePercent}" max="100" id="usage-progress-pc-${user.username}"></progress>` 
            : `<div class="usage-progress" id="usage-progress-pc-${user.username}"></div>`;
        
        tableHtml.push(`
            <tr id="row-${user.username}" class="hover">
                <td class="px-4 py-4">
                    <input type="checkbox" data-username="${user.username}" ${isChecked} class="user-checkbox checkbox checkbox-primary">
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-base-content" role="cell">${user.username}</td>
                
                <td id="status-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm" role="cell">
                    <span class="badge ${statusColor} text-xs font-semibold" id="status-badge-${user.username}">
                        ${statusText}
                    </span>
                </td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500" role="cell">${user.expiration_date || '永不'}</td>
                
                <td id="conn-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm font-medium text-primary" role="cell">${activeConnections}</td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-base-content" role="cell">${formatConnections(maxConnections)}</td>
                
                <td id="usage-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm font-medium text-base-content" role="cell">
                    <div id="usage-text-pc-${user.username}">${usageText} GB</div>
                    ${progressHtml}
                </td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono speed-cell" role="cell" id="speed-cell-${user.username}">
                    <span class="speed-up">↑ ${speedUp}</span> / 
                    <span class="speed-down">↓ ${speedDown}</span>
                </td>
                
                <td class="px-6 py-4 text-sm font-medium" role="cell">
                    <div class="flex flex-wrap gap-1">
                        <button onclick="confirmAction('${user.username}', null, null, 'killAll', '强制断开所有')" 
                                class="btn btn-error btn-xs" aria-label="强制断开 ${user.username}">踢下线</button>
                        <button onclick="openTrafficChartModal('${user.username}')"
                                class="btn btn-secondary btn-xs" aria-label="流量图 ${user.username}">流量图</button>
                        
                        <button onclick="openSettingsModal('${user.username}', '${user.expiration_date || ''}', ${user.quota_gb}, '${user.rate_kbps}', '${maxConnections}', '${fuseThreshold}', ${user.require_auth_header}, ${allowShell})" 
                                class="btn btn-primary btn-xs" aria-label="设置 ${user.username}">设置</button>
                                
                        <button onclick="confirmAction('${user.username}', '${toggleAction}', null, 'toggleStatus', '${toggleText}用户')" 
                                class="btn ${toggleColor} btn-xs" aria-label="${toggleText}用户 ${user.username}">${toggleText}</button>
                        <button onclick="openConnectionDetailsModal('${user.username}')" 
                                class="btn btn-info btn-xs" aria-label="查看用户连接详情 ${user.username}">详情</button>
                        <button onclick="confirmAction('${user.username}', 'delete', null, 'deleteUser', '删除用户')" 
                                class="btn btn-error btn-xs" aria-label="删除用户 ${user.username}">删除</button>
                    </div>
                </td>
            </tr>
        `);
        
        mobileHtml.push(buildUserCard(user, statusColor, statusText, toggleAction, toggleText, toggleColor, usageText, progressHtml));
    });
    
    tbody.innerHTML = tableHtml.join('');
    mobileContainer.innerHTML = mobileHtml.join('');
    bindCheckboxEvents();
}

function buildUserCard(user, statusColor, statusText, toggleAction, toggleText, toggleColor, usageText, usageProgressHtml) {
    let borderColor = 'border-primary';
    if (user.status === 'active') borderColor = 'border-success';
    if (user.status === 'paused' || user.status === 'fused') borderColor = 'border-warning';
    if (user.status === 'expired' || user.status === 'exceeded') borderColor = 'border-error';
    const isChecked = selectedUsers.includes(user.username) ? 'checked' : '';
    
    const cachedUser = allUsersCache.find(u => u.username === user.username);
    const speedUp = formatSpeedUnits(cachedUser?.realtime_speed_up || 0);
    const speedDown = formatSpeedUnits(cachedUser?.realtime_speed_down || 0);
    const activeConnections = cachedUser?.active_connections !== undefined ? cachedUser.active_connections : 0;
    
    const shellStatus = user.allow_shell === 1;
    const shellColor = shellStatus ? 'text-secondary' : 'text-gray-500';
    const shellText = shellStatus ? '已启用' : '已禁用';

    return `
    <div id="card-${user.username}" class="card bg-base-100 shadow-lg border-l-4 ${borderColor}">
        <div class="card-body p-4">
            <div class="flex justify-between items-center mb-3 pb-2 border-b border-base-300">
                <div class="flex items-center">
                    <input type="checkbox" data-username="${user.username}" ${isChecked} class="user-checkbox checkbox checkbox-primary mr-3">
                    <span class="font-bold text-lg text-base-content font-mono">${user.username}</span>
                </div>
                <span id="status-card-${user.username}" class="badge ${statusColor} text-xs font-semibold">
                    ${statusText}
                </span>
            </div>
            <div class="text-sm text-gray-600 space-y-1.5 mb-4">
                <p><strong>到期日:</strong> <span class="font-medium text-base-content">${user.expiration_date || '永不'}</span></p>
                
                <div id="usage-card-${user.username}" class="pt-1">
                    <strong>用量 (GB):</strong> <span id="usage-text-mobile-${user.username}" class="font-medium text-base-content">${usageText}</span>
                    ${usageProgressHtml}
                </div>
                
                <p><strong>连接/并发:</strong> 
                    <span id="conn-mobile-${user.username}" class="font-medium text-primary">${activeConnections}</span> / 
                    <span class="font-medium text-base-content">${formatConnections(user.max_connections)}</span>
                </p>
                
                <p class="speed-mobile"><strong>实时:</strong> 
                    <span class="speed-up" id="speed-up-mobile-${user.username}">↑ ${speedUp}</span> / 
                    <span class="speed-down" id="speed-down-mobile-${user.username}">↓ ${speedDown}</span>
                </p>
                
                <p><strong>认证:</strong> <span class="font-medium ${user.require_auth_header === 1 ? 'text-error' : 'text-success'}">${user.require_auth_header === 1 ? '需要头部' : '免认证'}</span></p>
                
                <p><strong>Shell (444):</strong> <span class="font-medium ${shellColor}">${shellText}</span></p>
            </div>
            <div class="grid grid-cols-3 gap-2">
                <button onclick="confirmAction('${user.username}', null, null, 'killAll', '强制断开所有')" 
                        class="btn btn-error btn-xs" aria-label="强制断开 ${user.username}">踢下线</button>
                <button onclick="openTrafficChartModal('${user.username}')"
                        class="btn btn-secondary btn-xs" aria-label="流量图 ${user.username}">流量图</button>
                
                <button onclick="openSettingsModal('${user.username}', '${user.expiration_date || ''}', ${user.quota_gb}, '${user.rate_kbps}', '${user.max_connections}', '${user.fuse_threshold_kbps}', ${user.require_auth_header}, ${user.allow_shell})" 
                        class="btn btn-primary btn-xs" aria-label="设置 ${user.username}">设置</button>
                        
                <button onclick="confirmAction('${user.username}', '${toggleAction}', null, 'toggleStatus', '${toggleText}用户')" 
                        class="btn ${toggleColor} btn-xs" aria-label="${toggleText}用户 ${user.username}">${toggleText}</button>
                <button onclick="openConnectionDetailsModal('${user.username}')" 
                        class="btn btn-info btn-xs" aria-label="查看用户连接详情 ${user.username}">详情</button>
                <button onclick="confirmAction('${user.username}', 'delete', null, 'deleteUser', '删除用户')" 
                        class="btn btn-error btn-xs" aria-label="删除用户 ${user.username}">删除</button>
            </div>
        </div>
    </div>`;
}

// --- WebSocket Client ---

function setWsStatusIcon(color, tip) {
    const button = document.getElementById('ws-status-button');
    const tooltip = document.getElementById('ws-status-tooltip');
    if (!button || !tooltip) return;

    tooltip.setAttribute('data-tip', tip);
    
    let iconName = 'wifi';
    let iconClass = 'w-5 h-5 transition-colors duration-300 ';

    switch (color) {
        case 'red':
            iconClass += 'status-light-red';
            iconName = 'wifi-off';
            break;
        case 'green':
            iconClass += 'status-light-green';
            iconName = 'wifi';
            break;
        case 'blue':
            iconClass += 'status-light-blue animate-spin'; 
            iconName = 'loader-2'; 
            break;
        case 'gray':
        default:
            iconClass += 'status-light-gray';
            iconName = 'wifi-off';
            break;
    }
    
    button.innerHTML = '';
    const newIcon = document.createElement('i');
    newIcon.id = 'ws-status-icon'; 
    newIcon.setAttribute('data-lucide', iconName);
    newIcon.className = iconClass;
    
    button.appendChild(newIcon);
    
    try {
        lucide.createIcons({
            nodes: [newIcon]
        });
    } catch (e) {
        newIcon.textContent = iconName; 
    }
}

function connectWebSocket() {
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }
    if (panelSocket) {
        panelSocket.close();
        panelSocket = null;
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/ui`;
    
    setWsStatusIcon('blue', '正在连接实时推送...'); 

    panelSocket = new WebSocket(wsUrl);

    panelSocket.onopen = (event) => {
        setWsStatusIcon('green', '实时推送已连接 (1秒/3秒刷新)');
    };

    panelSocket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            
            switch (message.type) {
                case 'status_connected':
                    setWsStatusIcon('green', '实时推送已连接 (1秒/3秒刷新)');
                    fetchAllStaticData(); 
                    break;
                
                case 'live_update':
                    if (message.payload) {
                        if (message.payload.users) {
                            handleSilentUpdate(message.payload.users);
                        }
                        if (message.payload.system) {
                            handleDashboardConnectionSilentUpdate(message.payload.system);
                            updateRealtimeTrafficChart(message.payload);
                        }
                    }
                    break;
                
                case 'system_update':
                    if (message.payload) {
                        handleSystemUpdateMessage(message.payload);
                    }
                    break;
                
                case 'users_changed':
                    // 状态发生变化时，强制全量拉取并重新渲染用户列表
                    fetchAllUsersAndRender();
                    break;
                
                case 'hosts_changed':
                    if (currentView === 'hosts') {
                        fetchHosts();
                    }
                    break;
                
                case 'auth_failed':
                    setWsStatusIcon('red', '实时推送身份验证失败');
                    showStatus('实时推送身份验证失败，请重新登录。', false);
                    panelSocket.close();
                    break;
            }
        } catch (e) {
            console.error('解析 WebSocket 消息失败:', e);
        }
    };

    panelSocket.onclose = (event) => {
        setWsStatusIcon('red', '实时推送已断开，正在重连...');
        if (!wsReconnectTimer) {
            wsReconnectTimer = setTimeout(connectWebSocket, 3000);
        }
    };

    panelSocket.onerror = (error) => {
        console.error('WebSocket 发生错误: ', error);
        setWsStatusIcon('red', '实时推送连接错误');
    };
}

/**
 * [AXIOM V6.0 OPTIMIZE] 只更新速度和连接数相关的 DOM 元素，最小化 DOM 操作。
 * @param {object} updatedUserStats 仅包含有变化的用户统计数据的对象
 */
function handleSilentUpdate(updatedUserStats) {
    if (currentView !== 'users') return; 

    for (const username in updatedUserStats) {
        if (!updatedUserStats.hasOwnProperty(username)) continue;
        
        const stats = updatedUserStats[username];
        const speedUpText = formatSpeedUnits(stats.speed_kbps?.upload || 0);
        const speedDownText = formatSpeedUnits(stats.speed_kbps?.download || 0);
        const connectionsText = stats.connections || 0;
        
        const userIndex = allUsersCache.findIndex(u => u.username === username);
        
        // 1. 更新本地缓存 (必须，因为其他视图或排序依赖它)
        if (userIndex !== -1) {
             // 合并实时速度/连接数到缓存
            allUsersCache[userIndex].realtime_speed_up = stats.speed_kbps?.upload || 0;
            allUsersCache[userIndex].realtime_speed_down = stats.speed_kbps?.download || 0;
            allUsersCache[userIndex].active_connections = connectionsText;
        } else {
            // 如果缓存中不存在，说明该用户可能来自 IP 统计 (SSH-UDP) 且面板从未加载，跳过
            continue; 
        }

        // 2. 更新 DOM (桌面版表格)
        const speedCell = document.getElementById(`speed-cell-${username}`);
        const connCell = document.getElementById(`conn-cell-${username}`); 

        if (speedCell) {
            speedCell.innerHTML = 
                `<span class="speed-up">↑ ${speedUpText}</span> / ` +
                `<span class="speed-down">↓ ${speedDownText}</span>`;
        }
        if (connCell) {
            connCell.textContent = connectionsText;
        }

        // 3. 更新 DOM (移动版卡片)
        const speedUpMobile = document.getElementById(`speed-up-mobile-${username}`);
        const speedDownMobile = document.getElementById(`speed-down-mobile-${username}`);
        const connMobile = document.getElementById(`conn-mobile-${username}`);

        if (speedUpMobile) speedUpMobile.textContent = `↑ ${speedUpText}`;
        if (speedDownMobile) speedDownMobile.textContent = `↓ ${speedDownText}`;
        if (connMobile) connMobile.textContent = connectionsText;
    }
}

function initRealtimeTrafficChart() {
    if (realtimeChartInstance) {
        realtimeChartInstance.destroy();
    }
    const ctx = document.getElementById('realtime-traffic-chart').getContext('2d');
    
    const initialLabels = Array(30).fill('');
    const initialDataUp = Array(30).fill(0);
    const initialDataDown = Array(30).fill(0);

    realtimeChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: initialLabels,
            datasets: [
                {
                    label: '上传 (KB/s)',
                    data: initialDataUp,
                    borderColor: '#34d399', // green-400
                    backgroundColor: 'rgba(52, 211, 153, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.3,
                    fill: true
                },
                {
                    label: '下载 (KB/s)',
                    data: initialDataDown,
                    borderColor: '#3b82f6', // blue-500
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false, 
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value, index, values) {
                            return value + ' KB/s';
                        }
                    }
                },
                x: {
                    ticks: { display: false } 
                }
            },
            plugins: {
                legend: { position: 'bottom', labels: { padding: 10 } },
                tooltip: {
                    intersect: false,
                    mode: 'index',
                }
            },
            interaction: {
                intersect: false,
                mode: 'index',
            }
        }
    });
}

function updateRealtimeTrafficChart(liveUpdatePayload) {
    if (!realtimeChartInstance || !liveUpdatePayload || !liveUpdatePayload.users) {
        return;
    }
    
    let totalSpeedUp = 0;
    let totalSpeedDown = 0;
    for (const username in liveUpdatePayload.users) {
        const userSpeed = liveUpdatePayload.users[username].speed_kbps;
        totalSpeedUp += (userSpeed?.upload || 0);
        totalSpeedDown += (userSpeed?.download || 0);
    }
    
    const labels = realtimeChartInstance.data.labels;
    const dataUp = realtimeChartInstance.data.datasets[0].data;
    const dataDown = realtimeChartInstance.data.datasets[1].data;

    labels.shift();
    dataUp.shift();
    dataDown.shift();

    const now = new Date();
    labels.push(now.toLocaleTimeString()); 
    dataUp.push(totalSpeedUp.toFixed(1));
    dataDown.push(totalSpeedDown.toFixed(1));

    realtimeChartInstance.update('none'); 
}

// --- API Calls ---

async function fetchData(url, options = {}) {
    try {
        const response = await fetch(API_BASE + url, options);
        if (response.status === 401) {
            showStatus("会话过期或权限不足，请重新登录。", false);
            if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
            if (panelSocket) panelSocket.close();
            window.location.assign('/login.html'); 
            return null;
        }
        if (response.redirected) {
            window.location.assign(response.url);
            return null;
        }
        const contentType = response.headers.get("content-type");
        
        if (!contentType || !contentType.includes("application/json")) {
            if (response.ok) {
                const text = await response.text();
                if (text.trim().startsWith('<!DOCTYPE html>')) {
                     showStatus("API 响应错误：会话可能已过期，请尝试重新登录。", false);
                     setTimeout(() => window.location.assign('/login.html'), 1000); 
                     return null;
                }
                showStatus("API 响应格式错误，可能返回了非 JSON 页面。", false);
                return null;
            }
        }
        
        const data = await response.json();
        
        if (!response.ok || (typeof data.success === 'boolean' && !data.success)) {
            showStatus(data.message || 'API Error: ' + url, false);
            return null;
        }
        return data;
    } catch (error) {
         showStatus('网络请求失败: ' + error.message, false);
        return null;
    }
}


// --- User Actions ---

function generateBase64Token(username, password) {
    if (!username || !password) return null; 
    try {
        const token = btoa(`${username}:${password}`); 
        return token;
    } catch (e) {
        return "编码失败";
    }
}

document.getElementById('add-user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;
    const expirationDays = document.getElementById('expiration-days').value;
    const quotaGb = document.getElementById('quota-gb').value;
    const rateKbps = document.getElementById('rate-kbps').value;
    const maxConnections = document.getElementById('new-max-connections').value;
    const requireAuth = document.getElementById('new-require-auth').checked; 
    const allowShell = document.getElementById('new-allow-shell').checked; 

    if (!/^[a-z0-9_]{3,16}$/.test(username)) {
        showStatus('用户名格式不正确 (3-16位小写字母/数字/下划线)', false);
        return;
    }
    showStatus('正在创建用户 ' + username + '...', true);

    const result = await fetchData('/users/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            username: username, 
            password: password, 
            expiration_days: parseInt(expirationDays),
            quota_gb: parseFloat(quotaGb),
            rate_kbps: parseInt(rateKbps),
            max_connections: parseInt(maxConnections),
            require_auth_header: requireAuth ? 1 : 0,
            allow_shell: allowShell ? 1 : 0 
        })
    });

    if (result) {
        showStatus(result.message, true);
        document.getElementById('add-user-form').reset();
        closeModal('add-user-modal');
        const tokenOutput = document.getElementById('new-connect-token');
        if (tokenOutput) {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
    }
});

async function openSettingsModal(username, expiry_date, quota_gb, rate_kbps, max_connections, fuse_threshold_kbps, require_auth_header, allow_shell) {
    document.getElementById('modal-username-title-settings').textContent = username;
    document.getElementById('modal-username-setting').value = username;
    document.getElementById('modal-expiry-date').value = expiry_date; 
    document.getElementById('modal-quota-gb').value = quota_gb;
    document.getElementById('modal-rate-kbps').value = rate_kbps;
    document.getElementById('modal-max-connections').value = (max_connections !== undefined) ? max_connections : 0;
    document.getElementById('modal-require-auth').checked = (require_auth_header === 1); 
    document.getElementById('modal-allow-shell').checked = (allow_shell === 1); 
    document.getElementById('modal-new-password').value = ''; 
    document.getElementById('modal-connect-token').value = TOKEN_PLACEHOLDER;
    openModal('settings-modal');
}

document.getElementById('modal-new-password').addEventListener('input', function() {
    const username = document.getElementById('modal-username-setting').value;
    const password = this.value;
    const tokenInput = document.getElementById('modal-connect-token');
    
    if (password) {
         const token = generateBase64Token(username, password);
         tokenInput.value = token;
    } else {
         tokenInput.value = TOKEN_PLACEHOLDER;
    }
});

async function saveUserSettings() {
    const username = document.getElementById('modal-username-setting').value;
    const expiry_date = document.getElementById('modal-expiry-date').value;
    const quota_gb = document.getElementById('modal-quota-gb').value;
    const rate_kbps = document.getElementById('modal-rate-kbps').value;
    const max_connections = document.getElementById('modal-max-connections').value;
    const new_password = document.getElementById('modal-new-password').value;
    const requireAuth = document.getElementById('modal-require-auth').checked; 
    const allowShell = document.getElementById('modal-allow-shell').checked; 
    
    closeModal('settings-modal');
    showStatus('正在保存用户 ' + username + ' 的设置并实时通知代理...', true);

    const result = await fetchData('/users/set_settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            username: username, 
            expiry_date: expiry_date, 
            quota_gb: parseFloat(quota_gb), 
            rate_kbps: parseInt(rate_kbps),
            max_connections: parseInt(max_connections),
            new_password: new_password,
            require_auth_header: requireAuth ? 1 : 0,
            allow_shell: allowShell ? 1 : 0 
        })
    });

    if (result) {
        showStatus(result.message, true);
    }
}

async function openTrafficChartModal(username) {
    document.getElementById('traffic-chart-username-title').textContent = username;
    document.getElementById('traffic-chart-loading').style.display = 'block';
    if (trafficChartInstance) {
        trafficChartInstance.destroy();
    }
    openModal('traffic-chart-modal');
    const data = await fetchData(`/users/traffic-history?username=${username}`);
    document.getElementById('traffic-chart-loading').style.display = 'none';

    if (data && data.history) {
        const history = data.history;
        const dates = history.map(item => item.date.substring(5)); 
        const usage = history.map(item => item.usage_gb);
        const ctx = document.getElementById('trafficChartCanvas').getContext('2d');
        trafficChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: dates,
                datasets: [{
                    label: '每日用量 (GB)',
                    data: usage,
                    borderColor: '#3b82f6', // blue-500
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, title: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: '流量 (GB)' } },
                    x: { title: { display: true, text: '日期' } }
                }
            }
        });
    } else {
         document.getElementById('traffic-chart-loading').textContent = '未能加载流量历史数据。';
         document.getElementById('traffic-chart-loading').style.display = 'block';
    }
}

// --- Payload Gen Logic ---

function generatePayload() {
    const CRLF = '[crlf]';
    const SPLIT = '[split]';
    const PROTOCOL = '[protocol]'; 
    const HOST_PORT = '[host_port]';
    const UA = '[ua]';
    
    const C = {
        splitEnable: document.getElementById('payload-split-enable').checked,
        r1Method: document.getElementById('payload-r1-method').value,
        r1Host: document.getElementById('payload-r1-host').value.trim() || HOST_PORT,
        r2Host: document.getElementById('payload-host').value.trim() || '[host]',
        r2Method: document.getElementById('payload-method').value,
        headerHost: document.getElementById('payload-header-host').checked,
        headerKeepAlive: document.getElementById('payload-header-keep-alive').checked,
        headerUserAgent: document.getElementById('payload-header-user-agent').checked,
        headerWebsocket: document.getElementById('payload-header-websocket').checked,
        headerOnlineHost: document.getElementById('payload-header-online-host').checked, 
        authMode: document.getElementById('payload-auth-mode').value,
        username: document.getElementById('payload-username').value.trim(),
        password: document.getElementById('payload-password').value,
        token: document.getElementById('payload-auth-token').value
    };
    
    let finalPayload = "";
    
    if (C.splitEnable) {
        let request1 = `${C.r1Method} ${C.r1Host} ${PROTOCOL}${CRLF}`;
        request1 += `Connection: close${CRLF}`; 
        request1 += CRLF; 
        finalPayload += request1;
        finalPayload += SPLIT + CRLF; 
    }
    
    let r2RequestLine = `${C.r2Method} http://${C.r2Host}/ ${PROTOCOL}${CRLF}`;
    if (C.authMode === 'uri') {
        if (!C.username) {
            showStatus('使用 URI 注入时必须填写用户名', false);
            return;
        }
        r2RequestLine = `${C.r2Method} http://${C.r2Host}/?user=${C.username} ${PROTOCOL}${CRLF}`;
    }

    let r2Headers = "";
    if (C.headerHost) {
        r2Headers += `Host: ${C.r2Host}${CRLF}`;
    }
    if (C.headerOnlineHost) {
        r2Headers += `X-Online-Host: ${C.r2Host}${CRLF}`;
    }
    if (C.headerUserAgent) {
        r2Headers += `User-Agent: ${UA}${CRLF}`;
    }
    
    if (C.authMode === 'proxy') {
        if (!C.token || C.token.startsWith('[')) {
            showStatus('使用认证头时必须填写用户名和密码', false);
            return;
        }
        r2Headers += `Proxy-Authorization: Basic ${C.token}${CRLF}`;
    }
    
    if (C.headerKeepAlive) {
        r2Headers += `Connection: Keep-Alive${CRLF}`;
    }
    if (C.headerWebsocket) {
        if (C.headerKeepAlive) {
            r2Headers = r2Headers.replace(`Connection: Keep-Alive${CRLF}`, `Connection: Upgrade${CRLF}`);
        } else {
            r2Headers += `Connection: Upgrade${CRLF}`;
        }
        r2Headers += `Upgrade: websocket${CRLF}`;
    }
    
    let request2 = r2RequestLine + r2Headers + CRLF; 
    finalPayload += request2;
    
    document.getElementById('payload-output').value = finalPayload;
    showStatus('载荷生成成功！', true);
}

function setupPayloadAuthListeners() {
    const usernameInput = document.getElementById('payload-username');
    const passwordInput = document.getElementById('payload-password');
    const tokenOutput = document.getElementById('payload-auth-token');
    
    if (!usernameInput || !passwordInput || !tokenOutput) {
        return;
    }
    
    const updateToken = () => {
        const username = usernameInput.value;
        const password = passwordInput.value;
        const token = generateBase64Token(username, password);
        if (token) {
            tokenOutput.value = token;
        } else {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
    };
    
    usernameInput.addEventListener('input', updateToken);
    passwordInput.addEventListener('input', updateToken);
}

function populatePayloadUserSelect() {
    const select = document.getElementById('payload-user-select');
    if (!select) return; 
    
    const currentValue = select.value;
    while (select.options.length > 1) {
        select.remove(1);
    }
    if (allUsersCache.length === 0) {
        return;
    }
    const fragment = document.createDocumentFragment();
    allUsersCache.forEach(user => {
        const option = document.createElement('option');
        option.value = user.username;
        option.textContent = user.username;
        fragment.appendChild(option);
    });
    select.appendChild(fragment);
    
    if (Array.from(select.options).some(opt => opt.value === currentValue)) {
        select.value = currentValue;
    }
}

function setupCreateUserTokenListeners() {
    const usernameInput = document.getElementById('new-username');
    const passwordInput = document.getElementById('new-password');
    const tokenOutput = document.getElementById('new-connect-token');

    if (!usernameInput || !passwordInput || !tokenOutput) {
        return;
    }

    const updateToken = () => {
        const username = usernameInput.value;
        const password = passwordInput.value;
        const token = generateBase64Token(username, password); 
        if (token) {
            tokenOutput.value = token;
        } else {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
    };

    usernameInput.addEventListener('input', updateToken);
    passwordInput.addEventListener('input', updateToken);
}

// --- Init & Events ---

async function initializeApp() {
    try {
        // 尝试加载初始配置，确保 FLASK_CONFIG 有值
        const data = await fetchData('/settings/config');
        if (data && data.config) {
            FLASK_CONFIG = {
                WSS_HTTP_PORT: data.config.wss_http_port,
                WSS_TLS_PORT: data.config.wss_tls_port,
                STUNNEL_PORT: data.config.stunnel_port,
                UDPGW_PORT: data.config.udpgw_port,
                SSH_UDP_PORT: data.config.ssh_udp_port,
                INTERNAL_WSS_PORT: data.config.internal_wss_port,
                XRAY_INTERNAL_PORT: data.config.xray_internal_port,
                PANEL_PORT: data.config.panel_port
            };
        } else {
             showStatus("无法加载核心配置，请刷新。", false);
             return;
        }
        
        if (typeof lucide === 'undefined' || typeof lucide.createIcons !== 'function') {
            showStatus('图标库(Lucide)加载失败，请刷新。', false);
            return;
        }
        
        lastUserStats = {}; 
        
        switchView('dashboard');
        
        connectWebSocket();
        
        setupPayloadAuthListeners(); 
        setupCreateUserTokenListeners();
        
        document.getElementById('user-search-input').addEventListener('input', () => {
            renderFilteredUserList();
        });
        
        document.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const sortKey = th.dataset.sortkey;
                if (currentSortKey === sortKey) {
                    currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSortKey = sortKey;
                    currentSortDir = 'asc';
                }
                renderFilteredUserList();
            });
        });

        const payloadUserSelect = document.getElementById('payload-user-select');
        if (payloadUserSelect) {
            payloadUserSelect.addEventListener('change', (e) => {
                const username = e.target.value;
                const usernameInput = document.getElementById('payload-username');
                const passwordInput = document.getElementById('payload-password');
                const tokenOutput = document.getElementById('payload-auth-token');
                
                if (username) {
                    usernameInput.value = username;
                    passwordInput.value = ''; 
                    tokenOutput.value = "[请输入密码]"; 
                    passwordInput.focus(); 
                } else {
                    usernameInput.value = '';
                    passwordInput.value = '';
                    tokenOutput.value = "[在此输入用户名和密码]";
                    usernameInput.focus();
                }
            });
        }

        const payloadSplitEnable = document.getElementById('payload-split-enable');
        if (payloadSplitEnable) {
            payloadSplitEnable.addEventListener('change', (e) => {
                const optionsDiv = document.getElementById('payload-split-options');
                if (e.target.checked) {
                    optionsDiv.style.display = 'block';
                } else {
                    optionsDiv.style.display = 'none';
                }
            });
        }
        
    } catch (e) {
        console.error("Failed to initialize app:", e);
        showStatus("应用初始化失败: " + e.message, false);
    }
}

document.getElementById('add-global-ban-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = document.getElementById('global-ban-ip').value;
    if (!ip) return showStatus('IP 地址不能为空', false);
    confirmAction(null, ip, null, 'banGlobal', '全局封禁 IP');
});

document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const old_password = document.getElementById('old-password').value;
    const new_password = document.getElementById('admin-new-password').value;
    const confirm_new_password = document.getElementById('admin-confirm-new-password').value;
    
    if (new_password !== confirm_new_password) {
        showStatus('新密码和确认密码不一致。', false);
        return;
    }
    if (new_password.length < 6) {
        showStatus('新密码长度必须至少为 6 位。', false);
        return;
    }
    showStatus('正在修改管理员密码...', true);
    const result = await fetchData('/settings/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password, new_password })
    });
    if (result) {
        showStatus(result.message, true);
        document.getElementById('change-password-form').reset();
    }
});


function clearSelections() {
    selectedUsers = [];
    document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = false);
    const selectAll = document.getElementById('select-all-users');
    if (selectAll) selectAll.checked = false;
    updateBatchActionBar();
}

function updateBatchActionBar() {
    const bar = document.getElementById('batch-action-bar');
    const countSpan = document.getElementById('selected-user-count');
    countSpan.textContent = selectedUsers.length;
    if (selectedUsers.length > 0) {
        bar.classList.add('visible');
    } else {
        bar.classList.remove('visible');
    }
}

function bindCheckboxEvents() {
    const selectAll = document.getElementById('select-all-users');
    if (selectAll) {
        selectAll.addEventListener('change', (e) => {
            const isChecked = e.target.checked;
            selectedUsers = [];
            const visibleUsernames = Array.from(document.querySelectorAll('#user-list-tbody .user-checkbox')).map(cb => cb.dataset.username);
            document.querySelectorAll('.user-checkbox').forEach(cb => {
                if (visibleUsernames.includes(cb.dataset.username)) {
                    cb.checked = isChecked;
                    if (isChecked) {
                        selectedUsers.push(cb.dataset.username);
                    }
                }
            });
            updateBatchActionBar();
        });
    }
    document.querySelectorAll('.user-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const username = e.target.dataset.username;
            if (e.target.checked) {
                if (!selectedUsers.includes(username)) {
                    selectedUsers.push(username);
                }
            } else {
                selectedUsers = selectedUsers.filter(u => u !== username);
            }
            document.querySelectorAll(`.user-checkbox[data-username="${username}"]`).forEach(box => box.checked = e.target.checked);
            const visibleCheckboxes = Array.from(document.querySelectorAll('#user-list-tbody .user-checkbox'));
            const allVisibleChecked = visibleCheckboxes.length > 0 && visibleCheckboxes.every(box => box.checked);
            if (selectAll) selectAll.checked = allVisibleChecked;
            updateBatchActionBar();
        });
    });
}

async function handleBatchAction(action) {
    if (selectedUsers.length === 0) {
        showStatus('请至少选择一个用户。', false);
        return;
    }
    let days = 0;
    let confirmTitle = '批量操作确认';
    let confirmMessage = `您确定要对选中的 ${selectedUsers.length} 个用户执行 "${action}" 操作吗？`;
    if (action === 'renew') {
        days = parseInt(document.getElementById('batch-renew-days').value) || 30;
        confirmTitle = '批量续期确认';
        confirmMessage = `您确定要为 ${selectedUsers.length} 个用户续期 ${days} 天吗？`;
    } else if (action === 'delete') {
        confirmTitle = '批量删除确认';
        confirmMessage = `警告：您确定要永久删除选中的 ${selectedUsers.length} 个用户吗？此操作不可逆！`;
    }
    document.getElementById('confirm-param1').value = action;
    document.getElementById('confirm-param2').value = JSON.stringify(selectedUsers);
    document.getElementById('confirm-param3').value = days;
    document.getElementById('confirm-type').value = 'batchAction';
    document.getElementById('confirm-title').textContent = confirmTitle;
    document.getElementById('confirm-message').innerHTML = confirmMessage;
    const confirmBtn = document.getElementById('confirm-action-btn');
    confirmBtn.className = 'btn btn-error'; 
    if (action === 'enable' || action === 'renew') {
         confirmBtn.className = 'btn btn-success';
    }
    confirmBtn.onclick = executeAction;
    openModal('confirm-modal');
}

function confirmAction(param1, param2, param3, type, titleText) {
    let message = '';
    document.getElementById('confirm-param1').value = param1 || ''; 
    document.getElementById('confirm-param2').value = param2 || ''; 
    document.getElementById('confirm-param3').value = param3 || ''; 
    document.getElementById('confirm-type').value = type;
    const username = param1;
    const action = param2;
    if (type === 'deleteUser') {
        message = '您确定要永久删除用户 <strong>' + username + '</strong> 吗？此操作不可逆，将删除系统账户和所有配置。';
    } else if (type === 'toggleStatus') {
        message = '您确定要 ' + (action === 'pause' ? '暂停' : '启用') + ' 用户 <strong>' + username + '</strong> 吗？';
    } else if (type === 'serviceControl') {
        message = '警告：您确定要重启核心服务 <strong>' + CORE_SERVICES_MAP[username] + '</strong> 吗？这可能会导致短暂的服务中断。';
    } else if (type === 'unbanGlobal') {
        message = '您确定要解除全局封禁 IP 地址 <strong>' + action + '</strong> 吗？';
    } else if (type === 'banGlobal') {
        message = '您确定要对 IP 地址 <strong>' + action + '</strong> 执行全局封禁操作吗？';
    } else if (type === 'resetTraffic') {
        message = '警告：您确定要将用户 <strong>' + username + '</strong> 的流量使用量和历史记录重置为 0 吗？';
    } else if (type === 'killAll') {
        message = '警告：您确定要强制断开用户 <strong>' + username + '</strong> 的所有活跃连接吗？这会强制用户重新连接。';
    } else if (type === 'batchAction') {
         return;
    }
    document.getElementById('confirm-title').textContent = titleText;
    document.getElementById('confirm-message').innerHTML = message;
    const confirmBtn = document.getElementById('confirm-action-btn');
    if (type.includes('ban') || type === 'deleteUser' || type === 'serviceControl' || type === 'killAll') {
         confirmBtn.className = 'btn btn-error';
    } else if (type.includes('enable') || type === 'unbanGlobal' || type === 'resetTraffic') {
         confirmBtn.className = 'btn btn-success';
    } else {
         confirmBtn.className = 'btn btn-primary';
    }
    confirmBtn.onclick = executeAction;
    openModal('confirm-modal');
}

async function executeAction() {
    closeModal('confirm-modal');
    const param1 = document.getElementById('confirm-param1').value;
    const param2 = document.getElementById('confirm-param2').value;
    const param3 = document.getElementById('confirm-param3').value;
    const type = document.getElementById('confirm-type').value;
    showStatus('正在执行 ' + type + ' 操作...', true);
    let url;
    let body = {};
    if (type === 'deleteUser') {
        url = '/users/delete';
        body = { username: param1 };
    } else if (type === 'toggleStatus') {
        url = '/users/status';
        body = { username: param1, action: param2 }; 
    } else if (type === 'resetTraffic') {
        url = '/users/reset_traffic';
        body = { username: param1 };
    } else if (type === 'serviceControl') {
        url = '/system/control';
        body = { service: param1, action: param2 }; 
    } else if (type === 'unbanGlobal') {
        url = '/ips/unban_global';
        body = { ip: param2 }; 
    } else if (type === 'banGlobal') {
        url = '/ips/ban_global';
        body = { ip: param2, reason: 'Manual Global Ban' };
    } else if (type === 'killAll') {
        url = '/users/kill_all';
        body = { username: param1 };
    } else if (type === 'batchAction') {
        url = '/users/batch-action';
        body = {
            action: param1,
            usernames: JSON.parse(param2),
            days: parseInt(param3) || 0
        };
    }
    const result = await fetchData(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (result) {
        showStatus(result.message, true);
        if (type === 'batchAction') {
            clearSelections();
        }
    }
}


window.onload = function() {
    initializeApp();
};
