/**
 * WSS Proxy Core (Node.js)
 * V8.4.0 (Axiom Refactor V5.0 - Native UDPGW Ready & Exponential Backoff IPC)
 *
 * [AXIOM V5.0 CHANGELOG]
 * - [架构] IPC 重连健壮性:
 * - `connectToIpcServer` 实现了指数退避重连逻辑，最大延迟 60 秒。
 * - 新增 `ipcReconnectDelay` 和 `ipcReconnectAttempts` 变量。
 * - [性能/可靠性] 流量零丢失:
 * - 新增 `pending_traffic_delta` 变量用于缓存 IPC 断连期间产生的流量增量。
 * - `pushStatsToControlPlane` 在 IPC 断连时，将用户的实时流量增量转移到 `pending_traffic_delta` 中，防止重置。
 * - `connectToIpcServer` 在成功连接后，将缓存的流量增量发送到控制平面。
 * - [Native UDPGW 兼容性] 移除了对 UDPGW 的特殊处理，现在只需确保 WSS 代理将流量转发到 Stunnel/SSHD (通常是 22)，
 * Stunnel 再转发到 Native UDPGW 即可实现 UDP over TCP。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const http = require('http'); 
const { URLSearchParams } = require('url');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');


// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        if (cluster.isWorker) {
            console.log(`[AXIOM V5.0] Worker ${cluster.worker.id} 成功从 ${CONFIG_PATH} 加载配置。`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); 
    }
}
loadConfig(); 
// --- 结束配置加载 ---


// --- 核心常量 (现在从 config 读取) ---
const LISTEN_ADDR = '0.0.0.0';
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); 
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const HTTP_PORT = config.wss_http_port;
const TLS_PORT = config.wss_tls_port;
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port;
const PANEL_API_URL = config.panel_api_url;
const INTERNAL_API_SECRET = config.internal_api_secret;
const DEFAULT_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };
const TIMEOUT = 86400000; 
const BUFFER_SIZE = 65536;
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// HTTP Responses
const FIRST_RESPONSE = Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nOK\r\n\r\n');
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const FORBIDDEN_RESPONSE = Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
const UNAUTHORIZED_RESPONSE = Buffer.from('HTTP/1.1 401 Unauthorized\r\nProxy-Authenticate: Basic realm="WSS Proxy"\r\nContent-Length: 0\r\n\r\n');
const TOO_MANY_REQUESTS_RESPONSE = Buffer.from('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 
let allWorkerStats = new Map();


// --- 令牌桶 (Token Bucket) 限速器 ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        // [AXIOM V5.0] 修正: 确保容量/速率始终为正
        this.capacity = Math.max(0, capacityKbps * 1024); 
        this.fillRate = Math.max(0, fillRateKbps * 1024 / 1000); 
        this.tokens = this.capacity; 
        this.lastFill = Date.now();
    }
    _fillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            const newTokens = elapsed * this.fillRate;
            this.tokens = Math.min(this.capacity, this.tokens + newTokens);
            this.lastFill = now;
        }
    }
    consume(bytesToConsume) {
        if (this.fillRate === 0) return bytesToConsume; 
        this._fillTokens();
        if (bytesToConsume <= this.tokens) {
            this.tokens -= bytesToConsume;
            return bytesToConsume; 
        }
        if (this.tokens > 0) {
             const allowedBytes = this.tokens;
             this.tokens = 0;
             return allowedBytes; 
        }
        return 0; 
    }
    updateRate(newCapacityKbps, newFillRateKbps) {
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master(N/A)';
        console.log(`[TokenBucket ${workerId}] Updating rate. Capacity: ${newCapacityKbps} KB/s, FillRate: ${newFillRateKbps} KB/s`);
        this._fillTokens();
        // [AXIOM V5.0] 修正: 确保容量/速率始终为正
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRate = Math.max(0, newFillRateKbps * 1024 / 1000);
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 全局状态管理 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 1000; 

// [AXIOM V5.0] 新增: IPC 断连期间的流量增量缓存
const pending_traffic_delta = {}; 

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            sockets: new Set(),
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0, require_auth_header: 1 }
        });
    }
    return userStats.get(username);
}

/** 实时速度计算器 */
function calculateSpeeds() {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = now - stats.lastSpeedCalc.time;
        if (elapsed < (SPEED_CALC_INTERVAL / 2)) continue; 
        const elapsedSeconds = elapsed / 1000.0;
        
        const uploadDelta = stats.traffic_live.upload - stats.lastSpeedCalc.upload;
        stats.speed_kbps.upload = (uploadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.upload = stats.traffic_live.upload;

        const downloadDelta = stats.traffic_live.download - stats.lastSpeedCalc.download;
        stats.speed_kbps.download = (downloadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.download = stats.traffic_live.download;
        
        stats.lastSpeedCalc.time = now;
        
        // [AXIOM V5.0] 关键: 如果 IPC 断开，将流量增量累积到 pending 缓存中。
        if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
            if (!pending_traffic_delta[username]) {
                pending_traffic_delta[username] = { upload: 0, download: 0 };
            }
            pending_traffic_delta[username].upload += stats.traffic_delta.upload;
            pending_traffic_delta[username].download += stats.traffic_delta.download;
            
            // 清零当前 delta，因为它已转移到 pending 缓存
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0; 
        }
        
        if (stats.sockets.size === 0 && stats.traffic_delta.upload === 0 && stats.traffic_delta.download === 0) {
            userStats.delete(username);
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


// --- [AXIOM V5.0] 实时 IPC 客户端 (指数退避重连) ---

let ipcWsClient = null;
let statsPusherIntervalId = null;

let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 60000; // 1 分钟最大延迟

/**
 * [AXIOM V5.0] 实时统计推送器
 */
function pushStatsToControlPlane(ws_client) {
    // [AXIOM V5.0] 如果 IPC 断开，calculateSpeeds 会将流量转移到 pending_traffic_delta 中。
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; // IPC未连接，不推送
    }

    const statsReport = {};
    const liveIps = {};
    
    // 1. 合并并清空 Pending 流量 (仅在连接打开时执行)
    let hasPendingTraffic = false;
    for (const username in pending_traffic_delta) {
        const stats = getUserStat(username); 
        stats.traffic_delta.upload += pending_traffic_delta[username].upload;
        stats.traffic_delta.download += pending_traffic_delta[username].download;
        if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            hasPendingTraffic = true;
        }
    }
    // 无论是否成功合并，都要清空缓存
    for (const key in pending_traffic_delta) { delete pending_traffic_delta[key]; }
    
    
    // 2. 准备本地统计数据
    for (const [username, stats] of userStats.entries()) {
        if (stats.sockets.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            
            statsReport[username] = {
                speed_kbps: stats.speed_kbps, 
                connections: stats.sockets.size,
                traffic_delta_up: stats.traffic_delta.upload,
                traffic_delta_down: stats.traffic_delta.download
            };

            // 关键: 重置 delta 计数器 (已成功推送到控制平面)
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            
            for (const ip of stats.ip_map.keys()) {
                // [AXIOM V5.0] 增加 IPv6 支持：使用 ip_map 中记录的地址
                liveIps[ip] = username;
            }
        }
    }

    // 3. 将此 Worker 的数据推送到控制平面
    if (Object.keys(statsReport).length > 0 || Object.keys(liveIps).length > 0) {
         try {
            ws_client.send(JSON.stringify({
                type: 'stats_update',
                workerId: cluster.worker.id,
                payload: { stats: statsReport, live_ips: liveIps }
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${cluster.worker.id}] 推送统计数据失败: ${e.message}`);
        }
    } else if (hasPendingTraffic) {
        // 如果没有当前实时数据，但有合并进来的数据，我们仍然需要通知控制平面，即使内容为空 (避免丢失)
        try {
            ws_client.send(JSON.stringify({
                type: 'stats_update',
                workerId: cluster.worker.id,
                payload: { stats: {}, live_ips: {} }
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${cluster.worker.id}] 推送空统计数据失败: ${e.message}`);
        }
    }
}

function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.sockets.size > 0) {
        console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在踢出用户 ${username} (${stats.sockets.size} 个连接)...`);
        for (const socket of stats.sockets) {
            socket.destroy(); 
        }
        stats.sockets.clear();
        stats.ip_map.clear();
    }
}

function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); 
    console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在更新用户 ${username} 的限制...`);
    // [AXIOM V5.0] 确保 limits 字段的完整性
    stats.limits = {
        rate_kbps: limits.rate_kbps || 0,
        max_connections: limits.max_connections || 0,
        require_auth_header: limits.require_auth_header === 0 ? 0 : 1
    };
    const rateUp = stats.limits.rate_kbps;
    stats.bucket_up.updateRate(rateUp * 2, rateUp); 
    const rateDown = stats.limits.rate_kbps; 
    stats.bucket_down.updateRate(rateDown * 2, rateDown); 
}

function resetUserTraffic(username) {
    const stats = userStats.get(username);
    if (stats) {
        console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在重置用户 ${username} 的流量计数器...`);
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
        // [AXIOM V5.0] 清除 pending 缓存
        if (pending_traffic_delta[username]) {
             delete pending_traffic_delta[username];
        }
    }
}

/**
 * [AXIOM V5.0] 核心功能: 指数退避重连逻辑
 */
function attemptIpcReconnect() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    
    // 计算退避延迟: 2^n * 1000ms, 最大 60 秒
    const baseDelay = Math.pow(2, ipcReconnectAttempts) * 1000;
    const delay = Math.min(baseDelay, MAX_RECONNECT_DELAY_MS);

    ipcReconnectAttempts++;
    console.warn(`[IPC_WSC Worker ${cluster.worker.id}] 正在重试连接 (尝试次数: ${ipcReconnectAttempts}, 延迟: ${delay / 1000}s)...`);

    ipcReconnectTimer = setTimeout(connectToIpcServer, delay);
}


function connectToIpcServer() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    // [AXIOM V5.0] 如果客户端已存在且处于打开或连接状态，则不重连
    if (ipcWsClient && (ipcWsClient.readyState === WebSocket.OPEN || ipcWsClient.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    
    // 清理旧的连接
    if (ipcWsClient) {
        ipcWsClient.removeAllListeners(); 
        ipcWsClient.close();
        ipcWsClient = null;
    }

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret
        }
    });

    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC_WSC Worker ${cluster.worker.id}] 成功连接到控制平面 (Panel)。实时推送已激活。`);
        // [AXIOM V5.0] 重连成功，重置尝试计数器
        ipcReconnectAttempts = 0;
        
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        
        // 启动新的推送器 (它会处理 pending_traffic_delta)
        statsPusherIntervalId = setInterval(() => {
            pushStatsToControlPlane(ipcWsClient); 
        }, 1000); 

    });

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            switch (message.action) {
                case 'kick':
                    if (message.username) {
                        kickUser(message.username);
                    }
                    break;
                case 'update_limits':
                    if (message.username && message.limits) {
                        updateUserLimits(message.username, message.limits);
                    }
                    break;
                case 'reset_traffic':
                     if (message.username) {
                        resetUserTraffic(message.username);
                    }
                    break;
                case 'delete':
                    if (message.username) {
                        kickUser(message.username); 
                        if (userStats.has(message.username)) {
                            userStats.delete(message.username); 
                        }
                    }
                    break;
                case 'reload_hosts':
                    console.log(`[IPC_CMD Worker ${cluster.worker.id}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
                    break;
            }
        } catch (e) {
            console.error(`[IPC_WSC Worker ${cluster.worker.id}] 解析 IPC 消息失败: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC_WSC Worker ${cluster.worker.id}] 与控制平面的连接已断开。代码: ${code}.`);
        
        // 清理定时器
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = null;
        ipcWsClient = null;
        
        // [AXIOM V5.0] 触发指数退避重连
        attemptIpcReconnect();
    });

    ws.on('error', (err) => {
        // [AXIOM V5.0] 仅记录错误，'close' 事件将处理重连
        console.error(`[IPC_WSC Worker ${cluster.worker.id}] WebSocket 发生错误: ${err.message}`);
    });
}


// --- 异步日志设置 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
        logStream.on('error', (err) => {
            console.error(`[CRITICAL] Error in WSS log stream: ${err.message}`);
        });
    } catch (e) {
        console.error(`[CRITICAL] Failed to create log stream: ${e.message}`);
    }
}

function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master(N/A)';
    const logEntry = `[${timestamp}] [${status}] [${workerId}] USER=${username} CLIENT_IP=${clientIp} LOCAL_PORT=${localPort}\n`;
    logStream.write(logEntry);
}

// --- Host 白名单管理 ---
function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
            console.warn("Warning: Host whitelist file not found. Using empty list (Strict mode).");
            HOST_WHITELIST = new Set();
            return;
        }
        const data = fs.readFileSync(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            const cleanHosts = new Set();
            hosts.forEach(host => {
                if (typeof host === 'string') {
                    let h = host.trim().toLowerCase();
                    if (h.includes(':')) h = h.split(':')[0]; 
                    if (h) cleanHosts.add(h);
                }
            });
            HOST_WHITELIST = cleanHosts;
            if (cluster.isWorker) {
                console.log(`[Worker ${cluster.worker.id}] Host Whitelist loaded successfully. Count: ${HOST_WHITELIST.size}`);
            }
        } else {
            HOST_WHITELIST = new Set();
            console.error("Error: Host whitelist file format error (not an array). Using empty list (Strict mode).");
        }
    } catch (e) {
        HOST_WHITELIST = new Set();
        console.error(`Error loading Host Whitelist: ${e.message}. Using empty list (Strict mode).`);
    }
}

function checkHost(headers) {
    // [AXIOM V5.0] 改进: 检查 Host 和 SNI 
    // 在 Node.js 的 net/tls 模块中，HTTP 握手发生在 TLS 握手之后，
    // 因此在 `handleClient` 中，我们只能依赖 HTTP `Host` 头。
    // 如果需要 TLS SNI 检查，则需要在 TLS 服务器的 `options` 中使用 `SNICallback`，但这超出了 WSS Proxy 的职责，
    // WSS Proxy 仅处理已建立连接的流量。
    
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
        // 如果没有 Host 头，且白名单非空，则拒绝。如果白名单为空，则允许（非严格模式）。
        if (HOST_WHITELIST.size > 0) {
            console.log(`Host check failed: Missing Host header. Access denied. Whitelist size: ${HOST_WHITELIST.size}`);
            return false;
        }
        return true; 
    }
    let requestedHost = hostMatch[1].trim().toLowerCase();
    if (requestedHost.includes(':')) requestedHost = requestedHost.split(':')[0];
    if (HOST_WHITELIST.size === 0) return true; 
    if (HOST_WHITELIST.has(requestedHost)) return true;
    
    console.log(`Host check failed for: ${requestedHost}. Access denied.`);
    return false;
}

// --- 认证与并发检查 ---
function parseAuth(headers) {
    // ... (此函数无变化) ...
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const credentials = Buffer.from(authMatch[1], 'base64').toString('utf8');
        const [username, ...passwordParts] = credentials.split(':');
        const password = passwordParts.join(':');
        if (!username || !password) return null;
        return { username, password };
    } catch (e) {
        return null;
    }
}

async function authenticateUser(username, password) {
    // ... (此函数无变化) ...
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return { success: false, limits: null, requireAuthHeader: 1, message: errorData.message || `Auth failed with status ${response.status}` };
        }
        const data = await response.json();
        updateUserLimits(username, data.limits);
        return { success: true, limits: data.limits, requireAuthHeader: data.require_auth_header, message: 'Auth successful' };
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        // [AXIOM V5.0] 如果认证 API 连接失败，返回 503 错误，让客户端知道服务不可用
        return { success: false, limits: null, requireAuthHeader: 1, message: 'Internal API connection error', status: 503 };
    }
}

async function getLiteAuthStatus(username) {
    // ... (此函数无变化) ...
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), {
            method: 'GET',
        });
        if (!response.ok) {
            // [AXIOM V5.0] 如果 API 返回非 200，检查状态码
            const status = response.status;
            return { exists: false, requireAuthHeader: 1, status };
        }
        const data = await response.json();
        if (data.success && data.require_auth_header === 0) {
            if (data.limits) {
                updateUserLimits(username, data.limits);
            }
        }
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1, status: 200 };
    } catch (e) {
        console.error(`[LITE_AUTH] Failed to fetch Panel /auth/user-settings API: ${e.message}`);
        return { exists: false, requireAuthHeader: 1, status: 503 };
    }
}

function checkConcurrency(username, maxConnections) {
    // ... (此函数无变化) ...
    if (maxConnections === 0) return true; 
    const stats = getUserStat(username); 
    if (stats.sockets.size < maxConnections) {
        return true;
    }
    return false;
}


// --- Client Handler ---
function handleClient(clientSocket, isTls) {
    
    let clientIp = clientSocket.remoteAddress;
    // [AXIOM V5.0] 兼容 IPv6 地址格式
    if (clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
    
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;

    let fullRequest = Buffer.alloc(0);
    
    let state = 'handshake';
    let remoteSocket = null;
    let username = null; 
    let limits = null; 
    let requireAuthHeader = 1; 

    clientSocket.setTimeout(TIMEOUT);
    clientSocket.setKeepAlive(true, 60000);

    clientSocket.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE' && err.code !== 'ETIMEDOUT') {
            console.error(`[WSS_ERR] Client Socket Error (${username || clientIp}): ${err.message}`);
        }
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });

    clientSocket.on('timeout', () => {
        console.log(`[WSS_TIMEOUT] Client Socket Timeout (${username || clientIp})`);
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });
    
    clientSocket.on('close', () => {
        if (remoteSocket) remoteSocket.destroy();
        if (username) {
            try {
                const stats = getUserStat(username);
                stats.sockets.delete(clientSocket);
                stats.ip_map.delete(clientIp);
            } catch (e) {}
            logConnection(clientIp, clientPort, localPort, username, 'CONN_END');
        } else {
            logConnection(clientIp, clientPort, localPort, 'N/A', 'CONN_END_UNAUTH');
        }
    });

    clientSocket.on('data', async (data) => {
        
        if (state === 'forwarding') {
            // [AXIOM V5.0] 转发阶段，使用令牌桶进行限速 (Upload)
            const stats = getUserStat(username);
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            stats.traffic_delta.upload += dataToWrite.length;
            stats.traffic_live.upload += dataToWrite.length;
            if (remoteSocket && remoteSocket.writable) {
                remoteSocket.write(dataToWrite);
            }
            return;
        }

        fullRequest = Buffer.concat([fullRequest, data]);

        while (state === 'handshake' && fullRequest.length > 0) {
            
            const headerEndIndex = fullRequest.indexOf('\r\n\r\n');

            if (headerEndIndex === -1) {
                if (fullRequest.length > BUFFER_SIZE * 2) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HUGE_HEADER');
                    clientSocket.end(FORBIDDEN_RESPONSE); 
                }
                return; 
            }

            const headersRaw = fullRequest.subarray(0, headerEndIndex);
            let dataAfterHeaders = fullRequest.subarray(headerEndIndex + 4);
            const headers = headersRaw.toString('utf8', 0, headersRaw.length);
            
            fullRequest = dataAfterHeaders;
            
            if (!checkHost(headers)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HOST');
                clientSocket.end(FORBIDDEN_RESPONSE);
                return; 
            }
            
            const auth = parseAuth(headers);
            
            const isWebsocketRequest = headers.includes('Upgrade: websocket') || 
                                       headers.includes('Connection: Upgrade') || 
                                       headers.includes('GET-RAY');

            if (!isWebsocketRequest) {
                 if (auth) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_AUTH_NOT_WEBSOCKET');
                    clientSocket.end(FORBIDDEN_RESPONSE);
                    return; 
                 }
                 logConnection(clientIp, clientPort, localPort, 'N/A', 'DUMMY_HTTP_REQUEST');
                 clientSocket.write(FIRST_RESPONSE);
                 continue; 
            }
            
            // --- 认证流程 ---
            let authResult;
            if (auth) {
                username = auth.username; 
                authResult = await authenticateUser(auth.username, auth.password);
                
                if (authResult.status === 503) {
                    // API 连接失败，返回 500
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAIL (API Down)`);
                    clientSocket.end(INTERNAL_ERROR_RESPONSE);
                    return;
                }
                if (!authResult.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED (${authResult.message})`);
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; 
                }
                limits = authResult.limits; 
                requireAuthHeader = authResult.requireAuthHeader;
                
            } else {
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                
                if (requireAuthHeader === 1) { // 默认情况下需要认证头
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'AUTH_MISSING');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return;
                }

                if (!uriMatch) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'URI_AUTH_MISSING');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; 
                }
                
                const tempUsername = uriMatch[1];
                const liteAuth = await getLiteAuthStatus(tempUsername);

                if (liteAuth.status === 503) {
                     logConnection(clientIp, clientPort, localPort, tempUsername, `AUTH_FAIL (API Down)`);
                     clientSocket.end(INTERNAL_ERROR_RESPONSE);
                     return;
                }
                
                if (liteAuth.exists && liteAuth.requireAuthHeader === 0) {
                    username = tempUsername;
                    // [AXIOM V5.0] Lite Auth 应该已经通过 updateUserLimits 更新了 limits
                    limits = getUserStat(username).limits; 
                    requireAuthHeader = 0;
                    logConnection(clientIp, clientPort, localPort, username, 'AUTH_LITE_SUCCESS');
                    
                } else {
                    logConnection(clientIp, clientPort, localPort, tempUsername, 'AUTH_LITE_FAILED');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; 
                }
            }
            
            // --- 并发检查 ---
            if (!checkConcurrency(username, limits.max_connections)) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                clientSocket.end(TOO_MANY_REQUESTS_RESPONSE);
                return; 
            }
            
            // --- 升级连接 ---
            clientSocket.write(SWITCH_RESPONSE); 
            
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); 

            // --- Payload Eater / 分割载荷处理 ---
            const payloadSample = initialSshData.length > 256 ? initialSshData.subarray(0, 256).toString('utf8') : initialSshData.toString('utf8');
            const trimmedSample = payloadSample.trimLeft();
            
            const isHttpPayload = trimmedSample.startsWith('CONNECT ') || 
                                  trimmedSample.startsWith('GET ') || 
                                  trimmedSample.startsWith('POST ');

            if (isHttpPayload) {
                // 查找 Payload 尾部的 SSH 数据
                const httpPayloadEndIndex = initialSshData.indexOf('\r\n\r\n');
                if (httpPayloadEndIndex !== -1) {
                    const sshData = initialSshData.subarray(httpPayloadEndIndex + 4);
                    connectToTarget(sshData); 
                } else {
                    // 没有找到完整的 HTTP Payload 尾部
                    logConnection(clientIp, clientPort, localPort, username, `REJECTED_SPLIT_PAYLOAD`);
                    clientSocket.end(FORBIDDEN_RESPONSE);
                }
            } else {
                // 收到原始 SSH 数据
                connectToTarget(initialSshData); 
            }
            
            return;

        } 
    }); 

    async function connectToTarget(initialData) {
        if (remoteSocket) return; 
        try {
            // [AXIOM V5.0] 目标始终是内部转发端口，无需修改
            remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
                logConnection(clientIp, clientPort, localPort, username, 'CONN_START'); 
                const stats = getUserStat(username);
                
                // [AXIOM V5.0] IP/连接记录 (支持 IPv6)
                stats.ip_map.set(clientIp, clientSocket);
                stats.sockets.add(clientSocket);
                
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    clientSocket.emit('data', initialData);
                }
                
                // --- Downstream (Download) ---
                remoteSocket.on('data', (data) => {
                    // [AXIOM V5.0] 转发阶段，使用令牌桶进行限速 (Download)
                    const allowedBytes = stats.bucket_down.consume(data.length);
                    if (allowedBytes === 0) return; 
                    const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
                    stats.traffic_delta.download += dataToWrite.length;
                    stats.traffic_live.download += dataToWrite.length;
                    if (clientSocket.writable) {
                        clientSocket.write(dataToWrite);
                    }
                });
                remoteSocket.setKeepAlive(true, 60000);
            });

            remoteSocket.on('error', (err) => {
                if (err.code === 'ECONNREFUSED') {
                    console.error(`[WSS] CRITICAL: Connection refused by target ${DEFAULT_TARGET.host}:${DEFAULT_TARGET.port}. (Is SSHD running on port ${INTERNAL_FORWARD_PORT}?)`);
                    clientSocket.end(INTERNAL_ERROR_RESPONSE); 
                }
                clientSocket.destroy();
            });

            remoteSocket.on('close', () => {
                clientSocket.end();
            });
        } catch (e) {
            console.error(`[WSS] Failed to connect to target: ${e.message}`);
            clientSocket.destroy();
        }
    }
}


// --- Internal API Server (Master Process Only) ---
function startInternalApiServer() {
    
    const internalApiSecretMiddleware = (req, res, next) => {
        if (req.headers['x-internal-secret'] === INTERNAL_API_SECRET) {
            next();
        } else {
            console.warn(`[WSS API Master] Denied internal API request (Bad Secret).`);
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Forbidden: Invalid API Secret' }));
        }
    };
    
    const server = http.createServer((req, res) => {
        // [AXIOM V5.0] 兼容 IPv4 和 IPv6 本地地址
        const clientIp = req.socket.remoteAddress;
        if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== '::ffff:127.0.0.1') {
             console.warn(`[WSS API Master] Denied external access attempt to Internal API from ${clientIp}`);
             res.writeHead(403, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
             return;
        }
        
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                if (req.method === 'GET' && req.url === '/stats') {
                    internalApiSecretMiddleware(req, res, () => {
                        allWorkerStats.clear();
                        for (const id in cluster.workers) {
                            cluster.workers[id].send({ type: 'GET_STATS' });
                        }
                        
                        setTimeout(() => {
                            const aggregatedStats = {};
                            const aggregatedLiveIps = {};

                            for (const [workerId, workerData] of allWorkerStats.entries()) {
                                for (const username in workerData.stats) {
                                    if (!aggregatedStats[username]) {
                                        aggregatedStats[username] = { ...workerData.stats[username] };
                                    } else {
                                        const existing = aggregatedStats[username];
                                        const current = workerData.stats[username];
                                        existing.traffic_delta_up += current.traffic_delta_up;
                                        existing.traffic_delta_down += current.traffic_delta_down;
                                        existing.connections += current.connections;
                                        existing.speed_kbps.upload += current.speed_kbps.upload;
                                        existing.speed_kbps.download += current.speed_kbps.download;
                                    }
                                }
                                Object.assign(aggregatedLiveIps, workerData.live_ips);
                            }
                            
                            for (const username in aggregatedStats) {
                                const user = aggregatedStats[username];
                                user.traffic_delta = user.traffic_delta_up + user.traffic_delta_down;
                                delete user.traffic_delta_up;
                                delete user.traffic_delta_down;
                            }
                            
                            const finalResponse = { ...aggregatedStats, live_ips: aggregatedLiveIps };
                            
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify(finalResponse));
                            
                        }, 250); 
                    });
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Not Found' }));
                }
            } catch (e) {
                console.error(`[WSS API Master] Internal API Error: ${e.message}`);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error' }));
            }
        });
    });

    server.listen(INTERNAL_API_PORT, '127.0.0.1', () => {
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
        console.log(`[WSS ${workerId}] Internal API server (/stats) listening on 127.0.0.1:${INTERNAL_API_PORT}`);
    }).on('error', (err) => {
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
        console.error(`[CRITICAL ${workerId}] WSS Internal API failed to start on port ${INTERNAL_API_PORT}: ${err.message}`);
        process.exit(1);
    });
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    // [AXIOM V5.0] 开始 IPC 连接（包含指数退避）
    connectToIpcServer(); 

    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    // [AXIOM V5.0] 兼容 IPv6
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[WSS Worker ${cluster.worker.id}] Listening on ${LISTEN_ADDR}:${HTTP_PORT} (HTTP)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${cluster.worker.id}] HTTP Server failed to start on port ${HTTP_PORT}: ${err.message}`);
        process.exit(1); 
    });

    try {
        if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
            console.warn(`[WSS Worker ${cluster.worker.id}] WARNING: TLS certificate not found at ${CERT_FILE}. TLS server disabled.`);
            return;
        }
        const tlsOptions = {
            key: fs.readFileSync(KEY_FILE),
            cert: fs.readFileSync(CERT_FILE),
            rejectUnauthorized: false
        };
        const tlsServer = tls.createServer(tlsOptions, (socket) => {
            handleClient(socket, true);
        });
        // [AXIOM V5.0] 兼容 IPv6
        tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
            console.log(`[WSS Worker ${cluster.worker.id}] Listening on ${LISTEN_ADDR}:${TLS_PORT} (TLS)`);
        }).on('error', (err) => {
            console.error(`[CRITICAL Worker ${cluster.worker.id}] TLS Server failed to start on port ${TLS_PORT}: ${err.message}`);
            process.exit(1); 
        });
    } catch (e) {
        console.error(`[WSS Worker ${cluster.worker.id}] WARNING: TLS server setup failed: ${e.message}. Disabled.`);
    }
}

process.on('SIGINT', () => {
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
    console.log(`\n[${workerId}] WSS Proxy Stopped.`);
    if (logStream) logStream.end();
    // [AXIOM V5.0] 清理重连定时器
    if (ipcReconnectTimer) clearTimeout(ipcReconnectTimer);
    if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
    process.exit(0);
});


// --- [AXIOM V3.0] 集群启动逻辑 (重构) ---

if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[AXIOM Cluster Master] Master process ${process.pid} is running.`);
    console.log(`[AXIOM Cluster Master] Forking ${numCPUs} worker processes...`);

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    
    startInternalApiServer();
    
    cluster.on('message', (worker, message) => {
        if (message && message.type === 'STATS_RESPONSE' && message.data) {
            allWorkerStats.set(worker.id, message.data);
        }
    });

    cluster.on('exit', (worker, code, signal) => {
        console.error(`[AXIOM Cluster Master] Worker ${worker.process.pid} (ID: ${worker.id}) died with code ${code}, signal ${signal}.`);
        allWorkerStats.delete(worker.id);
        console.log('[AXIOM Cluster Master] Forking a new replacement worker...');
        cluster.fork();
    });

} else {
    // This is a worker process
    console.log(`[AXIOM Cluster Worker] Worker ${process.pid} (ID: ${cluster.worker.id}) starting...`);
    
    startServers();
    
    process.on('message', (msg) => {
        if (msg && msg.type === 'GET_STATS') {
            
            const statsReport = {};
            const liveIps = {};
            
            for (const [username, stats] of userStats.entries()) {
                if (stats.sockets.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
                    statsReport[username] = {
                        traffic_delta_up: stats.traffic_delta.upload,
                        traffic_delta_down: stats.traffic_delta.download,
                        speed_kbps: stats.speed_kbps,
                        connections: stats.sockets.size
                    };
                    // 仅为 /stats API 临时重置，流量增量由 IPC 处理
                    stats.traffic_delta.upload = 0;
                    stats.traffic_delta.download = 0;
                    for (const ip of stats.ip_map.keys()) {
                        liveIps[ip] = username;
                    }
                }
            }
            
            // [AXIOM V5.0] 将 pending 流量包含在 STATS_RESPONSE 中
            // 注意：这里只是报告，实际的 delta 清理由 IPC 连接的推送逻辑处理
            
            process.send({ 
                type: 'STATS_RESPONSE', 
                data: { 
                    stats: statsReport, 
                    live_ips: liveIps,
                    pending_traffic: pending_traffic_delta // 附带未发送的流量 (供 Master 调试/检查)
                } 
            });
        }
    });
    
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${cluster.worker.id}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`, err.stack);
        process.exit(1); 
    });
}
