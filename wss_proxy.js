/**
 * WSS Proxy Core (Node.js)
 * V8.7.1 (Axiom Refactor V6.1 - Robust Traffic Delta Handling Fix)
 *
 * [AXIOM V6.1 FIXES]
 * - [TRAFFIC FIX] 移除 calculateSpeeds 中冗余且有风险的流量 delta 聚合逻辑。
 * - [TRAFFIC FIX] 统一在 pushStatsToControlPlane 中处理 stats.traffic_delta 到 pending_traffic_delta 的转移。
 * 这确保了 IPC 连接断开时，流量增量会被安全地缓存，直到连接恢复。
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
const crypto = require('crypto'); 


// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        // [V6.0 FIX] WSS Proxy 现在监听内部端口
        if (!config.wss_proxy_port_internal) config.wss_proxy_port_internal = 10080;
        if (cluster.isWorker) {
            console.log(`[AXIOM V6.0] Worker ${cluster.worker.id} 成功从 ${CONFIG_PATH} 加载配置。内部端口: ${config.wss_proxy_port_internal}`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); 
    }
}
loadConfig(); 
// --- 结束配置加载 ---


// --- 核心常量 (现在从 config 读取) ---
const LISTEN_ADDR = '127.0.0.1'; // [V6.0 FIX] 仅监听本地回环，由 Nginx 反代
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); 
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
// [V6.0 FIX] HTTP_PORT/TLS_PORT 不再用于监听，但保留配置项
const HTTP_PORT = config.wss_http_port || 80; 
const TLS_PORT = config.wss_tls_port || 443; 
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port;
const PANEL_API_URL = config.panel_api_url;
const INTERNAL_API_SECRET = config.internal_api_secret;
const DEFAULT_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };
const TIMEOUT = 86400000; 
const IDLE_TIMEOUT_MS = 60000; // [V6.0 NEW] 60秒空闲清理
const BUFFER_SIZE = 65536;
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// HTTP Responses (保持不变)
const FIRST_RESPONSE = Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nOK\r\n\r\n');
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const FORBIDDEN_RESPONSE = Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
const UNAUTHORIZED_RESPONSE = Buffer.from('HTTP/1.1 401 Unauthorized\r\nProxy-Authenticate: Basic realm="WSS Proxy"\r\nContent-Length: 0\r\n\r\n');
const TOO_MANY_REQUESTS_RESPONSE = Buffer.from('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 
let allWorkerStats = new Map();


// --- 令牌桶 (Token Bucket) 限速器 (保持不变) ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = Math.max(0, capacityKbps * 1024); 
        this.fillRateBase = Math.max(0, fillRateKbps * 1024 / 1000); 
        this.tokens = this.capacity; 
        this.lastFill = Date.now();
        this.currentRatio = 1.0; // [V6.0 NEW] 动态节流比例
    }
    _fillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            // [V6.0 FIX] 应用动态节流比例
            const actualFillRate = this.fillRateBase * this.currentRatio; 
            const newTokens = elapsed * actualFillRate;
            this.tokens = Math.min(this.capacity, this.tokens + newTokens);
            this.lastFill = now;
        }
    }
    consume(bytesToConsume) {
        if (this.fillRateBase === 0) return bytesToConsume; 
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
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRateBase = Math.max(0, newFillRateKbps * 1024 / 1000); // 存储基础填充率
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
    // [V6.0 NEW] 动态节流更新
    updateThrottle(ratio) {
        this._fillTokens();
        this.currentRatio = Math.min(1.0, Math.max(0.0, ratio)); // 确保在 0.0 到 1.0 之间
        console.log(`[TokenBucket] New throttle ratio set: ${this.currentRatio.toFixed(2)}`);
    }
}

// --- 全局状态管理 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 1000; 

const pending_traffic_delta = {}; // [V6.1 FIX] 仅用于存储 IPC 断开时积累的、待发送的流量增量
const WORKER_ID = cluster.isWorker ? cluster.worker.id : 'master';
let throttlingRatio = 1.0; // [V6.0 NEW] 全局节流比例

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            // [AXIOM V5.2] 存储连接元数据，键为 socket 引用
            connections: new Map(), // key: net.Socket, value: {id, clientIp, startTime, lastActivityTime}
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, // [V6.1 FIX] 实时累加，每次 pushStatsToControlPlane 时清零
            traffic_live: { upload: 0, download: 0 }, // 持续累加，用于速度计算
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
        
        // [V6.0 FIX] 在每次速度计算后，强制更新 TokenBucket 的节流比例
        stats.bucket_up.updateThrottle(throttlingRatio);
        stats.bucket_down.updateThrottle(throttlingRatio);

        // [V6.1 FIX] 移除此处冗余的流量增量持久化逻辑。
        // 清理逻辑现在统一在 pushStatsToControlPlane 中处理。
        
        // [AXIOM V5.5 FIX] 僵尸连接清理逻辑: 确保没有连接，且没有待推送的流量增量时才删除
        const hasPending = pending_traffic_delta[username] && 
                           (pending_traffic_delta[username].upload > 0 || pending_traffic_delta[username].download > 0);
                           
        // [V6.1 FIX] 增加对 stats.traffic_delta 的检查，确保新产生的流量也被考虑在内
        const hasRecentTraffic = stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0;

        if (stats.connections.size === 0 && !hasPending && !hasRecentTraffic) {
            userStats.delete(username);
            if (pending_traffic_delta[username]) {
                delete pending_traffic_delta[username];
            }
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


/**
 * [V6.0 NEW] 僵尸连接清理器 (每 30 秒运行一次)
 */
function checkLastActivity() {
    const now = Date.now();
    const idleTimeout = IDLE_TIMEOUT_MS; // 60000 ms

    for (const [username, stats] of userStats.entries()) {
        const connectionsToDelete = [];
        
        stats.connections.forEach((meta, socket) => {
            const lastActivity = meta.lastActivityTime || meta.startTime;
            if (now - lastActivity > idleTimeout) {
                console.warn(`[ZOMBIE Worker ${WORKER_ID}] 用户 ${username} 的连接 (IP: ${meta.clientIp}) 闲置超过 ${idleTimeout / 1000}s，正在销毁...`);
                socket.destroy();
                connectionsToDelete.push(socket);
                logConnection(meta.clientIp, 'N/A', 'N/A', username, 'CONN_END_IDLE');
            }
        });
        
        // 确保从 Map 中移除已销毁的连接
        connectionsToDelete.forEach(socket => {
            stats.connections.delete(socket);
            
            // 检查并删除 ip_map 中的对应项
            for (const [ip, s] of stats.ip_map.entries()) {
                 if (s === socket) {
                     stats.ip_map.delete(ip);
                     break;
                 }
            }
        });
    }
}
setInterval(checkLastActivity, 30000); // 30秒检查一次


// --- [AXIOM V5.0] 实时 IPC 客户端 (指数退避重连) ---

let ipcWsClient = null;
let statsPusherIntervalId = null;

let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 60000; 

/**
 * [AXIOM V5.0] 实时统计推送器
 */
function pushStatsToControlPlane(ws_client) {
    
    // 1. 统一将本次间隔的新流量 (stats.traffic_delta) 累加到待发送缓存 (pending_traffic_delta)
    for (const [username, stats] of userStats.entries()) {
        if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
             if (!pending_traffic_delta[username]) {
                 pending_traffic_delta[username] = { upload: 0, download: 0 };
             }
             pending_traffic_delta[username].upload += stats.traffic_delta.upload;
             pending_traffic_delta[username].download += stats.traffic_delta.download;
             
             // 清零本次间隔内的新流量计数器
             stats.traffic_delta.upload = 0;
             stats.traffic_delta.download = 0;
        }
    }
    
    // 如果 IPC 断开，流量已安全缓存，直接返回
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; 
    }

    const statsReport = {};
    const liveIps = {};
    
    // 2. 准备报告 payload (使用 pending_traffic_delta 作为流量增量)
    let hasPushableData = false;
    
    // 复制 pending 缓存，用于发送报告。
    // 注意：我们必须在发送成功后才能清除 pending 缓存。
    // 由于 Node.js ws 库的 send 是异步的，我们不能在发送前清除。
    // 但是 Panel 端的架构不发 ACK，我们只能假定发送成功即持久化成功。
    // 因此，我们在此处清除，并接受若 Panel 在持久化时崩溃，流量可能丢失的风险。
    const pendingDeltaSnapshot = { ...pending_traffic_delta };
    
    for (const [username, stats] of userStats.entries()) {
        const pending = pendingDeltaSnapshot[username];
        const currentDeltaUp = pending ? pending.upload : 0;
        const currentDeltaDown = pending ? pending.download : 0;
        
        // 只有有连接或有待发送流量的用户才需要报告
        if (stats.connections.size > 0 || currentDeltaUp > 0 || currentDeltaDown > 0) {
            
            // 聚合连接元数据
            let lastActivity = 0;
            stats.connections.forEach(meta => {
                 if (meta.lastActivityTime > lastActivity) {
                     lastActivity = meta.lastActivityTime;
                 }
            });
            
            statsReport[username] = {
                speed_kbps: stats.speed_kbps, 
                connections: stats.connections.size, 
                traffic_delta_up: currentDeltaUp,
                traffic_delta_down: currentDeltaDown,
                lastActivityTime: lastActivity, 
                source: 'wss'
            };

            if (currentDeltaUp > 0 || currentDeltaDown > 0) {
                 hasPushableData = true;
                 
                 // [V6.1 CRITICAL FIX] 清除已发送的 pending 缓存
                 if (pending_traffic_delta[username]) {
                     delete pending_traffic_delta[username];
                 }
            }
            
            for (const ip of stats.ip_map.keys()) {
                liveIps[ip] = username;
            }
        }
    }

    // 3. 将此 Worker 的数据推送到控制平面
    if (Object.keys(statsReport).length > 0 || Object.keys(liveIps).length > 0 || hasPushableData) {
         try {
            ws_client.send(JSON.stringify({
                type: 'stats_update',
                workerId: WORKER_ID, 
                payload: { 
                    stats: statsReport, 
                    live_ips: liveIps,
                    // [AXIOM V5.5 FIX] 即使没有流量也发送报告，确保 Panel 知道 Worker 仍在线
                    ping: true 
                }
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送统计数据失败: ${e.message}`);
        }
    }
}

function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.connections.size > 0) {
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在踢出用户 ${username} (${stats.connections.size} 个连接)...`);
        for (const socket of stats.connections.keys()) {
            socket.destroy(); 
        }
        stats.connections.clear();
        stats.ip_map.clear();
    }
}

function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); 
    console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在更新用户 ${username} 的限制...`);
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
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在重置用户 ${username} 的流量计数器...`);
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
        
        // [V6.1 FIX] 重置 pending 缓存
        if (pending_traffic_delta[username]) {
             delete pending_traffic_delta[username];
        }
    }
}

function attemptIpcReconnect() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    
    const baseDelay = Math.pow(2, ipcReconnectAttempts) * 1000;
    const delay = Math.min(baseDelay, MAX_RECONNECT_DELAY_MS);

    ipcReconnectAttempts++;
    console.warn(`[IPC_WSC Worker ${WORKER_ID}] 正在重试连接 (尝试次数: ${ipcReconnectAttempts}, 延迟: ${delay / 1000}s)...`);

    ipcReconnectTimer = setTimeout(connectToIpcServer, delay);
}


function connectToIpcServer() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    if (ipcWsClient && (ipcWsClient.readyState === WebSocket.OPEN || ipcWsClient.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const wsProtocol = 'ws:';
    const wsUrl = `${wsProtocol}//127.0.0.1:${config.panel_port}/ipc`;
    
    if (ipcWsClient) {
        ipcWsClient.removeAllListeners(); 
        ipcWsClient.close();
        ipcWsClient = null;
    }

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID 
        }
    });

    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC_WSC Worker ${WORKER_ID}] 成功连接到控制平面 (Panel)。实时推送已激活。`);
        ipcReconnectAttempts = 0;
        
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        
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
                        // [V6.1 FIX] 确保删除后清除 pending 缓存
                        if (pending_traffic_delta[message.username]) {
                            delete pending_traffic_delta[message.username];
                        }
                    }
                    break;
                case 'reload_hosts':
                    console.log(`[IPC_CMD Worker ${WORKER_ID}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
                    break;
                case 'throttle':
                    // [V6.0 NEW] 动态 QoS/节流指令
                    if (typeof message.ratio === 'number') {
                        throttlingRatio = message.ratio;
                        // 向 Panel 反馈确认
                        ws.send(JSON.stringify({ 
                            type: 'THROTTLE_FEEDBACK', 
                            workerId: WORKER_ID, 
                            ratio: throttlingRatio 
                        }));
                    }
                    break;
                case 'GET_METADATA':
                     if (message.username && message.requestId) {
                         // 响应控制平面的元数据请求
                         const stats = userStats.get(message.username);
                         const connections = [];
                         if (stats) {
                            stats.connections.forEach(meta => {
                                connections.push({
                                    id: meta.id,
                                    ip: meta.clientIp,
                                    start: meta.startTime,
                                    workerId: WORKER_ID 
                                });
                            });
                         }
                         
                         // 将响应发送回控制平面
                         ws.send(JSON.stringify({
                             type: 'METADATA_RESPONSE',
                             requestId: message.requestId,
                             username: message.username,
                             workerId: WORKER_ID,
                             connections: connections
                         }));
                         
                     }
                    break;
            }
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 解析 IPC 消息失败: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC_WSC Worker ${WORKER_ID}] 与控制平面的连接已断开。代码: ${code}.`);
        
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = null;
        ipcWsClient = null;
        
        attemptIpcReconnect();
    });

    ws.on('error', (err) => {
        console.error(`[IPC_WSC Worker ${WORKER_ID}] WebSocket 发生错误: ${err.message}`);
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
    const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master(N/A)';
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
                console.log(`[Worker ${WORKER_ID}] Host Whitelist loaded successfully. Count: ${HOST_WHITELIST.size}`);
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
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
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

/**
 * [V6.0 FIX] 优化认证流程：现在 Panel 返回 'allowed' 字段，消除了二次往返。
 */
async function authenticateUser(username, password) {
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json().catch(() => ({}));

        if (response.status === 429) { 
             // Concurrency Limit Reached
             return { success: false, status: 429, limits: null, message: data.message || 'Concurrency Limit Reached' };
        }
        
        if (!response.ok || !data.success || !data.allowed) {
            // Auth Failed (401/403) or Not Allowed (But Auth was successful)
            return { success: false, status: response.status, limits: null, requireAuthHeader: data.require_auth_header, message: data.message || `Auth failed with status ${response.status}` };
        }
        
        // Auth Success AND Allowed (Concurrency Check Passed)
        updateUserLimits(username, data.limits);
        return { 
            success: true, 
            status: 200, 
            limits: data.limits, 
            requireAuthHeader: data.require_auth_header, 
            message: 'Auth successful' 
        };
        
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        return { success: false, status: 503, limits: null, requireAuthHeader: 1, message: 'Internal API connection error' };
    }
}

async function getLiteAuthStatus(username) {
    // 简化 Lite Auth，仅检查是否允许 URI 认证
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), {
            method: 'GET',
        });
        if (!response.ok) {
            const status = response.status;
            return { exists: false, requireAuthHeader: 1, status };
        }
        const data = await response.json();
        
        // 如果用户存在且 require_auth_header 为 0，则允许
        if (data.success && data.require_auth_header === 0) {
            // 注意：Lite Auth 成功后，我们不能依赖这个接口来设置 limits，因为没有密码。
            // 依赖 Panel 在 auth success 时更新 limits。
             return { exists: data.success, requireAuthHeader: 0, status: 200 };
        }
        return { exists: data.success, requireAuthHeader: 1, status: 200 };
    } catch (e) {
        console.error(`[LITE_AUTH] Failed to fetch Panel /auth/user-settings API: ${e.message}`);
        return { exists: false, requireAuthHeader: 1, status: 503 };
    }
}

/**
 * [V6.0 DEPRECATED] 移除 checkConcurrency 函数，逻辑已合并到 Panel
 */


// --- Client Handler ---
function handleClient(clientSocket, isTls) {
    
    let clientIp = clientSocket.remoteAddress;
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
                // [AXIOM V6.0 FIX] 移除 connections 中的 socket 引用
                stats.connections.delete(clientSocket);
                stats.ip_map.delete(clientIp);
            } catch (e) {}
            logConnection(clientIp, clientPort, localPort, username, 'CONN_END');
        } else {
            logConnection(clientIp, clientPort, localPort, 'N/A', 'CONN_END_UNAUTH');
        }
    });

    clientSocket.on('data', async (data) => {
        
        // [V6.0 NEW] 更新活跃时间
        if (username) {
             const stats = getUserStat(username);
             const meta = stats.connections.get(clientSocket);
             if (meta) meta.lastActivityTime = Date.now();
        }

        if (state === 'forwarding') {
            const stats = getUserStat(username);
            
            // [V6.0 FIX] Downstream
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            
            // [V6.1 FIX] 流量增量累加
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
                // 如果请求体过大但头部未结束，拒绝
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
            let authResult = { success: false, status: 401, limits: null, requireAuthHeader: 1, message: 'No Auth Attempt' };
            let authAttempted = false;

            if (auth) {
                username = auth.username; 
                authResult = await authenticateUser(auth.username, auth.password);
                authAttempted = true;
                
            } else {
                // 尝试 URI 免认证
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                
                // [V6.0 FIX] 预先检查 Lite Auth 状态，避免不必要的 Auth 往返
                const liteAuth = await getLiteAuthStatus(username || (uriMatch ? uriMatch[1] : 'N/A'));
                requireAuthHeader = liteAuth.requireAuthHeader; // 设置 Lite Auth 状态
                
                if (liteAuth.status === 503) {
                     logConnection(clientIp, clientPort, localPort, 'N/A', `AUTH_FAIL (API Down)`);
                     clientSocket.end(INTERNAL_ERROR_RESPONSE);
                     return;
                }
                
                if (requireAuthHeader === 1) { 
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'AUTH_MISSING');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; 
                }

                if (uriMatch && liteAuth.exists && liteAuth.requireAuthHeader === 0) {
                    username = uriMatch[1];
                    // Lite Auth 成功，但需要再次调用 authenticateUser 来获取 limits 和 final check
                    // [V6.1 FIX] 使用正确的占位符密码 'lite_auth_placeholder'
                    authResult = await authenticateUser(username, 'lite_auth_placeholder'); 
                    authAttempted = true;
                    
                } else {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'URI_AUTH_FAILED');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; 
                }
            }
            
            // --- 最终授权结果判断 ---
            if (authResult.status === 429) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                clientSocket.end(TOO_MANY_REQUESTS_RESPONSE);
                return; 
            }
            
            if (!authResult.success) {
                if (authResult.status === 401 || authResult.status === 403) {
                     logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED (${authResult.message})`);
                     clientSocket.end(UNAUTHORIZED_RESPONSE);
                } else {
                     logConnection(clientIp, clientPort, localPort, username, `AUTH_ERROR (${authResult.message})`);
                     clientSocket.end(INTERNAL_ERROR_RESPONSE);
                }
                return;
            }
            
            limits = authResult.limits; 
            
            // --- 升级连接 ---
            clientSocket.write(SWITCH_RESPONSE); 
            
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); 

            // --- Payload Eater / 分割载荷处理 (AXIOM V5.5 FIX A6) ---
            const sshVersionMarker = Buffer.from('SSH-2.0-');
            const sshStartIndex = initialSshData.indexOf(sshVersionMarker);
            
            let dataToSend = initialSshData;
            
            if (sshStartIndex !== -1) {
                // 如果找到 SSH 头部，从头部开始发送
                dataToSend = initialSshData.subarray(sshStartIndex);
                logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_SUCCESS (Skipped ${sshStartIndex} bytes)`);
            } else if (initialSshData.length > 0) {
                 // 警告：未找到 SSH 标识符，但有数据。按原样发送。
                 logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_WARNING (No SSH Marker)`);
            }
            
            connectToTarget(dataToSend);
            
            return;

        } 
    }); 

    async function connectToTarget(initialData) {
        if (remoteSocket) return; 
        try {
            remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
                logConnection(clientIp, clientPort, localPort, username, 'CONN_START'); 
                const stats = getUserStat(username);
                
                // [AXIOM V6.0 FIX] 记录连接元数据，包括活跃时间
                const connectionId = crypto.randomUUID();
                const now = new Date().toISOString();
                stats.connections.set(clientSocket, {
                    id: connectionId,
                    clientIp: clientIp,
                    startTime: now,
                    lastActivityTime: Date.now(), // [V6.0 NEW]
                    workerId: WORKER_ID
                });
                
                stats.ip_map.set(clientIp, clientSocket);
                
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    clientSocket.emit('data', initialData);
                }
                
                // --- Downstream (Download) ---
                remoteSocket.on('data', (data) => {
                    // [V6.0 NEW] 更新活跃时间
                    const meta = stats.connections.get(clientSocket);
                    if (meta) meta.lastActivityTime = Date.now();
                    
                    const allowedBytes = stats.bucket_down.consume(data.length);
                    if (allowedBytes === 0) return; 
                    const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
                    
                    // [V6.1 FIX] 流量增量累加
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
    
    // NOTE: Master API Server on INTERNAL_API_PORT is only used for backward compatibility 
    // (/stats endpoint which is currently unused by Panel). 
    // The core IPC is now handled by WebSocket /ipc on Panel_Port.
    
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
        const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master';
        console.log(`[WSS ${workerId}] Internal API server (/stats) listening on 127.0.0.1:${INTERNAL_API_PORT}`);
    }).on('error', (err) => {
        const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master';
        console.error(`[CRITICAL ${workerId}] WSS Internal API failed to start on port ${INTERNAL_API_PORT}: ${err.message}`);
        process.exit(1);
    });
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    connectToIpcServer(); 

    // [V6.0 FIX] WSS Proxy 现在监听内部端口 (config.wss_proxy_port_internal)
    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    httpServer.listen(config.wss_proxy_port_internal, LISTEN_ADDR, () => {
        console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${config.wss_proxy_port_internal} (HTTP Internal)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${WORKER_ID}] HTTP Internal Server failed to start on port ${config.wss_proxy_port_internal}: ${err.message}`);
        process.exit(1); 
    });

    try {
        // [V6.0 FIX] 移除 TLS/443 监听，现在由 Nginx 负责 TLS 卸载
        console.log(`[WSS Worker ${WORKER_ID}] TLS Server disabled. Nginx will handle 443 port.`);
    } catch (e) {
        // Error handling for removed TLS server
    }
}

process.on('SIGINT', () => {
    const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master';
    console.log(`\n[${workerId}] WSS Proxy Stopped.`);
    if (logStream) logStream.end();
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
    console.log(`[AXIOM Cluster Worker] Worker ${process.pid} (ID: ${WORKER_ID}) starting...`);
    
    startServers();
    
    process.on('message', (msg) => {
        if (msg && msg.type === 'GET_STATS') {
            
            const statsReport = {};
            const liveIps = {};
            
            // [V6.1 FIX] 确保将所有新流量转移到 pending 缓存中，然后再报告 pending 中的数据
            for (const [username, stats] of userStats.entries()) {
                 if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
                     if (!pending_traffic_delta[username]) {
                         pending_traffic_delta[username] = { upload: 0, download: 0 };
                     }
                     pending_traffic_delta[username].upload += stats.traffic_delta.upload;
                     pending_traffic_delta[username].download += stats.traffic_delta.download;
                     
                     stats.traffic_delta.upload = 0;
                     stats.traffic_delta.download = 0;
                 }
            }

            for (const username in pending_traffic_delta) {
                const pending = pending_traffic_delta[username];
                
                if (pending.upload > 0 || pending.download > 0) {
                    
                     const stats = userStats.get(username) || {};

                     statsReport[username] = {
                        traffic_delta_up: pending.upload,
                        traffic_delta_down: pending.download,
                        speed_kbps: stats.speed_kbps || { upload: 0, download: 0 },
                        connections: stats.connections ? stats.connections.size : 0,
                        source: 'wss'
                     };
                     
                     // 此时不清除 pending，由 Master API 决定（虽然 Master API 很少使用）
                }
            }
            
            // 聚合 live IPs
            for (const [username, stats] of userStats.entries()) {
                for (const ip of stats.ip_map.keys()) {
                    liveIps[ip] = username;
                }
            }
            
            process.send({ 
                type: 'STATS_RESPONSE', 
                data: { 
                    stats: statsReport, 
                    live_ips: liveIps,
                    // [V6.1 FIX] 移除此处的 pending_traffic，因为它可能导致 Master 端清理失败
                    // pending_traffic: pending_traffic_delta 
                } 
            });
        }
    });
    
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${WORKER_ID}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`, err.stack);
        process.exit(1); 
    });
}
