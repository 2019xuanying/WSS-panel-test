/**
 * WSS Proxy Core (Node.js)
 * V8.5.0 (Axiom Refactor V5.2 - Live Connection Metadata)
 *
 * [AXIOM V5.2 CHANGELOG]
 * - [元数据记录] 重构 `userStats` 结构：
 * - `stats.sockets` (Set) 替换为 `stats.connections` (Map)，用于存储连接元数据。
 * - 在 `connectToTarget` 中，记录 `socketId`, `workerId`, `clientIp`, `startTime`。
 * - [API] 移除未使用的 /stats API 逻辑，但保留 `GET_STATS` 消息处理器。
 * - [元数据推送] 新增对 IPC 命令 `Youtube` 的支持，用于响应控制平面关于该 Worker 活跃连接的详细列表。
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
const crypto = require('crypto'); // 用于生成唯一的 socketId


// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        if (cluster.isWorker) {
            console.log(`[AXIOM V5.2] Worker ${cluster.worker.id} 成功从 ${CONFIG_PATH} 加载配置。`);
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
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRate = Math.max(0, newFillRateKbps * 1024 / 1000);
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 全局状态管理 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 1000; 

const pending_traffic_delta = {}; 
const WORKER_ID = cluster.isWorker ? cluster.worker.id : 'master';

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            // [AXIOM V5.2] 存储连接元数据，键为 socket 引用
            connections: new Map(), // key: net.Socket, value: {id, clientIp, startTime}
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
        
        if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
            if (!pending_traffic_delta[username]) {
                pending_traffic_delta[username] = { upload: 0, download: 0 };
            }
            pending_traffic_delta[username].upload += stats.traffic_delta.upload;
            pending_traffic_delta[username].download += stats.traffic_delta.download;
            
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0; 
        }
        
        // [AXIOM V5.2] 检查 connections.size
        if (stats.connections.size === 0 && stats.traffic_delta.upload === 0 && stats.traffic_delta.download === 0) {
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
const MAX_RECONNECT_DELAY_MS = 60000; 

/**
 * [AXIOM V5.0] 实时统计推送器
 */
function pushStatsToControlPlane(ws_client) {
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; 
    }

    const statsReport = {};
    const liveIps = {};
    
    // 1. 合并并清空 Pending 流量
    let hasPendingTraffic = false;
    for (const username in pending_traffic_delta) {
        const stats = getUserStat(username); 
        stats.traffic_delta.upload += pending_traffic_delta[username].upload;
        stats.traffic_delta.download += pending_traffic_delta[username].download;
        if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            hasPendingTraffic = true;
        }
    }
    for (const key in pending_traffic_delta) { delete pending_traffic_delta[key]; }
    
    
    // 2. 准备本地统计数据
    for (const [username, stats] of userStats.entries()) {
        if (stats.connections.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            
            statsReport[username] = {
                speed_kbps: stats.speed_kbps, 
                connections: stats.connections.size, // [AXIOM V5.2] 报告连接数量，而非 Map
                traffic_delta_up: stats.traffic_delta.upload,
                traffic_delta_down: stats.traffic_delta.download
            };

            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            
            for (const ip of stats.ip_map.keys()) {
                liveIps[ip] = username;
            }
        }
    }

    // 3. 将此 Worker 的数据推送到控制平面
    if (Object.keys(statsReport).length > 0 || Object.keys(liveIps).length > 0) {
         try {
            ws_client.send(JSON.stringify({
                type: 'stats_update',
                workerId: WORKER_ID, // [AXIOM V5.2] 使用常量
                payload: { stats: statsReport, live_ips: liveIps }
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送统计数据失败: ${e.message}`);
        }
    } else if (hasPendingTraffic) {
        try {
            ws_client.send(JSON.stringify({
                type: 'stats_update',
                workerId: WORKER_ID,
                payload: { stats: {}, live_ips: {} }
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送空统计数据失败: ${e.message}`);
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

    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    
    if (ipcWsClient) {
        ipcWsClient.removeAllListeners(); 
        ipcWsClient.close();
        ipcWsClient = null;
    }

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID // [AXIOM V5.2] 确保 Worker ID 发送
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

    // [AXIOM V5.2] 新增消息类型：GET_METADATA
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
                    console.log(`[IPC_CMD Worker ${WORKER_ID}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
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

// --- 认证与并发检查 (保持不变) ---

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

async function authenticateUser(username, password) {
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
        return { success: false, limits: null, requireAuthHeader: 1, message: 'Internal API connection error', status: 503 };
    }
}

async function getLiteAuthStatus(username) {
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
    if (maxConnections === 0) return true; 
    const stats = getUserStat(username); 
    // [AXIOM V5.2] 检查 connections.size
    if (stats.connections.size < maxConnections) {
        return true;
    }
    return false;
}


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
                // [AXIOM V5.2] 移除 connections 中的 socket 引用
                stats.connections.delete(clientSocket);
                stats.ip_map.delete(clientIp);
            } catch (e) {}
            logConnection(clientIp, clientPort, localPort, username, 'CONN_END');
        } else {
            logConnection(clientIp, clientPort, localPort, 'N/A', 'CONN_END_UNAUTH');
        }
    });

    clientSocket.on('data', async (data) => {
        
        if (state === 'forwarding') {
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
                
                if (requireAuthHeader === 1) { 
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
                const httpPayloadEndIndex = initialSshData.indexOf('\r\n\r\n');
                if (httpPayloadEndIndex !== -1) {
                    const sshData = initialSshData.subarray(httpPayloadEndIndex + 4);
                    connectToTarget(sshData); 
                } else {
                    logConnection(clientIp, clientPort, localPort, username, `REJECTED_SPLIT_PAYLOAD`);
                    clientSocket.end(FORBIDDEN_RESPONSE);
                }
            } else {
                connectToTarget(initialSshData); 
            }
            
            return;

        } 
    }); 

    async function connectToTarget(initialData) {
        if (remoteSocket) return; 
        try {
            remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
                logConnection(clientIp, clientPort, localPort, username, 'CONN_START'); 
                const stats = getUserStat(username);
                
                // [AXIOM V5.2] 记录连接元数据
                const connectionId = crypto.randomUUID();
                stats.connections.set(clientSocket, {
                    id: connectionId,
                    clientIp: clientIp,
                    startTime: new Date().toISOString(),
                    workerId: WORKER_ID
                });
                
                stats.ip_map.set(clientIp, clientSocket);
                
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    clientSocket.emit('data', initialData);
                }
                
                // --- Downstream (Download) ---
                remoteSocket.on('data', (data) => {
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

    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${HTTP_PORT} (HTTP)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${WORKER_ID}] HTTP Server failed to start on port ${HTTP_PORT}: ${err.message}`);
        process.exit(1); 
    });

    try {
        if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
            console.warn(`[WSS Worker ${WORKER_ID}] WARNING: TLS certificate not found at ${CERT_FILE}. TLS server disabled.`);
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
        tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
            console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${TLS_PORT} (TLS)`);
        }).on('error', (err) => {
            console.error(`[CRITICAL Worker ${WORKER_ID}] TLS Server failed to start on port ${TLS_PORT}: ${err.message}`);
            process.exit(1); 
        });
    } catch (e) {
        console.error(`[WSS Worker ${WORKER_ID}] WARNING: TLS server setup failed: ${e.message}. Disabled.`);
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
            
            for (const [username, stats] of userStats.entries()) {
                if (stats.connections.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
                    statsReport[username] = {
                        traffic_delta_up: stats.traffic_delta.upload,
                        traffic_delta_down: stats.traffic_delta.download,
                        speed_kbps: stats.speed_kbps,
                        connections: stats.connections.size
                    };
                    stats.traffic_delta.upload = 0;
                    stats.traffic_delta.download = 0;
                    for (const ip of stats.ip_map.keys()) {
                        liveIps[ip] = username;
                    }
                }
            }
            
            process.send({ 
                type: 'STATS_RESPONSE', 
                data: { 
                    stats: statsReport, 
                    live_ips: liveIps,
                    pending_traffic: pending_traffic_delta 
                } 
            });
        }
    });
    
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${WORKER_ID}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`, err.stack);
        process.exit(1); 
    });
}
