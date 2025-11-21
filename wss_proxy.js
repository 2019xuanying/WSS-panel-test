/**
 * WSS Proxy Core (Node.js)
 * V9.0.0 (Axiom V5.0 - Robust IPC & Offline Buffering)
 *
 * [AXIOM V5.0 CHANGELOG]
 * - [IPC] 健壮性升级:
 * - 新增应用层心跳 (Ping/Pong)，防止半开连接。
 * - 实现指数退避重连算法 (Exponential Backoff)。
 * - [数据] 零丢失计费 (Zero-Loss Accounting):
 * - 引入 offlineStatsQueue。当 IPC 断开时，流量数据累积在本地。
 * - 连接恢复后，自动补发离线期间产生的流量统计。
 * - [架构] 纯主动推送:
 * - 彻底移除旧版 GET_STATS 被动轮询逻辑。
 * - 适配原生 UDPGW (无需代码变更，仅需通过 SSH 隧道转发)。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');

// --- 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        if (cluster.isWorker) {
            console.log(`[AXIOM V5.0] Worker ${cluster.worker.id} 配置加载成功。`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载配置 ${CONFIG_PATH}: ${e.message}`);
        process.exit(1); 
    }
}
loadConfig();

// --- 核心常量 ---
const LISTEN_ADDR = '0.0.0.0';
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); 
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const HTTP_PORT = config.wss_http_port;
const TLS_PORT = config.wss_tls_port;
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port; // 仅用于兼容旧检查，V5.0 IPC 不依赖此
const PANEL_API_URL = config.panel_api_url;
const DEFAULT_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };
const TIMEOUT = 86400000; // 24h
const BUFFER_SIZE = 65536;
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// IPC 常量
const IPC_URL = `ws://127.0.0.1:${config.panel_port}/ipc`;
const PUSH_INTERVAL = 1000; // 1秒推送
const HEARTBEAT_INTERVAL = 5000; // 5秒心跳
const HEARTBEAT_TIMEOUT = 15000; // 15秒超时判定

// HTTP Responses
const FIRST_RESPONSE = Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nOK\r\n\r\n');
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const FORBIDDEN_RESPONSE = Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
const UNAUTHORIZED_RESPONSE = Buffer.from('HTTP/1.1 401 Unauthorized\r\nProxy-Authenticate: Basic realm="WSS Proxy"\r\nContent-Length: 0\r\n\r\n');
const TOO_MANY_REQUESTS_RESPONSE = Buffer.from('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 
const userStats = new Map();

// IPC 状态
let ipcWsClient = null;
let statsPusherIntervalId = null;
let heartbeatIntervalId = null;
let lastPingTime = 0;
let lastPongTime = 0;
let reconnectDelay = 1000;
// [AXIOM V5.0] 离线数据队列 Map<username, {up, down}>
let offlineStatsQueue = new Map(); 

// --- 令牌桶 (Token Bucket) ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = capacityKbps * 1024; 
        this.fillRate = fillRateKbps * 1024 / 1000; 
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
        this._fillTokens();
        this.capacity = newCapacityKbps * 1024;
        this.fillRate = newFillRateKbps * 1024 / 1000;
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 用户状态管理 ---
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

/** * 实时速度计算器 (1秒)
 * 注意：此函数仅计算速度，不再执行熔断判断
 */
function calculateSpeeds() {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = now - stats.lastSpeedCalc.time;
        if (elapsed < (PUSH_INTERVAL / 2)) continue; 
        const elapsedSeconds = elapsed / 1000.0;
        
        const uploadDelta = stats.traffic_live.upload - stats.lastSpeedCalc.upload;
        stats.speed_kbps.upload = (uploadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.upload = stats.traffic_live.upload;

        const downloadDelta = stats.traffic_live.download - stats.lastSpeedCalc.download;
        stats.speed_kbps.download = (downloadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.download = stats.traffic_live.download;
        
        stats.lastSpeedCalc.time = now;
        
        if (stats.sockets.size === 0 && stats.traffic_delta.upload === 0 && stats.traffic_delta.download === 0) {
            userStats.delete(username);
        }
    }
}
setInterval(calculateSpeeds, PUSH_INTERVAL);

// --- IPC 与 健壮性逻辑 ---

/**
 * 推送统计数据到控制平面
 * [AXIOM V5.0] 增加了离线队列处理
 */
function pushStatsToControlPlane() {
    const statsReport = {};
    const liveIps = {};
    let hasData = false;

    // 1. 收集当前 Worker 的数据
    for (const [username, stats] of userStats.entries()) {
        // 仅处理有活动的用户
        if (stats.sockets.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            
            statsReport[username] = {
                speed_kbps: stats.speed_kbps, 
                connections: stats.sockets.size,
                traffic_delta_up: stats.traffic_delta.upload,
                traffic_delta_down: stats.traffic_delta.download
            };

            // 关键: 收集完后清零本地增量
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            
            for (const ip of stats.ip_map.keys()) {
                liveIps[ip] = username;
            }
            hasData = true;
        }
    }

    // 2. 如果离线，存入队列
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
        if (hasData) {
            // console.log(`[IPC] 离线中... 缓存流量数据 (${Object.keys(statsReport).length} users)`);
            for (const username in statsReport) {
                const report = statsReport[username];
                const queued = offlineStatsQueue.get(username) || { up: 0, down: 0 };
                queued.up += report.traffic_delta_up;
                queued.down += report.traffic_delta_down;
                offlineStatsQueue.set(username, queued);
            }
        }
        return;
    }

    // 3. 如果在线，先发送离线队列 (如果有)
    if (offlineStatsQueue.size > 0) {
        const offlineReport = {};
        for (const [username, data] of offlineStatsQueue.entries()) {
            offlineReport[username] = {
                speed_kbps: { upload: 0, download: 0 }, // 补发数据不影响实时速度
                connections: 0, // 补发时不更新连接数
                traffic_delta_up: data.up,
                traffic_delta_down: data.down
            };
        }
        
        try {
            ipcWsClient.send(JSON.stringify({
                type: 'stats_update',
                workerId: cluster.worker.id,
                payload: { stats: offlineReport, live_ips: {} } // 补发不含 IP
            }));
            console.log(`[IPC] 已补发离线期间的流量数据 (${offlineStatsQueue.size} users)。`);
            offlineStatsQueue.clear();
        } catch (e) {
            console.error(`[IPC] 补发离线数据失败: ${e.message}`);
            // 发送失败则保留队列，下次再试
        }
    }

    // 4. 发送实时数据
    if (hasData) {
        try {
            ipcWsClient.send(JSON.stringify({
                type: 'stats_update',
                workerId: cluster.worker.id,
                payload: { stats: statsReport, live_ips: liveIps }
            }));
        } catch (e) {
            console.error(`[IPC] 推送实时数据失败: ${e.message}`);
        }
    }
}

function handleIpcMessage(message) {
    switch (message.action) {
        case 'kick':
            if (message.username) kickUser(message.username);
            break;
        case 'update_limits':
            if (message.username && message.limits) {
                updateUserLimits(message.username, message.limits);
            }
            break;
        case 'reset_traffic':
             if (message.username) resetUserTraffic(message.username);
            break;
        case 'delete':
            if (message.username) {
                kickUser(message.username); 
                userStats.delete(message.username); 
            }
            break;
        case 'reload_hosts':
            loadHostWhitelist();
            break;
    }
}

/**
 * [AXIOM V5.0] 健壮的 IPC 连接管理器
 */
function connectToIpcServer() {
    console.log(`[IPC] Worker ${cluster.worker.id} 正在连接控制平面...`);

    const ws = new WebSocket(IPC_URL, {
        headers: { 
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': cluster.worker.id 
        }
    });

    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC] 连接成功。重置退避延迟。`);
        reconnectDelay = 1000; // 重置延迟
        lastPingTime = Date.now();
        lastPongTime = Date.now();

        // 启动推送器
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = setInterval(pushStatsToControlPlane, PUSH_INTERVAL);

        // 启动心跳检测
        if (heartbeatIntervalId) clearInterval(heartbeatIntervalId);
        heartbeatIntervalId = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.ping(); // 发送 Ping
                lastPingTime = Date.now();
                
                // 检查僵死连接
                if (lastPingTime - lastPongTime > HEARTBEAT_TIMEOUT) {
                    console.warn(`[IPC] 心跳超时 (${HEARTBEAT_TIMEOUT}ms)。主动断开重连。`);
                    ws.terminate();
                }
            }
        }, HEARTBEAT_INTERVAL);
    });

    ws.on('pong', () => {
        lastPongTime = Date.now();
    });

    ws.on('message', (data) => {
        try {
            handleIpcMessage(JSON.parse(data.toString()));
        } catch (e) {
            console.error(`[IPC] 消息解析错误: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC] 连接断开 (Code: ${code})。离线队列已启用。${reconnectDelay/1000}秒后重连...`);
        cleanupIpc();
        
        // 指数退避重连
        setTimeout(connectToIpcServer, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 30000); // 最大 30秒
    });

    ws.on('error', (err) => {
        console.error(`[IPC] 连接错误: ${err.message}`);
        ws.terminate(); // 触发 close
    });
}

function cleanupIpc() {
    if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
    if (heartbeatIntervalId) clearInterval(heartbeatIntervalId);
    ipcWsClient = null;
}

// --- 用户管理逻辑 ---
function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.sockets.size > 0) {
        console.log(`[IPC] 踢出用户 ${username} (${stats.sockets.size} 连接)...`);
        for (const socket of stats.sockets) socket.destroy(); 
        stats.sockets.clear();
        stats.ip_map.clear();
    }
}

function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); 
    stats.limits = {
        rate_kbps: limits.rate_kbps || 0,
        max_connections: limits.max_connections || 0,
        require_auth_header: limits.require_auth_header === 0 ? 0 : 1
    };
    // 更新令牌桶
    stats.bucket_up.updateRate(stats.limits.rate_kbps * 2, stats.limits.rate_kbps); 
    stats.bucket_down.updateRate(stats.limits.rate_kbps * 2, stats.limits.rate_kbps); 
}

function resetUserTraffic(username) {
    const stats = userStats.get(username);
    if (stats) {
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
    }
}

// --- 日志与白名单 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
        logStream.on('error', (err) => console.error(`[LOG] Stream Error: ${err.message}`));
    } catch (e) { console.error(`[LOG] Create Error: ${e.message}`); }
}

function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const workerId = cluster.isWorker ? `W${cluster.worker.id}` : 'M';
    logStream.write(`[${timestamp}] [${status}] [${workerId}] USER=${username} IP=${clientIp}:${clientPort}\n`);
}

function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
            HOST_WHITELIST = new Set(); return;
        }
        const hosts = JSON.parse(fs.readFileSync(HOSTS_DB_PATH, 'utf8'));
        HOST_WHITELIST = new Set(hosts.map(h => h.split(':')[0].trim().toLowerCase()).filter(h => h));
        if (cluster.isWorker) console.log(`[Worker ${cluster.worker.id}] Host 白名单已重载: ${HOST_WHITELIST.size} 条`);
    } catch (e) {
        HOST_WHITELIST = new Set();
        console.error(`[HOSTS] 加载失败: ${e.message}`);
    }
}

function checkHost(headers) {
    if (HOST_WHITELIST.size === 0) return true;
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) return false;
    let host = hostMatch[1].trim().toLowerCase().split(':')[0];
    return HOST_WHITELIST.has(host);
}

// --- 认证逻辑 ---
function parseAuth(headers) {
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const creds = Buffer.from(authMatch[1], 'base64').toString('utf8').split(':');
        if (creds.length < 2) return null;
        return { username: creds[0], password: creds.slice(1).join(':') };
    } catch (e) { return null; }
}

async function authenticateUser(username, password) {
    try {
        // 即使 panel_port 变了，Proxy 也会重启，所以 config.panel_api_url 是新的
        const res = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!res.ok) return { success: false, message: `HTTP ${res.status}` };
        const data = await res.json();
        if (data.success) updateUserLimits(username, data.limits);
        return { success: true, limits: data.limits, requireAuthHeader: data.require_auth_header };
    } catch (e) { return { success: false, message: e.message }; }
}

async function getLiteAuthStatus(username) {
    try {
        const res = await fetch(`${PANEL_API_URL}/auth/user-settings?username=${username}`);
        if (!res.ok) return { exists: false };
        const data = await res.json();
        if (data.success && data.require_auth_header === 0) {
            // 刷新一下 limits (虽然 lite auth 通常意味着不做严格限制，但我们要保持一致)
            // 这里的逻辑稍微简化，假设面板会返回 limits，如果面板接口支持的话
            // 目前面板接口只返回 require_auth_header。为了健壮性，我们可以在 Panel V5.0 加上 limits 返回
            // 但为了不破坏协议，这里暂且不更新 limits (使用默认或旧值)
        }
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1 };
    } catch (e) { return { exists: false }; }
}

// --- Client Handler ---
function handleClient(clientSocket, isTls) {
    let clientIp = clientSocket.remoteAddress;
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;
    let fullRequest = Buffer.alloc(0);
    let state = 'handshake';
    let remoteSocket = null;
    let username = null; 
    let limits = null; 

    clientSocket.setTimeout(TIMEOUT);
    clientSocket.setKeepAlive(true, 60000);

    const cleanup = () => {
        if (remoteSocket) remoteSocket.destroy();
        if (username) {
            const stats = userStats.get(username);
            if (stats) {
                stats.sockets.delete(clientSocket);
                stats.ip_map.delete(clientIp);
            }
        }
        clientSocket.destroy();
    };

    clientSocket.on('error', cleanup);
    clientSocket.on('timeout', cleanup);
    clientSocket.on('close', cleanup);

    clientSocket.on('data', async (data) => {
        if (state === 'forwarding') {
            const stats = getUserStat(username);
            const allowed = stats.bucket_up.consume(data.length);
            if (allowed === 0) return; 
            const chunk = (allowed < data.length) ? data.subarray(0, allowed) : data;
            stats.traffic_delta.upload += chunk.length;
            stats.traffic_live.upload += chunk.length;
            if (remoteSocket && remoteSocket.writable) remoteSocket.write(chunk);
            return;
        }

        fullRequest = Buffer.concat([fullRequest, data]);

        if (state === 'handshake') {
            const headerEnd = fullRequest.indexOf('\r\n\r\n');
            if (headerEnd === -1) {
                if (fullRequest.length > BUFFER_SIZE) clientSocket.end(FORBIDDEN_RESPONSE);
                return;
            }

            const headersRaw = fullRequest.subarray(0, headerEnd).toString();
            const body = fullRequest.subarray(headerEnd + 4);
            fullRequest = body; // 剩余数据留给 SSH

            if (!checkHost(headersRaw)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECT_HOST');
                return clientSocket.end(FORBIDDEN_RESPONSE);
            }

            // 认证
            const auth = parseAuth(headersRaw);
            const isWs = headersRaw.includes('Upgrade: websocket') || headersRaw.includes('Connection: Upgrade');
            
            if (!isWs) { // 哑 HTTP 响应
                 if (auth) {
                     logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECT_HTTP_AUTH');
                     return clientSocket.end(FORBIDDEN_RESPONSE);
                 }
                 clientSocket.write(FIRST_RESPONSE); // Payload Eater
                 return;
            }

            if (auth) {
                username = auth.username;
                const res = await authenticateUser(username, auth.password);
                if (!res.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAIL_${res.message}`);
                    return clientSocket.end(UNAUTHORIZED_RESPONSE);
                }
                limits = res.limits;
            } else {
                // URI 认证
                const match = headersRaw.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                if (!match) return clientSocket.end(UNAUTHORIZED_RESPONSE);
                const tempUser = match[1];
                const lite = await getLiteAuthStatus(tempUser);
                if (!lite.exists || lite.requireAuthHeader !== 0) {
                    return clientSocket.end(UNAUTHORIZED_RESPONSE);
                }
                username = tempUser;
                limits = getUserStat(username).limits; // 可能为空，需注意
            }

            // 并发检查
            if (limits && limits.max_connections > 0) {
                const stats = getUserStat(username);
                if (stats.sockets.size >= limits.max_connections) {
                    logConnection(clientIp, clientPort, localPort, username, 'REJECT_CONCURRENCY');
                    return clientSocket.end(TOO_MANY_REQUESTS_RESPONSE);
                }
            }

            clientSocket.write(SWITCH_RESPONSE);
            connectToTarget(fullRequest);
        }
    });

    function connectToTarget(initialData) {
        // 连接到 SSH 端口 (22)
        // UDPGW 流量也是封装在 SSH 里的，所以只需要连 22
        remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
            logConnection(clientIp, clientPort, localPort, username, 'CONN_OPEN');
            const stats = getUserStat(username);
            stats.sockets.add(clientSocket);
            stats.ip_map.set(clientIp, clientSocket);
            state = 'forwarding';

            // 处理初始 SSH 数据 (Payload Eater 可能剩下的)
            // 检查是否是 HTTP 伪装
            const sample = initialData.slice(0, 100).toString().trim();
            if (sample.startsWith('CONNECT') || sample.startsWith('GET') || sample.startsWith('POST')) {
                const end = initialData.indexOf('\r\n\r\n');
                if (end !== -1) initialData = initialData.subarray(end + 4);
            }
            if (initialData.length > 0) remoteSocket.write(initialData);
        });

        remoteSocket.on('data', (data) => {
            const stats = getUserStat(username);
            const allowed = stats.bucket_down.consume(data.length);
            if (allowed === 0) return;
            const chunk = (allowed < data.length) ? data.subarray(0, allowed) : data;
            stats.traffic_delta.download += chunk.length;
            stats.traffic_live.download += chunk.length;
            if (clientSocket.writable) clientSocket.write(chunk);
        });

        remoteSocket.on('error', () => clientSocket.destroy());
        remoteSocket.on('close', () => clientSocket.end());
    }
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    connectToIpcServer(); // 启动健壮的 IPC

    const httpServer = net.createServer((s) => handleClient(s, false));
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[WSS] Worker ${cluster.worker.id} HTTP 监听于 ${HTTP_PORT}`);
    });

    try {
        if (fs.existsSync(CERT_FILE)) {
            const tlsServer = tls.createServer({
                key: fs.readFileSync(KEY_FILE),
                cert: fs.readFileSync(CERT_FILE),
                rejectUnauthorized: false
            }, (s) => handleClient(s, true));
            tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
                console.log(`[WSS] Worker ${cluster.worker.id} TLS 监听于 ${TLS_PORT}`);
            });
        }
    } catch (e) {
        console.warn(`[WSS] TLS 启动跳过: ${e.message}`);
    }
}

if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[AXIOM V5.0] Master ${process.pid} 启动。Forking ${numCPUs} workers...`);
    for (let i = 0; i < numCPUs; i++) cluster.fork();
    
    // Master 不需要监听 IPC，只有 Worker 需要连接 Panel
    
    cluster.on('exit', (worker) => {
        console.log(`[Master] Worker ${worker.id} died. Forking new...`);
        cluster.fork();
    });
} else {
    startServers();
    process.on('uncaughtException', (e) => {
        console.error(`[CRITICAL] Worker Crash: ${e.message}`, e.stack);
        process.exit(1);
    });
}
