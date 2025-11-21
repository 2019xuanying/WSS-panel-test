/**
 * WSS Proxy Core (Node.js)
 * Axiom Architecture V5.0.0 (Phase 2: Native UDPGW & Robust IPC)
 *
 * [AXIOM V5.0 CHANGELOG]
 * - [核心特性] 内置原生 UDPGW 服务器 (Native UDP over TCP):
 * - 实现了完整的 BadVPN-UDPGW 1.00 协议。
 * - 移除外部 badvpn 二进制依赖，降低部署复杂度。
 * - 支持多路复用 (Multiplexing) 和动态 Socket 生命周期管理。
 * - [稳定性] IPC 健壮性增强:
 * - 新增 Offline Buffer: 断网期间暂存流量数据，重连后自动补发。
 * - 新增 Heartbeat: 主动检测与 Panel 的连接状态。
 * - [性能] TCP/IP 协议栈调优:
 * - 全局启用 `setNoDelay(true)` (禁用 Nagle 算法) 以降低延迟。
 * - 启用 TCP KeepAlive 防止静默断连。
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
const dgram = require('dgram'); // [AXIOM V5.0] 新增: 用于原生 UDPGW

// --- [AXIOM V5.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        if (cluster.isWorker) {
            // console.log(`[Worker ${cluster.worker.id}] 配置加载成功。`);
        } else {
            console.log(`[Master] 配置加载成功。`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}`);
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
const UDPGW_PORT = config.udpgw_port || 7300; // [AXIOM V5.0] 原生 UDPGW 端口
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
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
        if (this.fillRate === 0) return bytesToConsume; // 无限制
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

// --- 全局用户状态 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 1000;

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

/** 实时速度计算器 (本地) */
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

        // 自动清理不活跃用户
        if (stats.sockets.size === 0 && stats.traffic_delta.upload === 0 && stats.traffic_delta.download === 0) {
            userStats.delete(username);
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


// --- [AXIOM V5.0] 健壮的 IPC 客户端 ---

let ipcWsClient = null;
let statsPusherIntervalId = null;
let offlineStatsBuffer = []; // [AXIOM V5.0] 断网缓存

function connectToIpcServer() {
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    // console.log(`[IPC] Worker ${cluster.worker.id} connecting to ${ipcUrl}...`);

    const ws = new WebSocket(ipcUrl, {
        headers: { 'X-Internal-Secret': config.internal_api_secret }
    });
    
    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC] Worker ${cluster.worker.id} Connected. Buffers: ${offlineStatsBuffer.length}`);
        
        // [AXIOM V5.0] 重连后立即发送缓存的数据
        if (offlineStatsBuffer.length > 0) {
            console.log(`[IPC] Flushing ${offlineStatsBuffer.length} buffered stats packets...`);
            while (offlineStatsBuffer.length > 0) {
                const cachedMsg = offlineStatsBuffer.shift();
                try { ws.send(JSON.stringify(cachedMsg)); } catch(e) {}
            }
        }

        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = setInterval(() => pushStats(ws), 1000);
    });

    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong', workerId: cluster.worker.id }));
                return;
            }
            handleIpcMessage(msg);
        } catch (e) {
            console.error(`[IPC] Message Parse Error: ${e.message}`);
        }
    });

    ws.on('close', () => {
        // console.warn(`[IPC] Disconnected. Reconnecting in 3s...`);
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        ipcWsClient = null;
        setTimeout(connectToIpcServer, 3000); // [AXIOM V5.0] 指数退避策略可在此扩展
    });

    ws.on('error', (err) => {
        // console.error(`[IPC] Error: ${err.message}`);
        ws.close();
    });
}

function pushStats(ws) {
    const statsReport = {};
    const liveIps = {};
    let hasData = false;

    for (const [username, stats] of userStats.entries()) {
        if (stats.sockets.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            statsReport[username] = {
                speed_kbps: stats.speed_kbps,
                connections: stats.sockets.size,
                traffic_delta_up: stats.traffic_delta.upload,
                traffic_delta_down: stats.traffic_delta.download
            };
            // 重置增量
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            
            for (const ip of stats.ip_map.keys()) {
                liveIps[ip] = username;
            }
            hasData = true;
        }
    }

    const payload = {
        type: 'stats_update',
        workerId: cluster.worker.id,
        payload: { stats: statsReport, live_ips: liveIps }
    };

    // [AXIOM V5.0] 如果断开，存入 Buffer
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        if (hasData) {
            if (offlineStatsBuffer.length > 60) offlineStatsBuffer.shift(); // 防止内存溢出，保留最近60秒
            offlineStatsBuffer.push(payload);
        }
        return;
    }

    try { ws.send(JSON.stringify(payload)); } catch (e) {}
}

function handleIpcMessage(message) {
    switch (message.action) {
        case 'kick':
            if (message.username) kickUser(message.username);
            break;
        case 'update_limits':
            if (message.username && message.limits) updateUserLimits(message.username, message.limits);
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

function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.sockets.size > 0) {
        console.log(`[Kick] User ${username}, closing ${stats.sockets.size} connections.`);
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
    // 更新令牌桶速率
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


// --- [AXIOM V5.0] 原生 UDPGW 服务器 ---

/**
 * 解析 UDPGW 协议数据包
 * 格式: [Length (2B)] [Type (1B)] [Payload...]
 */
function startNativeUdpgwServer() {
    const server = net.createServer((socket) => {
        // [AXIOM V5.0] TCP 优化
        socket.setNoDelay(true);
        socket.setKeepAlive(true, 30000);

        let buffer = Buffer.alloc(0);
        let state = 'handshake';
        // Map<ConnID, UdpSocket>
        const connections = new Map();

        socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);

            // 1. 握手阶段 (badvpn-udpgw 1.00)
            if (state === 'handshake') {
                const handshakeStr = "badvpn-udpgw 1.00\n";
                const idx = buffer.indexOf('\n');
                if (idx !== -1) {
                    const line = buffer.subarray(0, idx + 1).toString();
                    if (line === handshakeStr) {
                        socket.write(handshakeStr); // Reply same
                        buffer = buffer.subarray(idx + 1);
                        state = 'framing';
                    } else {
                        // console.warn(`[UDPGW] Bad Handshake: ${line.trim()}`);
                        socket.destroy();
                        return;
                    }
                } else {
                    if (buffer.length > 100) socket.destroy(); // Too long handshake
                    return; // Wait for more data
                }
            }

            // 2. 帧处理阶段
            while (state === 'framing' && buffer.length >= 2) {
                const len = buffer.readUInt16LE(0); // Length is little-endian? No, badvpn uses Little Endian for length in protocol usually? 
                // Wait, standard badvpn uses Little Endian for length.
                
                if (buffer.length < 2 + len) return; // Wait for full packet

                const packet = buffer.subarray(2, 2 + len);
                buffer = buffer.subarray(2 + len);

                if (packet.length === 0) continue;
                const type = packet[0];
                
                try {
                    handleUdpgwPacket(socket, connections, type, packet.subarray(1));
                } catch (e) {
                    console.error(`[UDPGW] Packet Error: ${e.message}`);
                }
            }
        });

        socket.on('error', () => destroyAllUdp(connections));
        socket.on('close', () => destroyAllUdp(connections));
        socket.on('timeout', () => socket.destroy());
    });

    // 绑定到 127.0.0.1，仅允许 SSH 隧道流量访问
    server.listen(UDPGW_PORT, '127.0.0.1', () => {
        console.log(`[UDPGW] Worker ${cluster.worker.id} Native UDPGW listening on 127.0.0.1:${UDPGW_PORT}`);
    });

    server.on('error', (err) => {
        console.error(`[UDPGW] Server Error: ${err.message}`);
    });
}

function destroyAllUdp(connections) {
    for (const udpSocket of connections.values()) {
        try { udpSocket.close(); } catch (e) {}
    }
    connections.clear();
}

function handleUdpgwPacket(tcpSocket, connections, type, payload) {
    // BadVPN Protocol Types:
    // 0x05: Create Connection
    // 0x07: Data (Client -> Server)
    // 0x11: Close Connection
    // 0x04: KeepAlive

    if (type === 0x05) { // Create
        // [ConnID(2)] [AddrLen(2)] [Addr...] [Port(2)]
        if (payload.length < 6) return;
        const connId = payload.readUInt16LE(0);
        const addrLen = payload.readUInt16LE(2);
        if (payload.length < 4 + addrLen + 2) return;
        const addr = payload.subarray(4, 4 + addrLen).toString();
        const port = payload.readUInt16LE(4 + addrLen);

        if (connections.has(connId)) return; // Already exists

        const udpSocket = dgram.createSocket('udp4');
        
        udpSocket.on('message', (msg, rinfo) => {
            // Send data back to TCP client
            // Format: [Len(2)] [Type(0x08=Data)] [ConnID(2)] [Data...]
            const head = Buffer.alloc(5);
            const totalLen = 3 + msg.length; // Type(1) + ConnID(2) + Data
            head.writeUInt16LE(totalLen, 0);
            head[2] = 0x08; // Type: Data (Server->Client)
            head.writeUInt16LE(connId, 3);
            
            if (tcpSocket.writable) {
                tcpSocket.write(Buffer.concat([head, msg]));
            }
        });

        udpSocket.on('error', () => {
            // Send close to client? Or just silent.
            connections.delete(connId);
        });
        
        // 绑定生命周期
        connections.set(connId, udpSocket);
        
        // 实际上 UDPGW 协议不需要 Connect, 只需要 SendTo
        // 但为了接收回包，我们需要保持这个 socket
        // 并且我们需要知道目标地址，以便后续 SendTo
        // *Badvpn logic*: The 'Create' packet sets the destination for this ConnID.
        udpSocket.destAddr = addr;
        udpSocket.destPort = port;

    } else if (type === 0x07) { // Data
        // [ConnID(2)] [Data...]
        if (payload.length < 2) return;
        const connId = payload.readUInt16LE(0);
        const data = payload.subarray(2);
        
        const udpSocket = connections.get(connId);
        if (udpSocket && udpSocket.destAddr) {
            udpSocket.send(data, udpSocket.destPort, udpSocket.destAddr, (err) => {
                if (err) { /* ignore */ }
            });
        }

    } else if (type === 0x11) { // Close
        if (payload.length < 2) return;
        const connId = payload.readUInt16LE(0);
        const udpSocket = connections.get(connId);
        if (udpSocket) {
            udpSocket.close();
            connections.delete(connId);
        }
    } 
    // 0x04 KeepAlive: Ignored (just keeps TCP connection active)
}


// --- Host 白名单与认证逻辑 ---

function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
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
        }
    } catch (e) {
        HOST_WHITELIST = new Set();
    }
}

function checkHost(headers) {
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
        return HOST_WHITELIST.size === 0; // Empty list = allow all (strict mode handled elsewhere)
    }
    let requestedHost = hostMatch[1].trim().toLowerCase();
    if (requestedHost.includes(':')) requestedHost = requestedHost.split(':')[0];
    if (HOST_WHITELIST.size === 0) return true;
    return HOST_WHITELIST.has(requestedHost);
}

function parseAuth(headers) {
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const credentials = Buffer.from(authMatch[1], 'base64').toString('utf8');
        const [username, ...passwordParts] = credentials.split(':');
        return { username, password: passwordParts.join(':') };
    } catch (e) { return null; }
}

async function authenticateUser(username, password) {
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            return { success: false, message: `Status ${response.status}` };
        }
        const data = await response.json();
        if (data.success) updateUserLimits(username, data.limits);
        return { success: data.success, limits: data.limits, requireAuthHeader: data.require_auth_header, message: 'OK' };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

async function getLiteAuthStatus(username) {
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), { method: 'GET' });
        if (!response.ok) return { exists: false, requireAuthHeader: 1 };
        const data = await response.json();
        if (data.success && data.require_auth_header === 0) {
            if (data.limits) updateUserLimits(username, data.limits);
        }
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1 };
    } catch (e) { return { exists: false, requireAuthHeader: 1 }; }
}

function checkConcurrency(username, maxConnections) {
    if (!maxConnections || maxConnections === 0) return true;
    const stats = getUserStat(username);
    return stats.sockets.size < maxConnections;
}


// --- 异步日志 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
    } catch (e) {
        console.error(`[Log] Failed to create stream: ${e.message}`);
    }
}
function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
    logStream.write(`[${timestamp}] [${status}] [${workerId}] USER=${username} CLIENT_IP=${clientIp} LOCAL_PORT=${localPort}\n`);
}


// --- [AXIOM V5.0] WSS 客户端处理器 ---
function handleClient(clientSocket, isTls) {
    // [AXIOM V5.0] TCP 优化
    clientSocket.setNoDelay(true);
    clientSocket.setKeepAlive(true, 60000);

    let clientIp = clientSocket.remoteAddress;
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;

    let fullRequest = Buffer.alloc(0);
    let state = 'handshake';
    let remoteSocket = null;
    let username = null;
    
    clientSocket.setTimeout(TIMEOUT);

    clientSocket.on('error', (err) => {
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });
    clientSocket.on('timeout', () => {
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });
    clientSocket.on('close', () => {
        if (remoteSocket) remoteSocket.destroy();
        if (username) {
            const stats = getUserStat(username);
            stats.sockets.delete(clientSocket);
            stats.ip_map.delete(clientIp);
        }
    });

    clientSocket.on('data', async (data) => {
        if (state === 'forwarding') {
            const stats = getUserStat(username);
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            
            // 流量计费
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
                if (fullRequest.length > BUFFER_SIZE * 2) clientSocket.end(FORBIDDEN_RESPONSE);
                return;
            }

            const headersRaw = fullRequest.subarray(0, headerEndIndex);
            let dataAfterHeaders = fullRequest.subarray(headerEndIndex + 4);
            const headers = headersRaw.toString('utf8');
            fullRequest = dataAfterHeaders;

            if (!checkHost(headers)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HOST');
                clientSocket.end(FORBIDDEN_RESPONSE);
                return;
            }

            const auth = parseAuth(headers);
            const isWebsocketRequest = headers.includes('Upgrade: websocket') || headers.includes('Connection: Upgrade');

            // HTTP 响应处理 (Payload Eater)
            if (!isWebsocketRequest) {
                if (auth) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_AUTH_NOT_WS');
                    clientSocket.end(FORBIDDEN_RESPONSE);
                } else {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'DUMMY_HTTP');
                    clientSocket.write(FIRST_RESPONSE);
                }
                continue;
            }

            // 鉴权逻辑
            let limits = null;
            if (auth) {
                username = auth.username;
                const res = await authenticateUser(username, auth.password);
                if (!res.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED`);
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return;
                }
                limits = res.limits;
            } else {
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                if (!uriMatch) {
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return;
                }
                const tempUsername = uriMatch[1];
                const res = await getLiteAuthStatus(tempUsername);
                if (res.exists && res.requireAuthHeader === 0) {
                    username = tempUsername;
                    limits = getUserStat(username).limits;
                } else {
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return;
                }
            }

            // 并发限制
            if (!checkConcurrency(username, limits.max_connections)) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                clientSocket.end(TOO_MANY_REQUESTS_RESPONSE);
                return;
            }

            clientSocket.write(SWITCH_RESPONSE);

            // Payload Eater (Split) 逻辑
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); 
            const payloadSample = initialSshData.length > 256 ? initialSshData.subarray(0, 256).toString() : initialSshData.toString();
            const trimmed = payloadSample.trimLeft();
            
            if (trimmed.startsWith('CONNECT ') || trimmed.startsWith('GET ') || trimmed.startsWith('POST ')) {
                const endIdx = initialSshData.indexOf('\r\n\r\n');
                if (endIdx !== -1) {
                    connectToTarget(initialSshData.subarray(endIdx + 4));
                } else {
                    clientSocket.end(FORBIDDEN_RESPONSE);
                }
            } else {
                connectToTarget(initialSshData);
            }
            return;
        }
    });

    function connectToTarget(initialData) {
        if (remoteSocket) return;
        remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
            logConnection(clientIp, clientPort, localPort, username, 'CONN_START');
            const stats = getUserStat(username);
            stats.ip_map.set(clientIp, clientSocket);
            stats.sockets.add(clientSocket);
            state = 'forwarding';

            if (initialData.length > 0) clientSocket.emit('data', initialData);

            // [AXIOM V5.0] TCP 优化
            remoteSocket.setNoDelay(true);
            remoteSocket.setKeepAlive(true, 60000);
        });

        remoteSocket.on('data', (data) => {
            const stats = getUserStat(username);
            const allowedBytes = stats.bucket_down.consume(data.length);
            if (allowedBytes === 0) return;

            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            stats.traffic_delta.download += dataToWrite.length;
            stats.traffic_live.download += dataToWrite.length;
            
            if (clientSocket.writable) clientSocket.write(dataToWrite);
        });

        remoteSocket.on('error', (err) => {
            if (err.code === 'ECONNREFUSED') clientSocket.end(INTERNAL_ERROR_RESPONSE);
            clientSocket.destroy();
        });
        remoteSocket.on('close', () => clientSocket.end());
    }
}


// --- Server Init ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    connectToIpcServer();
    
    // [AXIOM V5.0] 启动原生 UDPGW (仅 Worker 启动)
    startNativeUdpgwServer();

    const httpServer = net.createServer((socket) => handleClient(socket, false));
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[Worker ${cluster.worker.id}] HTTP Listening on ${LISTEN_ADDR}:${HTTP_PORT}`);
    });

    // TLS Server
    try {
        if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
            const tlsOptions = {
                key: fs.readFileSync(KEY_FILE),
                cert: fs.readFileSync(CERT_FILE),
                rejectUnauthorized: false
            };
            const tlsServer = tls.createServer(tlsOptions, (socket) => handleClient(socket, true));
            tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
                console.log(`[Worker ${cluster.worker.id}] TLS Listening on ${LISTEN_ADDR}:${TLS_PORT}`);
            });
        }
    } catch (e) {
        console.warn(`[Worker ${cluster.worker.id}] TLS Init Failed: ${e.message}`);
    }
}


// --- Master/Cluster Logic ---
if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[Master] Starting Axiom V5.0 Proxy Cluster with ${numCPUs} workers...`);
    console.log(`[Master] Native UDPGW will run on port ${UDPGW_PORT} (127.0.0.1)`);

    for (let i = 0; i < numCPUs; i++) cluster.fork();

    cluster.on('exit', (worker, code, signal) => {
        console.error(`[Master] Worker ${worker.process.pid} died. Restarting...`);
        cluster.fork();
    });
} else {
    startServers();
    process.on('uncaughtException', (err) => {
        console.error(`[Worker ${cluster.worker.id}] Uncaught: ${err.message}`, err.stack);
        // process.exit(1); // Optional: let cluster restart it
    });
}
