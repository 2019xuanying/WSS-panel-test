/**
 * Native UDP Gateway (BadVPN Protocol over TCP)
 * Axiom V5.5.4 Refactor - Ultimate Protocol Compatibility Fix.
 *
 * [AXIOM V5.5.4 CHANGELOG]
 * - [CRITICAL FIX] 协议兼容性：parseAuthToken 不再要求 'UDPGW01' 协议前缀。
 * - 只要在客户端发送的**第一行**中包含**有效的 'TOKEN:<Base64>' 字段**，即视为认证尝试并放行。
 * - 这解决了客户端发送无关前缀、二进制数据探测或非标准 BadVPN 协议头导致卡死的问题。
 */

const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const { URLSearchParams } = require('url');
const crypto = require('crypto');

// --- [AXIOM V5.0] 配置加载 (简化版) ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        console.log(`[Native_UDPGW] 成功从 ${CONFIG_PATH} 加载配置。`);
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); 
    }
}
loadConfig(); 
// --- 结束配置加载 ---

// --- 核心常量 ---
const UDPGW_PORT = config.udpgw_port || 7300;
const LISTEN_ADDR = '127.0.0.1'; // 仅监听本地地址，由 WSS/Stunnel 转发

const HANDSHAKE_CODE = Buffer.from('UDPGW01'); // 仅作常量保留，不再强制检查
const MAX_PACKET_SIZE = 65535; // UDP 最大数据包大小
const WORKER_ID = 'udpgw'; 
const SPEED_CALC_INTERVAL = 1000;
const PANEL_API_URL = config.panel_api_url;

// --- 状态管理 ---
let totalConnections = 0;
const userStats = new Map();
const pending_traffic_delta = {};
let ipcWsClient = null;
let statsPusherIntervalId = null;
let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 60000; 

// --- 令牌桶 (Token Bucket) 限速器 (从 wss_proxy.js 移植) ---
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
        console.log(`[TokenBucket UDPGW] Updating rate. Capacity: ${newCapacityKbps} KB/s, FillRate: ${newFillRateKbps} KB/s`);
        this._fillTokens();
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRate = Math.max(0, newFillRateKbps * 1024 / 1000);
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            // connections: key: net.Socket, value: {id, clientIp, startTime, udpSocket}
            connections: new Map(), 
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0 } 
        });
    }
    return userStats.get(username);
}

// --- IPC 辅助函数 (从 wss_proxy.js 移植) ---

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
        
        // 自动清理僵尸状态
        const hasPending = pending_traffic_delta[username] && 
                           (pending_traffic_delta[username].upload > 0 || pending_traffic_delta[username].download > 0);
                           
        if (stats.connections.size === 0 && !hasPending) {
            userStats.delete(username);
            if (pending_traffic_delta[username]) {
                delete pending_traffic_delta[username];
            }
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);

function pushStatsToControlPlane(ws_client) {
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; 
    }

    const statsReport = {};
    const liveIps = {};
    
    // 1. 合并并清空 Pending 流量
    let hasPushableData = false;
    for (const username in pending_traffic_delta) {
        const stats = getUserStat(username); 
        stats.traffic_delta.upload += pending_traffic_delta[username].upload;
        stats.traffic_delta.download += pending_traffic_delta[username].download;
        delete pending_traffic_delta[username];
    }
    
    
    // 2. 准备本地统计数据
    for (const [username, stats] of userStats.entries()) {
        if (stats.connections.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
            
            statsReport[username] = {
                speed_kbps: stats.speed_kbps, 
                connections: stats.connections.size, 
                traffic_delta_up: stats.traffic_delta.upload,
                traffic_delta_down: stats.traffic_delta.download,
                source: 'udpgw' 
            };
            
            if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
                 hasPushableData = true;
            }

            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            
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
        for (const tcpSocket of stats.connections.keys()) {
            const meta = stats.connections.get(tcpSocket);
            if (meta && meta.udpSocket) {
                try { meta.udpSocket.close(); } catch (e) {}
            }
            tcpSocket.destroy(); 
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
    };
    const rate = stats.limits.rate_kbps;
    stats.bucket_up.updateRate(rate * 2, rate); 
    stats.bucket_down.updateRate(rate * 2, rate); 
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

function parseAuthToken(rawString) {
    const parts = rawString.trim().split(/\s+/);
    
    // 1. [AXIOM V5.5.4 FIX] 不再检查 UDPGW01，仅查找 TOKEN: 部分
    const tokenPart = parts.find(p => p.startsWith('TOKEN:'));
    if (!tokenPart) return null;

    const base64Token = tokenPart.substring('TOKEN:'.length);
    if (!base64Token) return null;

    try {
        const credentials = Buffer.from(base64Token, 'base64').toString('utf8');
        // 2. 验证 Base64 解码后的格式是否为 user:pass
        const splitIndex = credentials.indexOf(':');
        if (splitIndex === -1) {
            console.error(`[AUTH] Credentials missing ':' separator.`);
            return null;
        }
        
        const username = credentials.substring(0, splitIndex);
        const password = credentials.substring(splitIndex + 1);
        
        if (!username || !password) return null;
        return { username, password };
    } catch (e) {
        console.error(`[AUTH] Base64 token decoding failed: ${e.message}`);
        return null;
    }
}

async function authenticateUser(username, password) {
    try {
        const response = await fetch(config.panel_api_url + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return { success: false, limits: null, message: errorData.message || `Auth failed with status ${response.status}` };
        }
        const data = await response.json();
        updateUserLimits(username, data.limits);
        return { success: true, limits: data.limits, message: 'Auth successful' };
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        return { success: false, limits: null, message: 'Internal API connection error', status: 503 };
    }
}

async function checkConcurrency(username, maxConnections) {
    if (maxConnections === 0) return true; 
    
    // 1. 本地检查 (快速失败)
    const stats = getUserStat(username); 
    if (stats.connections.size >= maxConnections) {
        return false;
    }

    // 2. 集群检查 (中央授权) - 使用 WSS Panel 的 API
    try {
        const params = new URLSearchParams({ username, worker_id: WORKER_ID });
        const response = await fetch(config.panel_api_url + '/auth/check-conn?' + params.toString(), {
            method: 'GET'
        });
        const data = await response.json();
        
        if (!response.ok || !data.success || !data.allowed) {
            return false;
        }
        
        return data.allowed;
        
    } catch (e) {
        console.error(`[CONCURRENCY] Cluster check failed: ${e.message}。使用本地检查结果。`);
        // 无法连接 Panel，如果本地检查通过，则暂时允许连接以保持网络可用性，但存在绕过风险。
        return (stats.connections.size < maxConnections);
    }
}


/**
 * 将 UDP 数据包封装成 BadVPN TCP 帧
 * @param {Buffer} data 原始 UDP 数据
 * @returns {Buffer} 包含 2字节长度前缀的 TCP 帧
 */
function encapsulate(data) {
    const len = data.length;
    const buffer = Buffer.alloc(2 + len);
    buffer.writeUInt16BE(len, 0); // Big Endian
    data.copy(buffer, 2);
    return buffer;
}

// --- TCP Client Handler ---

/**
 * 处理 BadVPN 协议的 TCP 客户端连接
 * @param {net.Socket} tcpSocket TCP 连接套接字
 */
function handleClient(tcpSocket) {
    
    totalConnections++;
    const clientId = `${tcpSocket.remoteAddress}:${tcpSocket.remotePort}`;
    const clientIp = tcpSocket.remoteAddress.startsWith('::ffff:') ? tcpSocket.remoteAddress.substring(7) : tcpSocket.remoteAddress;
    console.log(`[UDP_TCP] 新连接 ${clientId}. 当前总数: ${totalConnections}`);
    
    let authComplete = false; 
    let tcpBuffer = Buffer.alloc(0);
    let currentPacketLength = 0;
    let username = 'N/A';
    let stats = null; 
    
    // 为每个 TCP 连接创建一个专用的 UDP socket
    const udpSocket = dgram.createSocket('udp4');

    function cleanup() {
        totalConnections--;
        if (stats) {
            stats.connections.delete(tcpSocket);
            stats.ip_map.delete(clientIp);
        }
        try {
             udpSocket.close();
        } catch(e) {}
    }
    
    // --- UDP -> TCP 转发逻辑 (Tunneling) ---
    udpSocket.on('message', (msg, rinfo) => {
        if (!authComplete || !stats) return;

        try {
            const allowedBytes = stats.bucket_down.consume(msg.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < msg.length) ? msg.subarray(0, allowedBytes) : msg;
            
            stats.traffic_delta.download += dataToWrite.length;
            stats.traffic_live.download += dataToWrite.length;

            const framedData = encapsulate(dataToWrite);
            if (tcpSocket.writable) {
                tcpSocket.write(framedData);
            }
        } catch (e) {
            console.error(`[UDP_TCP ${clientId}] 转发 UDP->TCP 失败: ${e.message}`);
            // 不销毁连接，等待客户端自行超时或断开
        }
    });

    udpSocket.on('error', (err) => {
        console.error(`[UDP_SOC] UDP Socket 错误 ${clientId}: ${err.message}`);
        tcpSocket.destroy(); 
    });

    // --- TCP -> UDP 解析逻辑 (De-tunneling) ---
    tcpSocket.on('data', async (data) => {
        tcpBuffer = Buffer.concat([tcpBuffer, data]);
        
        // 1. 握手和认证阶段
        if (!authComplete) {
            
            // [AXIOM V5.5.1 FIX] 查找单行握手结束符 ('\n')
            const newlineIndex = tcpBuffer.indexOf('\n');
            if (newlineIndex === -1) {
                if (tcpBuffer.length > 512) {
                     console.warn(`[UDP_TCP ${clientId}] 握手包过长 (超过 512 bytes)。断开连接。`);
                     tcpSocket.destroy();
                }
                return; // 缓冲区不足
            }
            
            // 提取第一行 (包含可能的 \r)
            const headerRaw = tcpBuffer.subarray(0, newlineIndex).toString('utf8').trim();
            // [AXIOM V5.5.2 FIX] 增加日志，调试客户端发送的原始协议头
            console.log(`[UDP_TCP ${clientId}] 收到原始握手行 (Raw): ${headerRaw.substring(0, 100)}`);
            
            tcpBuffer = tcpBuffer.subarray(newlineIndex + 1); // 移除握手行和换行符
            
            // 1.1 认证
            const auth = parseAuthToken(headerRaw);

            if (!auth) {
                console.warn(`[UDP_TCP ${clientId}] 认证失败: 无效的握手或缺少 Base64 令牌。`);
                tcpSocket.destroy();
                return;
            }
            
            username = auth.username;
            const authResult = await authenticateUser(username, auth.password);

            if (!authResult.success) {
                console.warn(`[UDP_TCP ${clientId}] 用户 ${username} 认证失败: ${authResult.message}`);
                tcpSocket.destroy();
                return;
            }

            // 1.2 并发和限速检查
            stats = getUserStat(username); 
            
            if (!await checkConcurrency(username, authResult.limits.max_connections)) {
                console.warn(`[UDP_TCP ${clientId}] 用户 ${username} 超出并发限制 (${authResult.limits.max_connections})。`);
                tcpSocket.destroy();
                return; 
            }
            
            // 1.3 认证成功，进入转发状态
            authComplete = true;
            stats.connections.set(tcpSocket, {
                id: crypto.randomUUID(),
                clientIp: clientIp,
                startTime: new Date().toISOString(),
                udpSocket: udpSocket 
            });
            stats.ip_map.set(clientIp, tcpSocket);

            console.log(`[UDP_TCP ${clientId}] 用户 ${username} 认证成功，开始转发。`);
        }
        
        // 2. 数据包解析阶段 (只在认证成功后执行)
        while (authComplete && tcpBuffer.length >= 2) {
            if (currentPacketLength === 0) {
                // 读取下一个数据包的长度
                currentPacketLength = tcpBuffer.readUInt16BE(0);
                
                if (currentPacketLength > MAX_PACKET_SIZE || currentPacketLength <= 0) {
                    console.error(`[UDP_TCP ${clientId}] 无效的包长度: ${currentPacketLength}. 断开连接。`);
                    tcpSocket.destroy();
                    return;
                }
            }
            
            const requiredLength = 2 + currentPacketLength; // 2字节长度 + 数据长度
            
            if (tcpBuffer.length >= requiredLength) {
                // 成功读取一个完整的帧
                const udpPacket = tcpBuffer.subarray(2, requiredLength);
                
                // 流量控制 (上传)
                const allowedBytes = stats.bucket_up.consume(udpPacket.length);
                if (allowedBytes > 0) {
                    
                    const dataToProcess = (allowedBytes < udpPacket.length) ? udpPacket.subarray(0, allowedBytes) : udpPacket;
                    
                    stats.traffic_delta.upload += dataToProcess.length;
                    stats.traffic_live.upload += dataToProcess.length;
                    
                    // BadVPN 协议约定：4 bytes Dest IP + 2 bytes Dest Port + Raw UDP Data
                    if (dataToProcess.length >= 6) {
                        const destIp = `${dataToProcess[0]}.${dataToProcess[1]}.${dataToProcess[2]}.${dataToProcess[3]}`;
                        const destPort = dataToProcess.readUInt16BE(4);
                        const rawData = dataToProcess.subarray(6);

                        // 转发到目标 IP/Port
                        udpSocket.send(rawData, destPort, destIp, (err) => {
                            if (err) {
                                console.error(`[UDP_SOC] 发送到目标 ${destIp}:${destPort} 失败: ${err.message}`);
                            }
                        });
                    } else {
                        console.warn(`[UDP_TCP ${clientId}] 收到短数据包 (${dataToProcess.length} bytes)。跳过。`);
                    }
                } else {
                     // 限速触发，跳过转发，但继续处理缓冲区
                     console.warn(`[UDP_TCP ${clientId}] 用户 ${username} 上传限速触发。`);
                }

                // 准备处理下一个帧
                tcpBuffer = tcpBuffer.subarray(requiredLength);
                currentPacketLength = 0;
            } else {
                // 缓冲区不足，等待更多数据
                break;
            }
        }
    });
    
    tcpSocket.on('close', cleanup);
    tcpSocket.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
             console.error(`[UDP_TCP ${clientId}] TCP Socket 错误: ${err.message}`);
        }
        tcpSocket.destroy();
    });
    
    tcpSocket.setTimeout(60000); // 1分钟超时
    tcpSocket.on('timeout', () => {
        console.log(`[UDP_TCP ${clientId}] TCP 超时。`);
        tcpSocket.destroy();
    });
}


// --- 启动 TCP 服务器 (作为 BadVPN 协议监听器) ---
const server = net.createServer(handleClient);

server.listen(UDPGW_PORT, LISTEN_ADDR, () => {
    console.log(`[Native_UDPGW] 原生 UDPGW 服务器运行在 ${LISTEN_ADDR}:${UDPGW_PORT} (TCP BadVPN 协议)`);
    // 启动 IPC 客户端
    connectToIpcServer(); 
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[CRITICAL] Native UDPGW 启动失败: 端口 ${UDPGW_PORT} 已被占用。`);
    } else {
        console.error(`[CRITICAL] Native UDPGW 服务器错误: ${err.message}`);
    }
    process.exit(1);
});

// 优雅关闭
process.on('SIGINT', () => {
    console.log('\n[Native_UDPGW] 服务器停止中...');
    if (ipcReconnectTimer) clearTimeout(ipcReconnectTimer);
    if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
    server.close(() => {
        console.log('[Native_UDPGW] TCP 服务器已关闭。');
        process.exit(0);
    });
});
