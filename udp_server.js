/**
 * Native UDP Gateway (BadVPN Protocol over TCP)
 * Axiom V5.5.13 Refactor - Final Functionality and Frame Integrity Fix.
 *
 * [AXIOM V5.5.13 CHANGELOG]
 * - [CRITICAL FIX] 解决“无效的包长度: 0”导致连接断开的问题。
 * - 增加握手阶段的容错：在收到数据后，显式跳过一次缓冲区开头的 UDPGW01 协议头。
 * - 在帧解析循环中，忽略长度为 0 的 BadVPN 帧 (currentPacketLength === 0)，防止因客户端 Keep-Alive 或空包而断开。
 * - 恢复功能，让 UDP 流量可以正常通过。
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

const HANDSHAKE_CODE = Buffer.from('UDPGW01'); 
const MAX_PACKET_SIZE = 65535; // UDP 最大数据包大小
const MAX_HANDSHAKE_BUFFER_BYTES = 1024 * 1024; // 1MB 握手缓冲区限制
const WORKER_ID = 'udpgw'; 
const SPEED_CALC_INTERVAL = 1000;
const PANEL_API_URL = config.panel_api_url;

// [AXIOM V5.5.9 FIX] 推荐的 UDP Socket 缓冲区大小 (来自 sysctl 的 32MB 最大值)
const UDP_SOCKET_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB 显式设置

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
        // 如果 fillRate 为 0，不限速
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

// 由于取消了认证，我们使用一个简化结构来追踪和统计连接。
function getOrCreateConnectionStats(clientId, username) {
    const effectiveUsername = username; 
    
    if (!userStats.has(effectiveUsername)) {
        userStats.set(effectiveUsername, {
            connections: new Map(), 
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            // 在此假设限速和并发检查已经在上游完成，TokenBucket 默认不限速
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0 } 
        });
    }
    return userStats.get(effectiveUsername);
}


// --- IPC 辅助函数 (保持不变) ---

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
        const stats = userStats.get(username);
        if (stats) {
            stats.traffic_delta.upload += pending_traffic_delta[username].upload;
            stats.traffic_delta.download += pending_traffic_delta[username].download;
        }
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

// 移除 kickUser, updateUserLimits, resetUserTraffic 的内部实现，因为它们依赖 Panel 的 IPC 命令
// 但我们必须保留接收这些命令的 IPC 客户端，以防止错误日志
function kickUser(username) { /* Handled by WSS Proxy / Stunnel (pkill) */ }
function updateUserLimits(username, limits) { /* Handled by WSS Proxy / Stunnel */ }
function resetUserTraffic(username) { /* Handled by WSS Proxy / Stunnel */ }

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
            
            // UDPGW 只需要接收控制信号，但不需要执行本地限速更新（因为限速在 WSS Proxy 完成）
            // 这里保留了 kick/delete/reset_traffic 的调用，但内部实现为空或依赖上游
            switch (message.action) {
                case 'kick':
                case 'delete':
                case 'reset_traffic':
                case 'update_limits': // 尽管不执行限速，但需要接收命令避免 Worker 报错
                    // UDPGW Worker 忽略这些命令，因为用户是外部管理的
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

// [AXIOM V5.5.7] 移除所有认证 API 辅助函数

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
    
    let handshakeComplete = false; 
    let tcpBuffer = Buffer.alloc(0);
    let currentPacketLength = 0;
    
    // [AXIOM V5.5.7] 默认使用客户端 IP 作为伪用户名进行统计
    const username = `UDP_${clientIp}`; 
    const stats = getOrCreateConnectionStats(clientId, username); 
    
    // 为每个 TCP 连接创建一个专用的 UDP socket
    const udpSocket = dgram.createSocket('udp4');

    // [AXIOM V5.5.9 FIX] 应用性能调优
    tcpSocket.setNoDelay(true); // 禁用 Nagle 算法
    
    // [AXIOM V5.5.10 FIX] 容错处理：如果设置缓冲区大小失败，捕获错误并继续。
    try {
        udpSocket.setSendBufferSize(UDP_SOCKET_BUFFER_SIZE);
        udpSocket.setRecvBufferSize(UDP_SOCKET_BUFFER_SIZE);
    } catch (e) {
        // 如果是 EBADF (Bad File Descriptor) 或其他缓冲区错误，打印警告并忽略，防止进程崩溃
        console.warn(`[UDP_SOC ${clientId}] WARNING: Failed to set UDP buffer size (${e.code || e.message}). Using default buffers.`, e.code);
    }


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
        try {
            // [AXIOM V5.5.7] 限速检查 (Downstream)
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
        }
    });

    udpSocket.on('error', (err) => {
        console.error(`[UDP_SOC] UDP Socket 错误 ${clientId}: ${err.message}`);
        tcpSocket.destroy(); 
    });

    // [AXIOM V5.5.7] 连接建立时立即记录统计元数据
    stats.connections.set(tcpSocket, {
        id: crypto.randomUUID(),
        clientIp: clientIp,
        startTime: new Date().toISOString(),
        udpSocket: udpSocket 
    });
    stats.ip_map.set(clientIp, tcpSocket);
    
    console.log(`[UDP_TCP ${clientId}] 已跳过认证，等待 BadVPN 握手数据...`);
    
    // --- TCP -> UDP 解析逻辑 (De-tunneling) ---
    tcpSocket.on('data', async (data) => {
        tcpBuffer = Buffer.concat([tcpBuffer, data]);
        
        // 1. 握手（V5.5.12 FIX: 只要收到数据，就完成握手）
        if (!handshakeComplete) {
            // [AXIOM V5.5.12 FIX] 只要收到数据，立即进入转发状态
            handshakeComplete = true;
            
            // [AXIOM V5.5.13 FIX] 显式跳过 BadVPN 协议头 (UDPGW01)，兼容客户端的实现
            const handshakeIndex = tcpBuffer.indexOf(HANDSHAKE_CODE);
            if (handshakeIndex === 0) {
                 // 协议头在开头，跳过它
                 tcpBuffer = tcpBuffer.subarray(HANDSHAKE_CODE.length);
                 console.log(`[UDP_TCP ${clientId}] 收到协议头 (UDPGW01)，已跳过。`);
            } else if (handshakeIndex > 0 && handshakeIndex < tcpBuffer.length) {
                 // 协议头在中间，跳过头部之前的垃圾数据和协议头
                 tcpBuffer = tcpBuffer.subarray(handshakeIndex + HANDSHAKE_CODE.length);
                 console.log(`[UDP_TCP ${clientId}] 发现协议头 (UDPGW01) 嵌入，已跳过前面 ${handshakeIndex} 字节的垃圾数据。`);
            }
            
            console.log(`[UDP_TCP ${clientId}] 立即启动 BadVPN 帧解析。`);

            // 检查缓冲区是否包含更多数据，继续处理（调用自身进入 while 循环）
            tcpSocket.emit('data', Buffer.alloc(0)); 
            return;
        }
        
        // 2. 数据包解析阶段
        while (handshakeComplete && tcpBuffer.length >= 2) {
            if (currentPacketLength === 0) {
                // 读取下一个数据包的长度
                currentPacketLength = tcpBuffer.readUInt16BE(0);
                
                // [AXIOM V5.5.13 FIX] 忽略长度为 0 的帧，防止断开连接
                if (currentPacketLength === 0) {
                     tcpBuffer = tcpBuffer.subarray(2); // 消耗掉 2 字节长度
                     currentPacketLength = 0;
                     continue; // 继续循环，处理下一个帧
                }
                
                if (currentPacketLength > MAX_PACKET_SIZE || currentPacketLength < 6) { 
                    console.error(`[UDP_TCP ${clientId}] 无效的包长度: ${currentPacketLength}. 断开连接。`);
                    tcpSocket.destroy();
                    return;
                }
            }
            
            const requiredLength = 2 + currentPacketLength; // 2字节长度 + 数据长度
            
            if (tcpBuffer.length >= requiredLength) {
                // 成功读取一个完整的帧
                const udpPacket = tcpBuffer.subarray(2, requiredLength);
                
                // [AXIOM V5.5.7] 流量控制 (上传)
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
