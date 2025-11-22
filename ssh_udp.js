/**
 * SSH-UDP Service (Node.js)
 * V5.0.1 (Axiom - V6.0 Protocol Fix & IP-Based Stats)
 *
 * 优化:
 * 1. 协议修复: 移除 HTTP/1.1 200 OK 握手响应，切换到 Raw TCP 模式，兼容 UDP Custom。
 * 2. 流量统计: 切换为基于 IP 地址的统计 (IP_X.X.X.X)，实现无认证流量计量。
 * 3. 健壮性: 强化连接清理。
 */

const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');

// --- 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

try {
    const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
    config = JSON.parse(configData);
    console.log(`[SSH-UDP] Config loaded. Port: ${config.ssh_udp_port || 7400}`);
} catch (e) {
    process.exit(1);
}

const LISTEN_PORT = config.ssh_udp_port || 7400;
const LISTEN_ADDR = '0.0.0.0'; 
const WORKER_ID = 'ssh_udp';
const RECONNECT_DELAY = 3000;

// [V6.0 Change] 状态存储改为基于 IP 的 Map
const activeConnections = new Map(); 
let ipcWsClient = null;
let statsInterval = null;
let reconnectTimer = null;
const STATS_INTERVAL_MS = 1000;

// --- IPC ---
function connectToIpc() {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    ipcWsClient = new WebSocket(ipcUrl, {
        headers: { 'X-Internal-Secret': config.internal_api_secret, 'X-Worker-ID': WORKER_ID }
    });
    ipcWsClient.on('open', () => {
        console.log(`[SSH-UDP IPC] Connected.`);
        if (statsInterval) clearInterval(statsInterval);
        statsInterval = setInterval(pushStats, STATS_INTERVAL_MS);
    });
    ipcWsClient.on('close', () => {
        console.warn(`[SSH-UDP IPC] Disconnected. Retrying...`);
        reconnectTimer = setTimeout(connectToIpc, RECONNECT_DELAY);
    });
    ipcWsClient.on('error', (err) => {
        // [V6.0] 避免重复打印连接错误
        // console.error(`[SSH-UDP IPC] Error: ${err.message}`);
    });
}

/**
 * [V6.0 Change] 基于 IP 的流量统计上报
 */
function pushStats() {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) return;
    
    const statsReport = {};
    const liveIps = {};
    
    for (const [id, client] of activeConnections.entries()) {
        const clientIp = client.socket.remoteAddress;
        
        if (client.status === 'ACTIVE') {
            const userKey = `IP_${clientIp}`; 
            
            // 确保只上报有流量或有连接的 IP
            if (client.traffic.up > 0 || client.traffic.down > 0 || client.active_connections > 0) {
                 if (!statsReport[userKey]) {
                     statsReport[userKey] = { 
                         traffic_delta_up: 0, 
                         traffic_delta_down: 0, 
                         connections: 0, 
                         speed_kbps: { upload: 0, download: 0 },
                         source: WORKER_ID,
                         username: userKey // 使用 IP 作为用户名占位符
                     };
                 }
                // 聚合流量增量
                statsReport[userKey].traffic_delta_up += client.traffic.up;
                statsReport[userKey].traffic_delta_down += client.traffic.down;
                
                // 聚合连接数 (此 Worker 内的 TCP 连接数)
                statsReport[userKey].connections += client.active_connections;
                
                // 清零本次增量
                client.traffic.up = 0; 
                client.traffic.down = 0;
                
                // 上报活跃 IP
                liveIps[clientIp] = userKey;
            }
        }
    }
    
    // 如果没有活跃连接，仍然发送 ping 保持心跳
    if (Object.keys(statsReport).length > 0 || Object.keys(liveIps).length > 0) {
        ipcWsClient.send(JSON.stringify({ 
            type: 'stats_update', 
            workerId: WORKER_ID, 
            payload: { 
                stats: statsReport, 
                live_ips: liveIps, 
                ping: true 
            } 
        }));
    } else {
         // 发送空包作为心跳，确保 Panel 知道服务存活
         ipcWsClient.send(JSON.stringify({ type: 'stats_update', workerId: WORKER_ID, payload: { stats: {}, live_ips: {}, ping: true } }));
    }
}

/**
 * [V6.0 Change] 统一连接清理函数
 */
function cleanupConnection(clientSocket, clientId) {
    if (clientSocket.__cleaned) return;
    clientSocket.__cleaned = true;
    
    const client = activeConnections.get(clientId);
    if (client) {
         try { client.udpSocket.close(); } catch(e) {}
         activeConnections.delete(clientId);
    }
    if (!clientSocket.destroyed) clientSocket.destroy();
    
    console.log(`[SSH-UDP] Cleaned: ${clientId}`);
}

// --- BadVPN 转发逻辑 ---
function setupBadVpnForwarding(client) {
    const { socket, clientId } = client;
    client.udpSocket = dgram.createSocket('udp4');
    client.buffer = Buffer.alloc(0); 

    client.udpSocket.on('error', (err) => {
        console.error(`[UDP Socket Error] ${clientId}: ${err.message}`);
        cleanupConnection(socket, clientId);
    });
    
    // UDP -> TCP
    client.udpSocket.on('message', (msg, rinfo) => {
        const parts = rinfo.address.split('.');
        if (parts.length !== 4) return;

        const len = 6 + msg.length;
        // BadVPN Frame: [Length(2 LE)] [IP(4)] [Port(2 LE)] [Data]
        const frame = Buffer.alloc(2 + len);
        frame.writeUInt16LE(len, 0);
        
        // Write IP
        frame[2] = parseInt(parts[0]); 
        frame[3] = parseInt(parts[1]); 
        frame[4] = parseInt(parts[2]); 
        frame[5] = parseInt(parts[3]);
        
        // Write Port (Little Endian)
        frame.writeUInt16LE(rinfo.port, 6);
        
        msg.copy(frame, 8);

        client.traffic.down += frame.length;
        if (!socket.destroyed) socket.write(frame);
    });

    // TCP -> UDP
    socket.on('data', (chunk) => {
        // [V6.0] 流量统计
        // client.traffic.up += chunk.length; // 统计在解包后进行，避免统计协议头
        
        // 拼接到现有缓冲区
        client.buffer = Buffer.concat([client.buffer, chunk]);

        while (client.buffer.length >= 2) {
            const len = client.buffer.readUInt16LE(0);
            
            // Keep-alive (0x0000)
            if (len === 0) { 
                client.buffer = client.buffer.subarray(2); 
                client.traffic.up += 2; // 计入流量 delta
                continue; 
            }
            
            if (client.buffer.length < 2 + len) break; // 等待更多数据

            const body = client.buffer.subarray(2, 2 + len);
            client.buffer = client.buffer.subarray(2 + len);
            
            // [V6.0] 计入流量 delta (包含 BadVPN 协议头 2 + len)
            client.traffic.up += (2 + len);

            if (len < 6) continue;

            const destIp = `${body[0]}.${body[1]}.${body[2]}.${body[3]}`;
            const destPort = body.readUInt16LE(4);
            const payload = body.subarray(6);

            // 发送 UDP (增加错误捕获，防止单次发送失败导致连接断开)
            try {
                client.udpSocket.send(payload, destPort, destIp, (err) => {
                    // if (err) console.error(`[UDP Send Error] ${err.message}`);
                });
            } catch (e) {
                // console.error(`[UDP Sync Error] ${e.message}`);
            }
        }
    });
}

// --- TCP Server ---
const server = net.createServer((socket) => {
    const clientId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[SSH-UDP] Connect: ${clientId}`);
    
    const client = {
        socket,
        clientId, // 存储 ID
        status: 'ACTIVE', // [V6.0 Fix] 默认为 Active，跳过 HTTP 握手状态
        traffic: { up: 0, down: 0 },
        active_connections: 1, // 当前 TCP 连接计数
        udpSocket: null,
        buffer: Buffer.alloc(0)
    };
    activeConnections.set(clientId, client);

    // [V6.0 Fix] 统一清理
    const cleanupHandler = (err) => {
        if (err && err.code !== 'ECONNRESET') console.error(`[Socket] ${clientId} Error: ${err.message}`);
        cleanupConnection(socket, clientId);
    }
    
    socket.on('close', cleanupHandler);
    socket.on('error', cleanupHandler);
    socket.on('timeout', cleanupHandler); // 确保超时也被清理

    // [V6.0 Protocol Fix] 移除 HTTP 握手，直接开始转发
    console.log(`[SSH-UDP] Raw TCP connection accepted. Forwarding...`);
    
    // 初始化转发逻辑
    setupBadVpnForwarding(client);
    
    // 立即开始读取数据
    socket.resume(); 
});

server.listen(LISTEN_PORT, LISTEN_ADDR, () => {
    console.log(`[SSH-UDP] Service listening on ${LISTEN_ADDR}:${LISTEN_PORT} (Raw TCP/BadVPN Protocol)`);
    connectToIpc();
});

server.on('error', (err) => {
    console.error(`[SSH-UDP] Startup Error: ${err.message}`);
    process.exit(1);
});
