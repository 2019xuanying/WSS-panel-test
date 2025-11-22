/**
 * Native UDPGW (Node.js Implementation of BadVPN Protocol)
 * Integrates with WSS-Panel for traffic accounting and management.
 *
 * Features:
 * 1. Implements BadVPN-UDPGW protocol (Little Endian framing).
 * 2. Handles 'UDPGW01' handshake sent by HTTP Custom.
 * 3. Integrates IPC for real-time traffic reporting to WSS Panel.
 * 4. Supports TCP packet coalescing/fragmentation (Sticky packets).
 * 5. This service listens locally (127.0.0.1) and is generally proxied by WSS Proxy.
 */

const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const crypto = require('crypto');

// --- 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

try {
    const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
    config = JSON.parse(configData);
    console.log(`[Native_UDPGW] Config loaded from ${CONFIG_PATH}`);
} catch (e) {
    console.error(`[CRITICAL] Failed to load config: ${e.message}`);
    process.exit(1);
}

// --- 常量定义 ---
const UDPGW_PORT = config.udpgw_port || 7300;
const LISTEN_ADDR = '127.0.0.1'; // Listen strictly on localhost, exposed via WSS/Stunnel
const MAX_PACKET_SIZE = 65535;
const WORKER_ID = 'udpgw';
// BadVPN uses Little Endian for packet lengths
const HANDSHAKE_STR = 'UDPGW01';

// --- 状态管理 ---
let totalConnections = 0;
const userStats = new Map(); // key: "IP_Port", value: statsObject
const pending_traffic_delta = {};
let ipcWsClient = null;
let statsPusherIntervalId = null;
let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;

// --- 流量统计辅助函数 ---
function getOrCreateConnectionStats(clientId, username) {
    if (!userStats.has(clientId)) {
        userStats.set(clientId, {
            username: username,
            connections: new Map(), // key: tcpSocket, value: metadata
            traffic_delta: { upload: 0, download: 0 },
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }
        });
    }
    return userStats.get(clientId);
}

// --- IPC 通信 (上报流量) ---
function connectToIpcServer() {
    if (ipcReconnectTimer) clearTimeout(ipcReconnectTimer);
    
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    console.log(`[IPC] Connecting to panel at ${ipcUrl}...`);

    ipcWsClient = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID
        }
    });

    ipcWsClient.on('open', () => {
        console.log('[IPC] Connected to WSS Panel.');
        ipcReconnectAttempts = 0;
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = setInterval(pushStats, 1000);
    });

    ipcWsClient.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            // This BadVPN worker does not handle authentication, only receives kick commands
            if (msg.action === 'kick' && msg.username) {
                // For this non-authenticated worker, we can't reliably kick by username
                // But we must handle the command if it was passed up
                // (In the current architecture, WSS Proxy handles actual user kicking)
                console.log(`[IPC] Received kick command for user: ${msg.username}. Ignored by non-auth UDPGW.`);
            }
        } catch (e) {
            console.error(`[IPC] Msg Error: ${e.message}`);
        }
    });

    ipcWsClient.on('error', (e) => console.error(`[IPC] Error: ${e.message}`));
    
    ipcWsClient.on('close', () => {
        console.warn('[IPC] Disconnected. Retrying...');
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        ipcReconnectTimer = setTimeout(connectToIpcServer, 3000);
    });
}

function pushStats() {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) return;

    // BadVPN traffic is usually accounted for at the WSS Proxy level (TCP tunnel layer).
    // This worker's primary role is functional UDP relaying.
    // However, it must send a 'ping' to the panel to confirm service health.
    ipcWsClient.send(JSON.stringify({
        type: 'stats_update',
        workerId: WORKER_ID,
        payload: { stats: {}, live_ips: {}, ping: true }
    }));
}

// --- TCP 客户端处理 (BadVPN 协议解析) ---
function handleClient(tcpSocket) {
    totalConnections++;
    const clientIp = tcpSocket.remoteAddress;
    const clientId = `${clientIp}:${tcpSocket.remotePort}`;
    
    // 创建专用的 UDP Socket 用于此 TCP 连接
    const udpSocket = dgram.createSocket('udp4');

    // TCP 缓冲区
    let buffer = Buffer.alloc(0);
    let state = 'HANDSHAKE'; // HANDSHAKE -> FRAMING

    // 错误处理
    const cleanup = () => {
        try { udpSocket.close(); } catch(e) {}
        tcpSocket.destroy();
        totalConnections--;
    };

    tcpSocket.on('error', cleanup);
    tcpSocket.on('close', cleanup);
    udpSocket.on('error', (err) => {
        console.error(`[UDP Error] ${clientId}: ${err.message}`);
        cleanup();
    });

    // 处理从 UDP 回来的数据 -> 封装回 TCP
    udpSocket.on('message', (msg, rinfo) => {
        // BadVPN Frame: [Length(2 LE)] [IP(4)] [Port(2 LE)] [Data]
        
        // 1. 构造头部
        const ipParts = rinfo.address.split('.').map(Number);
        if (ipParts.length !== 4) return; 

        const port = rinfo.port;

        // Payload length = 4 (IP) + 2 (Port) + msg.length
        const payloadLen = 6 + msg.length;
        
        // Total Frame = 2 (Len Header) + Payload
        const frame = Buffer.alloc(2 + payloadLen);

        // Write Frame Length (Little Endian)
        frame.writeUInt16LE(payloadLen, 0);

        // Write IP
        frame[2] = ipParts[0];
        frame[3] = ipParts[1];
        frame[4] = ipParts[2];
        frame[5] = ipParts[3];

        // Write Port (Little Endian)
        frame.writeUInt16LE(port, 6);

        // Write Data
        msg.copy(frame, 8);

        // Send to TCP
        if (!tcpSocket.destroyed) {
            tcpSocket.write(frame);
        }
    });

    // 处理 TCP 传入的数据 (解包 -> 发送 UDP)
    tcpSocket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        // 1. 握手检测 (Optional but used by HTTP Custom)
        if (state === 'HANDSHAKE') {
            const handshakeBuf = Buffer.from(HANDSHAKE_STR);
            if (buffer.length >= handshakeBuf.length) {
                const head = buffer.subarray(0, handshakeBuf.length);
                if (head.equals(handshakeBuf)) {
                    buffer = buffer.subarray(handshakeBuf.length);
                }
                state = 'FRAMING';
            } else {
                state = 'FRAMING'; 
            }
        }

        // 2. 数据帧解析
        while (state === 'FRAMING' && buffer.length >= 2) {
            // Read Length (2 bytes Little Endian)
            const packetLen = buffer.readUInt16LE(0);

            // Keep-alive check (Length 0)
            if (packetLen === 0) {
                buffer = buffer.subarray(2);
                continue;
            }

            // Check if we have the full packet
            if (buffer.length < 2 + packetLen) {
                break; // Wait for more data
            }

            // Extract Packet Body
            // Body format: [DestIP(4)] [DestPort(2 LE)] [Data...]
            const packetBody = buffer.subarray(2, 2 + packetLen);
            
            // Move buffer forward
            buffer = buffer.subarray(2 + packetLen);

            // Parse Body
            if (packetLen < 6) {
                console.error(`[${clientId}] Malformed packet (too short)`);
                cleanup();
                return;
            }

            const destIp = `${packetBody[0]}.${packetBody[1]}.${packetBody[2]}.${packetBody[3]}`;
            const destPort = packetBody.readUInt16LE(4);
            const payload = packetBody.subarray(6);

            // Send UDP
            udpSocket.send(payload, destPort, destIp, (err) => {
                if (err) console.error(`[UDP Send Fail] ${destIp}:${destPort} - ${err.message}`);
            });
        }
    });
}

// --- 启动服务器 ---
const server = net.createServer(handleClient);

server.listen(UDPGW_PORT, LISTEN_ADDR, () => {
    console.log(`[Native_UDPGW] Listening on ${LISTEN_ADDR}:${UDPGW_PORT} (BadVPN Protocol)`);
    connectToIpcServer();
});

server.on('error', (err) => {
    console.error(`[CRITICAL] Server error: ${err.message}`);
    process.exit(1);
});

// 优雅退出
process.on('SIGINT', () => {
    if (ipcWsClient) ipcWsClient.close();
    server.close(() => {
        console.log('[Native_UDPGW] TCP Server closed.');
        process.exit(0);
    });
});
