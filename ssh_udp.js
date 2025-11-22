/**
 * SSH-UDP Service (Node.js)
 * V1.0.0 (Axiom - Authenticated UDP over TCP)
 *
 * 功能：
 * 1. 监听 0.0.0.0 公网端口（从 config.json 读取）。
 * 2. 接收客户端连接，解析首包鉴权信息 (username:password)。
 * 3. 通过 IPC 向面板验证用户合法性（鉴权、状态、配额）。
 * 4. 验证通过后，执行 BadVPN 协议转发 UDP 数据。
 * 5. 实时精确上报用户流量到面板，实现精确定位和计费。
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
    console.error(`[CRITICAL] Failed to load config: ${e.message}`);
    process.exit(1);
}

// --- 常量定义 ---
const LISTEN_PORT = config.ssh_udp_port || 7400;
const LISTEN_ADDR = '0.0.0.0'; // 公网监听
const WORKER_ID = 'ssh_udp';
const RECONNECT_DELAY = 3000;

// --- 状态管理 ---
const activeConnections = new Map(); // key: requestId, value: { socket, username, stats... }
let ipcWsClient = null;
let statsInterval = null;
let reconnectTimer = null;

// --- 辅助：IPC 连接与鉴权 ---

function connectToIpc() {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    ipcWsClient = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID
        }
    });

    ipcWsClient.on('open', () => {
        console.log('[IPC] Connected to Panel.');
        if (statsInterval) clearInterval(statsInterval);
        statsInterval = setInterval(pushStats, 1000);
    });

    ipcWsClient.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            // 处理来自面板的鉴权响应
            if (msg.type === 'AUTH_RESULT') {
                handleAuthResult(msg);
            }
            // 处理踢人指令 (虽然 SSH-UDP 不依赖 WSS/Stunnel，但也要处理面板的主动断开)
            if (msg.action === 'kick' && msg.username) {
                kickUser(msg.username);
            }
        } catch (e) {
            console.error(`[IPC] Msg Error: ${e.message}`);
        }
    });

    ipcWsClient.on('close', () => {
        console.warn('[IPC] Disconnected. Retrying...');
        reconnectTimer = setTimeout(connectToIpc, RECONNECT_DELAY);
    });

    ipcWsClient.on('error', (e) => console.error(`[IPC] Error: ${e.message}`));
}

// 发送鉴权请求
function verifyUser(socket, username, password) {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
        console.error('[AUTH] IPC not ready. Rejecting connection.');
        socket.end();
        return;
    }
    
    // 使用 socket 的 remotePort 作为临时请求 ID
    const requestId = `${socket.remoteAddress}:${socket.remotePort}`;
    socket.requestId = requestId;
    
    // 暂时挂起 socket 数据读取，等待鉴权
    socket.pause();
    
    // 存储待处理连接
    activeConnections.set(requestId, { 
        socket, 
        username, 
        status: 'PENDING_AUTH',
        traffic: { up: 0, down: 0 } 
    });

    ipcWsClient.send(JSON.stringify({
        action: 'verify_user',
        requestId: requestId,
        username: username,
        password: password
    }));
}

// 处理鉴权结果
function handleAuthResult(msg) {
    const client = activeConnections.get(msg.requestId);
    if (!client) return;

    const { socket } = client;

    if (msg.success) {
        // 鉴权成功
        client.status = 'ACTIVE';
        // 初始化 BadVPN 逻辑
        setupBadVpnForwarding(client);
        console.log(`[AUTH] User ${client.username} verified. Tunnel active.`);
        // 恢复数据流
        socket.resume();
        
        // 传输残留数据（鉴权包后的 BadVPN 数据）
        if (client.pendingBuffer && client.pendingBuffer.length > 0) {
            // 手动触发 data 事件来处理残留的 BadVPN 帧
            socket.emit('data', client.pendingBuffer);
            client.pendingBuffer = null; 
        }
    } else {
        // 鉴权失败
        console.log(`[AUTH] Failed for ${client.username}: ${msg.message}`);
        
        // 发送 401 响应 (可选，取决于客户端期望) 或直接断开
        socket.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); 
        activeConnections.delete(msg.requestId);
    }
}

// 踢人逻辑：查找用户所有活跃的 SSH-UDP 连接并断开
function kickUser(username) {
    let kickedCount = 0;
    for (const [id, client] of activeConnections.entries()) {
        if (client.username === username && client.socket && !client.socket.destroyed) {
            client.socket.destroy();
            kickedCount++;
            activeConnections.delete(id);
        }
    }
    if (kickedCount > 0) {
        console.log(`[KICK] Kicked ${kickedCount} SSH-UDP connections for user ${username}.`);
    }
}

// 推送流量统计 (精确到用户名)
function pushStats() {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) return;

    const statsReport = {};
    const liveIps = {};

    for (const [id, client] of activeConnections.entries()) {
        if (client.status === 'ACTIVE') {
            const username = client.username;
            
            if (!statsReport[username]) {
                statsReport[username] = {
                    traffic_delta_up: 0,
                    traffic_delta_down: 0,
                    speed_kbps: { upload: 0, download: 0 }, 
                    connections: 0,
                    source: WORKER_ID // 'ssh_udp'
                };
            }
            
            statsReport[username].traffic_delta_up += client.traffic.up;
            statsReport[username].traffic_delta_down += client.traffic.down;
            statsReport[username].connections += 1;
            
            const ip = id.split(':')[0]; 
            liveIps[ip] = username;

            // 清零增量
            client.traffic.up = 0;
            client.traffic.down = 0;
        }
    }

    ipcWsClient.send(JSON.stringify({
        type: 'stats_update',
        workerId: WORKER_ID,
        payload: { stats: statsReport, live_ips: liveIps, ping: true }
    }));
}


// --- BadVPN 转发逻辑 (协议解析与封装) ---

function setupBadVpnForwarding(client) {
    const { socket } = client;
    client.udpSocket = dgram.createSocket('udp4');
    let buffer = Buffer.alloc(0);

    // 错误处理
    const cleanup = () => {
        try { client.udpSocket.close(); } catch(e) {}
        activeConnections.delete(socket.requestId);
    };
    socket.on('close', cleanup);
    socket.on('error', cleanup);
    client.udpSocket.on('error', () => socket.destroy());

    // 1. UDP 回包 -> 封装为 TCP (与 BadVPN 协议一致)
    client.udpSocket.on('message', (msg, rinfo) => {
        // BadVPN Frame: [Length(2 LE)] [IP(4)] [Port(2 LE)] [Data]
        const ipParts = rinfo.address.split('.').map(Number);
        if (ipParts.length !== 4) return;

        const payloadLen = 6 + msg.length;
        const frame = Buffer.alloc(2 + payloadLen);

        frame.writeUInt16LE(payloadLen, 0); // Length
        frame[2] = ipParts[0]; frame[3] = ipParts[1]; frame[4] = ipParts[2]; frame[5] = ipParts[3]; // IP
        frame.writeUInt16LE(rinfo.port, 6); // Port
        msg.copy(frame, 8); // Data

        client.traffic.down += frame.length;

        if (!socket.destroyed) socket.write(frame);
    });

    // 2. TCP 数据 -> 解包 -> 发送 UDP (与 BadVPN 协议一致)
    socket.on('data', (chunk) => {
        client.traffic.up += chunk.length;
        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length >= 2) {
            const packetLen = buffer.readUInt16LE(0); // BadVPN header is LE

            if (packetLen === 0) { // Keep-alive
                buffer = buffer.subarray(2);
                continue;
            }

            if (buffer.length < 2 + packetLen) break; 

            // 提取包体: [IP(4)] [Port(2)] [Data...]
            const body = buffer.subarray(2, 2 + packetLen);
            buffer = buffer.subarray(2 + packetLen);

            if (packetLen < 6) continue; 

            const destIp = `${body[0]}.${body[1]}.${body[2]}.${body[3]}`;
            const destPort = body.readUInt16LE(4);
            const payload = body.subarray(6);

            client.udpSocket.send(payload, destPort, destIp, (err) => {
                if (err) console.error(`[UDP Error] Send failed: ${err.message}`);
            });
        }
    });
}


// --- TCP 服务器 (公网入口) ---

const server = net.createServer((socket) => {
    let handshakeBuffer = Buffer.alloc(0);
    let isHandshakeDone = false;
    const clientIp = socket.remoteAddress;

    socket.on('data', (chunk) => {
        if (isHandshakeDone) return; 

        handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);

        // 尝试解析 "username:password"
        const str = handshakeBuffer.toString('utf8');
        
        // 匹配格式: username:password 
        // 限制长度在 100 字节内，防止缓冲区溢出攻击
        if (handshakeBuffer.length > 100) {
            console.log(`[SSH-UDP] Handshake buffer overflow from ${clientIp}. Closing.`);
            socket.destroy();
            return;
        }

        // 匹配 user:pass 格式，允许字母数字下划线作为用户名，密码允许任意非空白字符
        const match = str.match(/^([a-zA-Z0-9_]{3,30}):([^\s\x00\r\n]{1,128})/);
        
        if (match) {
            isHandshakeDone = true;
            socket.removeAllListeners('data'); 
            
            const username = match[1];
            const password = match[2];
            const authStr = match[0];
            
            // 跳过鉴权字符串和紧随其后的空白符/换行符
            let skipLen = authStr.length;
            while (skipLen < handshakeBuffer.length && (handshakeBuffer[skipLen] === 10 || handshakeBuffer[skipLen] === 13 || handshakeBuffer[skipLen] === 32)) {
                skipLen++; // Skip \n, \r, or space
            }
            
            // 保存剩余的 BadVPN 数据帧
            const pendingData = handshakeBuffer.subarray(skipLen);
            
            // 发起鉴权，并将 pendingData 附加到客户端状态中
            verifyUser(socket, username, password);
            
            setTimeout(() => {
                const client = activeConnections.get(socket.requestId);
                if (client) client.pendingBuffer = pendingData;
            }, 0);

        } else if (handshakeBuffer.length >= 6) {
            // 如果长度超过6字节且不是 user:pass，可以尝试嗅探 BadVPN 握手
            const handshakeBuf = Buffer.from('UDPGW01');
            if (handshakeBuffer.subarray(0, handshakeBuf.length).equals(handshakeBuf)) {
                 // 如果客户端发的是无鉴权的 BadVPN 握手，直接拒绝。
                 socket.end('HTTP/1.1 401 Unauthorized - Auth Required\r\n\r\n');
                 console.log(`[SSH-UDP] Rejected bare BadVPN handshake from ${clientIp}.`);
                 socket.destroy();
                 isHandshakeDone = true;
            }
        }
    });

    socket.on('error', () => {});
});

server.listen(LISTEN_PORT, LISTEN_ADDR, () => {
    console.log(`[SSH-UDP] Auth Server listening on ${LISTEN_ADDR}:${LISTEN_PORT}`);
    connectToIpc();
});

server.on('error', (err) => {
    console.error(`[SSH-UDP] Server start error: ${err.message}`);
    // 公网端口绑定失败通常是端口已被占用
    process.exit(1);
});
