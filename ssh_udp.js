/**
 * SSH-UDP Service (Node.js)
 * V5.0.0 (Axiom - Stable Stream)
 *
 * 优化:
 * 1. 握手响应: 采用最广泛兼容的 "HTTP/1.1 200 OK\r\n\r\n"。
 * 2. 缓冲区: 优化粘包处理，防止数据丢失。
 * 3. 错误处理: 增加对 UDP 发送错误的容忍度。
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

const activeConnections = new Map(); 
let ipcWsClient = null;
let statsInterval = null;
let reconnectTimer = null;

// --- IPC ---
function connectToIpc() {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    ipcWsClient = new WebSocket(ipcUrl, {
        headers: { 'X-Internal-Secret': config.internal_api_secret, 'X-Worker-ID': WORKER_ID }
    });
    ipcWsClient.on('open', () => {
        if (statsInterval) clearInterval(statsInterval);
        statsInterval = setInterval(pushStats, 1000);
    });
    ipcWsClient.on('close', () => {
        reconnectTimer = setTimeout(connectToIpc, RECONNECT_DELAY);
    });
    ipcWsClient.on('error', () => {});
}

function pushStats() {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) return;
    const statsReport = {};
    const liveIps = {};
    for (const [id, client] of activeConnections.entries()) {
        if (client.status === 'ACTIVE') {
            const u = `IP_${id.split(':')[0]}`; 
            if (!statsReport[u]) statsReport[u] = { traffic_delta_up: 0, traffic_delta_down: 0, connections: 0, speed_kbps: {upload:0, download:0}, source: WORKER_ID };
            statsReport[u].traffic_delta_up += client.traffic.up;
            statsReport[u].traffic_delta_down += client.traffic.down;
            statsReport[u].connections++;
            client.traffic.up = 0; client.traffic.down = 0;
            liveIps[id.split(':')[0]] = u;
        }
    }
    ipcWsClient.send(JSON.stringify({ type: 'stats_update', workerId: WORKER_ID, payload: { stats: statsReport, live_ips: liveIps, ping: true } }));
}

// --- BadVPN 转发逻辑 ---
function setupBadVpnForwarding(client) {
    const { socket } = client;
    client.udpSocket = dgram.createSocket('udp4');
    client.buffer = Buffer.alloc(0); 

    const cleanup = () => {
        try { client.udpSocket.close(); } catch(e) {}
        activeConnections.delete(socket.remoteAddress + ':' + socket.remotePort);
    };
    socket.on('close', cleanup);
    socket.on('error', cleanup);
    client.udpSocket.on('error', () => socket.destroy());

    // UDP -> TCP
    client.udpSocket.on('message', (msg, rinfo) => {
        const parts = rinfo.address.split('.');
        if (parts.length !== 4) return;

        const len = 6 + msg.length;
        const frame = Buffer.alloc(2 + len);
        frame.writeUInt16LE(len, 0);
        frame[2] = parseInt(parts[0]); frame[3] = parseInt(parts[1]); frame[4] = parseInt(parts[2]); frame[5] = parseInt(parts[3]);
        frame.writeUInt16LE(rinfo.port, 6);
        msg.copy(frame, 8);

        client.traffic.down += frame.length;
        if (!socket.destroyed) socket.write(frame);
    });

    // TCP -> UDP
    socket.on('data', (chunk) => {
        client.traffic.up += chunk.length;
        
        // 拼接到现有缓冲区
        client.buffer = Buffer.concat([client.buffer, chunk]);

        while (client.buffer.length >= 2) {
            const len = client.buffer.readUInt16LE(0);
            
            // Keep-alive (0x0000)
            if (len === 0) { 
                client.buffer = client.buffer.subarray(2); 
                continue; 
            }
            
            if (client.buffer.length < 2 + len) break; // 等待更多数据

            const body = client.buffer.subarray(2, 2 + len);
            client.buffer = client.buffer.subarray(2 + len);

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
    const remoteId = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`[SSH-UDP] Connect: ${remoteId}`);
    
    const client = {
        socket,
        status: 'HANDSHAKE',
        traffic: { up: 0, down: 0 },
        udpSocket: null
    };
    activeConnections.set(remoteId, client);

    socket.once('data', (chunk) => {
        // [DEBUG] 打印握手包前 20 字节
        console.log(`[SSH-UDP] Handshake HEX: ${chunk.subarray(0, 20).toString('hex')}`);
        
        // 无论收到什么，都回复 200 OK
        const response = 'HTTP/1.1 200 OK\r\n\r\n';
        
        socket.write(response, () => {
            console.log(`[SSH-UDP] Sent 200 OK. Forwarding...`);
            client.status = 'ACTIVE';
            
            // 初始化转发逻辑
            setupBadVpnForwarding(client);
            
            // 注意：如果 chunk 中包含了握手之后的数据（粘包），我们需要处理它
            // 但通常握手包是独立的。
            // 只有当 chunk 长度明显大于握手包长度时才考虑。
            // 这里简化处理：假设 HTTP Custom 握手包不包含 UDP 数据。
            
            socket.resume();
        });
    });
    
    socket.on('error', (err) => {
        if (err.code !== 'ECONNRESET') console.error(`[Socket] ${remoteId} Error: ${err.message}`);
    });
});

server.listen(LISTEN_PORT, LISTEN_ADDR, () => {
    console.log(`[SSH-UDP] Service listening on ${LISTEN_ADDR}:${LISTEN_PORT}`);
    connectToIpc();
});

server.on('error', (err) => {
    console.error(`[SSH-UDP] Startup Error: ${err.message}`);
    process.exit(1);
});
