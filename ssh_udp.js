/**
 * SSH-UDP Service (Node.js)
 * V2.2.0 (Axiom - Minimalist Handshake)
 *
 * 优化说明:
 * 1. 响应头精简为最基础的 "HTTP/1.1 200 OK\r\n\r\n"，最大程度兼容 HTTP Custom。
 * 2. 增加连接级调试日志，用于确认防火墙是否通过。
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
    ipcWsClient.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'AUTH_RESULT') handleAuthResult(msg);
            if (msg.action === 'kick' && msg.username) kickUser(msg.username);
        } catch (e) {}
    });
    ipcWsClient.on('close', () => {
        reconnectTimer = setTimeout(connectToIpc, RECONNECT_DELAY);
    });
    ipcWsClient.on('error', () => {});
}

function verifyUser(socket, username, password) {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
        socket.destroy();
        return;
    }
    const requestId = `${socket.remoteAddress}:${socket.remotePort}`;
    socket.requestId = requestId;
    socket.pause();
    activeConnections.set(requestId, { socket, username, status: 'PENDING', traffic: { up: 0, down: 0 } });
    ipcWsClient.send(JSON.stringify({ action: 'verify_user', requestId, username, password }));
}

function handleAuthResult(msg) {
    const client = activeConnections.get(msg.requestId);
    if (!client) return;
    const { socket } = client;

    if (msg.success) {
        client.status = 'ACTIVE';
        // [FIX] 极简响应，模拟 newudpgw 二进制行为
        socket.write('HTTP/1.1 200 OK\r\n\r\n', () => {
            setupBadVpnForwarding(client);
            socket.resume();
            if (client.pendingBuffer) {
                socket.emit('data', client.pendingBuffer);
                client.pendingBuffer = null;
            }
        });
        console.log(`[SSH-UDP] Auth success: ${client.username} (${socket.remoteAddress})`);
    } else {
        console.log(`[SSH-UDP] Auth failed: ${client.username}`);
        socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        activeConnections.delete(msg.requestId);
    }
}

function kickUser(username) {
    for (const [id, client] of activeConnections.entries()) {
        if (client.username === username) {
            if (client.socket) client.socket.destroy();
            activeConnections.delete(id);
        }
    }
}

function pushStats() {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) return;
    const statsReport = {};
    const liveIps = {};
    for (const [id, client] of activeConnections.entries()) {
        if (client.status === 'ACTIVE') {
            const u = client.username;
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

function setupBadVpnForwarding(client) {
    const { socket } = client;
    client.udpSocket = dgram.createSocket('udp4');
    let buffer = Buffer.alloc(0);

    const cleanup = () => {
        try { client.udpSocket.close(); } catch(e) {}
        activeConnections.delete(socket.requestId);
    };
    socket.on('close', cleanup);
    socket.on('error', cleanup);
    client.udpSocket.on('error', () => socket.destroy());

    client.udpSocket.on('message', (msg, rinfo) => {
        const parts = rinfo.address.split('.');
        if (parts.length !== 4) return;
        const len = 6 + msg.length;
        const frame = Buffer.alloc(2 + len);
        frame.writeUInt16LE(len, 0);
        frame[2] = parts[0]; frame[3] = parts[1]; frame[4] = parts[2]; frame[5] = parts[3];
        frame.writeUInt16LE(rinfo.port, 6);
        msg.copy(frame, 8);
        client.traffic.down += frame.length;
        if (!socket.destroyed) socket.write(frame);
    });

    socket.on('data', (chunk) => {
        client.traffic.up += chunk.length;
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 2) {
            const len = buffer.readUInt16LE(0);
            if (len === 0) { buffer = buffer.subarray(2); continue; }
            if (buffer.length < 2 + len) break;
            const body = buffer.subarray(2, 2 + len);
            buffer = buffer.subarray(2 + len);
            if (len < 6) continue;
            const destIp = `${body[0]}.${body[1]}.${body[2]}.${body[3]}`;
            const destPort = body.readUInt16LE(4);
            const payload = body.subarray(6);
            client.udpSocket.send(payload, destPort, destIp);
        }
    });
}

const server = net.createServer((socket) => {
    // [DEBUG] 这个日志必须出现，否则就是防火墙拦截
    console.log(`[SSH-UDP] TCP Connect: ${socket.remoteAddress}`);
    
    let buffer = Buffer.alloc(0);
    let done = false;

    socket.on('data', (chunk) => {
        if (done) return;
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > 512) { socket.destroy(); return; } // 防爆
        
        const str = buffer.toString('utf8');
        const match = str.match(/^\s*([a-zA-Z0-9_]{3,30}):([^\s\x00\r\n]{1,128})/);
        
        if (match) {
            done = true;
            socket.removeAllListeners('data');
            
            // 查找分隔符（兼容 \n, \r\n 或无）
            let end = match[0].length;
            while (end < buffer.length && buffer[end] <= 32) end++;
            
            const pending = buffer.subarray(end);
            verifyUser(socket, match[1], match[2]);
            
            if (pending.length > 0) {
                setTimeout(() => {
                    const c = activeConnections.get(socket.requestId);
                    if (c) c.pendingBuffer = pending;
                }, 0);
            }
        }
    });
    socket.on('error', () => {});
});

server.listen(LISTEN_PORT, LISTEN_ADDR, () => {
    console.log(`[SSH-UDP] Listening on ${LISTEN_ADDR}:${LISTEN_PORT}`);
    connectToIpc();
});
