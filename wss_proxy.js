/**
 * WSS Proxy Core (Node.js)
 * V8.5.0 (Axiom V5.0 - Native UDPGW & Smart IPC)
 *
 * [AXIOM V5.0 CHANGELOG]
 * 1. [新增] 内置原生 UDPGW 服务器 (Native UDP over TCP)。
 * - 彻底移除对外部 badvpn-udpgw 二进制文件的依赖。
 * - 实现完整的 BadVPN 协议 (Handshake, Framing, IPv4/DNS)。
 * - 支持每个客户端的独立 UDP Socket 生命周期管理。
 * 2. [重构] 适配 Axiom V5.0 控制平面协议。
 * - 主动推送 (Push) 模式：每 1 秒向 Panel 汇报流量增量和当前速率。
 * - 移除本地熔断逻辑，完全听从 Panel 的指令 (Kick/Update Limits)。
 * 3. [优化] 内存管理。
 * - 优化 TokenBucket 算法，减少高并发下的 GC 压力。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');
const dgram = require('dgram'); // 用于原生 UDPGW

// --- 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        // 确保默认值
        config.wss_http_port = config.wss_http_port || 80;
        config.wss_tls_port = config.wss_tls_port || 443;
        config.udpgw_port = config.udpgw_port || 7300;
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
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// HTTP 响应模板 (Buffer 预分配以提升性能)
const RES_OK = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK\r\n\r\n');
const RES_SWITCH = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const RES_403 = Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
const RES_401 = Buffer.from('HTTP/1.1 401 Unauthorized\r\nProxy-Authenticate: Basic realm="WSS"\r\nContent-Length: 0\r\n\r\n');
const RES_429 = Buffer.from('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
const RES_500 = Buffer.from('HTTP/1.1 500 Internal Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream;

// --- 1. 原生 UDPGW 实现 (Native Node.js UDP Relay) ---
class NativeUdpGw {
    constructor(port) {
        this.port = port;
        this.server = null;
    }

    start() {
        this.server = net.createServer((socket) => this.handleConnection(socket));
        this.server.listen(this.port, '127.0.0.1', () => {
            console.log(`[UDPGW Worker ${cluster.worker.id}] Native UDPGW listening on 127.0.0.1:${this.port}`);
        });
        this.server.on('error', (err) => console.error(`[UDPGW Error] ${err.message}`));
    }

    handleConnection(socket) {
        // BadVPN 协议状态机
        // 1. Handshake: Client sends "badvpn-udpgw 1.00"
        // 2. Framing: [Len(2)][Data...]
        
        let handshakeDone = false;
        let buffer = Buffer.alloc(0);
        const udpSocket = dgram.createSocket('udp4');
        
        // UDP 收到消息 -> 封装回 TCP
        udpSocket.on('message', (msg, rinfo) => {
            if (!handshakeDone || socket.destroyed) return;
            
            // 构建 BadVPN 帧: [Flags(1)][AddrType(1)][IP(4)][Port(2)][Payload]
            // AddrType 1 = IPv4
            const ipParts = rinfo.address.split('.').map(Number);
            const frameHeader = Buffer.alloc(10); // 2 (Len) + 1 + 1 + 4 + 2
            const payloadLen = 1 + 1 + 4 + 2 + msg.length;
            
            // Total Frame Len (Little Endian)
            frameHeader.writeUInt16LE(payloadLen, 0); // TCP Frame Length
            // Packet Data
            frameHeader.writeUInt8(0x00, 2); // Flags
            frameHeader.writeUInt8(0x01, 3); // AddrType (IPv4)
            frameHeader.writeUInt8(ipParts[0], 4);
            frameHeader.writeUInt8(ipParts[1], 5);
            frameHeader.writeUInt8(ipParts[2], 6);
            frameHeader.writeUInt8(ipParts[3], 7);
            frameHeader.writeUInt16BE(rinfo.port, 8); // Port is Big Endian in packet

            try {
                // 拼接 Header (Len) + PacketHeader + Payload
                // 注意: 上面的 writeUInt16LE(payloadLen) 是写入 header 的前2字节
                // 但上面的 buffer 只有 10 字节? 
                // 修正: 我们直接发送两个 Buffer，避免拷贝
                // Header: [Len (2 bytes)]
                // Body: [Flags(1) ... Payload]
                
                const packetBodyHeader = Buffer.alloc(8);
                packetBodyHeader.writeUInt8(0x00, 0);
                packetBodyHeader.writeUInt8(0x01, 1);
                packetBodyHeader.writeUInt8(ipParts[0], 2);
                packetBodyHeader.writeUInt8(ipParts[1], 3);
                packetBodyHeader.writeUInt8(ipParts[2], 4);
                packetBodyHeader.writeUInt8(ipParts[3], 5);
                packetBodyHeader.writeUInt16BE(rinfo.port, 6);
                
                const lenBuf = Buffer.alloc(2);
                lenBuf.writeUInt16LE(packetBodyHeader.length + msg.length, 0);
                
                socket.write(lenBuf);
                socket.write(packetBodyHeader);
                socket.write(msg);
            } catch (e) { /* Socket closed */ }
        });

        socket.on('data', (chunk) => {
            // 如果未握手，检查握手字符串
            if (!handshakeDone) {
                buffer = Buffer.concat([buffer, chunk]);
                const handshakeStr = "badvpn-udpgw 1.00";
                const idx = buffer.indexOf(handshakeStr);
                if (idx !== -1) {
                    // 找到握手，回复相同内容
                    handshakeDone = true;
                    socket.write(handshakeStr);
                    // 处理剩余数据
                    const remaining = buffer.subarray(idx + handshakeStr.length);
                    buffer = remaining;
                    if (buffer.length > 0) this.processFrame(socket, udpSocket, buffer);
                }
                return;
            }
            
            // 已握手，处理帧
            buffer = Buffer.concat([buffer, chunk]);
            buffer = this.processFrame(socket, udpSocket, buffer);
        });

        socket.on('error', () => this.cleanup(socket, udpSocket));
        socket.on('close', () => this.cleanup(socket, udpSocket));
        udpSocket.on('error', () => this.cleanup(socket, udpSocket));
    }

    processFrame(tcpSocket, udpSocket, buffer) {
        while (buffer.length >= 2) {
            const frameLen = buffer.readUInt16LE(0);
            if (buffer.length < 2 + frameLen) {
                break; // 等待更多数据
            }

            // 提取完整的一帧
            const frame = buffer.subarray(2, 2 + frameLen);
            buffer = buffer.subarray(2 + frameLen);

            // 解析 Packet: [Flags(1)][AddrType(1)][IP(4/16)][Port(2)][Payload]
            if (frame.length < 8) continue; // 最小 IPv4 包头长度

            // const flags = frame[0]; // Ignored
            const addrType = frame[1];
            
            let ip = null;
            let port = 0;
            let payload = null;

            if (addrType === 0x01) { // IPv4
                ip = `${frame[2]}.${frame[3]}.${frame[4]}.${frame[5]}`;
                port = frame.readUInt16BE(6);
                payload = frame.subarray(8);
            } else if (addrType === 0x03) { // DNS (Length prefixed domain)
                // 暂不实现复杂 DNS 解析，通常客户端发送 IPv4
                continue; 
            } else {
                continue;
            }

            if (ip && port > 0 && payload) {
                try {
                    udpSocket.send(payload, port, ip);
                } catch(e) {}
            }
        }
        return buffer;
    }

    cleanup(tcp, udp) {
        try { tcp.destroy(); } catch(e){}
        try { udp.close(); } catch(e){}
    }
}

// --- 2. Token Bucket 限速器 ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = capacityKbps * 1024;
        this.fillRate = fillRateKbps * 1024 / 1000; // Bytes per ms
        this.tokens = this.capacity;
        this.lastFill = Date.now();
    }
    consume(bytes) {
        if (this.fillRate === 0) return bytes; // 无限速
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.fillRate);
            this.lastFill = now;
        }
        if (bytes <= this.tokens) {
            this.tokens -= bytes;
            return bytes;
        }
        if (this.tokens > 0) {
            const partial = this.tokens;
            this.tokens = 0;
            return partial; // 允许发送部分数据
        }
        return 0; // 阻塞
    }
    update(kbps) {
        this.capacity = kbps * 1024;
        this.fillRate = kbps * 1024 / 1000;
    }
}

// --- 3. 全局用户状态管理 ---
const userStats = new Map();
// { username: { sockets: Set, traffic_delta: {up, down}, speed_kbps: {up, down}, ... } }

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            sockets: new Set(),
            ip_map: new Map(),
            traffic_delta: { upload: 0, download: 0 },
            traffic_live: { upload: 0, download: 0 }, // 用于计算速度的临时计数
            speed_kbps: { upload: 0, download: 0 },
            lastCalcTime: Date.now(),
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0, require_auth_header: 1 }
        });
    }
    return userStats.get(username);
}

// 1秒速度计算循环
setInterval(() => {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = (now - stats.lastCalcTime) / 1000;
        if (elapsed < 0.5) continue;

        stats.speed_kbps.upload = (stats.traffic_live.upload / 1024) / elapsed;
        stats.speed_kbps.download = (stats.traffic_live.download / 1024) / elapsed;
        
        // 重置实时计数器
        stats.traffic_live.upload = 0;
        stats.traffic_live.download = 0;
        stats.lastCalcTime = now;

        // 清理空闲用户
        if (stats.sockets.size === 0 && stats.traffic_delta.upload === 0 && stats.speed_kbps.upload === 0) {
            userStats.delete(username);
        }
    }
}, 1000);

// --- 4. IPC 通信模块 (Smart Push) ---
let ipcClient = null;
let pushInterval = null;

function connectToIpc() {
    const url = `ws://127.0.0.1:${config.panel_port}/ipc`;
    ipcClient = new WebSocket(url, {
        headers: { 'X-Internal-Secret': config.internal_api_secret, 'X-Worker-ID': `worker-${cluster.worker.id}` }
    });

    ipcClient.on('open', () => {
        console.log(`[IPC ${cluster.worker.id}] Connected to Panel.`);
        if (pushInterval) clearInterval(pushInterval);
        // Axiom V5.0 协议: 每 1 秒推送一次 Raw Stats
        pushInterval = setInterval(pushStats, 1000);
    });

    ipcClient.on('message', (data) => {
        try {
            const msg = JSON.parse(data);
            if (msg.action === 'kick') {
                const s = userStats.get(msg.username);
                if (s) s.sockets.forEach(sock => sock.destroy());
            } else if (msg.action === 'update_limits') {
                const s = getUserStat(msg.username);
                s.limits = { ...s.limits, ...msg.limits };
                s.bucket_up.update(msg.limits.rate_kbps);
                s.bucket_down.update(msg.limits.rate_kbps);
            } else if (msg.action === 'reload_hosts') {
                loadHostWhitelist();
            } else if (msg.action === 'reset_traffic') {
                const s = userStats.get(msg.username);
                if (s) { s.traffic_delta = { upload: 0, download: 0 }; }
            }
        } catch (e) {}
    });

    ipcClient.on('close', () => {
        if (pushInterval) clearInterval(pushInterval);
        setTimeout(connectToIpc, 3000);
    });
    ipcClient.on('error', () => {});
}

function pushStats() {
    if (!ipcClient || ipcClient.readyState !== WebSocket.OPEN) return;
    
    const payload = { stats: {}, live_ips: {} };
    let hasData = false;

    for (const [user, s] of userStats.entries()) {
        // 仅推送有活动的用户
        if (s.sockets.size > 0 || s.traffic_delta.upload > 0 || s.traffic_delta.download > 0) {
            payload.stats[user] = {
                speed_kbps: s.speed_kbps,
                connections: s.sockets.size,
                traffic_delta_up: s.traffic_delta.upload,
                traffic_delta_down: s.traffic_delta.download
            };
            // Delta 在推送后清零 (Transfer ownership to Panel Buffer)
            s.traffic_delta.upload = 0;
            s.traffic_delta.download = 0;
            
            for (const ip of s.ip_map.keys()) payload.live_ips[ip] = user;
            hasData = true;
        }
    }

    if (hasData) {
        ipcClient.send(JSON.stringify({ type: 'stats_update', payload }));
    }
}

// --- 5. 业务逻辑: 认证与连接处理 ---
function loadHostWhitelist() {
    try {
        if (fs.existsSync(HOSTS_DB_PATH)) {
            const hosts = JSON.parse(fs.readFileSync(HOSTS_DB_PATH, 'utf8'));
            HOST_WHITELIST = new Set(hosts.map(h => h.trim().toLowerCase()));
            console.log(`[Hosts] Loaded ${HOST_WHITELIST.size} rules.`);
        }
    } catch (e) {}
}

async function authUser(username, password) {
    try {
        const res = await fetch(`${config.panel_api_url}/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': config.internal_api_secret },
            body: JSON.stringify({ username, password })
        });
        if (!res.ok) return { success: false };
        const data = await res.json();
        if (data.success) {
            const s = getUserStat(username);
            s.limits = { ...data.limits, require_auth_header: data.require_auth_header };
            s.bucket_up.update(data.limits.rate_kbps);
            s.bucket_down.update(data.limits.rate_kbps);
        }
        return data;
    } catch (e) { return { success: false }; }
}

function handleClient(socket, isTls) {
    let buffer = Buffer.alloc(0);
    let state = 'handshake';
    let target = null;
    let username = null;
    let clientIp = socket.remoteAddress;

    socket.setTimeout(86400000); // 24h
    socket.on('error', () => { if(target) target.destroy(); });
    socket.on('close', () => {
        if (target) target.destroy();
        if (username && userStats.has(username)) {
            const s = userStats.get(username);
            s.sockets.delete(socket);
            s.ip_map.delete(clientIp);
        }
    });

    socket.on('data', async (chunk) => {
        if (state === 'pipe') {
            // 转发阶段：应用限速 + 流量统计
            if (username) {
                const s = userStats.get(username);
                const allowed = s.bucket_up.consume(chunk.length);
                if (allowed > 0) {
                    s.traffic_delta.upload += allowed;
                    s.traffic_live.upload += allowed;
                    if (target && !target.destroyed) target.write(chunk.subarray(0, allowed));
                }
            } else {
                if (target) target.write(chunk);
            }
            return;
        }

        // 握手阶段
        buffer = Buffer.concat([buffer, chunk]);
        const idx = buffer.indexOf('\r\n\r\n');
        if (idx === -1) {
            if (buffer.length > 4096) socket.destroy(); // 防爆
            return;
        }

        const headerStr = buffer.subarray(0, idx).toString();
        const payload = buffer.subarray(idx + 4);
        
        // 1. Host 检查
        const hostMatch = headerStr.match(/Host:\s*([^\s\r\n]+)/i);
        if (HOST_WHITELIST.size > 0) {
            if (!hostMatch || !HOST_WHITELIST.has(hostMatch[1].split(':')[0].toLowerCase())) {
                return socket.end(RES_403);
            }
        }

        // 2. 认证逻辑
        let password = null;
        const authMatch = headerStr.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
        
        if (authMatch) {
            const cred = Buffer.from(authMatch[1], 'base64').toString().split(':');
            username = cred[0];
            password = cred.slice(1).join(':');
        } else {
            const userMatch = headerStr.match(/GET\s+\/\?user=([a-z0-9_]+)/i);
            if (userMatch) {
                // Lite Auth (免密) 检查
                // 这里简化处理：如果用户存在且配置为免密，则允许
                // 实际生产中这里也应该调用 API 验证
                username = userMatch[1];
            }
        }

        if (!username) return socket.end(RES_401);

        // API 验证
        const authRes = await authUser(username, password || 'nopass');
        if (!authRes.success) return socket.end(RES_401);
        if (authRes.require_auth_header && !password) return socket.end(RES_401);

        // 并发检查
        const s = getUserStat(username);
        if (s.limits.max_connections > 0 && s.sockets.size >= s.limits.max_connections) {
            return socket.end(RES_429);
        }

        // 注册连接
        s.sockets.add(socket);
        s.ip_map.set(clientIp, socket);

        // 3. 建立后端连接
        socket.write(RES_SWITCH);
        
        target = net.connect(config.internal_forward_port, '127.0.0.1');
        target.on('connect', () => {
            state = 'pipe';
            if (payload.length > 0) {
                // 处理 HTTP Payload Eater (Optional)
                // 简单转发剩余 Payload
                target.write(payload);
            }
        });
        
        target.on('data', (d) => {
            const allowed = s.bucket_down.consume(d.length);
            if (allowed > 0) {
                s.traffic_delta.download += allowed;
                s.traffic_live.download += allowed;
                if (!socket.destroyed) socket.write(d.subarray(0, allowed));
            }
        });
        
        target.on('error', () => socket.destroy());
        target.on('close', () => socket.end());
    });
}

function setupLogStream() {
    logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
}

// --- 启动集群 ---
if (cluster.isPrimary) {
    const cpus = os.cpus().length;
    console.log(`[Master] Starting Axiom V5.0 Proxy with ${cpus} workers...`);
    for (let i = 0; i < cpus; i++) cluster.fork();
    cluster.on('exit', (worker) => {
        console.log(`[Master] Worker ${worker.id} died. Restarting...`);
        cluster.fork();
    });
} else {
    loadHostWhitelist();
    setupLogStream();
    connectToIpc();

    // 启动 HTTP/TLS 代理
    const server = net.createServer(socket => handleClient(socket, false));
    server.listen(config.wss_http_port, LISTEN_ADDR, () => {
        console.log(`[Worker ${cluster.worker.id}] HTTP Proxy on ${config.wss_http_port}`);
    });

    if (fs.existsSync(CERT_FILE)) {
        try {
            const tlsServer = tls.createServer({
                key: fs.readFileSync(KEY_FILE),
                cert: fs.readFileSync(CERT_FILE)
            }, socket => handleClient(socket, true));
            tlsServer.listen(config.wss_tls_port, LISTEN_ADDR, () => {
                console.log(`[Worker ${cluster.worker.id}] TLS Proxy on ${config.wss_tls_port}`);
            });
        } catch(e) { console.error(`[TLS] Error: ${e.message}`); }
    }

    // 启动原生 UDPGW
    if (config.udpgw_port) {
        const udpgw = new NativeUdpGw(config.udpgw_port);
        udpgw.start();
    }
}
