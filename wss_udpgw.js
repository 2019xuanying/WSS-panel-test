/**
 * WSS Native UDPGW Service (Node.js Implementation)
 * Axiom V5.0 - Native Replacement for BadVPN-UDPGW
 * * [功能描述]
 * 这是一个纯 Node.js 实现的 UDP-over-TCP 网关。
 * 它完全替代了传统的 C++ badvpn-udpgw 二进制文件。
 * * [核心特性]
 * 1. 零依赖: 仅使用 Node.js 原生 'net' 和 'dgram' 模块。
 * 2. 协议兼容: 完整支持 BadVPN 协议 (Frame = Length(2byte) + Body)。
 * 3. 内存管理: TCP 连接断开时自动销毁关联的 UDP Socket。
 * 4. 高性能: 使用 Buffer 处理二进制流，支持 TCP 粘包/拆包解析。
 * * [协议格式]
 * Request (TCP -> UDP):
 * [Length (2 bytes, LE)] [Packet]
 * Packet: [Flags (1 byte, 0x00=IPv4)] [DestIP (4 bytes)] [DestPort (2 bytes, BE)] [Payload]
 * * Response (UDP -> TCP):
 * [Length (2 bytes, LE)] [Packet]
 * Packet: [Flags (1 byte, 0x00=IPv4)] [SrcIP (4 bytes)] [SrcPort (2 bytes, BE)] [Payload]
 */

const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');

// --- 配置加载 ---
// 默认路径，可根据实际环境调整
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');

let config = {
    udpgw_port: 7300 // 默认端口
};

function loadConfig() {
    try {
        if (fs.existsSync(CONFIG_PATH)) {
            const rawData = fs.readFileSync(CONFIG_PATH, 'utf8');
            const parsed = JSON.parse(rawData);
            if (parsed.udpgw_port) {
                config.udpgw_port = parseInt(parsed.udpgw_port);
            }
        } else {
            console.warn(`[UDPGW] 配置文件未找到 (${CONFIG_PATH})，使用默认端口 7300。`);
        }
    } catch (e) {
        console.error(`[UDPGW] 加载配置失败: ${e.message}。使用默认配置。`);
    }
}

loadConfig();

// --- 常量定义 ---
const LISTEN_PORT = config.udpgw_port;
const LISTEN_HOST = '127.0.0.1'; // UDPGW 通常仅监听本地，由 WSS Proxy 转发
const MAX_PACKET_SIZE = 65535;
const HEADER_SIZE = 2; // Length 字段长度

// --- 工具函数: IP/Port 解析 ---

/**
 * 将 4字节 Buffer 解析为 IP 字符串 (如 "8.8.8.8")
 */
function parseIp(buffer, offset) {
    return `${buffer[offset]}.${buffer[offset+1]}.${buffer[offset+2]}.${buffer[offset+3]}`;
}

/**
 * 将 IP 字符串转换为 4字节 Buffer
 */
function ipToBuffer(ip) {
    const parts = ip.split('.').map(Number);
    return Buffer.from(parts);
}

// --- 核心服务逻辑 ---

const server = net.createServer((tcpSocket) => {
    const clientAddr = `${tcpSocket.remoteAddress}:${tcpSocket.remotePort}`;
    // console.log(`[UDPGW] 新客户端连接: ${clientAddr}`);

    // 每个 TCP 客户端分配一个独立的 UDP Socket (实现 NAT 映射)
    const udpSocket = dgram.createSocket('udp4');
    
    // 状态标记
    let isClosed = false;

    // TCP 数据缓冲区 (处理粘包)
    let buffer = Buffer.alloc(0);

    // --- 1. 处理 TCP -> UDP (上行) ---
    
    tcpSocket.on('data', (chunk) => {
        // 将新数据追加到缓冲区
        buffer = Buffer.concat([buffer, chunk]);

        // 循环解析帧
        while (true) {
            // 检查是否有完整的长度头 (2字节)
            if (buffer.length < HEADER_SIZE) {
                break;
            }

            // 读取帧长度 (Little Endian)
            // 注意: BadVPN 协议中，Length = Payload Length (Flags + IP + Port + Data)
            const frameLen = buffer.readUInt16LE(0);

            // 检查是否有完整的帧数据
            if (buffer.length < HEADER_SIZE + frameLen) {
                break; // 数据不够，等待下一个 chunk
            }

            // 提取帧数据
            const frameBody = buffer.subarray(HEADER_SIZE, HEADER_SIZE + frameLen);
            
            // 将已处理的数据从缓冲区移除
            buffer = buffer.subarray(HEADER_SIZE + frameLen);

            // 解析 Frame Body
            // Format: [Flags(1)] [IP(4)] [Port(2)] [Data...]
            if (frameBody.length < 7) {
                console.error(`[UDPGW] [${clientAddr}] 丢弃畸形包: 长度不足`);
                continue;
            }

            const flags = frameBody[0];
            if (flags !== 0x00) {
                // 目前仅支持 IPv4 (0x00)
                // console.warn(`[UDPGW] [${clientAddr}] 忽略非 IPv4 包 (Flags: ${flags})`);
                continue;
            }

            const destIp = parseIp(frameBody, 1);
            const destPort = frameBody.readUInt16BE(5); // Port is Big Endian
            const udpPayload = frameBody.subarray(7);

            // 发送 UDP 包
            try {
                udpSocket.send(udpPayload, destPort, destIp, (err) => {
                    if (err) {
                        console.error(`[UDPGW] UDP 发送错误: ${err.message}`);
                    }
                });
            } catch (e) {
                console.error(`[UDPGW] UDP 发送异常: ${e.message}`);
            }
        }
    });

    // --- 2. 处理 UDP -> TCP (下行) ---

    udpSocket.on('message', (msg, rinfo) => {
        if (isClosed) return;

        // 构造 BadVPN 响应帧
        // [Length (2, LE)] [Flags(1)] [SrcIP(4)] [SrcPort(2, BE)] [Data]
        
        const ipBuf = ipToBuffer(rinfo.address);
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(rinfo.port, 0);
        
        // 计算总长度
        const packetLen = 1 + 4 + 2 + msg.length; // Flags + IP + Port + Data
        
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16LE(packetLen, 0);

        const flagsBuf = Buffer.from([0x00]); // IPv4

        // 拼接完整 TCP 帧
        const tcpFrame = Buffer.concat([lenBuf, flagsBuf, ipBuf, portBuf, msg]);

        // 写入 TCP Socket
        // 使用 write 并检查返回值，如果缓冲区满则暂停 (虽然 UDPGW 一般流量不大，但为了健壮性)
        const canWrite = tcpSocket.write(tcpFrame);
        if (!canWrite) {
            // 背压处理: 如果 TCP 写缓冲区满，理论上应该暂停 UDP 接收，
            // 但 dgram 模块不像 Stream 那样容易暂停。
            // 鉴于 UDP 允许丢包，这里我们不做复杂处理，依赖 TCP 自身的缓冲机制。
        }
    });

    udpSocket.on('error', (err) => {
        console.error(`[UDPGW] UDP Socket 错误: ${err.message}`);
        cleanup();
    });

    // --- 3. 生命周期管理 & 错误处理 ---

    function cleanup() {
        if (isClosed) return;
        isClosed = true;
        
        // console.log(`[UDPGW] 客户端断开: ${clientAddr}`);
        
        try {
            udpSocket.close();
        } catch (e) { /* ignore */ }
        
        try {
            tcpSocket.destroy();
        } catch (e) { /* ignore */ }
    }

    tcpSocket.on('error', (err) => {
        // ECONNRESET 是常见的客户端强制断开，不需要打印错误堆栈
        if (err.code !== 'ECONNRESET') {
            console.error(`[UDPGW] TCP 错误 [${clientAddr}]: ${err.message}`);
        }
        cleanup();
    });

    tcpSocket.on('close', () => {
        cleanup();
    });

    tcpSocket.on('timeout', () => {
        cleanup();
    });
    
    // 设置超时 (例如 10 分钟无活动则断开，防止死连接)
    tcpSocket.setTimeout(600000); 
});

// --- 启动服务 ---

server.on('error', (err) => {
    console.error(`[UDPGW] 严重错误: 服务启动失败 - ${err.message}`);
    process.exit(1);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log(`[UDPGW] Native UDPGW 服务已启动`);
    console.log(`[UDPGW] 监听地址: ${LISTEN_HOST}:${LISTEN_PORT}`);
    console.log(`[UDPGW] 模式: Pure Node.js (无 badvpn 依赖)`);
});

// 优雅退出
process.on('SIGINT', () => {
    console.log('\n[UDPGW] 正在停止服务...');
    server.close();
    process.exit(0);
});
