/**
 * Native UDP Gateway (BadVPN Protocol over TCP)
 * Axiom V5.0 Refactor - Built-in replacement for badvpn-udpgw.
 *
 * This server listens on a local TCP port (e.g., 127.0.0.1:7300) and
 * acts as a UDP-over-TCP proxy using the BadVPN protocol framing.
 * It is designed to be decoupled from wss_proxy.js.
 *
 * [Protocol Implementation Details]
 * - Handshake: Simple 'UDPGW01' required on connection start.
 * - Framing: Each UDP packet is prefixed by a 2-byte length field (big-endian).
 * - UDP Socket: A dedicated UDP socket is created for each TCP client.
 */

const net = require('net');
const dgram = require('dgram');
const fs = require('fs');
const path = require('path');

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
const TCP_BUFFER_SIZE = 65536;

// --- 状态管理 ---
let totalConnections = 0;

/**
 * 将 UDP 数据包封装成 BadVPN TCP 帧
 * @param {Buffer} data 原始 UDP 数据
 * @returns {Buffer} 包含 2字节长度前缀的 TCP 帧
 */
function encapsulate(data) {
    // 2-byte length prefix (BadVPN protocol)
    const len = data.length;
    const buffer = Buffer.alloc(2 + len);
    buffer.writeUInt16BE(len, 0); // Big Endian
    data.copy(buffer, 2);
    return buffer;
}

/**
 * 处理 BadVPN 协议的 TCP 客户端连接
 * @param {net.Socket} tcpSocket TCP 连接套接字
 */
function handleClient(tcpSocket) {
    
    totalConnections++;
    const clientId = `${tcpSocket.remoteAddress}:${tcpSocket.remotePort}`;
    console.log(`[UDP_TCP] 新连接 ${clientId}. 当前总数: ${totalConnections}`);
    
    let handshakeComplete = false;
    let tcpBuffer = Buffer.alloc(0);
    let currentPacketLength = 0;
    
    // 为每个 TCP 连接创建一个专用的 UDP socket
    const udpSocket = dgram.createSocket('udp4');
    
    // --- UDP -> TCP 转发逻辑 (Tunneling) ---
    udpSocket.on('message', (msg, rinfo) => {
        // [AXIOM V5.0] 收到目标 UDP 服务的响应
        try {
            const framedData = encapsulate(msg);
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

    udpSocket.on('listening', () => {
        // console.log(`[UDP_SOC] UDP Socket 正在监听 on ${udpSocket.address().port}`);
        // 可以用于发送初始握手数据（如果需要，但BadVPN通常不需要）
    });

    // --- TCP -> UDP 解析逻辑 (De-tunneling) ---
    tcpSocket.on('data', (data) => {
        tcpBuffer = Buffer.concat([tcpBuffer, data]);
        
        // 1. 握手阶段
        if (!handshakeComplete) {
            if (tcpBuffer.length < HANDSHAKE_CODE.length) {
                return; // 缓冲区不足以进行握手
            }
            const receivedHandshake = tcpBuffer.subarray(0, HANDSHAKE_CODE.length);
            if (receivedHandshake.equals(HANDSHAKE_CODE)) {
                handshakeComplete = true;
                tcpBuffer = tcpBuffer.subarray(HANDSHAKE_CODE.length);
                // console.log(`[UDP_TCP ${clientId}] 握手成功。`);
            } else {
                console.warn(`[UDP_TCP ${clientId}] 握手失败。断开连接。`);
                tcpSocket.end();
                return;
            }
        }
        
        // 2. 数据包解析阶段
        while (tcpBuffer.length >= 2) {
            if (currentPacketLength === 0) {
                // 读取下一个数据包的长度
                currentPacketLength = tcpBuffer.readUInt16BE(0);
                
                if (currentPacketLength > MAX_PACKET_SIZE || currentPacketLength <= 0) {
                    console.error(`[UDP_TCP ${clientId}] 无效的包长度: ${currentPacketLength}. 断开连接。`);
                    tcpSocket.end();
                    return;
                }
            }
            
            const requiredLength = 2 + currentPacketLength; // 2字节长度 + 数据长度
            
            if (tcpBuffer.length >= requiredLength) {
                // 成功读取一个完整的帧
                const udpPacket = tcpBuffer.subarray(2, requiredLength);
                
                // [AXIOM V5.0] BadVPN 协议约定：
                // UDP packet = 4 bytes Dest IP + 2 bytes Dest Port + Raw UDP Data
                if (udpPacket.length < 6) {
                    console.warn(`[UDP_TCP ${clientId}] 收到短数据包 (${udpPacket.length} bytes)。跳过。`);
                } else {
                    const destIp = `${udpPacket[0]}.${udpPacket[1]}.${udpPacket[2]}.${udpPacket[3]}`;
                    const destPort = udpPacket.readUInt16BE(4);
                    const rawData = udpPacket.subarray(6);

                    // 转发到目标 UDP 服务 (例如 127.0.0.1:22 for DNS or 127.0.0.1:53)
                    // 注意: BadVPN客户端直接提供最终目标IP和端口，不需要转发到内部SSH/UDPGW端口。
                    // 但通常客户端被配置为仅转发到本地 DNS/代理 (如 10.0.0.1:53)
                    
                    // 为了兼容 BadVPN-UDPGW 的传统用法 (SSH Tunnel作为出口)，我们应该将数据包
                    // 发送到本地 SSHD (例如 127.0.0.1:22) 上的 SOCKS/UDP 代理。
                    // 但 BadVPN 协议本身是点对点且携带目标地址的。
                    // 
                    // 假设客户端发送的目标地址是 **最终目标**。
                    // 客户端通常被配置为发送到 10.0.0.1:53 (VPN DNS) 或 8.8.8.8 (Google DNS)。
                    // 如果 SSHD 隧道端点正在处理这些，我们需要发送到实际的 UDP 服务器。
                    
                    // 转发到目标 IP/Port
                    udpSocket.send(rawData, destPort, destIp, (err) => {
                        if (err) {
                             console.error(`[UDP_SOC] 发送到目标 ${destIp}:${destPort} 失败: ${err.message}`);
                        }
                    });
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
    
    tcpSocket.on('close', () => {
        totalConnections--;
        // console.log(`[UDP_TCP] 连接关闭 ${clientId}. 剩余总数: ${totalConnections}`);
        udpSocket.close(); // 关闭关联的 UDP socket
    });

    tcpSocket.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
             console.error(`[UDP_TCP ${clientId}] TCP Socket 错误: ${err.message}`);
        }
        // 错误发生时，'close' 事件会紧随其后，进行清理。
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
    server.close(() => {
        console.log('[Native_UDPGW] TCP 服务器已关闭。');
        process.exit(0);
    });
});
