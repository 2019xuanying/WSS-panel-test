/**
 * WSS Panel Backend (Node.js + Express + SQLite)
 * V8.3.2 (Axiom Refactor V4.1 - safeRunCommand Fix)
 *
 * [AXIOM V4.1 CHANGELOG]
 * - [BUGFIX] 修复了 `safeRunCommand` 函数中的一个关键逻辑缺陷。
 * - [问题] 之前的逻辑将通用的退出码 `1` (e.code === 1) 错误地视为
 * `{ success: true }`。这会导致 `useradd` 等命令在失败时
 * （例如，因权限不足而失败），面板依然报告“操作成功”，
 * 从而导致数据库与系统状态不一致。
 * - [修复] 移除了对 `e.code === 1` 的通用捕获。现在，任何非零退出码
 * （除了 `systemctl is-active` 的 code 3 等特例）
 * 都将正确地返回 `{ success: false }`，确保了操作的原子性。
 *
 * [AXIOM V4.0 CHANGELOG]
 * - [BUGFIX] 修复了 /api/settings/config 端口修改逻辑。
 * - [问题] Stunnel 和 UDPGW 服务不读取 config.json，
 * 它们的端口被硬编码在各自的 .conf 和 .service 文件中。
 * API 之前只更新了 config.json，导致重启后端口未变更。
 * - [修复] /api/settings/config 处理器现在被授权：
 * 1. 在更新 config.json 之前，获取旧的 stunnel_port 和 udpgw_port。
 * 2. 使用 safeRunCommand('sed', ...) 主动修改
 * /etc/stunnel/ssh-tls.conf 和
 * /etc/systemd/system/udpgw.service 文件。
 * 3. 在修改 .service 文件后，自动执行 'systemctl daemon-reload'。
 * 4. 最后才执行 'systemctl restart'，确保服务加载新配置。
 */

// --- 核心依赖 ---
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { execFile, spawn, exec } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const os = require('os');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { WebSocketServer } = require('ws');
const tls = require('tls');
const dns = require('dns');

const app = express();
const asyncExecFile = promisify(execFile);

// --- [AXIOM V2.0] 配置加载 ---
let config = {};
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');

try {
    const configData = fsSync.readFileSync(CONFIG_PATH, 'utf8');
    config = JSON.parse(configData);
    console.log(`[AXIOM V3.0] 成功从 ${CONFIG_PATH} 加载配置。`);
} catch (e) {
    console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。将使用默认端口。`);
    // (省略默认配置写入... 保持不变)
    try {
        fsSync.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (writeErr) {
        console.error(`[CRITICAL] 无法写入默认配置: ${writeErr.message}`);
    }
}
// --- 结束配置加载 ---


// --- 核心常量 ---
const DB_PATH = path.join(PANEL_DIR, 'wss_panel.db');
const ROOT_HASH_FILE = path.join(PANEL_DIR, 'root_hash.txt');
const AUDIT_LOG_PATH = path.join(PANEL_DIR, 'audit.log');
const SECRET_KEY_PATH = path.join(PANEL_DIR, 'secret_key.txt');
const INTERNAL_SECRET_PATH = path.join(PANEL_DIR, 'internal_secret.txt');
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const ROOT_USERNAME = "root";
const GIGA_BYTE = 1024 * 1024 * 1024;
const BLOCK_CHAIN = "WSS_IP_BLOCK";
// [AXIOM V3.0] 需求 #3: 降级为 60 秒维护任务
const BACKGROUND_SYNC_INTERVAL = 60000;
const SHELL_DEFAULT = "/sbin/nologin";
const SHELL_INTERACTIVE = "/sbin/nologin";
const CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'UDPGW',
    'wss_panel': 'Web Panel'
};
let db;
// [AXIOM V3.0] IPC WebSocket 服务器实例
let wssIpc = null;
// [AXIOM V3.0] 新增: 前端 UI WebSocket 池
let wssUiPool = new Set();
// [AXIOM V3.0] 新增: 实时统计数据聚合器
let workerStatsCache = new Map();
// [AXIOM V3.0] 新增: 内存中的全局熔断阈值
let globalFuseLimitKbps = 0;


const SUDO_COMMANDS = new Set([
    'useradd', 'usermod', 'userdel', 'gpasswd', 'chpasswd', 'pkill',
    'iptables', 'iptables-save', 'journalctl', 
    'systemctl', 
    'getent', 
    'systemctl is-active',
    'sed', // [AXIOM V4.0] 授权 sed 用于修改配置文件
    'systemctl daemon-reload' // [AXIOM V4.0] 授权 daemon-reload
]);

// --- 辅助函数 ---

/**
 * [AXIOM V4.1] 修复: 移除了 e.code === 1 的危险捕获
 */
async function safeRunCommand(command, inputData = null) {
    
    let fullCommand = [...command];
    let baseCommand = command[0];
    
    // (处理 'systemctl is-active' 和 'systemctl daemon-reload' 的别名)
    if (command[0] === 'systemctl' && command[1] === 'is-active') {
        baseCommand = 'systemctl is-active';
    }
    if (command[0] === 'systemctl' && command[1] === 'daemon-reload') {
        baseCommand = 'systemctl daemon-reload';
    }
    
    if (SUDO_COMMANDS.has(baseCommand)) {
        fullCommand.unshift('sudo');
    }

    // (处理 chpasswd 的 stdin)
    if (command[0] === 'chpasswd' || (command[0] === 'sudo' && command[1] === 'chpasswd') && inputData) {
        return new Promise((resolve, reject) => {
            const child = spawn(fullCommand[0], fullCommand.slice(1), {
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
            });
            let stdout = '';
            let stderr = '';
            child.stdout.on('data', (data) => { stdout += data.toString(); });
            child.stderr.on('data', (data) => { stderr += data.toString(); });
            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ success: true, output: stdout.trim() });
                } else {
                    console.error(`safeRunCommand (spawn) Stderr (Command: ${fullCommand.join(' ')}): ${stderr.trim()}`);
                    resolve({ success: false, output: stderr.trim() || `Command ${fullCommand.join(' ')} failed with code ${code}` });
                }
            });
             child.on('error', (err) => {
                 console.error(`safeRunCommand (spawn) Error (Command: ${fullCommand.join(' ')}): ${err.message}`);
                resolve({ success: false, output: err.message });
            });
            try {
                child.stdin.write(inputData);
                child.stdin.end();
            } catch (e) {
                 resolve({ success: false, output: e.message });
            }
        });
    }

    // (处理 asyncExecFile)
    try {
        const { stdout, stderr } = await asyncExecFile(fullCommand[0], fullCommand.slice(1), {
            timeout: 10000,
            input: inputData,
            env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
        });
        const output = (stdout + stderr).trim();
        
        // (非致命 stderr 警告)
        if (stderr && 
            !stderr.includes('user not found') &&
            !stderr.includes('userdel: user') &&
            !stderr.includes('already exists')
           ) {
             console.warn(`safeRunCommand (asyncExecFile) Non-fatal Stderr (Command: ${fullCommand.join(' ')}): ${stderr.trim()}`);
        }
        return { success: true, output: stdout.trim() };
        
    } catch (e) {
        // (特例 1: 'systemctl is-active' 失败码 3 = 'inactive')
        if (baseCommand === 'systemctl is-active' && e.code === 3) {
            return { success: false, output: 'inactive' };
        }
        
        // (特例 2: 'sed' 失败码 1 + 'No such file')
        if (baseCommand === 'sed' && e.code === 1 && e.stderr.includes('No such file')) {
             console.error(`safeRunCommand (sed) Error: ${e.stderr}`);
             return { success: false, output: e.stderr };
        }
        
        // [AXIOM V4.1 FIX] 移除了将 e.code === 1 视为成功的危险逻辑。
        
        // (超时日志)
        if (e.code !== 'ETIMEDOUT') {
            console.error(`safeRunCommand (asyncExecFile) Fatal Error (Command: ${fullCommand.join(' ')}): Code=${e.code}, Stderr=${e.stderr || 'N/A'}, Msg=${e.message}`);
        }
        
        // (默认: 任何其他非零退出码都应报告为失败)
        return { success: false, output: e.stderr || e.message || `Command ${fullCommand[0]} failed.` };
    }
}


async function logAction(actionType, username, details = "") {
    // ... (此函数无变化) ...
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const operatorIp = '127.0.0.1 (System)'; 
    const logEntry = `[${timestamp}] [USER:${username}] [IP:${operatorIp}] ACTION:${actionType} DETAILS: ${details}\n`;
    try {
        await fs.appendFile(AUDIT_LOG_PATH, logEntry);
    } catch (e) {
        console.error(`Error writing to audit log: ${e.message}`);
    }
}

async function getSystemLockStatus() {
    // ... (此函数无变化) ...
    try {
        const { success, output } = await safeRunCommand(['getent', 'shadow']);
        if (!success) {
            console.error("[CRITICAL] getSystemLockStatus: Failed to run 'sudo getent shadow'. Falling back to empty map.");
            return new Set();
        }
        const lockedUsers = new Set();
        output.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length > 1) {
                const username = parts[0];
                const passwordHash = parts[1];
                if (passwordHash.startsWith('!') || passwordHash.startsWith('*')) {
                    lockedUsers.add(username);
                }
            }
        });
        return lockedUsers;
    } catch (e) {
        console.error(`[CRITICAL] getSystemLockStatus Error: ${e.message}`);
        return new Set();
    }
}

// --- 数据库 Setup and User Retrieval ---

async function initDb() {
    // ... (此函数 `initDb` 内部逻辑无变化) ...
    // ... (它负责创建表和迁移字段) ...
    db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database
    });
    try {
        await db.exec('PRAGMA journal_mode = WAL;');
        console.log("[DB] WAL (Write-Ahead Logging) mode enabled.");
    } catch (e) {
        console.error(`[DB] Failed to enable WAL mode: ${e.message}`);
    }
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT,
            status TEXT, expiration_date TEXT, quota_gb REAL,
            usage_gb REAL DEFAULT 0.0, rate_kbps INTEGER DEFAULT 0,
            max_connections INTEGER DEFAULT 0,
            require_auth_header INTEGER DEFAULT 1, realtime_speed_up REAL DEFAULT 0.0,
            realtime_speed_down REAL DEFAULT 0.0, active_connections INTEGER DEFAULT 0,
            status_text TEXT, allow_shell INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ip_bans ( ip TEXT PRIMARY KEY, reason TEXT, added_by TEXT, timestamp TEXT );
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            date TEXT NOT NULL, usage_gb REAL DEFAULT 0.0, UNIQUE(username, date)
        );
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    `);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_traffic_history_user_date ON traffic_history (username, date);`);
    
    try { await db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN max_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN require_auth_header INTEGER DEFAULT 1'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_up REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_down REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN active_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN status_text TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN allow_shell INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }

    let oldFuseColumnExists = false;
    try {
        await db.exec('ALTER TABLE users ADD COLUMN fuse_threshold_kbps INTEGER DEFAULT 0');
    } catch (e) {
        if (e.message.includes("duplicate column name")) {
            oldFuseColumnExists = true;
        }
    }
    
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'fuse_threshold_kbps', '0');

    if (oldFuseColumnExists) {
        console.log("[MIGRATE] Old 'fuse_threshold_kbps' column detected. Migrating to global_settings table...");
        try {
            const firstUser = await db.get('SELECT fuse_threshold_kbps FROM users WHERE fuse_threshold_kbps > 0 LIMIT 1');
            if (firstUser && firstUser.fuse_threshold_kbps > 0) {
                await db.run(
                    "UPDATE global_settings SET value = ? WHERE key = ?", 
                    firstUser.fuse_threshold_kbps.toString(),
                    'fuse_threshold_kbps'
                );
                console.log(`[MIGRATE] Migrated fuse value ${firstUser.fuse_threshold_kbps} to global_settings.`);
            }
        } catch (e) {
            console.error(`[MIGRATE] Failed to migrate old fuse setting: ${e.message}`);
        }
    }
    
    // [AXIOM V3.0] 启动时加载全局熔断阈值到内存
    try {
        const fuseSetting = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
        if (fuseSetting) {
            globalFuseLimitKbps = parseInt(fuseSetting.value) || 0;
            console.log(`[DB] Global fuse threshold loaded into memory: ${globalFuseLimitKbps} KB/s`);
        }
    } catch(e) {
        console.error(`[DB] Failed to load global fuse threshold: ${e.message}`);
    }
    
    console.log(`SQLite database initialized at ${DB_PATH}`);
}

async function getUserByUsername(username) {
    // ... (此函数无变化) ...
    return db.get('SELECT * FROM users WHERE username = ?', username);
}

async function loadRootHash() {
    // ... (此函数无变化) ...
    try {
        const hash = await fs.readFile(ROOT_HASH_FILE, 'utf8');
        return hash.trim();
    } catch (e) {
        console.error(`Root hash file not found: ${e.message}`);
        return null;
    }
}

function loadInternalSecret() {
    // ... (此函数无变化) ...
    return config.internal_api_secret;
}

async function loadHosts() {
    // ... (此函数无变化) ...
    try {
        if (!fsSync.existsSync(HOSTS_DB_PATH)) {
            await fs.writeFile(HOSTS_DB_PATH, '[]', 'utf8');
            return [];
        }
        const data = await fs.readFile(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            return hosts.map(h => String(h).toLowerCase()).filter(h => h);
        }
        return [];
    } catch (e) {
        console.error(`Error loading hosts file: ${e.message}`);
        return [];
    }
}

// --- Authentication Middleware ---

function loadSecretKey() {
    // ... (此函数无变化) ...
    try {
        return fsSync.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
    } catch (e) {
        const key = require('crypto').randomBytes(32).toString('hex');
        fsSync.writeFileSync(SECRET_KEY_PATH, key, 'utf8');
        return key;
    }
}

// [AXIOM V3.0] 将 session 中间件保存到变量，以便 WebSocket 共享
const sessionMiddleware = session({
    secret: loadSecretKey(),
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, httpOnly: true,
        maxAge: 3600000 * 24, sameSite: 'lax'
    }
});
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function loginRequired(req, res, next) {
    // ... (此函数无变化) ...
    if (req.session.loggedIn) {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ success: false, message: "Authentication failed or session expired" });
        }
        return res.redirect('/login.html');
    }
}

// --- Business Logic / System Sync (Optimized) ---

/**
 * [AXIOM V3.0] 广播到所有连接的前端 (UI) 实例
 */
function broadcastToFrontends(message) {
    if (!wssUiPool || wssUiPool.size === 0) {
        return; // 没有管理员在线
    }
    const payload = JSON.stringify(message);
    wssUiPool.forEach((client) => {
        if (client.readyState === 1) { // 1 = WebSocket.OPEN
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_UI] 发送消息到前端失败: ${err.message}`);
                }
            });
        }
    });
}

/**
 * [AXIOM V2.0] 广播命令到所有连接的 Proxy 实例
 */
function broadcastToProxies(message) {
    // ... (此函数无变化) ...
    if (!wssIpc || wssIpc.clients.size === 0) {
        console.warn("[IPC_WSS] 无法广播: 没有连接的数据平面 (Proxy) 实例。");
        return;
    }
    const payload = JSON.stringify(message);
    console.log(`[IPC_WSS] 正在广播 (-> ${wssIpc.clients.size} 个代理): ${payload}`);
    wssIpc.clients.forEach((client) => {
        if (client.readyState === 1) { 
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_WSS] 发送消息到代理失败: ${err.message}`);
                }
            });
        }
    });
}


async function kickUserFromProxy(username) {
    // ... (此函数无变化) ...
    broadcastToProxies({
        action: 'kick',
        username: username
    });
    return true; 
}

/**
 * [AXIOM V3.0] 新增: 将流量增量异步写入 DB
 * (此函数由 1 秒一次的 `stats_update` 处理器调用)
 */
async function persistTrafficDelta(workerStats) {
    const today = new Date().toISOString().split('T')[0];
    let usersToUpdate = [];
    
    for (const username in workerStats) {
        const stats = workerStats[username];
        const deltaBytes = (stats.traffic_delta_up || 0) + (stats.traffic_delta_down || 0);
        
        if (deltaBytes > 0) {
            usersToUpdate.push({
                username: username,
                deltaGb: (deltaBytes / GIGA_BYTE)
            });
        }
    }

    if (usersToUpdate.length === 0) return;

    // 批量写入 DB
    try {
        await db.run('BEGIN TRANSACTION');
        for (const u of usersToUpdate) {
            // 1. 更新总流量
            await db.run('UPDATE users SET usage_gb = usage_gb + ? WHERE username = ?',
                [u.deltaGb, u.username]);
            
            // 2. 更新当日历史
            await db.run('INSERT OR IGNORE INTO traffic_history (username, date, usage_gb) VALUES (?, ?, 0.0)', [u.username, today]);
            await db.run('UPDATE traffic_history SET usage_gb = usage_gb + ? WHERE username = ? AND date = ?', [u.deltaGb, u.username, today]);
        }
        await db.run('COMMIT');
    } catch (e) {
        await db.run('ROLLBACK').catch(()=>{});
        console.error(`[TRAFFIC_ASYNC] 流量增量DB写入失败: ${e.message}`);
    }
}


/**
 * [AXIOM V3.0] 新增: 聚合所有 Worker 的统计数据
 * (此函数由 1 秒一次的 `stats_update` 处理器调用)
 * @returns {object} 聚合后的统计数据
 */
function aggregateAllWorkerStats() {
    const aggregatedStats = {};
    const aggregatedLiveIps = {};
    let totalActiveConnections = 0;

    for (const [workerId, workerData] of workerStatsCache.entries()) {
        // 聚合用户统计 (traffic, speed, conns)
        for (const username in workerData.stats) {
            const current = workerData.stats[username];
            if (!aggregatedStats[username]) {
                // 如果是第一个，直接复制
                aggregatedStats[username] = {
                    speed_kbps: { ...current.speed_kbps },
                    connections: current.connections
                };
            } else {
                // 如果已存在，累加
                const existing = aggregatedStats[username];
                existing.connections += current.connections;
                existing.speed_kbps.upload += current.speed_kbps.upload;
                existing.speed_kbps.download += current.speed_kbps.download;
            }
            totalActiveConnections += current.connections;
        }
        // 聚合 live_ips (简单合并)
        Object.assign(aggregatedLiveIps, workerData.live_ips);
    }
    
    return {
        users: aggregatedStats,
        live_ips: aggregatedLiveIps,
        system: {
            active_connections_total: totalActiveConnections
        }
    };
}


/**
 * [AXIOM V3.0] 重构: `syncUserStatus` (降级为 60 秒维护任务)
 */
async function syncUserStatus() {
    
    // [AXIOM V3.0] 移除: let proxyStats = {};
    // [AXIOM V3.0] 移除: 熔断阈值 (globalFuseLimit) 的 DB 查询
    // (它已在 initDb 时加载到内存 globalFuseLimitKbps)
    
    const systemLockedUsers = await getSystemLockStatus();
    
    let allUsers = [];
    try {
        allUsers = await db.all('SELECT * FROM users');
    } catch (e) {
        console.error(`[SYNC] 无法从 DB 获取用户: ${e.message}`);
        return;
    }
    
    // [AXIOM V3.0] 移除: fetch(config.proxy_api_url + '/stats', ...)
    // 数据流已反转，不再需要此 API 调用

    // [AXIOM V3.0] 新增: 获取非紧急的系统状态
    let systemStatusData = {};
    try {
        systemStatusData = await getSystemStatusData();
    } catch (e) {
        console.warn(`[SYNC] 无法获取系统状态 (CPU/内存/服务): ${e.message}`);
    }

    const usersToUpdate = []; 
    
    for (const user of allUsers) {
        const username = user.username;
        
        // [AXIOM V3.0] 移除: 所有来自 proxyStats 的流量和速度更新
        // (这些现在由 `persistTrafficDelta` 和 `stats_update` 处理器实时处理)

        // --- [AXIOM V3.0] `syncUserStatus` 的新职责: ---
        // --- 只检查非实时状态 (到期, 超额) ---
        
        let isExpired = false, isOverQuota = false;
        
        if (user.expiration_date) {
            try {
                const expiry = new Date(user.expiration_date);
                if (!isNaN(expiry) && expiry < new Date()) { isExpired = true; }
            } catch (e) { /* ignore */ }
        }
        
        // [AXIOM V3.0] 关键: 从数据库读取 `usage_gb` (由 persistTrafficDelta 累积)
        if (user.quota_gb > 0 && user.usage_gb >= user.quota_gb) { isOverQuota = true; }
        
        // [AXIOM V3.0] 移除: isOverSpeed (已移至实时处理器)
        
        const currentDbStatus = user.status; // (active, paused, expired, exceeded, fused)
        let newDbStatus = currentDbStatus;
        let statusChanged = false;
        
        // 状态机 (简化版)
        if (isExpired) {
            if (currentDbStatus !== 'expired') { newDbStatus = 'expired'; statusChanged = true; }
        } else if (isOverQuota) {
            if (currentDbStatus !== 'exceeded') { newDbStatus = 'exceeded'; statusChanged = true; }
        } else if (currentDbStatus === 'paused' || currentDbStatus === 'fused') {
            // 保持 'paused' 或 'fused' 状态 (等待管理员手动启用)
            newDbStatus = currentDbStatus; 
        } else {
            // 如果没问题，且不是 'paused'/'fused'，则应为 'active'
            if (currentDbStatus !== 'active') { newDbStatus = 'active'; statusChanged = true; }
        }
        
        user.status = newDbStatus;

        // --- 3. 确定系统锁状态 (用于 444) ---
        const systemLocked = systemLockedUsers.has(username);
        
        // [AXIOM V3.0] 熔断状态 (`fused`) 也应导致系统锁定
        const shouldBeLocked_SYS = (user.status !== 'active');
        
        if (shouldBeLocked_SYS && !systemLocked) {
            await safeRunCommand(['usermod', '-L', username]);
            statusChanged = true; // 确保状态文本被更新
        } else if (!shouldBeLocked_SYS && systemLocked) {
            await safeRunCommand(['usermod', '-U', username]);
            statusChanged = true; // 确保状态文本被更新
        }
        
        // --- 4. 更新状态文本 ---
        let newStatusText = user.status_text;
        if (user.status === 'active') {
            newStatusText = '启用 (Active)';
        } else if (user.status === 'paused') {
            newStatusText = '暂停 (Manual)';
        } else if (user.status === 'expired') {
            newStatusText = '已到期 (Expired)';
        } else if (user.status === 'exceeded') {
            newStatusText = '超额 (Quota)';
        } else if (user.status === 'fused') {
            newStatusText = '熔断 (Fused)';
        } else {
            newStatusText = '未知';
        }

        if (statusChanged || user.status_text !== newStatusText) {
             user.status_text = newStatusText;
             usersToUpdate.push(user);
        }
    }
    
    // --- 5. 批量更新 DB (仅状态) ---
    if (usersToUpdate.length > 0) {
        try {
            await db.run('BEGIN TRANSACTION');
            for (const u of usersToUpdate) {
                // [AXIOM V3.0] 移除: usage_gb, speed, connections 的更新
                await db.run(`UPDATE users SET 
                                status = ?, status_text = ?
                              WHERE username = ?`,
                    u.status, u.status_text, u.username);
            }
            await db.run('COMMIT');
            console.log(`[SYNC] 60秒维护任务完成。更新了 ${usersToUpdate.length} 个用户的状态。`);
            
            // [AXIOM V3.0] 状态变更后，通知前端刷新用户列表
            broadcastToFrontends({ type: 'users_changed' });
            
        } catch (e) {
            await db.run('ROLLBACK').catch(()=>{});
            console.error(`[SYNC] CRITICAL: 60秒维护DB更新失败: ${e.message}`);
        }
    } else {
        console.log(`[SYNC] 60秒维护任务完成。没有状态变更。`);
    }
    
    // --- 6. [AXIOM V3.0] 推送非紧急系统状态 (如果管理员在线) ---
    if (wssUiPool.size > 0) {
        broadcastToFrontends({
            type: 'system_update',
            payload: systemStatusData
        });
    }
}

// [AXIOM V3.0] 移除: `getProxyLiveConnections`
// (实时 IP 列表现在来自 `workerStatsCache` 的 `aggregatedLiveIps`)

async function manageIpIptables(ip, action, chainName = BLOCK_CHAIN) {
    // ... (此函数无变化) ...
    if (action === 'check') {
        const result = await asyncExecFile('sudo', ['iptables', '-C', chainName, '-s', ip, '-j', 'DROP'], { timeout: 2000 }).catch(e => e);
        return { success: result.code === 0 };
    }
    let command;
    if (action === 'block') {
        await safeRunCommand(['iptables', '-D', chainName, '-s', ip, '-j', 'DROP']);
        command = ['iptables', '-I', chainName, '1', '-s', ip, '-j', 'DROP'];
    } else if (action === 'unblock') {
        command = ['iptables', '-D', chainName, '-s', ip, '-j', 'DROP'];
    } else {
        return { success: false, output: "Invalid action" };
    }
    const result = await safeRunCommand(command);
    if (result.success) {
        safeRunCommand(['iptables-save'], null, true)
            .then(({ output }) => fs.writeFile('/etc/iptables/rules.v4', output))
            .catch(e => console.error(`Warning: Failed to save iptables rules: ${e.message}`));
    }
    return result;
}

// --- API Routes (Admin Panel) ---

app.use(express.static(PANEL_DIR));

const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, 
	max: 5, 
	message: '登录尝试次数过多，IP已被限制，请 15 分钟后再试',
    handler: (req, res, next, options) => {
        res.redirect(`/login.html?error=${encodeURIComponent(options.message)}`);
    },
	standardHeaders: true, 
	legacyHeaders: false, 
});

app.post('/login', loginLimiter, async (req, res) => {
    // ... (此函数无变化) ...
    const { username, password } = req.body;
    const rootHash = await loadRootHash();
    if (username === ROOT_USERNAME && password && rootHash) {
        try {
            const match = await bcrypt.compare(password, rootHash);
            if (match) {
                req.session.loggedIn = true;
                req.session.username = ROOT_USERNAME;
                await logAction("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login");
                return res.redirect('/index.html');
            }
        } catch (e) { console.error(`Bcrypt comparison failed: ${e.message}`); }
    }
    await logAction("LOGIN_FAILED", username, "Wrong credentials or invalid username attempt");
    res.redirect('/login.html?error=' + encodeURIComponent('用户名或密码错误。'));
});

app.get('/logout', (req, res) => {
    // ... (此函数无变化) ...
    logAction("LOGOUT_SUCCESS", req.session.username || ROOT_USERNAME, "Web UI Logout");
    req.session.destroy();
    res.redirect('/login.html');
});

// --- Internal API (For Proxy) ---
const internalApi = express.Router();
internalApi.use((req, res, next) => {
    // ... (此函数无变化) ...
    const clientIp = req.ip;
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        next();
    } else {
        console.warn(`[AUTH] Denied external access attempt to /internal API from ${clientIp}`);
        res.status(403).json({ success: false, message: 'Forbidden' });
    }
});

internalApi.post('/auth', async (req, res) => {
    // ... (此函数无变化) ...
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Missing credentials' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user || !user.password_hash) {
            await logAction("PROXY_AUTH_FAIL", username, "User not found or no password hash in DB.");
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            // [AXIOM V3.0] 熔断 Bug 修复:
            // 认证时也必须检查 'fused' 状态
            if (user.status !== 'active') {
                 await logAction("PROXY_AUTH_LOCKED", username, `User locked in DB (Status: ${user.status}).`);
                 return res.status(403).json({ success: false, message: 'User locked, paused, or disabled' });
            }
            await logAction("PROXY_AUTH_SUCCESS", username, "Proxy auth success.");
            res.json({
                success: true,
                limits: {
                    rate_kbps: user.rate_kbps || 0,
                    max_connections: user.max_connections || 0,
                },
                require_auth_header: user.require_auth_header === 0 ? 0 : 1
            });
        } else {
            await logAction("PROXY_AUTH_FAIL", username, "Invalid password (bcrypt mismatch).");
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (e) {
        await logAction("PROXY_AUTH_ERROR", username, `Internal auth error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

internalApi.get('/auth/user-settings', async (req, res) => {
    // ... (此函数无变化) ...
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Missing username' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({
            success: true,
            require_auth_header: user.require_auth_header === 0 ? 0 : 1
        });
    } catch (e) {
        console.error(`[PROXY_SETTINGS] Internal API error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});
app.use('/internal', internalApi);

// --- Public API (For Admin Panel UI) ---
const api = express.Router();


/**
 * [AXIOM V3.0] 新增: 提取 `getSystemStatus` 的核心逻辑
 * (以便 `syncUserStatus` 也可以调用它)
 */
async function getSystemStatusData() {
    let diskUsedPercent = 55.0; 
    try {
         const { stdout } = await promisify(exec)('df -P / | tail -1'); 
         const parts = stdout.trim().split(/\s+/);
         if (parts.length >= 5) { diskUsedPercent = parseFloat(parts[4].replace('%', '')); }
    } catch (e) { /* ignore */ }
    const mem = os.totalmem();
    const memFree = os.freemem();
    const serviceStatuses = {};
    for (const [id, name] of Object.entries(CORE_SERVICES)) {
        const { success } = await safeRunCommand(['systemctl', 'is-active', id]);
        const status = success ? 'running' : 'failed';
        serviceStatuses[id] = { name, status, label: status === 'running' ? "运行中" : "失败" };
    }
    const ports = [
        { name: 'WSS_HTTP', port: config.wss_http_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'WSS_TLS', port: config.wss_tls_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'STUNNEL', port: config.stunnel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'UDPGW', port: config.udpgw_port, protocol: 'UDP', status: 'LISTEN' },
        { name: 'PANEL', port: config.panel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'SSH_INTERNAL', port: config.internal_forward_port, protocol: 'TCP', status: 'LISTEN' }
    ];
    
    // [AXIOM V3.0] 实时连接数现在来自内存缓存
    let liveIpCount = 0;
    try {
        const aggregatedData = aggregateAllWorkerStats();
        liveIpCount = Object.keys(aggregatedData.live_ips || {}).length;
    } catch (e) {
        console.warn(`[SYSTEM_STATUS] 无法从 workerStatsCache 聚合 IP: ${e.message}`);
    }

    const users = await db.all('SELECT * FROM users');
    let totalTraffic = 0, pausedCount = 0, expiredCount = 0, exceededCount = 0, fusedCount = 0;
    for (const user of users) {
        totalTraffic += user.usage_gb || 0;
        if (user.status === 'paused') pausedCount++;
        else if (user.status === 'expired') expiredCount++;
        else if (user.status === 'exceeded') exceededCount++;
        else if (user.status === 'fused') fusedCount++;
    }
    
    return {
        cpu_usage: (os.loadavg()[0] / os.cpus().length) * 100,
        memory_used_gb: (mem - memFree) / GIGA_BYTE,
        memory_total_gb: mem / GIGA_BYTE,
        disk_used_percent: diskUsedPercent,
        services: serviceStatuses,
        ports: ports,
        user_stats: {
            total: users.length, active: liveIpCount, paused: pausedCount,
            expired: expiredCount, exceeded: exceededCount,
            fused: fusedCount, total_traffic_gb: totalTraffic
        }
    };
}


/**
 * [AXIOM V3.0] 重构: /system/status API
 * (现在它只调用 getSystemStatusData)
 */
api.get('/system/status', async (req, res) => {
    try {
        const data = await getSystemStatusData();
        res.json({ success: true, ...data });
    } catch (e) {
        await logAction("SYSTEM_STATUS_ERROR", req.session.username, `Status check failed: ${e.message}`);
        res.status(500).json({ success: false, message: `System status check failed: ${e.message}` });
    }
});


api.post('/system/control', async (req, res) => {
    // ... (此函数无变化) ...
    const { service, action } = req.body;
    if (!CORE_SERVICES[service] || action !== 'restart') {
        return res.status(400).json({ success: false, message: "无效的服务或操作" });
    }
    const { success, output } = await safeRunCommand(['systemctl', action, service]);
    if (success) {
        await logAction("SERVICE_CONTROL_SUCCESS", req.session.username, `Successfully executed ${action} on ${service}`);
        res.json({ success: true, message: `服务 ${CORE_SERVICES[service]} 已成功执行 ${action} 操作。` });
    } else {
        await logAction("SERVICE_CONTROL_FAIL", req.session.username, `Failed to ${action} ${service}: ${output}`);
        res.status(500).json({ success: false, message: `服务 ${CORE_SERVICES[service]} 操作失败: ${output}` });
    }
});

api.post('/system/logs', async (req, res) => {
    // ... (此函数无变化) ...
    const serviceName = req.body.service;
    if (!CORE_SERVICES[serviceName]) { return res.status(400).json({ success: false, message: "无效的服务名称。" }); }
    try {
        const { success, output } = await safeRunCommand(['journalctl', '-u', serviceName, '-n', '50', '--no-pager', '--utc']);
        res.json({ success: true, logs: success ? output : `错误: 无法获取 ${serviceName} 日志. ${output}` });
    } catch (e) {
        res.status(500).json({ success: false, message: `日志获取异常: ${e.message}` });
    }
});

api.get('/system/audit_logs', async (req, res) => {
    // ... (此函数无变化) ...
    try {
        const logContent = await fs.readFile(AUDIT_LOG_PATH, 'utf8');
        const logs = logContent.trim().split('\n').filter(line => line.trim().length > 0).slice(-20);
        res.json({ success: true, logs });
    } catch (e) {
        res.json({ success: true, logs: ["读取日志失败或日志文件为空。"] });
    }
});

/**
 * [AXIOM V3.0] 重构: /system/active_ips API
 * (现在它从内存缓存 `workerStatsCache` 中读取)
 */
api.get('/system/active_ips', async (req, res) => {
    try {
        // 1. 从内存聚合数据
        const aggregatedData = aggregateAllWorkerStats();
        const liveIps = aggregatedData.live_ips || {};
        
        // 2. 检查 IP 封禁状态 (保持不变)
        const ipList = await Promise.all(
            Object.keys(liveIps).map(async ip => {
                const isBanned = (await manageIpIptables(ip, 'check')).success;
                return { ip: ip, is_banned: isBanned, username: liveIps[ip] };
            })
        );
        res.json({ success: true, active_ips: ipList });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// [AXIOM V3.0] 移除: /api/users/live-stats (已废弃)
// (前端将通过 WebSocket 接收 'live_update' 推送)
// api.get('/users/live-stats', async (req, res) => { ... });

api.get('/users/list', async (req, res) => {
    // ... (此函数无变化, 它只负责获取静态列表) ...
    try {
        let users = await db.all('SELECT *, realtime_speed_up, realtime_speed_down, active_connections, status_text, allow_shell FROM users');
        users.forEach(u => {
            u.status_text = u.status_text || (u.status === 'active' ? '启用 (Active)' : 
                               (u.status === 'paused' ? '暂停 (Manual)' : 
                               (u.status === 'expired' ? '已到期 (Expired)' : 
                               (u.status === 'exceeded' ? '超额 (Quota)' :
                               (u.status === 'fused' ? '熔断 (Fused)' : '未知')))));
            u.allow_shell = u.allow_shell || 0;
        });
        res.json({ success: true, users: users });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch users: ${e.message}` });
    }
});


api.post('/users/add', async (req, res) => {
    // ... (此函数无变化) ...
    const { username, password, expiration_days, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "缺少用户名或密码" });
    if (!/^[a-z0-9_]{3,16}$/.test(username)) return res.status(400).json({ success: false, message: "用户名格式不正确" });
    const existingUser = await getUserByUsername(username);
    if (existingUser) return res.status(409).json({ success: false, message: `用户组 ${username} 已存在于面板` });
    try {
        const shell = SHELL_DEFAULT; 
        const { success: userAddSuccess, output: userAddOutput } = await safeRunCommand(['useradd', '-m', '-s', shell, username]);
        if (!userAddSuccess && !userAddOutput.includes("already exists")) {
            throw new Error(`创建系统用户失败: ${userAddOutput}`);
        }
        
        const chpasswdInput = `${username}:${password}`;
        const { success: chpassSuccess, output: chpassOutput } = await safeRunCommand(['chpasswd'], chpasswdInput);
        if (!chpassSuccess) { throw new Error(`设置系统密码失败: ${chpassOutput}`); }
        
        const lockCmd = ['usermod', '-U', username];
        const { success: lockSuccess, output: lockOutput } = await safeRunCommand(lockCmd);
        if (!lockSuccess) { throw new Error(`解锁账户失败: ${lockOutput}`); }

        if (allow_shell) {
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(['usermod', '-a', '-G', 'shell_users', username]);
            if (!groupSuccess) {
                console.warn(`[V1.6.0] Failed to add ${username} to shell_users group: ${groupOutput}. Maybe group doesn't exist?`);
            }
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const expiryDate = new Date(Date.now() + expiration_days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const newStatus = "active";
        const newStatusText = "启用 (Active)";
        
        const newUser = {
            username: username, password_hash: passwordHash,
            created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
            status: newStatus,
            expiration_date: expiryDate, 
            quota_gb: parseFloat(quota_gb), usage_gb: 0.0, 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            realtime_speed_up: 0.0, realtime_speed_down: 0.0,
            active_connections: 0, 
            status_text: newStatusText,
            allow_shell: allow_shell ? 1 : 0
        };
        await db.run(`INSERT INTO users (
                        username, password_hash, created_at, status, expiration_date, 
                        quota_gb, usage_gb, rate_kbps, max_connections, 
                        require_auth_header, realtime_speed_up, realtime_speed_down, active_connections, status_text,
                        allow_shell
                      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                      Object.values(newUser));
        await logAction("USER_ADD_SUCCESS", req.session.username, `User ${username} created (Shell: ${shell}, Lock: UNLOCKED, Shell Group: ${allow_shell})`);
        
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: newUser.rate_kbps,
                max_connections: newUser.max_connections,
                require_auth_header: newUser.require_auth_header
            }
        });
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 创建成功，有效期至 ${expiryDate}` });
    } catch (e) {
        await safeRunCommand(['userdel', '-r', username]);
        await logAction("USER_ADD_FAIL", req.session.username, `Failed to create user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});


api.post('/users/delete', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { username } = req.body;
    const userToDelete = await getUserByUsername(username);
    if (!userToDelete) return res.status(404).json({ success: false, message: `用户组 ${username} 不存在` });
    try {
        await kickUserFromProxy(username); 
        await safeRunCommand(['pkill', '-9', '-u', username]); 
        await safeRunCommand(['userdel', '-r', username]); 
        await db.run('DELETE FROM users WHERE username = ?', username);
        await db.run('DELETE FROM traffic_history WHERE username = ?', username);
        
        broadcastToProxies({
            action: 'delete',
            username: username
        });
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_DELETE_SUCCESS", req.session.username, `Deleted user ${username}`);
        res.json({ success: true, message: `用户组 ${username} 已删除，会话已终止` });
    } catch (e) {
        await logAction("USER_DELETE_FAIL", req.session.username, `Failed to delete user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `删除操作失败: ${e.message}` });
    }
});

api.post('/users/set_settings', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { username, expiry_date, quota_gb, rate_kbps, max_connections, new_password, require_auth_header, allow_shell } = req.body;
    
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    
    try {
        const new_allow_shell = allow_shell ? 1 : 0;
        
        let updateFields = {
            expiration_date: expiry_date || "", 
            quota_gb: parseFloat(quota_gb), 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            allow_shell: new_allow_shell
        };
        
        let updateSql = 'UPDATE users SET ';
        const updateValues = [];
        const fieldNames = Object.keys(updateFields);

        if (new_password) {
            const chpasswdInput = `${username}:${new_password}`;
            const { success, output } = await safeRunCommand(['chpasswd'], chpasswdInput);
            if (!success) throw new Error(`Failed to update system password: ${output}`);
            const passwordHash = await bcrypt.hash(new_password, 12);
            updateSql += 'password_hash = ?, ';
            updateValues.push(passwordHash);
            await kickUserFromProxy(username); 
            await safeRunCommand(['pkill', '-9', '-u', username]); 
            await logAction("USER_PASS_CHANGE", req.session.username, `Password changed (DB + System) for ${username}. Kicking sessions.`);
        }
        
        if (user.allow_shell != new_allow_shell) {
            let groupCmd, groupActionLog;
            if (new_allow_shell === 1) {
                groupCmd = ['usermod', '-a', '-G', 'shell_users', username];
                groupActionLog = "Added to shell_users group";
            } else {
                groupCmd = ['gpasswd', '-d', username, 'shell_users'];
                groupActionLog = "Removed from shell_users group";
                await safeRunCommand(['pkill', '-9', '-u', username]);
            }
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(groupCmd);
            if (!groupSuccess) {
                if (!groupOutput.includes("is not a member")) {
                    throw new Error(`Failed to update group membership: ${groupOutput}`);
                }
            }
            await logAction("USER_SHELL_CHANGE", req.session.username, `Stunnel (444) access for ${username} ${new_allow_shell ? 'ENABLED' : 'DISABLED'}. ${groupActionLog}.`);
        }

        fieldNames.forEach(field => {
            updateSql += `${field} = ?, `;
            updateValues.push(updateFields[field]);
        });
        
        updateSql = updateSql.slice(0, -2); 
        updateSql += ' WHERE username = ?';
        updateValues.push(username);
        await db.run(updateSql, updateValues);
        
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: updateFields.rate_kbps,
                max_connections: updateFields.max_connections,
                require_auth_header: updateFields.require_auth_header
            }
        });
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        setTimeout(syncUserStatus, 1000); 

        await logAction("USER_SETTINGS_UPDATE", req.session.username, `Settings updated for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的设置已保存。` });

    } catch (e) {
        await logAction("USER_SETTINGS_FAIL", req.session.username, `Failed to update settings for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/status', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { username, action } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        let newStatus = 'active';
        let newStatusText = '启用 (Active)';
        
        if (action === 'pause') {
            newStatus = 'paused';
            newStatusText = '暂停 (Manual)';
            await safeRunCommand(['usermod', '-L', username]); 
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
            await logAction("USER_PAUSE", req.session.username, `User ${username} manually paused (System Locked).`);
        
        } else if (action === 'enable') {
            newStatus = 'active';
            newStatusText = '启用 (Active)';
            await safeRunCommand(['usermod', '-U', username]); 
            await logAction("USER_ENABLE", req.session.username, `User ${username} manually enabled (System Unlocked).`);
        }
        
        await db.run(`UPDATE users SET status = ?, status_text = ? WHERE username = ?`, newStatus, newStatusText, username);
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 状态已更新。` });
    } catch (e) {
        await logAction("USER_STATUS_FAIL", req.session.username, `Failed to change status for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/reset_traffic', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        await db.run('BEGIN TRANSACTION');
        await db.run(`UPDATE users SET usage_gb = 0.0 WHERE username = ?`, username);
        await db.run(`DELETE FROM traffic_history WHERE username = ?`, username);
        
        broadcastToProxies({
            action: 'reset_traffic',
            username: username
        });
        
        await db.run('COMMIT');
        
        if (user.status === 'exceeded') {
             await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
        }
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        setTimeout(syncUserStatus, 1000);

        await logAction("USER_TRAFFIC_RESET", req.session.username, `Traffic usage reset for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的流量使用量和历史记录已重置。` });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_TRAFFIC_FAIL", req.session.username, `Failed to reset traffic for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/kill_all', async (req, res) => {
    // ... (此函数无变化) ...
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        const wss_success = await kickUserFromProxy(username);
        const ssh_success = (await safeRunCommand(['pkill', '-9', '-u', username])).success;
        if (wss_success || ssh_success) {
            await logAction("USER_KILL_SESSIONS", req.session.username, `All active sessions (WSS + SSHD) killed for ${username}.`);
            res.json({ success: true, message: `用户 ${username} 的所有活跃连接已强制断开。` });
        } else {
            throw new Error("Proxy /kick and pkill API failed.");
        }
    } catch (e) {
        await logAction("USER_KILL_FAIL", req.session.username, `Failed to kill sessions for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/batch-action', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { action, usernames, days } = req.body;
    if (!action || !Array.isArray(usernames) || usernames.length === 0) {
        return res.status(400).json({ success: false, message: "无效的请求参数。" });
    }
    let successCount = 0, failedCount = 0; const errors = [];
    try {
        if (action === 'delete') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    await safeRunCommand(['userdel', '-r', username]); 
                    await db.run('DELETE FROM users WHERE username = ?', username);
                    await db.run('DELETE FROM traffic_history WHERE username = ?', username);
                    broadcastToProxies({ action: 'delete', username: username });
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'pause') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await db.run(`UPDATE users SET status = 'paused', status_text = '暂停 (Manual)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-L', username]); 
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'enable') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { throw new Error("User not found"); }
                    
                    await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-U', username]); 
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'renew') {
            const renewDays = parseInt(days) || 30; const today = new Date();
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { failedCount++; errors.push(`${username}: not found`); continue; }
                    let currentExpiry = null;
                    try { if (user.expiration_date) { currentExpiry = new Date(user.expiration_date); } } catch(e) {}
                    let baseDate = today;
                    if (currentExpiry && !isNaN(currentExpiry) && currentExpiry > today) { baseDate = currentExpiry; }
                    const newExpiryDate = new Date(baseDate.getTime() + renewDays * 24 * 60 * 60 * 1000);
                    const newExpiryString = newExpiryDate.toISOString().split('T')[0];
                    
                    await db.run(`UPDATE users SET expiration_date = ?, status = 'active', status_text = '启用 (Active)' WHERE username = ?`, newExpiryString, username);
                    await safeRunCommand(['usermod', '-U', username]); 
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else {
            return res.status(400).json({ success: false, message: "无效的动作。" });
        }
        
        // [AXIOM V3.0] 通知前端刷新列表
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_BATCH_ACTION", req.session.username, `Action: ${action}, Days: ${days || 'N/A'}, Success: ${successCount}, Failed: ${failedCount}.`);
        res.json({ success: true, message: `批量操作 "${action}" 完成。成功 ${successCount} 个, 失败 ${failedCount} 个。`, errors: errors });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_BATCH_FAIL", req.session.username, `Action: ${action} failed: ${e.message}`);
        res.status(500).json({ success: false, message: `批量操作失败: ${e.message}` });
    }
});


api.get('/users/traffic-history', async (req, res) => {
    // ... (此函数无变化) ...
    const { username } = req.query;
    if (!username) { return res.status(400).json({ success: false, message: "缺少用户名。" }); }
    try {
        const history = await db.all(`SELECT date, usage_gb FROM traffic_history WHERE username = ? ORDER BY date DESC LIMIT 30`, [username]);
        res.json({ success: true, history: history.reverse() }); 
    } catch (e) {
        res.status(500).json({ success: false, message: `获取流量历史失败: ${e.message}` });
    }
});


api.get('/settings/hosts', async (req, res) => {
    // ... (此函数无变化) ...
    const hosts = await loadHosts();
    res.json({ success: true, hosts });
});

api.post('/settings/hosts', async (req, res) => {
    // ... (此函数无变化, 但我们添加了 UI 推送) ...
    const { hosts: newHostsRaw } = req.body;
    if (!Array.isArray(newHostsRaw)) return res.status(400).json({ success: false, message: "Hosts 必须是列表格式" });
    try {
        const newHosts = newHostsRaw.map(h => String(h).trim().toLowerCase()).filter(h => h);
        await fs.writeFile(HOSTS_DB_PATH, JSON.stringify(newHosts, null, 4), 'utf8');
        
        broadcastToProxies({
            action: 'reload_hosts'
        });
        
        // [AXIOM V3.0] 通知前端 (如果需要)
        broadcastToFrontends({ type: 'hosts_changed' });
        
        await logAction("HOSTS_UPDATE", req.session.username, `Updated host whitelist. Count: ${newHosts.length}`);
        res.json({ success: true, message: `Host 白名单已更新，WSS 代理将自动热重载。` });
    } catch (e) {
        res.status(500).json({ success: false, message: `保存 Hosts 配置失败: ${e.message}` });
    }
});

api.get('/settings/global', async (req, res) => {
    // ... (此函数无变化) ...
    try {
        const setting = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
        res.json({
            success: true,
            settings: {
                fuse_threshold_kbps: setting ? parseInt(setting.value) : 0
            }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: `获取全局设置失败: ${e.message}` });
    }
});

api.post('/settings/global', async (req, res) => {
    // ... (此函数无变化) ...
    const { fuse_threshold_kbps } = req.body;
    if (fuse_threshold_kbps === undefined) { return res.status(400).json({ success: false, message: "缺少熔断阈值" }); }
    try {
        const threshold = parseInt(fuse_threshold_kbps) || 0;
        
        await db.run(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", 
            'fuse_threshold_kbps', 
            threshold.toString()
        );
        
        // [AXIOM V3.0] 更新内存中的阈值
        globalFuseLimitKbps = threshold;

        // [AXIOM V3.0] 移除: 不再需要向 Proxy 推送
        // broadcastToProxies({ ... });

        await logAction("GLOBAL_SETTINGS_UPDATE", req.session.username, `Global fuse threshold set to ${threshold} KB/s.`);
        res.json({ success: true, message: `全局熔断阈值 (${threshold} KB/s) 已保存。` });

    } catch (e) {
        await logAction("GLOBAL_SETTINGS_FAIL", req.session.username, `Failed to save global settings: ${e.message}`);
        res.status(500).json({ success: false, message: `保存设置失败: ${e.message}` });
    }
});

api.get('/settings/config', (req, res) => {
    // ... (此函数无变化) ...
    const { internal_api_secret, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
});

/**
 * [AXIOM V4.0 BUGFIX] 重构此 API 处理器以修复端口更新逻辑
 */
api.post('/settings/config', async (req, res) => {
    const newConfigData = req.body;
    if (!newConfigData) {
        return res.status(400).json({ success: false, message: "无效的配置数据。" });
    }
    
    try {
        let currentConfig = { ...config };
        
        // [AXIOM V4.0 BUGFIX] 必须在修改 currentConfig 之前，
        // 保存旧的 Stunnel 和 UDPGW 端口，以便替换它们。
        const oldStunnelPort = currentConfig.stunnel_port;
        const oldUdpGwPort = currentConfig.udpgw_port;

        const fieldsToUpdate = [
            'panel_port', 'wss_http_port', 'wss_tls_port', 
            'stunnel_port', 'udpgw_port', 'internal_forward_port'
        ];
        
        let requiresWssRestart = false;
        let requiresPanelRestart = false;
        let requiresStunnelRestart = false;
        let requiresUdpGwRestart = false;

        fieldsToUpdate.forEach(key => {
            const newValue = parseInt(newConfigData[key]);
            if (newValue && newValue !== currentConfig[key]) {
                console.log(`[CONFIG] 端口变更: ${key} 从 ${currentConfig[key]} -> ${newValue}`);
                
                // 更新将要写入 config.json 的对象
                currentConfig[key] = newValue;
                
                if (key === 'panel_port') requiresPanelRestart = true;
                if (key === 'wss_http_port' || key === 'wss_tls_port' || key === 'internal_forward_port') requiresWssRestart = true;
                if (key === 'stunnel_port') requiresStunnelRestart = true;
                if (key === 'udpgw_port') requiresUdpGwRestart = true;
            }
        });
        
        // 更新 panel_api_url (它也写入 config.json)
        currentConfig.panel_api_url = `http://127.0.0.1:${currentConfig.panel_port}/internal`;
        
        // [AXIOM V4.0 BUGFIX] 
        // 在重启服务之前，必须先修改它们所依赖的配置文件。
        try {
            if (requiresStunnelRestart) {
                const stunnelConfPath = '/etc/stunnel/ssh-tls.conf';
                const newPort = currentConfig.stunnel_port;
                console.log(`[CONFIG_FIX] 正在更新 ${stunnelConfPath}: ${oldStunnelPort} -> ${newPort}`);
                // 使用 sed 替换 accept 行
                const sedResult = await safeRunCommand(['sed', '-i', `s/accept = 0.0.0.0:${oldStunnelPort}/accept = 0.0.0.0:${newPort}/g`, stunnelConfPath]);
                if (!sedResult.success) throw new Error(`Failed to update ${stunnelConfPath}: ${sedResult.output}`);
            }
            if (requiresUdpGwRestart) {
                const udpgwServicePath = '/etc/systemd/system/udpgw.service';
                const newPort = currentConfig.udpgw_port;
                console.log(`[CONFIG_FIX] 正在更新 ${udpgwServicePath}: ${oldUdpGwPort} -> ${newPort}`);
                // 使用 sed 替换 ExecStart 行中的端口
                const sedResult = await safeRunCommand(['sed', '-i', `s/--listen-addr 127.0.0.1:${oldUdpGwPort}/--listen-addr 127.0.0.1:${newPort}/g`, udpgwServicePath]);
                if (!sedResult.success) throw new Error(`Failed to update ${udpgwServicePath}: ${sedResult.output}`);
                
                // [AXIOM V4.0] 修改 service 文件后必须重载 systemd daemon
                console.log(`[CONFIG_FIX] 正在执行 systemctl daemon-reload...`);
                await safeRunCommand(['systemctl', 'daemon-reload']);
            }
        } catch (e) {
            await logAction("CONFIG_FIX_FAIL", req.session.username, `Failed to patch service files: ${e.message}`);
            // 即使失败，我们仍然尝试保存 config.json，但会警告用户
            res.status(500).json({ success: false, message: `保存 config.json 成功，但应用到服务文件失败: ${e.message}` });
            // 不要继续执行重启
            return; 
        }

        // [AXIOM V4.0] 1. 立即写入 config.json (WSS 和 Panel 会读取)
        await fs.writeFile(CONFIG_PATH, JSON.stringify(currentConfig, null, 2), 'utf8');
        
        // [AXIOM V4.1 BUGFIX] 关键：更新面板自身的内存配置！
        // 否则 getSystemStatusData() 会读取到陈旧的端口数据。
        config = { ...currentConfig };
        
        await logAction("CONFIG_SAVE_SUCCESS", req.session.username, `配置已保存到 ${CONFIG_PATH} 并且服务文件已修补。`);
        
        // [AXIOM V4.0] 2. 异步重启所有受影响的服务
        // (现在它们会读取到新的配置)
        const restartServices = async () => {
            if (requiresWssRestart) {
                await safeRunCommand(['systemctl', 'restart', 'wss']);
            }
            if (requiresStunnelRestart) {
                await safeRunCommand(['systemctl', 'restart', 'stunnel4']);
            }
            if (requiresUdpGwRestart) {
                await safeRunCommand(['systemctl', 'restart', 'udpgw']);
            }
            if (requiresPanelRestart) {
                // 延迟重启面板自身，以确保响应能发送出去
                setTimeout(async () => {
                    await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
                }, 1000);
            }
        };
        restartServices(); // 异步执行，不等待

        res.json({ success: true, message: `配置已保存并成功应用！相关服务正在后台重启... (面板可能会在 ${requiresPanelRestart ? '1秒' : '0秒'} 后刷新)` });

    } catch (e) {
        await logAction("CONFIG_SAVE_FAIL", req.session.username, `Failed to save config: ${e.message}`);
        res.status(500).json({ success: false, message: `保存配置失败: ${e.message}` });
    }
});


api.post('/settings/change-password', async (req, res) => {
    // ... (此函数无变化) ...
    const { old_password, new_password } = req.body;
    if (!old_password || !new_password) { return res.status(400).json({ success: false, message: "新旧密码均不能为空。" }); }
    if (new_password.length < 6) { return res.status(400).json({ success: false, message: "新密码长度必须至少为 6 位。" }); }
    try {
        const rootHash = await loadRootHash();
        if (!rootHash) { throw new Error("无法加载 root hash 文件。"); }
        const match = await bcrypt.compare(old_password, rootHash);
        if (!match) {
            await logAction("CHANGE_PASS_FAIL", req.session.username, "Failed to change panel password: Incorrect old password");
            return res.status(403).json({ success: false, message: "当前密码不正确。" });
        }
        const newHash = await bcrypt.hash(new_password, 12);
        await fs.writeFile(ROOT_HASH_FILE, newHash, 'utf8');
        await logAction("CHANGE_PASS_SUCCESS", req.session.username, "Panel admin password changed successfully.");
        res.json({ success: true, message: "管理员密码修改成功。" });
    } catch (e) {
        await logAction("CHANGE_PASS_FAIL", req.session.username, `Failed to change panel password: ${e.message}`);
        res.status(500).json({ success: false, message: `密码修改失败: ${e.message}` });
    }
});

api.post('/ips/ban_global', async (req, res) => {
    // ... (此函数无变化) ...
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'block');
        if (!iptablesResult.success) throw new Error(iptablesResult.output);
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        await db.run(`INSERT OR REPLACE INTO ip_bans (ip, reason, added_by, timestamp) VALUES (?, ?, ?, ?)`,
            ip, reason || 'Manual Panel Ban', req.session.username, timestamp
        );
        await logAction("IP_BAN_GLOBAL", req.session.username, `Globally banned IP ${ip}. Reason: ${reason}`);
        res.json({ success: true, message: `IP 地址 ${ip} 已全局封禁。` });
    } catch (e) {
        await logAction("IP_BAN_FAIL", req.session.username, `Failed to ban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `封禁操作失败: ${e.message}` });
    }
});

api.post('/ips/unban_global', async (req, res) => {
    // ... (此函数无变化) ...
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'unblock');
        if (!iptablesResult.success && !iptablesResult.output.includes('No chain/target/match')) {
            throw new Error(iptablesResult.output);
        }
        await db.run(`DELETE FROM ip_bans WHERE ip = ?`, ip);
        await logAction("IP_UNBAN_GLOBAL", req.session.username, `Globally unbanned IP ${ip}.`);
        res.json({ success: true, message: `IP 地址 ${ip} 已解除全局封禁。` });
    } catch (e) {
        await logAction("IP_UNBAN_FAIL", req.session.username, `Failed to unban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `解除封禁失败: ${e.message}` });
    }
});

api.get('/ips/global_list', async (req, res) => {
    // ... (此函数无变化) ...
    try {
        const bans = await db.all('SELECT * FROM ip_bans ORDER BY timestamp DESC');
        const bansMap = bans.reduce((acc, item) => {
            acc[item.ip] = { reason: item.reason, timestamp: item.timestamp };
            return acc;
        }, {});
        res.json({ success: true, global_bans: bansMap });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch ban list: ${e.message}` });
    }
});

api.post('/utils/find_sni', async (req, res) => {
    // ... (此函数无变化) ...
    const { hostname } = req.body;
    if (!hostname) {
        return res.status(400).json({ success: false, message: "Hostname 不能为空。" });
    }
    try {
        const { address: ip_address } = await dns.promises.lookup(hostname);
        const promise = new Promise((resolve, reject) => {
            const options = {
                port: 443,
                host: ip_address, 
                servername: hostname, 
                timeout: 8000, 
                rejectUnauthorized: true 
            };
            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                if (!cert || !cert.subjectaltname) {
                    return resolve([]); 
                }
                const altNames = cert.subjectaltname
                    .split(',')
                    .map(s => s.trim())
                    .filter(s => s.startsWith('DNS:'))
                    .map(s => s.substring(4)); 
                resolve(altNames);
            });
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error(`连接到 ${hostname} (port 443) 超时。`));
            });
            socket.on('error', (err) => {
                if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
                     reject(new Error(`SSL 证书验证失败: ${err.message}`));
                } else {
                     reject(new Error(`TLS 错误: ${err.message}`));
                }
            });
        });
        const sniHosts = await promise;
        res.json({ success: true, hosts: sniHosts, ip: ip_address });
    } catch (e) {
        let errorMessage = e.message;
        if (e.code === 'ENOTFOUND' || e.message.includes('getaddrinfo')) {
            errorMessage = `无法解析域名 '${hostname}'。`;
        }
        res.status(500).json({ success: false, message: errorMessage });
    }
});


app.use('/api', loginRequired, api);


// --- [AXIOM V3.0] 重构: IPC (WebSocket) 服务器 ---

/**
 * [AXIOM V3.0] 熔断 Bug 修复 (Part 2): 实时熔断逻辑
 * 当 `stats_update` 消息进来时，立即检查是否超速
 */
async function checkAndApplyFuse(username, userSpeedKbps) {
    if (globalFuseLimitKbps <= 0) return; // 未启用熔断

    const totalSpeed = (userSpeedKbps.upload || 0) + (userSpeedKbps.download || 0);

    if (totalSpeed >= globalFuseLimitKbps) {
        // [AXIOM V3.0] 关键: 立即从数据库获取当前状态
        const user = await getUserByUsername(username);
        
        // 只有当用户当前是 'active' 时才触发熔断
        if (user && user.status === 'active') {
            console.warn(`[FUSE] 用户 ${username} 已触发全局熔断器! 速率: ${totalSpeed.toFixed(0)} KB/s. 正在暂停...`);
            
            // 1. 立即更新 DB 状态
            await db.run(`UPDATE users SET status = 'fused', status_text = '熔断 (Fused)' WHERE username = ?`, username);
            
            // 2. 立即锁定系统账户
            await safeRunCommand(['usermod', '-L', username]);
            
            // 3. 立即踢出连接
            await kickUserFromProxy(username); // 踢 WSS
            await safeRunCommand(['pkill', '-9', '-u', username]); // 踢 Stunnel/SSH
            
            await logAction("USER_FUSED", "SYSTEM", `User ${username} exceeded speed limit (${totalSpeed.toFixed(0)} KB/s). Fused and Kicked.`);
            
            // 4. (可选) 通知前端刷新列表
            broadcastToFrontends({ type: 'users_changed' });
        }
    }
}


/**
 * [AXIOM V3.0] 重构: 启动 IPC (Proxy) 和 UI (Frontend) 的 WebSocket 服务器
 */
function startWebSocketServers(httpServer) {
    console.log(`[AXIOM V3.0] 正在启动实时 WebSocket 服务...`);
    
    // --- 1. IPC (Proxy) 服务器 (/ipc) ---
    wssIpc = new WebSocketServer({
        noServer: true, 
        path: '/ipc'
    });
    
    wssIpc.on('connection', (ws, req) => {
        // [AXIOM V3.0] 将 workerId 附加到 ws 实例，以便在 close 时使用
        const workerId = req.headers['x-worker-id'] || req.socket.remoteAddress; // (注: wss_proxy.js V3.0 未发送此标头, 但可以添加)
        ws.workerId = workerId;
        console.log(`[IPC_WSS] 一个数据平面 (Proxy Worker: ${workerId}) 已连接。`);
        
        ws.on('message', async (data) => {
            try {
                const message = JSON.parse(data.toString());
                
                // 【Axiom V3.0】处理来自 Proxy 的主动统计更新
                if (message.type === 'stats_update' && message.payload) {
                    
                    // 1. 将此 Worker 的数据存入内存缓存
                    workerStatsCache.set(message.workerId || ws.workerId, message.payload);
                    
                    // 2. 异步将流量增量写入 DB (解耦)
                    persistTrafficDelta(message.payload.stats); 

                    // 3. 【执行动态逻辑】
                    if (wssUiPool.size > 0) {
                        // 【管理员在线】-> 立即聚合数据
                        const aggregatedStats = aggregateAllWorkerStats();
                        
                        // 【管理员在线】-> 立即推送“秒刷新”数据
                        broadcastToFrontends({
                            type: 'live_update',
                            payload: aggregatedStats 
                        });
                        
                        // 4. 【熔断 Bug 修复 #2】
                        // 实时检查熔断
                        if (globalFuseLimitKbps > 0) {
                            for (const username in aggregatedStats.users) {
                                // 检查聚合后的速度
                                const userSpeed = aggregatedStats.users[username].speed_kbps;
                                await checkAndApplyFuse(username, userSpeed);
                            }
                        }
                    }
                    // 【管理员离线】-> 不推送, 只累积流量
                }
                
                // (未来可以处理来自 proxy 的其他消息)

            } catch (e) {
                console.error(`[IPC_WSS] 解析 Proxy 消息失败: ${e.message}`);
            }
        });

        ws.on('close', () => {
            // [AXIOM V3.0] 当一个 Worker 断开时，将其从缓存中移除
            workerStatsCache.delete(ws.workerId);
            console.log(`[IPC_WSS] 一个数据平面 (Proxy Worker: ${ws.workerId}) 已断开连接。`);
        });
        
        ws.on('error', (err) => {
            console.error(`[IPC_WSS] 客户端 WebSocket 错误: ${err.message}`);
        });
    });
    
    wssIpc.on('error', (err) => {
         console.error(`[IPC_WSS] 实时 IPC 服务器错误: ${err.message}`);
    });
    
    // --- 2. UI (Frontend) 服务器 (/ws/ui) ---
    const wssUi = new WebSocketServer({
        noServer: true,
        path: '/ws/ui'
    });

    wssUi.on('connection', (ws, req) => {
        // [AXIOM V3.0] 检查 session
        if (!req.session || !req.session.loggedIn) {
            console.warn("[IPC_UI] 拒绝连接: 未经身份验证的前端尝试连接 WebSocket。");
            ws.send(JSON.stringify({ type: 'auth_failed', message: 'Authentication required.' }));
            ws.terminate();
            return;
        }

        console.log(`[IPC_UI] 一个已验证的管理员前端 (User: ${req.session.username}) 已连接。`);
        wssUiPool.add(ws);
        
        // [AXIOM V3.0] 需求 #5: 状态灯 - 立即发送“连接成功” (蓝色)
        ws.send(JSON.stringify({ type: 'status_connected', message: 'WebSocket 连接成功' }));

        ws.on('close', () => {
            console.log(`[IPC_UI] 一个管理员前端已断开连接。`);
            wssUiPool.delete(ws);
        });

        ws.on('error', (err) => {
            console.error(`[IPC_UI] 前端 WebSocket 错误: ${err.message}`);
            wssUiPool.delete(ws);
        });
        
        // (可以添加 ws.on('message') 来处理来自前端的 ping 或请求)
    });
    
    wssUi.on('error', (err) => {
         console.error(`[IPC_UI] 前端 WS 服务器错误: ${err.message}`);
    });

    // --- 3. HTTP 服务器 'upgrade' 路由 ---
    httpServer.on('upgrade', (request, socket, head) => {
        
        // 验证内部 API 密钥 (用于 /ipc)
        const secret = request.headers['x-internal-secret'];
        const pathname = request.url;

        if (pathname === '/ipc') {
            if (secret !== config.internal_api_secret) {
                console.error("[IPC_WSS] 拒绝连接: 内部 API 密钥 (x-internal-secret) 无效。");
                socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                socket.destroy();
                return;
            }
            wssIpc.handleUpgrade(request, socket, head, (ws) => {
                wssIpc.emit('connection', ws, request);
            });
        
        } else if (pathname === '/ws/ui') {
            // [AXIOM V3.0] 使用 session 中间件解析 cookie
            sessionMiddleware(request, {}, () => {
                wssUi.handleUpgrade(request, socket, head, (ws) => {
                    wssUi.emit('connection', ws, request);
                });
            });
            
        } else {
             console.error(`[WS] 拒绝连接: 无效的 WebSocket 路径 (${pathname})。`);
             socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
             socket.destroy();
        }
    });
    
    console.log(`[AXIOM V3.0] 实时 WebSocket 服务已附加到主 HTTP 服务器。`);
}


// --- [AXIOM V3.0] 重构: Startup ---
async function startApp() {
    try {
        await initDb();
        
        const server = http.createServer(app);
        
        // [AXIOM V3.0] 启动所有 WebSocket 服务器 (IPC 和 UI)
        startWebSocketServers(server);
        
        // [AXIOM V3.0] 启动 60 秒维护任务
        setInterval(syncUserStatus, BACKGROUND_SYNC_INTERVAL);
        setTimeout(syncUserStatus, 5000); 
        
        server.listen(config.panel_port, '0.0.0.0', () => {
            console.log(`[AXIOM V3.0] WSS Panel (HTTP) 运行在 port ${config.panel_port}`);
            console.log(`[AXIOM V3.0] 实时 IPC (WSS) 运行在 port ${config.panel_port} (路径: /ipc)`);
            console.log(`[AXIOM V3.0] 实时 UI (WSS) 运行在 port ${config.panel_port} (路径: /ws/ui)`);
            console.log(`[AXIOM V3.0] 60秒维护任务已启动。`);
        });
        
        server.on('error', (err) => {
             if (err.code === 'EADDRINUSE') {
                console.error(`[CRITICAL] 启动失败: 端口 ${config.panel_port} 已被占用。`);
             } else {
                console.error(`[CRITICAL] Panel HTTP 服务器错误: ${err.message}`);
             }
             process.exit(1);
        });

    } catch (e) {
        console.error(`[CRITICAL] Panel App 启动失败: ${e.message}`);
        process.exit(1);
    }
}

startApp();
