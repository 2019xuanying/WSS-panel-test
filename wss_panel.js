/**
 * WSS Panel Backend (Node.js + Express + SQLite)
 * V8.5.0 (Axiom Refactor V5.0 - Native UDP & Layered Push)
 *
 * [AXIOM V5.0 CHANGELOG]
 * - [性能] 分层推送:
 * - 引入 `liveUpdateInterval` (1秒) 和 `systemUpdateInterval` (3秒) 定时器。
 * - 仅在 `wssUiPool.size > 0` 时启动实时推送。
 * - `pushLiveUpdates` 仅推送活跃用户和流量数据。
 * - `pushSystemUpdates` 仅推送 CPU/内存/服务状态 (3秒)。
 * - [性能] 智能推送: 只有当用户数据或系统状态发生变化时才广播给前端。
 * - [性能/稳定性] DB 批量写入优化:
 * - `persistTrafficDelta` 现在使用优化的批量 SQL 逻辑，提高高并发写入的稳定性。
 * - [修复] 端口配置:
 * - `/settings/config` API 修复了对 `udpgw` 服务的配置修改逻辑，以兼容 Native UDPGW (即不再修改 .service 文件，因为 Native UDPGW 直接读取 config.json)。
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
    console.log(`[AXIOM V5.0] 成功从 ${CONFIG_PATH} 加载配置。`);
} catch (e) {
    console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。将使用默认端口。`);
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
const STUNNEL_CONF = '/etc/stunnel/ssh-tls.conf'; // [AXIOM V5.0] 端口修改目标文件
const ROOT_USERNAME = "root";
const GIGA_BYTE = 1024 * 1024 * 1024;
const BLOCK_CHAIN = "WSS_IP_BLOCK";
const BACKGROUND_SYNC_INTERVAL = 60000; // 60秒维护任务 (状态机/系统锁定)
const CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    // [AXIOM V5.0] 替换为新的 Native UDPGW 服务名
    'udp_server': 'Native UDPGW',
    'wss_panel': 'Web Panel'
};
let db;

// --- [AXIOM V5.0] 实时推送状态管理 ---
let wssIpc = null;
let wssUiPool = new Set();
let workerStatsCache = new Map();
let globalFuseLimitKbps = 0;

// [AXIOM V5.0] 性能优化定时器
let liveUpdateInterval = null; // 1秒用户流量/连接推送
let systemUpdateInterval = null; // 3秒系统状态推送
let isRealtimePushing = false; // 实时推送状态标志

// [AXIOM V5.0] 智能推送：存储上一次推送的聚合数据，以便比较变化
let lastAggregatedStats = { users: {}, live_ips: {} };
let lastSystemStatus = {};


const SUDO_COMMANDS = new Set([
    'useradd', 'usermod', 'userdel', 'gpasswd', 'chpasswd', 'pkill',
    'iptables', 'iptables-save', 'journalctl', 
    'systemctl', 
    'getent', 
    'systemctl is-active',
    'sed', 
    'systemctl daemon-reload' 
]);

// --- 辅助函数 (safeRunCommand, logAction, getSystemLockStatus 等保持不变) ---

/**
 * [AXIOM V4.1] 修复: 移除了 e.code === 1 的危险捕获
 */
async function safeRunCommand(command, inputData = null) {
    
    let fullCommand = [...command];
    let baseCommand = command[0];
    
    if (command[0] === 'systemctl' && command[1] === 'is-active') {
        baseCommand = 'systemctl is-active';
    }
    if (command[0] === 'systemctl' && command[1] === 'daemon-reload') {
        baseCommand = 'systemctl daemon-reload';
    }
    
    if (SUDO_COMMANDS.has(baseCommand)) {
        fullCommand.unshift('sudo');
    }

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

    try {
        const { stdout, stderr } = await asyncExecFile(fullCommand[0], fullCommand.slice(1), {
            timeout: 10000,
            input: inputData,
            env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
        });
        const output = (stdout + stderr).trim();
        
        if (stderr && 
            !stderr.includes('user not found') &&
            !stderr.includes('userdel: user') &&
            !stderr.includes('already exists')
           ) {
             console.warn(`safeRunCommand (asyncExecFile) Non-fatal Stderr (Command: ${fullCommand.join(' ')}): ${stderr.trim()}`);
        }
        return { success: true, output: stdout.trim() };
        
    } catch (e) {
        if (baseCommand === 'systemctl is-active' && e.code === 3) {
            return { success: false, output: 'inactive' };
        }
        
        if (baseCommand === 'sed' && e.code === 1 && e.stderr.includes('No such file')) {
             console.error(`safeRunCommand (sed) Error: ${e.stderr}`);
             return { success: false, output: e.stderr };
        }
        
        if (e.code !== 'ETIMEDOUT') {
            console.error(`safeRunCommand (asyncExecFile) Fatal Error (Command: ${fullCommand.join(' ')}): Code=${e.code}, Stderr=${e.stderr || 'N/A'}, Msg=${e.message}`);
        }
        
        return { success: false, output: e.stderr || e.message || `Command ${fullCommand[0]} failed.` };
    }
}


async function logAction(actionType, username, details = "") {
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


// --- 数据库 Setup and User Retrieval (initDb 保持不变) ---

async function initDb() {
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
    return db.get('SELECT * FROM users WHERE username = ?', username);
}

// --- Authentication Middleware (保持不变) ---

function loadSecretKey() {
    try {
        return fsSync.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
    } catch (e) {
        const key = require('crypto').randomBytes(32).toString('hex');
        fsSync.writeFileSync(SECRET_KEY_PATH, key, 'utf8');
        return key;
    }
}

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
    if (req.session.loggedIn) {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ success: false, message: "Authentication failed or session expired" });
        }
        return res.redirect('/login.html');
    }
}

// --- Business Logic / System Sync ---

function broadcastToFrontends(message) {
    if (!wssUiPool || wssUiPool.size === 0) {
        return; 
    }
    const payload = JSON.stringify(message);
    wssUiPool.forEach((client) => {
        if (client.readyState === 1) { 
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_UI] 发送消息到前端失败: ${err.message}`);
                }
            });
        }
    });
}

function broadcastToProxies(message) {
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
    broadcastToProxies({
        action: 'kick',
        username: username
    });
    return true; 
}

/**
 * [AXIOM V5.0] 核心优化: 批量写入流量增量到 DB (解决高并发写入问题)
 */
async function persistTrafficDelta(workerStats) {
    const today = new Date().toISOString().split('T')[0];
    let userDeltaList = [];
    
    // 1. 聚合所有 Worker 的流量增量
    for (const username in workerStats) {
        const stats = workerStats[username];
        const deltaBytes = (stats.traffic_delta_up || 0) + (stats.traffic_delta_down || 0);
        if (deltaBytes > 0) {
            userDeltaList.push({
                username: username,
                deltaGb: (deltaBytes / GIGA_BYTE)
            });
        }
    }

    if (userDeltaList.length === 0) return;

    // 2. 批量写入 DB (优化了 UPDATE 和 INSERT 的逻辑)
    try {
        await db.run('BEGIN TRANSACTION');
        
        // --- A. 批量更新主表 (users) ---
        // 使用 REPLACE INTO 模拟 ON CONFLICT UPDATE (但此处我们使用 UPDATE 提高可读性)
        // 鉴于 SQLite 不支持多行 UPDATE，我们使用循环，但在事务中性能可接受。
        // 为了进一步优化性能，我们合并主表更新和历史表更新。

        const historyUpdates = [];
        for (const u of userDeltaList) {
            // 1. 更新主表总流量
            await db.run('UPDATE users SET usage_gb = usage_gb + ? WHERE username = ?',
                [u.deltaGb, u.username]);
            
            // 2. 准备历史表更新数据
            historyUpdates.push(u);
        }
        
        // --- B. 批量更新历史表 (traffic_history) ---
        for (const u of historyUpdates) {
             // 采用 INSERT OR IGNORE + UPDATE 的模式来模拟 UPSERT
            await db.run('INSERT OR IGNORE INTO traffic_history (username, date, usage_gb) VALUES (?, ?, 0.0)', [u.username, today]);
            await db.run('UPDATE traffic_history SET usage_gb = usage_gb + ? WHERE username = ? AND date = ?', [u.deltaGb, u.username, today]);
        }
        
        await db.run('COMMIT');
    } catch (e) {
        await db.run('ROLLBACK').catch(()=>{});
        console.error(`[TRAFFIC_ASYNC] 流量增量DB批量写入失败: ${e.message}`);
    }
}


/**
 * [AXIOM V3.0] 聚合所有 Worker 的统计数据
 */
function aggregateAllWorkerStats() {
    const aggregatedStats = {};
    const aggregatedLiveIps = {};
    let totalActiveConnections = 0;

    for (const [workerId, workerData] of workerStatsCache.entries()) {
        for (const username in workerData.stats) {
            const current = workerData.stats[username];
            if (!aggregatedStats[username]) {
                aggregatedStats[username] = {
                    speed_kbps: { ...current.speed_kbps },
                    connections: current.connections
                };
            } else {
                const existing = aggregatedStats[username];
                existing.connections += current.connections;
                existing.speed_kbps.upload += current.speed_kbps.upload;
                existing.speed_kbps.download += current.speed_kbps.download;
            }
            totalActiveConnections += current.connections;
        }
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
 * [AXIOM V5.0] 核心功能: 1秒实时流量/连接推送
 */
function pushLiveUpdates() {
    if (!isRealtimePushing) return;
    
    const aggregatedData = aggregateAllWorkerStats();
    
    // 1. 检查用户流量/连接数据是否有变化
    const usersToPush = {};
    let usersChanged = false;

    for (const username in aggregatedData.users) {
        const current = aggregatedData.users[username];
        const last = lastAggregatedStats.users[username];

        // 检查连接数、上传速度或下载速度是否有显著变化
        const hasChange = !last ||
            current.connections !== last.connections ||
            Math.abs(current.speed_kbps.upload - (last.speed_kbps.upload || 0)) > 0.1 ||
            Math.abs(current.speed_kbps.download - (last.speed_kbps.download || 0)) > 0.1;

        if (hasChange) {
            usersToPush[username] = current;
            usersChanged = true;
        }
    }
    
    // 2. 检查全局活跃 IP 数量是否有变化
    const currentLiveIpCount = Object.keys(aggregatedData.live_ips).length;
    const lastLiveIpCount = Object.keys(lastAggregatedStats.live_ips).length;
    
    let systemChanged = false;
    if (currentLiveIpCount !== lastLiveIpCount) {
        systemChanged = true;
    }
    
    // 3. 推送有变化的数据
    if (usersChanged || systemChanged) {
         broadcastToFrontends({
            type: 'live_update',
            payload: { 
                users: usersToPush,
                system: { 
                    active_connections_total: aggregatedData.system.active_connections_total 
                } 
            }
        });
        
        // 4. 更新上次推送缓存 (仅更新被推送的数据)
        for (const username in usersToPush) {
            lastAggregatedStats.users[username] = aggregatedData.users[username];
        }
        // 更新全局连接数缓存
        lastAggregatedStats.system = aggregatedData.system; 
    }
}

/**
 * [AXIOM V5.0] 核心功能: 3秒系统状态推送
 */
async function pushSystemUpdates() {
    if (!isRealtimePushing) return;
    
    const systemStatusData = await getSystemStatusData();
    let isChanged = false;

    // 检查 CPU/内存/磁盘是否有变化 (使用 JSON.stringify 快速比较，但忽略 user_stats)
    const currentStatus = { ...systemStatusData };
    delete currentStatus.user_stats;
    
    const lastJSON = JSON.stringify(lastSystemStatus);
    const currentJSON = JSON.stringify(currentStatus);

    if (lastJSON !== currentJSON) {
        isChanged = true;
        // console.log("[PUSH] System status changed, pushing update.");
    }

    if (isChanged) {
        broadcastToFrontends({
            type: 'system_update',
            payload: systemStatusData
        });
        
        // 更新上次推送缓存
        lastSystemStatus = currentStatus;
    }
}


/**
 * [AXIOM V5.0] 启动/停止实时推送机制 (由 UI 连接/断开触发)
 */
function toggleRealtimePush(shouldStart) {
    if (shouldStart && !isRealtimePushing) {
        // 启动实时推送
        console.log("[PUSH] 启动 1秒/3秒 实时推送定时器...");
        isRealtimePushing = true;
        
        // 1. 启动 1 秒流量/连接推送
        if (liveUpdateInterval) clearInterval(liveUpdateInterval);
        liveUpdateInterval = setInterval(pushLiveUpdates, 1000);
        
        // 2. 启动 3 秒系统状态推送
        if (systemUpdateInterval) clearInterval(systemUpdateInterval);
        systemUpdateInterval = setInterval(pushSystemUpdates, 3000);
        
    } else if (!shouldStart && isRealtimePushing) {
        // 停止实时推送
        console.log("[PUSH] 停止 1秒/3秒 实时推送定时器 (管理员已离线)。");
        isRealtimePushing = false;
        if (liveUpdateInterval) clearInterval(liveUpdateInterval);
        if (systemUpdateInterval) clearInterval(systemUpdateInterval);
        liveUpdateInterval = null;
        systemUpdateInterval = null;
        
        // 重置缓存以备下次连接时进行全量推送
        lastAggregatedStats = { users: {}, live_ips: {} };
        lastSystemStatus = {};
    }
}


/**
 * [AXIOM V3.0] 60秒维护任务
 */
async function syncUserStatus() {
    // [AXIOM V5.0] 当管理员离线时，此任务成为唯一的数据持久化机制
    const systemLockedUsers = await getSystemLockStatus();
    let allUsers = [];
    try {
        allUsers = await db.all('SELECT * FROM users');
    } catch (e) {
        console.error(`[SYNC] 无法从 DB 获取用户: ${e.message}`);
        return;
    }
    
    const usersToUpdate = []; 
    
    for (const user of allUsers) {
        const username = user.username;
        
        let isExpired = false, isOverQuota = false;
        
        if (user.expiration_date) {
            try {
                const expiry = new Date(user.expiration_date);
                if (!isNaN(expiry) && expiry < new Date()) { isExpired = true; }
            } catch (e) { /* ignore */ }
        }
        
        if (user.quota_gb > 0 && user.usage_gb >= user.quota_gb) { isOverQuota = true; }
        
        const currentDbStatus = user.status; 
        let newDbStatus = currentDbStatus;
        let statusChanged = false;
        
        if (isExpired) {
            if (currentDbStatus !== 'expired') { newDbStatus = 'expired'; statusChanged = true; }
        } else if (isOverQuota) {
            if (currentDbStatus !== 'exceeded') { newDbStatus = 'exceeded'; statusChanged = true; }
        } else if (currentDbStatus === 'paused' || currentDbStatus === 'fused') {
            newDbStatus = currentDbStatus; 
        } else {
            if (currentDbStatus !== 'active') { newDbStatus = 'active'; statusChanged = true; }
        }
        
        user.status = newDbStatus;

        const systemLocked = systemLockedUsers.has(username);
        const shouldBeLocked_SYS = (user.status !== 'active');
        
        if (shouldBeLocked_SYS && !systemLocked) {
            await safeRunCommand(['usermod', '-L', username]);
            statusChanged = true; 
        } else if (!shouldBeLocked_SYS && systemLocked) {
            await safeRunCommand(['usermod', '-U', username]);
            statusChanged = true; 
        }
        
        let newStatusText = user.status_text;
        if (user.status === 'active') { newStatusText = '启用 (Active)'; } 
        else if (user.status === 'paused') { newStatusText = '暂停 (Manual)'; } 
        else if (user.status === 'expired') { newStatusText = '已到期 (Expired)'; } 
        else if (user.status === 'exceeded') { newStatusText = '超额 (Quota)'; } 
        else if (user.status === 'fused') { newStatusText = '熔断 (Fused)'; } 
        else { newStatusText = '未知'; }

        if (statusChanged || user.status_text !== newStatusText) {
             user.status_text = newStatusText;
             usersToUpdate.push(user);
        }
    }
    
    if (usersToUpdate.length > 0) {
        try {
            await db.run('BEGIN TRANSACTION');
            for (const u of usersToUpdate) {
                await db.run(`UPDATE users SET 
                                status = ?, status_text = ?
                              WHERE username = ?`,
                    u.status, u.status_text, u.username);
            }
            await db.run('COMMIT');
            console.log(`[SYNC] 60秒维护任务完成。更新了 ${usersToUpdate.length} 个用户的状态。`);
            
            // 状态变更后，通知前端刷新用户列表 (仅在有人在线时)
            if (wssUiPool.size > 0) {
                broadcastToFrontends({ type: 'users_changed' });
            }
            
        } catch (e) {
            await db.run('ROLLBACK').catch(()=>{});
            console.error(`[SYNC] CRITICAL: 60秒维护DB更新失败: ${e.message}`);
        }
    } else {
        // console.log(`[SYNC] 60秒维护任务完成。没有状态变更。`);
    }
}


async function manageIpIptables(ip, action, chainName = BLOCK_CHAIN) {
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
    logAction("LOGOUT_SUCCESS", req.session.username || ROOT_USERNAME, "Web UI Logout");
    req.session.destroy();
    res.redirect('/login.html');
});

// --- Internal API (For Proxy) ---
const internalApi = express.Router();
internalApi.use((req, res, next) => {
    const clientIp = req.ip;
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        next();
    } else {
        console.warn(`[AUTH] Denied external access attempt to /internal API from ${clientIp}`);
        res.status(403).json({ success: false, message: 'Forbidden' });
    }
});

internalApi.post('/auth', async (req, res) => {
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
 * [AXIOM V5.0] 提取: 获取系统状态的核心逻辑
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
        // [AXIOM V5.0] Native UDPGW 现在只在 127.0.0.1 监听 TCP
        { name: 'NATIVE_UDPGW', port: config.udpgw_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'PANEL', port: config.panel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'SSH_INTERNAL', port: config.internal_forward_port, protocol: 'TCP', status: 'LISTEN' }
    ];
    
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
    const { service, action } = req.body;
    // [AXIOM V5.0] 检查新的 CORE_SERVICES
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
    try {
        const logContent = await fs.readFile(AUDIT_LOG_PATH, 'utf8');
        const logs = logContent.trim().split('\n').filter(line => line.trim().length > 0).slice(-20);
        res.json({ success: true, logs });
    } catch (e) {
        res.json({ success: true, logs: ["读取日志失败或日志文件为空。"] });
    }
});

api.get('/system/active_ips', async (req, res) => {
    try {
        const aggregatedData = aggregateAllWorkerStats();
        const liveIps = aggregatedData.live_ips || {};
        
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

api.get('/users/list', async (req, res) => {
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
    const { username, password, expiration_days, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "缺少用户名或密码" });
    if (!/^[a-z0-9_]{3,16}$/.test(username)) return res.status(400).json({ success: false, message: "用户名格式不正确" });
    const existingUser = await getUserByUsername(username);
    if (existingUser) return res.status(409).json({ success: false, message: `用户组 ${username} 已存在于面板` });
    try {
        const shell = "/sbin/nologin"; 
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
        
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 创建成功，有效期至 ${expiryDate}` });
    } catch (e) {
        await safeRunCommand(['userdel', '-r', username]);
        await logAction("USER_ADD_FAIL", req.session.username, `Failed to create user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});


api.post('/users/delete', async (req, res) => {
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
        
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_DELETE_SUCCESS", req.session.username, `Deleted user ${username}`);
        res.json({ success: true, message: `用户组 ${username} 已删除，会话已终止` });
    } catch (e) {
        await logAction("USER_DELETE_FAIL", req.session.username, `Failed to delete user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `删除操作失败: ${e.message}` });
    }
});

api.post('/users/set_settings', async (req, res) => {
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
        
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 状态已更新。` });
    } catch (e) {
        await logAction("USER_STATUS_FAIL", req.session.username, `Failed to change status for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/reset_traffic', async (req, res) => {
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
    const hosts = await loadHosts();
    res.json({ success: true, hosts });
});

async function loadHosts() {
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

api.post('/settings/hosts', async (req, res) => {
    const { hosts: newHostsRaw } = req.body;
    if (!Array.isArray(newHostsRaw)) return res.status(400).json({ success: false, message: "Hosts 必须是列表格式" });
    try {
        const newHosts = newHostsRaw.map(h => String(h).trim().toLowerCase()).filter(h => h);
        await fs.writeFile(HOSTS_DB_PATH, JSON.stringify(newHosts, null, 4), 'utf8');
        
        broadcastToProxies({
            action: 'reload_hosts'
        });
        
        broadcastToFrontends({ type: 'hosts_changed' });
        
        await logAction("HOSTS_UPDATE", req.session.username, `Updated host whitelist. Count: ${newHosts.length}`);
        res.json({ success: true, message: `Host 白名单已更新，WSS 代理将自动热重载。` });
    } catch (e) {
        res.status(500).json({ success: false, message: `保存 Hosts 配置失败: ${e.message}` });
    }
});

api.get('/settings/global', async (req, res) => {
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
    const { fuse_threshold_kbps } = req.body;
    if (fuse_threshold_kbps === undefined) { return res.status(400).json({ success: false, message: "缺少熔断阈值" }); }
    try {
        const threshold = parseInt(fuse_threshold_kbps) || 0;
        
        await db.run(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", 
            'fuse_threshold_kbps', 
            threshold.toString()
        );
        
        globalFuseLimitKbps = threshold;

        await logAction("GLOBAL_SETTINGS_UPDATE", req.session.username, `Global fuse threshold set to ${threshold} KB/s.`);
        res.json({ success: true, message: `全局熔断阈值 (${threshold} KB/s) 已保存。` });

    } catch (e) {
        await logAction("GLOBAL_SETTINGS_FAIL", req.session.username, `Failed to save global settings: ${e.message}`);
        res.status(500).json({ success: false, message: `保存设置失败: ${e.message}` });
    }
});

api.get('/settings/config', (req, res) => {
    const { internal_api_secret, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
});

/**
 * [AXIOM V5.0] 增强端口配置修改的稳定性，并兼容 Native UDPGW
 */
api.post('/settings/config', async (req, res) => {
    const newConfigData = req.body;
    if (!newConfigData) {
        return res.status(400).json({ success: false, message: "无效的配置数据。" });
    }
    
    try {
        let currentConfig = { ...config };
        
        const oldStunnelPort = currentConfig.stunnel_port;
        
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
                
                currentConfig[key] = newValue;
                
                if (key === 'panel_port') requiresPanelRestart = true;
                if (key === 'wss_http_port' || key === 'wss_tls_port' || key === 'internal_forward_port') requiresWssRestart = true;
                if (key === 'stunnel_port') requiresStunnelRestart = true;
                // [AXIOM V5.0] Native UDPGW 端口变更
                if (key === 'udpgw_port') requiresUdpGwRestart = true;
            }
        });
        
        currentConfig.panel_api_url = `http://127.0.0.1:${currentConfig.panel_port}/internal`;
        
        try {
            if (requiresStunnelRestart) {
                const newPort = currentConfig.stunnel_port;
                console.log(`[CONFIG_FIX] 正在更新 ${STUNNEL_CONF}: ${oldStunnelPort} -> ${newPort}`);
                // 使用 sed 替换 accept 行
                const sedResult = await safeRunCommand(['sed', '-i', `s/accept = 0.0.0.0:${oldStunnelPort}/accept = 0.0.0.0:${newPort}/g`, STUNNEL_CONF]);
                if (!sedResult.success) throw new Error(`Failed to update ${STUNNEL_CONF}: ${sedResult.output}`);
            }
            
            // [AXIOM V5.0] 移除对 udpgw.service.template 的 sed 修改。
            // Native UDPGW (udp_server.js) 直接读取 config.json。
            // 我们只需要确保服务重启即可。
            
        } catch (e) {
            await logAction("CONFIG_FIX_FAIL", req.session.username, `Failed to patch service files: ${e.message}`);
            res.status(500).json({ success: false, message: `保存 config.json 成功，但应用到服务文件失败: ${e.message}` });
            return; 
        }

        // 1. 立即写入 config.json
        await fs.writeFile(CONFIG_PATH, JSON.stringify(currentConfig, null, 2), 'utf8');
        
        // 2. 更新面板自身的内存配置
        config = { ...currentConfig };
        
        await logAction("CONFIG_SAVE_SUCCESS", req.session.username, `配置已保存到 ${CONFIG_PATH} 并且服务文件已修补。`);
        
        // 3. 异步重启所有受影响的服务
        const restartServices = async () => {
            if (requiresWssRestart) {
                await safeRunCommand(['systemctl', 'restart', 'wss']);
            }
            if (requiresStunnelRestart) {
                await safeRunCommand(['systemctl', 'restart', 'stunnel4']);
            }
            // [AXIOM V5.0] 重启新的 Native UDPGW 服务
            if (requiresUdpGwRestart) {
                await safeRunCommand(['systemctl', 'restart', 'udp_server']);
            }
            if (requiresPanelRestart) {
                setTimeout(async () => {
                    await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
                }, 1000);
            }
        };
        restartServices(); 

        res.json({ success: true, message: `配置已保存并成功应用！相关服务正在后台重启... (面板可能会在 ${requiresPanelRestart ? '1秒' : '0秒'} 后刷新)` });

    } catch (e) {
        await logAction("CONFIG_SAVE_FAIL", req.session.username, `Failed to save config: ${e.message}`);
        res.status(500).json({ success: false, message: `保存配置失败: ${e.message}` });
    }
});


api.post('/settings/change-password', async (req, res) => {
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


// --- IPC (WebSocket) 服务器 ---


async function checkAndApplyFuse(username, userSpeedKbps) {
    if (globalFuseLimitKbps <= 0) return; 

    const totalSpeed = (userSpeedKbps.upload || 0) + (userSpeedKbps.download || 0);

    if (totalSpeed >= globalFuseLimitKbps) {
        const user = await getUserByUsername(username);
        
        if (user && user.status === 'active') {
            console.warn(`[FUSE] 用户 ${username} 已触发全局熔断器! 速率: ${totalSpeed.toFixed(0)} KB/s. 正在暂停...`);
            
            await db.run(`UPDATE users SET status = 'fused', status_text = '熔断 (Fused)' WHERE username = ?`, username);
            
            await safeRunCommand(['usermod', '-L', username]);
            
            await kickUserFromProxy(username); 
            await safeRunCommand(['pkill', '-9', '-u', username]); 
            
            await logAction("USER_FUSED", "SYSTEM", `User ${username} exceeded speed limit (${totalSpeed.toFixed(0)} KB/s). Fused and Kicked.`);
            
            broadcastToFrontends({ type: 'users_changed' });
        }
    }
}


function startWebSocketServers(httpServer) {
    console.log(`[AXIOM V5.0] 正在启动实时 WebSocket 服务...`);
    
    // --- 1. IPC (Proxy) 服务器 (/ipc) ---
    wssIpc = new WebSocketServer({
        noServer: true, 
        path: '/ipc'
    });
    
    wssIpc.on('connection', (ws, req) => {
        // [AXIOM V5.0] 从请求头获取 Worker ID
        const workerId = req.headers['x-worker-id'] || req.socket.remoteAddress;
        ws.workerId = workerId;
        console.log(`[IPC_WSS] 一个数据平面 (Proxy Worker: ${workerId}) 已连接。`);
        
        ws.on('message', async (data) => {
            try {
                const message = JSON.parse(data.toString());
                
                if (message.type === 'stats_update' && message.payload) {
                    
                    // 1. 将此 Worker 的数据存入内存缓存
                    workerStatsCache.set(message.workerId || ws.workerId, message.payload);
                    
                    // 2. 异步将流量增量写入 DB (解耦)
                    persistTrafficDelta(message.payload.stats); 

                    // 3. 执行动态逻辑
                    if (wssUiPool.size > 0) {
                        const aggregatedStats = aggregateAllWorkerStats();
                        
                        // 4. 实时检查熔断 (基于聚合速度)
                        if (globalFuseLimitKbps > 0) {
                            for (const username in aggregatedStats.users) {
                                const userSpeed = aggregatedStats.users[username].speed_kbps;
                                await checkAndApplyFuse(username, userSpeed);
                            }
                        }
                    }
                }
            } catch (e) {
                console.error(`[IPC_WSS] 解析 Proxy 消息失败: ${e.message}`);
            }
        });

        ws.on('close', () => {
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
        if (!req.session || !req.session.loggedIn) {
            console.warn("[IPC_UI] 拒绝连接: 未经身份验证的前端尝试连接 WebSocket。");
            ws.send(JSON.stringify({ type: 'auth_failed', message: 'Authentication required.' }));
            ws.terminate();
            return;
        }

        console.log(`[IPC_UI] 一个已验证的管理员前端 (User: ${req.session.username}) 已连接。`);
        wssUiPool.add(ws);
        
        // 第一次连接成功，检查是否需要启动实时推送
        if (wssUiPool.size === 1) {
            toggleRealtimePush(true);
        }
        
        ws.send(JSON.stringify({ type: 'status_connected', message: 'WebSocket 连接成功' }));

        ws.on('close', () => {
            console.log(`[IPC_UI] 一个管理员前端已断开连接。`);
            wssUiPool.delete(ws);
            
            // 检查是否所有管理员都已离线
            if (wssUiPool.size === 0) {
                toggleRealtimePush(false);
            }
        });

        ws.on('error', (err) => {
            console.error(`[IPC_UI] 前端 WebSocket 错误: ${err.message}`);
            wssUiPool.delete(ws);
        });
    });
    
    wssUi.on('error', (err) => {
         console.error(`[IPC_UI] 前端 WS 服务器错误: ${err.message}`);
    });

    // --- 3. HTTP 服务器 'upgrade' 路由 ---
    httpServer.on('upgrade', (request, socket, head) => {
        
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
    
    console.log(`[AXIOM V5.0] 实时 WebSocket 服务已附加到主 HTTP 服务器。`);
}


// --- [AXIOM V3.0] 重构: Startup ---
async function startApp() {
    try {
        await initDb();
        
        const server = http.createServer(app);
        
        startWebSocketServers(server);
        
        // 60秒维护任务 (无论管理员是否在线，都保持运行)
        setInterval(syncUserStatus, BACKGROUND_SYNC_INTERVAL);
        setTimeout(syncUserStatus, 5000); 
        
        server.listen(config.panel_port, '0.0.0.0', () => {
            console.log(`[AXIOM V5.0] WSS Panel (HTTP) 运行在 port ${config.panel_port}`);
            console.log(`[AXIOM V5.0] 实时 IPC (WSS) 运行在 port ${config.panel_port} (路径: /ipc)`);
            console.log(`[AXIOM V5.0] 实时 UI (WSS) 运行在 port ${config.panel_port} (路径: /ws/ui)`);
            console.log(`[AXIOM V5.0] 60秒维护任务已启动。`);
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
