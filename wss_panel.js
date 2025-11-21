/**
 * WSS Panel Backend (Node.js + Express + SQLite)
 * V8.5.0 (Axiom V5.0 - Smart Push & Buffered IO - FULL RELEASE)
 *
 * [AXIOM V5.0 CHANGELOG]
 * 1. [性能] 引入“差异化推送” (Diff-Push) 机制。
 * - 仅在管理员在线时，每 1 秒计算一次数据快照差异并推送。
 * - 仅推送发生变化的字段，大幅降低 WebSocket 带宽和前端重绘压力。
 * 2. [稳定性] 实现“异步缓冲写入队列” (TrafficBuffer)。
 * - 流量增量不再实时写入 DB，而是暂存内存。
 * - 每 10 秒批量执行一次 DB 事务，彻底解决高并发下的 SQLITE_BUSY 问题。
 * 3. [架构] 配置管理升级为 EnvironmentFile 模式。
 * - 端口修改不再通过 sed 暴力替换，而是生成 /etc/wss-panel/wss.env。
 * 4. [解耦] 系统状态 (CPU/RAM) 监控独立为 3 秒低频循环。
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

// --- [AXIOM V5.0] 路径与配置 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
const ENV_FILE_PATH = path.join(PANEL_DIR, 'wss.env'); // 新增：环境变量文件
const DB_PATH = path.join(PANEL_DIR, 'wss_panel.db');
const ROOT_HASH_FILE = path.join(PANEL_DIR, 'root_hash.txt');
const AUDIT_LOG_PATH = path.join(PANEL_DIR, 'audit.log');
const SECRET_KEY_PATH = path.join(PANEL_DIR, 'secret_key.txt');
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');

const ROOT_USERNAME = "root";
const GIGA_BYTE = 1024 * 1024 * 1024;
const SHELL_DEFAULT = "/sbin/nologin";
const CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'UDPGW',
    'wss_panel': 'Web Panel'
};

// 默认配置
let config = {
    panel_port: 54321,
    wss_http_port: 80,
    wss_tls_port: 443,
    stunnel_port: 444,
    udpgw_port: 7300,
    internal_forward_port: 22,
    internal_api_port: 54322,
    internal_api_secret: "default-secret",
    panel_api_url: "http://127.0.0.1:54321/internal"
};

// 加载配置
try {
    if (fsSync.existsSync(CONFIG_PATH)) {
        const loaded = JSON.parse(fsSync.readFileSync(CONFIG_PATH, 'utf8'));
        config = { ...config, ...loaded };
        console.log(`[INIT] 配置已加载: Panel Port ${config.panel_port}`);
    } else {
        // 写入默认配置
        fsSync.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
    }
} catch (e) {
    console.error(`[INIT] 配置加载失败，使用默认值: ${e.message}`);
}

// --- 全局状态管理 (Global State) ---
let db;
let wssIpc = null;
let wssUiPool = new Set(); // 在线管理员连接池

// [AXIOM V5.0] 内存缓冲与快照
const workerStatsCache = new Map(); // Map<WorkerID, Payload>
const trafficBuffer = new Map();    // Map<Username, DeltaBytes>
let lastUiSnapshot = {};            // 上一次推送给 UI 的完整数据快照 (用于 Diff)
let globalFuseLimitKbps = 0;        // 全局熔断阈值

// sudo 许可命令白名单
const SUDO_COMMANDS = new Set([
    'useradd', 'usermod', 'userdel', 'gpasswd', 'chpasswd', 'pkill',
    'iptables', 'iptables-save', 'journalctl', 'systemctl', 'getent', 'sed',
    'systemctl is-active', 'systemctl daemon-reload'
]);

// --- 辅助函数 ---

function loadSecretKey() {
    try {
        return fsSync.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
    } catch (e) {
        const key = crypto.randomBytes(32).toString('hex');
        fsSync.writeFileSync(SECRET_KEY_PATH, key, 'utf8');
        return key;
    }
}

// [AXIOM V5.0] 更新环境变量文件
async function updateEnvFile(conf) {
    const content = [
        `# WSS Panel Environment Variables (Auto-generated)`,
        `PANEL_PORT=${conf.panel_port}`,
        `WSS_HTTP_PORT=${conf.wss_http_port}`,
        `WSS_TLS_PORT=${conf.wss_tls_port}`,
        `STUNNEL_PORT=${conf.stunnel_port}`,
        `UDPGW_PORT=${conf.udpgw_port}`,
        `INTERNAL_FORWARD_PORT=${conf.internal_forward_port}`,
        `NODE_PATH=/usr/lib/node_modules:/usr/local/lib/node_modules:${PANEL_DIR}/node_modules`
    ].join('\n');
    
    try {
        await fs.writeFile(ENV_FILE_PATH, content, 'utf8');
        console.log(`[CONFIG] 环境变量文件已更新: ${ENV_FILE_PATH}`);
    } catch (e) {
        console.error(`[CONFIG] 写入环境变量文件失败: ${e.message}`);
        throw e;
    }
}

async function safeRunCommand(command, inputData = null) {
    let fullCommand = [...command];
    let baseCommand = command[0];
    if (command[0] === 'systemctl' && (command[1] === 'is-active' || command[1] === 'daemon-reload')) {
        baseCommand = `systemctl ${command[1]}`;
    }
    
    if (SUDO_COMMANDS.has(baseCommand)) {
        fullCommand.unshift('sudo');
    }

    if (command[0] === 'chpasswd' || (command[0] === 'sudo' && command[1] === 'chpasswd')) {
        return new Promise((resolve) => {
            const child = spawn(fullCommand[0], fullCommand.slice(1), { stdio: ['pipe', 'pipe', 'pipe'] });
            let out = '', err = '';
            child.stdout.on('data', d => out += d);
            child.stderr.on('data', d => err += d);
            child.on('close', code => resolve({ success: code === 0, output: code === 0 ? out.trim() : err.trim() }));
            child.on('error', e => resolve({ success: false, output: e.message }));
            if (inputData) {
                child.stdin.write(inputData);
                child.stdin.end();
            }
        });
    }

    try {
        const { stdout, stderr } = await asyncExecFile(fullCommand[0], fullCommand.slice(1), { timeout: 15000, input: inputData });
        return { success: true, output: stdout.trim() };
    } catch (e) {
        if (baseCommand.includes('is-active') && e.code === 3) return { success: false, output: 'inactive' };
        return { success: false, output: e.stderr || e.message };
    }
}

async function logAction(action, user, details) {
    const log = `[${new Date().toISOString()}] [USER:${user}] ACTION:${action} DETAILS: ${details}\n`;
    fs.appendFile(AUDIT_LOG_PATH, log).catch(console.error);
}

async function manageIpIptables(ip, action, chainName = 'WSS_IP_BLOCK') {
    if (action === 'check') {
        const result = await safeRunCommand(['iptables', '-C', chainName, '-s', ip, '-j', 'DROP']);
        return { success: result.success };
    }
    let command;
    if (action === 'block') {
        await safeRunCommand(['iptables', '-D', chainName, '-s', ip, '-j', 'DROP']); // Prevent duplicates
        command = ['iptables', '-I', chainName, '1', '-s', ip, '-j', 'DROP'];
    } else if (action === 'unblock') {
        command = ['iptables', '-D', chainName, '-s', ip, '-j', 'DROP'];
    } else {
        return { success: false, output: "Invalid action" };
    }
    const result = await safeRunCommand(command);
    if (result.success) {
        safeRunCommand(['iptables-save']).then(({ output }) => fs.writeFile('/etc/iptables/rules.v4', output)).catch(()=>{});
    }
    return result;
}

// --- 数据库初始化 ---
async function initDb() {
    db = await open({ filename: DB_PATH, driver: sqlite3.Database });
    await db.exec('PRAGMA journal_mode = WAL;');
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT,
            status TEXT, expiration_date TEXT, quota_gb REAL,
            usage_gb REAL DEFAULT 0.0, rate_kbps INTEGER DEFAULT 0,
            max_connections INTEGER DEFAULT 0, require_auth_header INTEGER DEFAULT 1,
            active_connections INTEGER DEFAULT 0, status_text TEXT, allow_shell INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ip_bans ( ip TEXT PRIMARY KEY, reason TEXT, added_by TEXT, timestamp TEXT );
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            date TEXT NOT NULL, usage_gb REAL DEFAULT 0.0, UNIQUE(username, date)
        );
        CREATE TABLE IF NOT EXISTS global_settings ( key TEXT PRIMARY KEY, value TEXT );
    `);
    
    const row = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
    if (row) globalFuseLimitKbps = parseInt(row.value) || 0;
    console.log(`[DB] 数据库初始化完成。全局熔断阈值: ${globalFuseLimitKbps} KB/s`);
}

async function getUserByUsername(username) {
    return db.get('SELECT * FROM users WHERE username = ?', username);
}

// --- 广播与通知 ---
function broadcastToFrontends(msg) {
    const str = JSON.stringify(msg);
    wssUiPool.forEach(ws => {
        if (ws.readyState === 1) ws.send(str);
    });
}

function broadcastToProxies(msg) {
    if (wssIpc) {
        const str = JSON.stringify(msg);
        wssIpc.clients.forEach(c => {
            if (c.readyState === 1) c.send(str);
        });
    }
}

async function kickUserFromProxy(username) {
    broadcastToProxies({ action: 'kick', username });
}


// --- [AXIOM V5.0] 核心逻辑 ---

// 1. 缓冲写入
function accumulateTraffic(username, deltaBytes) {
    if (deltaBytes <= 0) return;
    const current = trafficBuffer.get(username) || 0;
    trafficBuffer.set(username, current + deltaBytes);
}

async function flushTrafficBuffer() {
    if (trafficBuffer.size === 0) return;
    const bufferSnapshot = new Map(trafficBuffer);
    trafficBuffer.clear();
    const today = new Date().toISOString().split('T')[0];
    const usersToUpdate = [];
    for (const [username, delta] of bufferSnapshot) {
        usersToUpdate.push({ username, deltaGb: delta / GIGA_BYTE });
    }
    try {
        await db.run('BEGIN TRANSACTION');
        for (const u of usersToUpdate) {
            await db.run('UPDATE users SET usage_gb = usage_gb + ? WHERE username = ?', [u.deltaGb, u.username]);
            await db.run('INSERT OR IGNORE INTO traffic_history (username, date, usage_gb) VALUES (?, ?, 0.0)', [u.username, today]);
            await db.run('UPDATE traffic_history SET usage_gb = usage_gb + ? WHERE username = ? AND date = ?', [u.deltaGb, u.username, today]);
        }
        await db.run('COMMIT');
    } catch (e) {
        console.error(`[BUFFER] 流量落盘失败: ${e.message}`);
        await db.run('ROLLBACK').catch(() => {});
        for (const [username, delta] of bufferSnapshot) accumulateTraffic(username, delta);
    }
}

// 2. Diff 计算
function computeDiff(currentStats, lastStats) {
    const diff = {};
    let hasChanges = false;
    if (currentStats.users && lastStats.users) {
        diff.users = {};
        for (const user in currentStats.users) {
            const currUser = currentStats.users[user];
            const lastUser = lastStats.users[user] || {};
            let userDiff = {};
            let userChanged = false;
            if (currUser.speed_kbps.upload !== (lastUser.speed_kbps?.upload)) { userDiff.speed_kbps = currUser.speed_kbps; userChanged = true; }
            if (currUser.connections !== lastUser.connections) { userDiff.connections = currUser.connections; userChanged = true; }
            if (currUser.status !== lastUser.status) { userDiff.status = currUser.status; userDiff.status_text = currUser.status_text; userChanged = true; }
            if (userChanged) { diff.users[user] = userDiff; hasChanges = true; }
        }
    } else if (currentStats.users) { diff.users = currentStats.users; hasChanges = true; }
    if (currentStats.system) { diff.system = currentStats.system; hasChanges = true; }
    return hasChanges ? diff : null;
}

// 3. 聚合
function aggregateWorkerStats() {
    const aggregated = { users: {}, live_ips: {}, system: { active_connections_total: 0 } };
    for (const [workerId, payload] of workerStatsCache) {
        const { stats, live_ips } = payload;
        Object.assign(aggregated.live_ips, live_ips);
        for (const username in stats) {
            const s = stats[username];
            if (!aggregated.users[username]) {
                aggregated.users[username] = {
                    speed_kbps: { upload: 0, download: 0 },
                    connections: 0,
                    status: 'active',
                    status_text: '启用 (Active)'
                };
            }
            const u = aggregated.users[username];
            u.speed_kbps.upload += s.speed_kbps.upload;
            u.speed_kbps.download += s.speed_kbps.download;
            u.connections += s.connections;
            aggregated.system.active_connections_total += s.connections;
        }
    }
    return aggregated;
}


// --- Express Setup ---
app.use(session({
    secret: loadSecretKey(),
    resave: false, saveUninitialized: true,
    cookie: { maxAge: 86400000 } // 24h
}));
app.use(bodyParser.json());
app.use(express.static(PANEL_DIR));

// Login Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 5,
    handler: (req, res) => res.redirect(`/login.html?error=${encodeURIComponent('登录尝试次数过多，请稍后再试')}`)
});

const authMiddleware = (req, res, next) => {
    if (req.session.loggedIn) next();
    else res.status(401).json({ success: false, message: 'Unauthorized' });
};

// --- API Routes: Auth ---
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const rootHash = await fs.readFile(ROOT_HASH_FILE, 'utf8');
        if (username === ROOT_USERNAME && await bcrypt.compare(password, rootHash.trim())) {
            req.session.loggedIn = true;
            req.session.username = username;
            await logAction("LOGIN", username, "Web UI Login Success");
            return res.redirect('/index.html');
        }
    } catch (e) {}
    await logAction("LOGIN_FAIL", username, "Web UI Login Failed");
    res.redirect('/login.html?error=' + encodeURIComponent('用户名或密码错误'));
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

// --- API Routes: System ---
app.get('/api/system/status', authMiddleware, async (req, res) => {
    const data = await getSystemStatsFull();
    res.json({ success: true, ...data });
});

app.post('/api/system/control', authMiddleware, async (req, res) => {
    const { service, action } = req.body;
    if (!CORE_SERVICES[service] || action !== 'restart') return res.status(400).json({ success: false, message: "Invalid request" });
    const result = await safeRunCommand(['systemctl', action, service]);
    if (result.success) await logAction("SVC_CONTROL", req.session.username, `Restarted ${service}`);
    res.json(result);
});

app.post('/api/system/logs', authMiddleware, async (req, res) => {
    const { service } = req.body;
    if (!CORE_SERVICES[service]) return res.status(400).json({ success: false });
    const result = await safeRunCommand(['journalctl', '-u', service, '-n', '50', '--no-pager', '--utc']);
    res.json({ success: true, logs: result.output });
});

app.get('/api/system/audit_logs', authMiddleware, async (req, res) => {
    try {
        const logs = (await fs.readFile(AUDIT_LOG_PATH, 'utf8')).trim().split('\n').filter(l => l).slice(-50);
        res.json({ success: true, logs });
    } catch (e) { res.json({ success: true, logs: [] }); }
});

app.get('/api/system/active_ips', authMiddleware, async (req, res) => {
    const agg = aggregateWorkerStats();
    const active_ips = [];
    for (const [ip, user] of Object.entries(agg.live_ips)) {
        const is_banned = (await manageIpIptables(ip, 'check')).success;
        active_ips.push({ ip, username: user, is_banned });
    }
    res.json({ success: true, active_ips });
});

// --- API Routes: Settings ---
app.get('/api/settings/config', authMiddleware, (req, res) => {
    const { internal_api_secret, ...safeConf } = config;
    res.json({ success: true, config: safeConf });
});

app.post('/api/settings/config', authMiddleware, async (req, res) => {
    const newConf = req.body;
    try {
        const mergedConfig = { ...config, ...newConf };
        mergedConfig.panel_api_url = `http://127.0.0.1:${mergedConfig.panel_port}/internal`;
        
        await fs.writeFile(CONFIG_PATH, JSON.stringify(mergedConfig, null, 2));
        await updateEnvFile(mergedConfig);
        config = mergedConfig;

        const servicesToRestart = ['wss', 'stunnel4', 'udpgw'];
        if (newConf.panel_port !== config.panel_port) servicesToRestart.push('wss_panel');
        
        (async () => {
            await safeRunCommand(['systemctl', 'daemon-reload']);
            for (const svc of servicesToRestart) await safeRunCommand(['systemctl', 'restart', svc]);
        })();

        await logAction("CONFIG_UPDATE", req.session.username, "Updated system ports and restarted services");
        res.json({ success: true, message: '配置已保存，服务正在重启...' });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.get('/api/settings/global', authMiddleware, async (req, res) => {
    res.json({ success: true, settings: { fuse_threshold_kbps: globalFuseLimitKbps } });
});

app.post('/api/settings/global', authMiddleware, async (req, res) => {
    const { fuse_threshold_kbps } = req.body;
    const val = parseInt(fuse_threshold_kbps) || 0;
    globalFuseLimitKbps = val;
    await db.run("INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", 'fuse_threshold_kbps', val.toString());
    await logAction("SETTINGS_GLOBAL", req.session.username, `Set fuse threshold to ${val}`);
    res.json({ success: true, message: '全局设置已保存' });
});

app.get('/api/settings/hosts', authMiddleware, async (req, res) => {
    try {
        const data = await fs.readFile(HOSTS_DB_PATH, 'utf8');
        res.json({ success: true, hosts: JSON.parse(data) });
    } catch (e) { res.json({ success: true, hosts: [] }); }
});

app.post('/api/settings/hosts', authMiddleware, async (req, res) => {
    try {
        const hosts = req.body.hosts || [];
        await fs.writeFile(HOSTS_DB_PATH, JSON.stringify(hosts, null, 4));
        broadcastToProxies({ action: 'reload_hosts' });
        broadcastToFrontends({ type: 'hosts_changed' });
        await logAction("HOSTS_UPDATE", req.session.username, `Updated hosts list (${hosts.length} items)`);
        res.json({ success: true, message: 'Hosts 已保存' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/settings/change-password', authMiddleware, async (req, res) => {
    const { old_password, new_password } = req.body;
    const rootHash = await fs.readFile(ROOT_HASH_FILE, 'utf8');
    if (await bcrypt.compare(old_password, rootHash.trim())) {
        const newHash = await bcrypt.hash(new_password, 12);
        await fs.writeFile(ROOT_HASH_FILE, newHash);
        await logAction("PASS_CHANGE", req.session.username, "Changed admin password");
        res.json({ success: true, message: '密码修改成功' });
    } else {
        res.status(403).json({ success: false, message: '旧密码错误' });
    }
});

// --- API Routes: User Management (完整逻辑) ---
app.get('/api/users/list', authMiddleware, async (req, res) => {
    const users = await db.all('SELECT * FROM users');
    res.json({ success: true, users });
});

app.post('/api/users/add', authMiddleware, async (req, res) => {
    const { username, password, expiration_days, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "Missing fields" });

    const exists = await db.get("SELECT username FROM users WHERE username = ?", username);
    if (exists) return res.status(409).json({ success: false, message: "User exists" });

    try {
        await safeRunCommand(['useradd', '-m', '-s', SHELL_DEFAULT, username]);
        await safeRunCommand(['chpasswd'], `${username}:${password}`);
        await safeRunCommand(['usermod', '-U', username]);
        if (allow_shell) await safeRunCommand(['usermod', '-a', '-G', 'shell_users', username]);

        const hash = await bcrypt.hash(password, 12);
        const expiry = new Date(Date.now() + expiration_days * 86400000).toISOString().split('T')[0];
        
        await db.run(`INSERT INTO users (username, password_hash, created_at, status, expiration_date, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell, status_text) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, '启用 (Active)')`,
            [username, hash, new Date().toISOString(), expiry, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell]);

        broadcastToFrontends({ type: 'users_changed' });
        broadcastToProxies({ action: 'update_limits', username, limits: { rate_kbps, max_connections, require_auth_header } });
        
        await logAction("USER_ADD", req.session.username, `Created user ${username}`);
        res.json({ success: true, message: '用户创建成功' });
    } catch (e) {
        await safeRunCommand(['userdel', '-r', username]);
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/users/delete', authMiddleware, async (req, res) => {
    const { username } = req.body;
    try {
        await kickUserFromProxy(username);
        await safeRunCommand(['pkill', '-9', '-u', username]);
        await safeRunCommand(['userdel', '-r', username]);
        await db.run('DELETE FROM users WHERE username = ?', username);
        await db.run('DELETE FROM traffic_history WHERE username = ?', username);
        
        broadcastToProxies({ action: 'delete', username });
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_DEL", req.session.username, `Deleted user ${username}`);
        res.json({ success: true, message: '用户已删除' });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/users/set_settings', authMiddleware, async (req, res) => {
    const { username, expiry_date, quota_gb, rate_kbps, max_connections, new_password, require_auth_header, allow_shell } = req.body;
    try {
        if (new_password) {
            const hash = await bcrypt.hash(new_password, 12);
            await db.run("UPDATE users SET password_hash = ? WHERE username = ?", [hash, username]);
            await safeRunCommand(['chpasswd'], `${username}:${new_password}`);
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
        }

        if (allow_shell) await safeRunCommand(['usermod', '-a', '-G', 'shell_users', username]);
        else {
            await safeRunCommand(['gpasswd', '-d', username, 'shell_users']);
            await safeRunCommand(['pkill', '-9', '-u', username]);
        }

        await db.run(`UPDATE users SET expiration_date=?, quota_gb=?, rate_kbps=?, max_connections=?, require_auth_header=?, allow_shell=? WHERE username=?`,
            [expiry_date, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell, username]);
        
        broadcastToProxies({ action: 'update_limits', username, limits: { rate_kbps, max_connections, require_auth_header } });
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_EDIT", req.session.username, `Updated ${username}`);
        res.json({ success: true, message: '设置已更新' });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/api/users/status', authMiddleware, async (req, res) => {
    const { username, action } = req.body;
    try {
        const status = action === 'enable' ? 'active' : 'paused';
        const text = action === 'enable' ? '启用 (Active)' : '暂停 (Manual)';
        await db.run("UPDATE users SET status=?, status_text=? WHERE username=?", [status, text, username]);
        
        if (action === 'enable') await safeRunCommand(['usermod', '-U', username]);
        else {
            await safeRunCommand(['usermod', '-L', username]);
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
        }
        
        broadcastToFrontends({ type: 'users_changed' });
        await logAction("USER_STATUS", req.session.username, `${action} user ${username}`);
        res.json({ success: true, message: `用户状态已更新为 ${status}` });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/users/reset_traffic', authMiddleware, async (req, res) => {
    const { username } = req.body;
    try {
        await db.run("UPDATE users SET usage_gb = 0 WHERE username = ?", username);
        await db.run("DELETE FROM traffic_history WHERE username = ?", username);
        
        // 如果因流量超额被停用，自动激活
        const user = await db.get("SELECT status FROM users WHERE username = ?", username);
        if (user.status === 'exceeded') {
             await db.run("UPDATE users SET status='active', status_text='启用 (Active)' WHERE username=?", username);
             await safeRunCommand(['usermod', '-U', username]);
        }
        
        broadcastToProxies({ action: 'reset_traffic', username });
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("TRAFFIC_RESET", req.session.username, `Reset traffic for ${username}`);
        res.json({ success: true, message: '流量已重置' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/users/kill_all', authMiddleware, async (req, res) => {
    const { username } = req.body;
    try {
        await kickUserFromProxy(username);
        await safeRunCommand(['pkill', '-9', '-u', username]);
        res.json({ success: true, message: '强制下线指令已发送' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/users/batch-action', authMiddleware, async (req, res) => {
    const { action, usernames, days } = req.body;
    try {
        await db.run('BEGIN TRANSACTION');
        for (const u of usernames) {
            if (action === 'delete') {
                await kickUserFromProxy(u);
                await safeRunCommand(['pkill', '-9', '-u', u]);
                await safeRunCommand(['userdel', '-r', u]);
                await db.run('DELETE FROM users WHERE username=?', u);
            } else if (action === 'pause') {
                await db.run("UPDATE users SET status='paused', status_text='暂停 (Manual)' WHERE username=?", u);
                await safeRunCommand(['usermod', '-L', u]);
                await kickUserFromProxy(u);
            } else if (action === 'enable') {
                await db.run("UPDATE users SET status='active', status_text='启用 (Active)' WHERE username=?", u);
                await safeRunCommand(['usermod', '-U', u]);
            } else if (action === 'renew') {
                const user = await db.get("SELECT expiration_date FROM users WHERE username=?", u);
                let base = new Date();
                if (user && user.expiration_date && new Date(user.expiration_date) > base) base = new Date(user.expiration_date);
                const newExp = new Date(base.getTime() + days * 86400000).toISOString().split('T')[0];
                await db.run("UPDATE users SET expiration_date=?, status='active', status_text='启用 (Active)' WHERE username=?", [newExp, u]);
                await safeRunCommand(['usermod', '-U', u]);
            }
        }
        await db.run('COMMIT');
        broadcastToFrontends({ type: 'users_changed' });
        if (action === 'delete' || action === 'pause') broadcastToProxies({ action: 'batch_update' }); // Generic signal
        
        await logAction("BATCH", req.session.username, `Action ${action} on ${usernames.length} users`);
        res.json({ success: true, message: '批量操作完成' });
    } catch (e) {
        await db.run('ROLLBACK');
        res.status(500).json({ success: false, message: e.message });
    }
});

app.get('/api/users/traffic-history', authMiddleware, async (req, res) => {
    const { username } = req.query;
    const history = await db.all("SELECT date, usage_gb FROM traffic_history WHERE username=? ORDER BY date DESC LIMIT 30", username);
    res.json({ success: true, history: history.reverse() });
});

// --- API Routes: IP Ban & Tools ---
app.post('/api/ips/ban_global', authMiddleware, async (req, res) => {
    const { ip, reason } = req.body;
    const result = await manageIpIptables(ip, 'block');
    if (result.success) {
        await db.run("INSERT OR REPLACE INTO ip_bans (ip, reason, added_by, timestamp) VALUES (?,?,?,?)", [ip, reason, req.session.username, new Date().toISOString()]);
        await logAction("IP_BAN", req.session.username, `Banned ${ip}`);
        res.json({ success: true, message: 'IP 已封禁' });
    } else res.status(500).json(result);
});

app.post('/api/ips/unban_global', authMiddleware, async (req, res) => {
    const { ip } = req.body;
    const result = await manageIpIptables(ip, 'unblock');
    if (result.success) {
        await db.run("DELETE FROM ip_bans WHERE ip=?", ip);
        await logAction("IP_UNBAN", req.session.username, `Unbanned ${ip}`);
        res.json({ success: true, message: 'IP 已解封' });
    } else res.status(500).json(result);
});

app.get('/api/ips/global_list', authMiddleware, async (req, res) => {
    const bans = await db.all("SELECT * FROM ip_bans");
    const map = {}; bans.forEach(b => map[b.ip] = b);
    res.json({ success: true, global_bans: map });
});

app.post('/api/utils/find_sni', authMiddleware, async (req, res) => {
    const { hostname } = req.body;
    try {
        const { address } = await dns.promises.lookup(hostname);
        const socket = tls.connect({ port: 443, host: address, servername: hostname, timeout: 5000, rejectUnauthorized: false }, () => {
            const cert = socket.getPeerCertificate();
            socket.end();
            const alt = cert.subjectaltname ? cert.subjectaltname.split(',').map(s => s.trim().replace('DNS:', '')) : [];
            res.json({ success: true, ip: address, hosts: alt });
        });
        socket.on('error', e => res.status(500).json({ success: false, message: e.message }));
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- Internal API (Proxy Auth) ---
internalApi.post('/auth', async (req, res) => {
    const { username, password } = req.body;
    if (req.headers['x-internal-secret'] !== config.internal_api_secret && req.ip !== '127.0.0.1' && req.ip !== '::1') {
        return res.status(403).json({ success: false });
    }
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    if (user && await bcrypt.compare(password, user.password_hash)) {
        if (user.status !== 'active') return res.status(403).json({ success: false, message: 'User locked' });
        res.json({ 
            success: true, 
            limits: { rate_kbps: user.rate_kbps, max_connections: user.max_connections },
            require_auth_header: user.require_auth_header 
        });
    } else {
        res.status(401).json({ success: false });
    }
});

// --- 系统状态获取 ---
async function getSystemStatsFull() {
    const mem = os.totalmem();
    const memFree = os.freemem();
    let disk = 0;
    try { const { stdout } = await asyncExecFile('df', ['-P', '/']); disk = parseFloat(stdout.split('\n')[1].split(/\s+/)[4]); } catch(e){}
    
    const services = {};
    for (const [k, v] of Object.entries(CORE_SERVICES)) {
        services[k] = { name: v, status: (await safeRunCommand(['systemctl', 'is-active', k])).output === 'active' ? 'running' : 'failed' };
    }
    
    const users = await db.all('SELECT status FROM users');
    const stats = { total: users.length, active: 0, paused: 0, expired: 0, exceeded: 0, fused: 0, total_traffic_gb: 0 };
    const all_users = await db.all('SELECT usage_gb FROM users');
    all_users.forEach(u => stats.total_traffic_gb += u.usage_gb);
    users.forEach(u => { if(stats[u.status]!==undefined) stats[u.status]++; });
    
    // 实时活跃连接数 (From memory cache)
    const agg = aggregateWorkerStats();
    stats.active = Object.keys(agg.live_ips).length;

    const ports = [
        { name: 'WSS_HTTP', port: config.wss_http_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'WSS_TLS', port: config.wss_tls_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'STUNNEL', port: config.stunnel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'UDPGW', port: config.udpgw_port, protocol: 'UDP', status: 'LISTEN' },
        { name: 'PANEL', port: config.panel_port, protocol: 'TCP', status: 'LISTEN' }
    ];

    return {
        cpu_usage: os.loadavg()[0] * 10, 
        memory_used_gb: (mem - memFree) / GIGA_BYTE,
        memory_total_gb: mem / GIGA_BYTE,
        disk_used_percent: disk,
        services,
        ports,
        user_stats: stats
    };
}


// --- 定时任务循环 ---

// 1. [10秒] 缓冲区刷盘
setInterval(flushTrafficBuffer, 10000);

// 2. [60秒] 维护任务
setInterval(async () => {
    const users = await db.all('SELECT * FROM users');
    const now = new Date();
    let changed = false;
    
    await db.run('BEGIN TRANSACTION');
    for (const u of users) {
        let newStatus = u.status;
        let newStatusText = u.status_text;
        
        if (u.expiration_date && new Date(u.expiration_date) < now) {
            newStatus = 'expired'; newStatusText = '已到期 (Expired)';
        }
        if (u.quota_gb > 0 && u.usage_gb >= u.quota_gb) {
            newStatus = 'exceeded'; newStatusText = '超额 (Quota)';
        }
        
        if (newStatus !== u.status && u.status !== 'paused' && u.status !== 'fused') {
            await db.run('UPDATE users SET status=?, status_text=? WHERE username=?', [newStatus, newStatusText, u.username]);
            if (newStatus !== 'active') {
                await safeRunCommand(['usermod', '-L', u.username]);
                await kickUserFromProxy(u.username);
            }
            changed = true;
        }
    }
    await db.run('COMMIT');
    if (changed) broadcastToFrontends({ type: 'users_changed' });
}, 60000);

// 3. [1秒] UI Diff 推送
setInterval(async () => {
    if (wssUiPool.size === 0) return;
    const currentAggregated = aggregateWorkerStats();
    
    // 熔断检查
    if (globalFuseLimitKbps > 0) {
        for (const [user, data] of Object.entries(currentAggregated.users)) {
            const totalSpeed = data.speed_kbps.upload + data.speed_kbps.download;
            if (totalSpeed > globalFuseLimitKbps) {
                await db.run("UPDATE users SET status='fused', status_text='熔断 (Fused)' WHERE username=?", user);
                await safeRunCommand(['usermod', '-L', user]);
                await kickUserFromProxy(user);
                broadcastToFrontends({ type: 'users_changed' });
            }
        }
    }

    const diff = computeDiff(currentAggregated, lastUiSnapshot);
    if (diff) {
        broadcastToFrontends({ type: 'live_update', payload: diff });
        lastUiSnapshot = JSON.parse(JSON.stringify(currentAggregated));
    }
}, 1000);

// 4. [3秒] 系统状态推送
setInterval(async () => {
    if (wssUiPool.size === 0) return;
    const sysData = await getSystemStatsFull();
    broadcastToFrontends({ type: 'live_update', payload: { system: sysData } });
}, 3000);


// --- WebSocket Server ---
function startWebSocketServers(server) {
    wssIpc = new WebSocketServer({ noServer: true, path: '/ipc' });
    wssIpc.on('connection', (ws, req) => {
        const workerId = req.headers['x-worker-id'] || 'unknown';
        ws.on('message', (msg) => {
            try {
                const data = JSON.parse(msg);
                if (data.type === 'stats_update') {
                    workerStatsCache.set(workerId, data.payload);
                    for (const [u, s] of Object.entries(data.payload.stats)) {
                        accumulateTraffic(u, (s.traffic_delta_up || 0) + (s.traffic_delta_down || 0));
                    }
                }
            } catch(e) {}
        });
        ws.on('close', () => workerStatsCache.delete(workerId));
    });

    const wssUi = new WebSocketServer({ noServer: true, path: '/ws/ui' });
    wssUi.on('connection', (ws, req) => {
        if (!req.session.loggedIn) { ws.close(); return; }
        wssUiPool.add(ws);
        ws.send(JSON.stringify({ type: 'status_connected' }));
        ws.on('close', () => wssUiPool.delete(ws));
    });

    server.on('upgrade', (request, socket, head) => {
        if (request.url === '/ipc') {
            if (request.headers['x-internal-secret'] === config.internal_api_secret) {
                wssIpc.handleUpgrade(request, socket, head, ws => wssIpc.emit('connection', ws, request));
            } else { socket.destroy(); }
        } else if (request.url === '/ws/ui') {
            sessionMiddleware(request, {}, () => {
                wssUi.handleUpgrade(request, socket, head, ws => {
                    if (request.session && request.session.loggedIn) wssUi.emit('connection', ws, request);
                    else socket.destroy();
                });
            });
        }
    });
}

const sessionMiddleware = session({
    secret: loadSecretKey(),
    resave: false, saveUninitialized: true,
    cookie: { maxAge: 86400000 }
});

// --- 启动 ---
(async () => {
    await initDb();
    const server = http.createServer(app);
    startWebSocketServers(server);
    server.listen(config.panel_port, '0.0.0.0', () => {
        console.log(`[START] Axiom V5.0 Control Plane running on port ${config.panel_port}`);
    });
})();
