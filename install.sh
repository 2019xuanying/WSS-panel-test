#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V5.0.0 (Axiom Refactor - Native UDPGW & EnvFile)
#
# [AXIOM V5.0 CHANGELOG]
# - 移除: BadVPN-udpgw 编译流程 (已由 Node.js 原生实现替代)。
# - 移除: udpgw.service (现在是 wss.service 的一部分)。
# - 新增: EnvironmentFile 支持 (/etc/wss-panel/wss.env)。
# - 优化: 极速部署，无需编译等待。
# ==========================================================


# =============================
# 文件路径定义
# =============================
REPO_ROOT=$(dirname "$0")

# 安装目录
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log" 
CONFIG_PATH="$PANEL_DIR/config.json"
ENV_FILE_PATH="$PANEL_DIR/wss.env" # [AXIOM V5.0] 新增
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" 
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"

# 脚本目标路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"

# SSHD Stunnel 路径
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"


# 创建基础目录
mkdir -p "$PANEL_DIR" 
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# [AXIOM V5.0] 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (Axiom V5.0) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

# 1. 端口
read -p "  1. WSS HTTP 端口 [80]: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "  2. WSS TLS 端口 [443]: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "  3. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "  4. UDPGW (Native) 端口 [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  5. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

read -p "  6. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p "  7. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

# 2. 服务用户 (最小权限)
read -p "  8. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}

# --- IPC (进程间通信) 端口配置 ---
INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"

echo "---------------------------------"
echo "配置确认："
echo "Panel 用户: $panel_user"
echo "WSS (80/443) -> $WSS_HTTP_PORT/$WSS_TLS_PORT (转发至 $INTERNAL_FORWARD_PORT)"
echo "UDPGW (Native) -> $UDPGW_PORT (集成在 WSS 进程中)"
echo "Stunnel (444) -> $STUNNEL_PORT (转发至 $SSHD_STUNNEL_PORT)"
echo "Web Panel (HTTP) -> $PANEL_PORT"
echo "---------------------------------"


# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。面板端口: $PANEL_PORT"
else
    echo "==== 管理面板配置 (首次或重置) ===="
    
    echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
    while true; do
      read -s -p "面板密码: " pw1 && echo
      read -s -p "请再次确认密码: " pw2 && echo
      if [ -z "$pw1" ]; then
        echo "密码不能为空，请重新输入。"
        continue
      fi
      if [ "$pw1" != "$pw2" ]; then
        echo "两次输入不一致，请重试。"
        continue
      fi
      PANEL_ROOT_PASS_RAW="$pw1"
      break
    done
fi


echo "----------------------------------"
echo "==== 系统清理与依赖检查 (V5.0) ===="
# 停止所有相关服务并清理旧文件
systemctl stop wss stunnel4 udpgw wss_panel sshd_stunnel || true
# [AXIOM V5.0] 禁用旧的 udpgw 服务 (如果存在)
systemctl disable udpgw || true
rm -f /etc/systemd/system/udpgw.service

# 依赖检查和安装
apt update -y
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js (推荐 v18/v20 LTS)..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# [AXIOM V5.0] 移除 cmake, build-essential 等编译依赖，因为不再编译 badvpn
apt install -y wget curl git net-tools openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo || echo "警告: 依赖安装失败，可能影响功能。"

if ! id -u "$panel_user" >/dev/null 2>&1; then
    echo "正在创建系统用户 '$panel_user'..."
    adduser --system --no-create-home "$panel_user"
else
    echo "系统用户 '$panel_user' 已存在。"
fi

echo "安装 Node.js 依赖..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
if ! npm install --production; then
    echo "严重警告: Node.js 核心依赖安装失败。"
    exit 1
fi
echo "Node.js 依赖安装成功。"

# 首次部署，计算 ROOT hash
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    PANEL_ROOT_PASS_HASH=$(node -e "const bcrypt = require('bcrypt'); const hash = bcrypt.hashSync('$PANEL_ROOT_PASS_RAW', 12); console.log(hash);")
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
    echo "使用 bcrypt 生成 ROOT 密码哈希并保存。"
fi

if [ ! -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

if [ ! -f "$INTERNAL_SECRET_PATH" ]; then
    INTERNAL_SECRET=$(openssl rand -hex 32)
    echo "$INTERNAL_SECRET" > "$INTERNAL_SECRET_PATH"
fi
INTERNAL_SECRET=$(cat "$INTERNAL_SECRET_PATH")

chmod 600 "$ROOT_HASH_FILE"
chmod 600 "$SECRET_KEY_FILE"
chmod 600 "$INTERNAL_SECRET_PATH"

echo "正在创建 config.json 配置文件..."
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_http_port": $WSS_HTTP_PORT,
  "wss_tls_port": $WSS_TLS_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL"
}
EOF
chmod 600 "$CONFIG_PATH"

# [AXIOM V5.0] 生成 wss.env 环境变量文件
echo "正在生成 wss.env 环境变量文件..."
tee "$ENV_FILE_PATH" > /dev/null <<EOF
# WSS Panel Environment Variables (Auto-generated)
PANEL_PORT=$PANEL_PORT
WSS_HTTP_PORT=$WSS_HTTP_PORT
WSS_TLS_PORT=$WSS_TLS_PORT
STUNNEL_PORT=$STUNNEL_PORT
UDPGW_PORT=$UDPGW_PORT
INTERNAL_FORWARD_PORT=$INTERNAL_FORWARD_PORT
NODE_PATH=/usr/lib/node_modules:/usr/local/lib/node_modules:$PANEL_DIR/node_modules
EOF
chmod 644 "$ENV_FILE_PATH"

echo "----------------------------------"


# =============================
# 配置 Sudoers
# =============================
echo "==== 配置 Sudoers (最小权限) ===="
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
CMD_USERADD=$(command -v useradd)
CMD_USERMOD=$(command -v usermod)
CMD_USERDEL=$(command -v userdel)
CMD_GPGPASSWD=$(command -v gpasswd)
CMD_CHPASSWD=$(command -v chpasswd)
CMD_PKILL=$(command -v pkill)
CMD_IPTABLES=$(command -v iptables)
CMD_IPTABLES_SAVE=$(command -v iptables-save)
CMD_JOURNALCTL=$(command -v journalctl)
CMD_SYSTEMCTL=$(command -v systemctl)
CMD_GETENT=$(command -v getent)
CMD_SED=$(command -v sed)

tee "$SUDOERS_FILE" > /dev/null <<EOF
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERADD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERMOD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERDEL
$panel_user ALL=(ALL) NOPASSWD: $CMD_GPGPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_CHPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_PKILL
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES_SAVE
$panel_user ALL=(ALL) NOPASSWD: $CMD_JOURNALCTL
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
EOF

chmod 440 "$SUDOERS_FILE"
if ! visudo -c -f "$SUDOERS_FILE"; then
    rm -f "$SUDOERS_FILE"
    exit 1
fi
echo "Sudoers 配置完成。"
echo "----------------------------------"


# =============================
# 内核调优 (Buffer Tuning)
# =============================
echo "==== 配置内核网络参数 (Buffer Tuning) ===="
# [AXIOM V5.0] 依然保留，虽然 Node.js 原生 UDPGW 不直接依赖这些，但对 TCP 性能有益
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
cat >> /etc/sysctl.conf <<EOF
# WSS_NET_START
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 5
# UDP Buffer
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
# WSS_NET_END
EOF
sysctl -p > /dev/null
echo "----------------------------------"

# =============================
# 部署代码文件
# =============================
echo "==== 部署 Node.js 代码文件 ===="
cp "$REPO_ROOT/wss_proxy.js" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
cp "$REPO_ROOT/wss_panel.js" "$PANEL_BACKEND_DEST"
chmod +x "$PANEL_BACKEND_DEST"
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
cp "$REPO_ROOT/app.js" "$PANEL_JS_DEST"
cp "$REPO_ROOT/login.html" "$LOGIN_HTML_DEST"
if [ ! -f "$DB_PATH" ]; then echo "Database will be initialized on start."; fi
[ ! -f "$WSS_LOG_FILE" ] && touch "$WSS_LOG_FILE"
[ ! -f "$PANEL_DIR/audit.log" ] && touch "$PANEL_DIR/audit.log"
[ ! -f "$PANEL_DIR/hosts.json" ] && echo '[]' > "$PANEL_DIR/hosts.json"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 (保持不变)
# =============================
echo "==== 重新安装 Stunnel4 ===="
if ! getent group shell_users >/dev/null; then groupadd shell_users; fi

mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem

# [AXIOM V5.0] 注意：Stunnel 仍使用静态文件配置，因为不支持 EnvironmentFile 注入到 .conf
# 但 API 会使用 sed 来修改它 (兼容旧逻辑)
tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$SSHD_STUNNEL_PORT
EOF

systemctl enable stunnel4
systemctl restart stunnel4
echo "----------------------------------"


# =============================
# [AXIOM V5.0] UDPGW 移除 (已集成)
# =============================
echo "==== 清理旧版 BadVPN UDPGW ===="
if [ -f "/etc/systemd/system/udpgw.service" ]; then
    systemctl stop udpgw || true
    systemctl disable udpgw || true
    rm -f "/etc/systemd/system/udpgw.service"
    echo "已移除独立的 udpgw.service (功能已集成至 wss.service)。"
fi
# 不再需要编译 badvpn
echo "跳过 BadVPN 编译 (使用 Node.js 原生实现)。"
echo "----------------------------------"

# =============================
# IPTABLES & Systemd
# =============================
echo "==== 配置 IPTABLES ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

if ! command -v netfilter-persistent >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent || true
fi
if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES"
    systemctl enable netfilter-persistent || true
    systemctl start netfilter-persistent || true
fi
echo "----------------------------------"

echo "==== 部署 Systemd 服务 (EnvFile Mode) ===="

# 1. WSS Service (Proxy Data Plane)
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
tee "$WSS_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=WSS Node.js Proxy Core (Data Plane)
After=network.target
After=wss_panel.service
BindsTo=wss_panel.service

[Service]
Type=simple
EnvironmentFile=$ENV_FILE_PATH
Environment=PANEL_DIR_ENV=$PANEL_DIR
ExecStart=/usr/bin/node $WSS_PROXY_PATH
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal
# 允许 Node 绑定低端口 (如果不是 root 运行，虽然这里配置为 root)
# AmbientCapabilities=CAP_NET_BIND_SERVICE

ExecStartPre=/bin/bash -c "touch $WSS_LOG_FILE && chmod 644 $WSS_LOG_FILE"

[Install]
WantedBy=multi-user.target
EOF

# 2. WSS Panel Service (Control Plane)
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
tee "$PANEL_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Control Plane)
After=network.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE_PATH
Environment=PANEL_DIR_ENV=$PANEL_DIR
WorkingDirectory=$PANEL_DIR
ExecStart=/usr/bin/node $PANEL_BACKEND_FILE

Restart=on-failure
User=$panel_user
Group=$panel_user

[Install]
WantedBy=multi-user.target
EOF

chown -R "$panel_user:$panel_user" "$PANEL_DIR"
chown "$panel_user:$panel_user" "$WSS_LOG_FILE"
chown "$panel_user:$panel_user" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"

systemctl daemon-reload
systemctl enable wss_panel
systemctl start wss_panel
systemctl enable wss
systemctl start wss
echo "----------------------------------"

# =============================
# SSHD 配置 (保持不变)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
if ! grep -q "^Port $INTERNAL_FORWARD_PORT" "$SSHD_CONFIG" && [ "$INTERNAL_FORWARD_PORT" != "22" ]; then
    sed -i -E "/^[#\s]*Port /d" "$SSHD_CONFIG"
    echo "Port $INTERNAL_FORWARD_PORT" >> "$SSHD_CONFIG"
fi
cat >> "$SSHD_CONFIG" <<EOF
# WSS_TUNNEL_BLOCK_START
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    AllowTcpForwarding yes
# WSS_TUNNEL_BLOCK_END
EOF

cp "$SSHD_CONFIG" "$SSHD_STUNNEL_CONFIG"
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_STUNNEL_CONFIG"
sed -i -E "/^[#\s]*Port /d" "$SSHD_STUNNEL_CONFIG"
sed -i -E "/^[#\s]*ListenAddress /d" "$SSHD_STUNNEL_CONFIG"
cat >> "$SSHD_STUNNEL_CONFIG" <<EOF
# WSS_STUNNEL_BLOCK_START
Port $SSHD_STUNNEL_PORT
ListenAddress 127.0.0.1
ListenAddress ::1
PasswordAuthentication yes
KbdInteractiveAuthentication yes
AllowTcpForwarding yes
AllowGroups shell_users
# WSS_STUNNEL_BLOCK_END
EOF

tee "$SSHD_STUNNEL_SERVICE" > /dev/null <<EOF
[Unit]
Description=OpenSSH Stunnel Service
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run
[Service]
ExecStart=/usr/sbin/sshd -D -f $SSHD_STUNNEL_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF

chmod 600 "$SSHD_CONFIG"
chmod 600 "$SSHD_STUNNEL_CONFIG"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel

# Final Restart
systemctl restart stunnel4
systemctl restart wss_panel
systemctl restart wss

echo "=================================================="
echo "✅ 部署完成！(Axiom V5.0 - Native UDP Edition)"
echo "=================================================="
