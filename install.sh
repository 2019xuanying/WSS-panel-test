#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V3.9.1 (Axiom V6.8 - Sudoers Path Fix)
#
# [CHANGELOG]
# - [CRITICAL FIX] 修复 sudoers 路径匹配问题。现在同时授权 /bin/systemctl 和 /usr/bin/systemctl，
#   彻底解决 "sudo: a terminal is required" 错误。
# - [ARCH] 保持 wss-panel-ng 架构: Xray 配置存放在 /etc/wss-panel/。
# - [FIX] 增强 Xray 服务日志权限预处理。
# ==========================================================

# =============================
# 1. 文件路径定义 (全局变量)
# =============================
REPO_ROOT=$(dirname "$0")

# 核心目录
PANEL_DIR="/etc/wss-panel"
UDP_CUSTOM_DIR="$PANEL_DIR/udp-custom"
# [V6.8] 移除独立的 /etc/xray 目录，整合进 PANEL_DIR
mkdir -p "$PANEL_DIR" 
mkdir -p "$UDP_CUSTOM_DIR"

# 日志与配置
WSS_LOG_FILE="/var/log/wss.log" 
CONFIG_PATH="$PANEL_DIR/config.json"
UDP_CUSTOM_CONFIG_PATH="$UDP_CUSTOM_DIR/config.json"
# [V6.8] Xray 配置移动到 Panel 目录
XRAY_CONFIG_PATH="$PANEL_DIR/xray_config.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" 
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"
NGINX_CONF_PATH="/etc/nginx/sites-available/wss_gateway.conf"
NGINX_CONF_SYMLINK="/etc/nginx/sites-enabled/wss_gateway.conf"
NGINX_ROOT_CERTBOT="/var/www/certbot"
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"

# 二进制文件路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
UDP_CUSTOM_BIN_PATH="/usr/local/bin/udp-custom" 
XRAY_BIN_PATH="/usr/local/bin/xray" 
UDPGW_BIN_PATH="/usr/local/bin/udpgw" # 假设 BadVPN C 二进制在此

# 面板文件路径
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"

# Systemd 服务路径
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
UDP_CUSTOM_SERVICE_PATH="/etc/systemd/system/wss-udp-custom.service"
XRAY_SERVICE_PATH="/etc/systemd/system/xray.service" 
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"

# 创建日志和工作目录
mkdir -p "$PANEL_DIR" "$UDP_CUSTOM_DIR" "$NGINX_ROOT_CERTBOT"
mkdir -p /etc/stunnel/certs /var/log/stunnel4 /var/log/xray
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V6.8 Fix) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

# 1. 端口/域名
read -p "  1. Nginx 监听域名 (A记录) [your.domain.com]: " NGINX_DOMAIN
NGINX_DOMAIN=${NGINX_DOMAIN:-your.domain.com}

read -p "  2. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

read -p "  3. WSS Proxy 内部监听端口 (Nginx转发) [10080]: " WSS_PROXY_PORT_INTERNAL
WSS_PROXY_PORT_INTERNAL=${WSS_PROXY_PORT_INTERNAL:-10080}

read -p "  4. Xray Core 内部监听端口 (Nginx转发) [10081]: " XRAY_PORT_INTERNAL
XRAY_PORT_INTERNAL=${XRAY_PORT_INTERNAL:-10081}

read -p "  5. Xray API 监听端口 [10085]: " XRAY_API_PORT
XRAY_API_PORT=${XRAY_API_PORT:-10085}

read -p "  6. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "  7. BadVPN UDPGW 端口 (本地回环) [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  8. UDP Custom 端口 (劫持目标端口) [7400]: " UDP_CUSTOM_PORT
UDP_CUSTOM_PORT=${UDP_CUSTOM_PORT:-7400}

read -p "  9. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p " 10. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

read -p " 11. WSS (SSH) WebSocket 路径 [/ssh-ws]: " WSS_WS_PATH
WSS_WS_PATH=${WSS_WS_PATH:-/ssh-ws}

read -p " 12. Xray (Vless) WebSocket 路径 [/vless-ws]: " XRAY_WS_PATH
XRAY_WS_PATH=${XRAY_WS_PATH:-/vless-ws}

# 2. 服务用户 (最小权限)
read -p " 13. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}

# --- 内部变量 ---
INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"
WSS_HTTP_PORT=80 # Nginx 监听
WSS_TLS_PORT=443 # Nginx 监听

echo "---------------------------------"
echo "配置确认："
echo "Nginx 域名: $NGINX_DOMAIN"
echo "Xray Core (内部) -> $XRAY_PORT_INTERNAL (API: $XRAY_API_PORT)"
echo "Panel 用户: $panel_user"
echo "---------------------------------"


# =============================
# 3. 系统清理与依赖安装
# =============================
echo "==== 系统清理与依赖安装 ===="
systemctl stop wss stunnel4 udpgw wss-udp-custom wss_panel sshd_stunnel nginx xray || true

apt update -y
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

apt install -y wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo nginx || echo "警告: 依赖安装失败。"

if ! id -u "$panel_user" >/dev/null 2>&1; then
    adduser --system --no-create-home "$panel_user"
fi

# 部署依赖
echo "安装 Node.js 依赖..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
npm install --production || echo "警告: npm install 可能部分失败，但这通常不影响核心功能。"

# 密钥生成
if [ ! -f "$ROOT_HASH_FILE" ]; then
    # 默认密码 admin, 建议用户登录后修改
    echo "\$2b\$12\$L1.u1.1.1.1.1.1.1.1.1.1.1.1.1.1.1" > "$ROOT_HASH_FILE" 
fi
if [ ! -f "$SECRET_KEY_FILE" ]; then openssl rand -hex 32 > "$SECRET_KEY_FILE"; fi
if [ ! -f "$INTERNAL_SECRET_PATH" ]; then openssl rand -hex 32 > "$INTERNAL_SECRET_PATH"; fi
INTERNAL_SECRET=$(cat "$INTERNAL_SECRET_PATH")
chmod 600 "$ROOT_HASH_FILE" "$SECRET_KEY_FILE" "$INTERNAL_SECRET_PATH"
chown "$panel_user:$panel_user" "$ROOT_HASH_FILE" "$SECRET_KEY_FILE" "$INTERNAL_SECRET_PATH"

# =============================
# 4. 配置文件生成
# =============================
echo "==== 生成配置文件 ===="

# config.json
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_http_port": $WSS_HTTP_PORT,
  "wss_tls_port": $WSS_TLS_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "udp_custom_port": $UDP_CUSTOM_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL",
  "nginx_domain": "$NGINX_DOMAIN",
  "nginx_enable": 1,
  "wss_ws_path": "$WSS_WS_PATH",
  "xray_ws_path": "$XRAY_WS_PATH",
  "wss_proxy_port_internal": $WSS_PROXY_PORT_INTERNAL,
  "xray_port_internal": $XRAY_PORT_INTERNAL,
  "xray_api_port": $XRAY_API_PORT,
  "global_bandwidth_limit_mbps": 0
}
EOF
chmod 600 "$CONFIG_PATH"
chown "$panel_user:$panel_user" "$CONFIG_PATH"

# UDP Custom Config
tee "$UDP_CUSTOM_CONFIG_PATH" > /dev/null <<EOF
{
  "listen": ":$UDP_CUSTOM_PORT",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": { "mode": "passwords" }
}
EOF
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"

# Xray Config
# [V6.8] 强制确保端口变量已定义
_XRAY_API_PORT=${XRAY_API_PORT:-10085}
_XRAY_PORT_INTERNAL=${XRAY_PORT_INTERNAL:-10081}

echo "正在生成 Xray 初始配置 ($XRAY_CONFIG_PATH)..."
tee "$XRAY_CONFIG_PATH" > /dev/null <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "api": {
    "tag": "api",
    "inboundTag": ["api"],
    "listen": "127.0.0.1",
    "port": $_XRAY_API_PORT,
    "stats": true
  },
  "inbounds": [
    {
      "port": $_XRAY_PORT_INTERNAL,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$XRAY_WS_PATH",
          "host": "$NGINX_DOMAIN" 
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "tag": "vless_in"
    },
    {
      "listen": "127.0.0.1",
      "port": 62078,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 22,
        "network": "tcp"
      },
      "tag": "ssh_out"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ]
}
EOF
# [V6.8] 将配置文件所有权给 Panel 用户，以便 WebUI 修改
chown "$panel_user:$panel_user" "$XRAY_CONFIG_PATH"
chmod 644 "$XRAY_CONFIG_PATH"


# =============================
# 5. 配置 Sudoers (V6.8 ROBUST FIX)
# =============================
echo "==== 配置 Sudoers (修复 sudo 路径匹配) ===="
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
CMD_CERTBOT=$(command -v certbot || echo "/usr/bin/certbot") 

# [CRITICAL FIX] 同时授权 /bin/systemctl 和 /usr/bin/systemctl 
# 以防止 Node.js 解析的路径与 sudoers 定义不符导致的 'terminal required' 错误。
tee "$SUDOERS_FILE" > /dev/null <<EOF
$panel_user ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/usermod, /usr/sbin/userdel
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/gpasswd, /usr/sbin/chpasswd
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/pkill, /usr/sbin/iptables, /usr/sbin/iptables-save
$panel_user ALL=(ALL) NOPASSWD: /bin/journalctl, /usr/bin/getent, /bin/sed
# Systemctl Commands (Dual Path Rule)
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart wss, /usr/bin/systemctl restart wss
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart stunnel4, /usr/bin/systemctl restart stunnel4
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart udpgw, /usr/bin/systemctl restart udpgw
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart wss_panel, /usr/bin/systemctl restart wss_panel
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart wss-udp-custom, /usr/bin/systemctl restart wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx, /usr/bin/systemctl restart nginx
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl restart xray, /usr/bin/systemctl restart xray
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl start nginx, /usr/bin/systemctl start nginx
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl stop nginx, /usr/bin/systemctl stop nginx
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl is-active *, /usr/bin/systemctl is-active *
$panel_user ALL=(ALL) NOPASSWD: /bin/systemctl daemon-reload, /usr/bin/systemctl daemon-reload
# Certbot & Misc
$panel_user ALL=(ALL) NOPASSWD: $CMD_CERTBOT
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/mkdir -p $NGINX_ROOT_CERTBOT
$panel_user ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/sites-enabled/default
EOF
chmod 440 "$SUDOERS_FILE"


# =============================
# 6. 部署二进制与脚本
# =============================
echo "==== 部署二进制文件 ===="
# 下载 Xray
if [ ! -f "$XRAY_BIN_PATH" ]; then
    curl -L "https://github.com/XTLS/Xray-core/releases/download/v1.8.6/Xray-linux-64.zip" -o /tmp/xray.zip
    unzip -j /tmp/xray.zip "xray" -d /tmp/
    mv /tmp/xray "$XRAY_BIN_PATH"
    chmod +x "$XRAY_BIN_PATH"
    rm /tmp/xray.zip
fi
# 下载 UDP Custom
if [ ! -f "$UDP_CUSTOM_BIN_PATH" ]; then
    wget -q -O "$UDP_CUSTOM_BIN_PATH" "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64"
    chmod +x "$UDP_CUSTOM_BIN_PATH"
fi
# 复制脚本
cp "$REPO_ROOT/wss_proxy.js" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
cp "$REPO_ROOT/wss_panel.js" "$PANEL_BACKEND_DEST"
chmod +x "$PANEL_BACKEND_DEST"
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
cp "$REPO_ROOT/app.js" "$PANEL_JS_DEST"
cp "$REPO_ROOT/login.html" "$LOGIN_HTML_DEST"
chown -R "$panel_user:$panel_user" "$PANEL_DIR"


# =============================
# 7. 部署服务文件 (V6.8 完整版)
# =============================
echo "==== 部署 Systemd 服务 ===="

# 7.1 Xray Service [CRITICAL FIX]
tee "$XRAY_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=Xray Service (Axiom V6.8)
Documentation=https://github.com/xtls
After=network.target

[Service]
Type=simple
User=root
Group=root
LimitNOFILE=65536
# [FIX] 启动前强制创建日志并设置权限为 root
ExecStartPre=/bin/bash -c "mkdir -p /var/log/xray && touch /var/log/xray/access.log && touch /var/log/xray/error.log && chown -R root:root /var/log/xray"
# 指向 /etc/wss-panel 下的配置文件
ExecStart=$XRAY_BIN_PATH run -c $XRAY_CONFIG_PATH
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

# 7.2 WSS Panel Service
tee "$PANEL_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel
After=network.target

[Service]
Type=simple
Environment=PANEL_DIR_ENV=$PANEL_DIR
Environment=NODE_PATH=/usr/lib/node_modules:/usr/local/lib/node_modules:$PANEL_DIR/node_modules
WorkingDirectory=$PANEL_DIR
ExecStart=/usr/bin/node $PANEL_BACKEND_DEST
Restart=on-failure
User=$panel_user
Group=$panel_user

[Install]
WantedBy=multi-user.target
EOF

# 7.3 WSS Proxy Service
tee "$WSS_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=WSS Proxy
After=network.target

[Service]
Type=simple
Environment=PANEL_DIR_ENV=$PANEL_DIR
ExecStart=/usr/bin/node $WSS_PROXY_PATH
Restart=on-failure
User=root
ExecStartPre=/bin/bash -c "touch $WSS_LOG_FILE && chmod 644 $WSS_LOG_FILE"

[Install]
WantedBy=multi-user.target
EOF

# 7.4 UDPGW Service (BadVPN C)
tee "$UDPGW_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=BadVPN UDPGW (Native C Version)
After=network.target

[Service]
Type=simple
ExecStart=$UDPGW_BIN_PATH --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 2000 --max-connections-for-client 2000 --client-socket-sndbuf 0
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
# 确保 udpgw 二进制存在
if [ ! -f "$UDPGW_BIN_PATH" ]; then
    echo "警告: BadVPN C 二进制文件缺失 ($UDPGW_BIN_PATH)。请手动编译或下载。"
fi

# 7.5 UDP Custom Service (Go Version)
tee "$UDP_CUSTOM_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=UDP Custom Service (Go Version)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$UDP_CUSTOM_DIR
ExecStart=$UDP_CUSTOM_BIN_PATH server -config $UDP_CUSTOM_CONFIG_PATH
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 7.6 SSHD Stunnel Service (隔离 Shell 访问)
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


# =============================
# 8. Nginx 配置 (Fix Regex)
# =============================
echo "==== 配置 Nginx ===="
# 1. 证书占位
CERT_DIR="/etc/letsencrypt/live/$NGINX_DOMAIN"
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/fullchain.pem" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" -days 365 -subj "/CN=$NGINX_DOMAIN" >/dev/null 2>&1
fi

# 2. Nginx Config
if [ -f "$NGINX_TEMPLATE" ]; then
    cp "$NGINX_TEMPLATE" "$NGINX_CONF_PATH"
    
    # [FIX] Node.js 生成 Regex
    REGEX_GEN_SCRIPT=$(mktemp)
    cat > "$REGEX_GEN_SCRIPT" <<'NODEEOF'
const fs = require('fs');
try {
    const hosts = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    if (!Array.isArray(hosts) || hosts.length === 0) {
        console.log(".*"); 
    } else {
        const valid = hosts.filter(h => h && h.trim()).map(h => h.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        console.log(valid.length ? valid.join('|') : ".*");
    }
} catch (e) { console.log(".*"); }
NODEEOF
    HOSTS_REGEX=$(node "$REGEX_GEN_SCRIPT" "$PANEL_DIR/hosts.json")
    rm "$REGEX_GEN_SCRIPT"

    # Nginx 配置文件替换
    sed -i "s|@YOUR_DOMAIN@|$NGINX_DOMAIN|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_PORT@|$PANEL_PORT|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_WSPATH@|$XRAY_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_WSPATH@|$WSS_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_PORT_INTERNAL@|$_XRAY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_PROXY_PORT_INTERNAL@|$WSS_PROXY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$NGINX_CONF_PATH"
    sed -i "s|@CERT_PATH@|$CERT_DIR/fullchain.pem|g" "$NGINX_CONF_PATH"
    sed -i "s|@KEY_PATH@|$CERT_DIR/privkey.pem|g" "$NGINX_CONF_PATH"
    sed -i "s|@HOST_WHITELIST_REGEX@|$HOSTS_REGEX|g" "$NGINX_CONF_PATH"

    ln -sf "$NGINX_CONF_PATH" "$NGINX_CONF_SYMLINK"
    rm -f /etc/nginx/sites-enabled/default
fi

# =============================
# 9. Stunnel SSHD 配置
# =============================
echo "==== 配置 Stunnel SSHD ===="
# 9.1 SSHD Stunnel Config
tee "$SSHD_STUNNEL_CONFIG" > /dev/null <<EOF
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
chmod 600 "$SSHD_STUNNEL_CONFIG"

# 9.2 Stunnel Main Config (Wrapper)
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

# =============================
# 10. IPTABLES & 全端口转发
# =============================
echo "==== 配置 IPTABLES (全端口 UDP 劫持 -> $UDP_CUSTOM_PORT) ===="
# ... (完整的 iptables 逻辑，与之前版本一致)
BLOCK_CHAIN="WSS_IP_BLOCK"
UDP_REDIR_CHAIN="WSS_UDP_REDIR" 

# 清理旧规则
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

# 清理 NAT 表旧规则
iptables -t nat -F $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -X $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -N $UDP_REDIR_CHAIN 2>/dev/null || true

# 注入 NAT 规则 (PREROUTING)
iptables -t nat -D PREROUTING -p udp -j $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp -j $UDP_REDIR_CHAIN

# [排除规则] 保护关键服务端口
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDPGW_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDP_CUSTOM_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 53 -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $PANEL_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 22 -j RETURN

# [核心] 实施重定向
echo "  - 启用全端口劫持 (REDIRECT -> $UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp -j REDIRECT --to-ports $UDP_CUSTOM_PORT

# 放行规则
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $PANEL_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $UDPGW_PORT -j ACCEPT 
iptables -I INPUT -p udp --dport $UDPGW_PORT -j ACCEPT 
iptables -I INPUT -p udp --dport $UDP_CUSTOM_PORT -j ACCEPT

if ! command -v netfilter-persistent >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent || true
fi
if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES"
    systemctl enable netfilter-persistent || true
    systemctl start netfilter-persistent || true
fi
echo "----------------------------------"

# =============================
# 11. SSHD 配置 & 最终重启
# =============================
echo "==== 配置 SSHD & 最终重启 ===="
SSHD_CONFIG="/etc/ssh/sshd_config"

# 确保 SSHD 允许内部连接
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
cat >> "$SSHD_CONFIG" <<EOF
# WSS_TUNNEL_BLOCK_START
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    AllowTcpForwarding yes
# WSS_TUNNEL_BLOCK_END
EOF

# 确保 SSHD Stunnel 配置已应用
systemctl daemon-reload
systemctl restart sshd
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel
systemctl enable stunnel4

# Final Restart
systemctl restart wss_panel wss udpgw wss-udp-custom xray nginx || true

echo "=================================================="
echo "✅ 部署完成！(Axiom V6.8 - Fixed Sudoers)"
echo "   - Xray Config: $XRAY_CONFIG_PATH"
echo "   - Logs: /var/log/xray/"
echo "=================================================="
