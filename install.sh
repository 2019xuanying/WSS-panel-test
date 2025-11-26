#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V3.2 (Axiom V6.0 - Fix SSL & Nginx Regex)
#
# [CHANGELOG]
# - [FIX] 修复 Nginx 启动时的 pcre_compile 错误 (空 Host 白名单导致)。
# - [FIX] 自动生成自签名 SSL 证书以解决 Nginx 首次启动失败的问题。
# - [FIX] 修正 Nginx 模板变量替换逻辑。
# ==========================================================

# =============================
# 1. 文件路径定义 (全局变量)
# =============================
REPO_ROOT=$(dirname "$0")

# 核心目录
PANEL_DIR="/etc/wss-panel"
UDP_CUSTOM_DIR="$PANEL_DIR/udp-custom"
XRAY_DIR="/etc/xray" # Xray 配置目录
mkdir -p "$PANEL_DIR" 
mkdir -p "$UDP_CUSTOM_DIR"
mkdir -p "$XRAY_DIR"

# 日志与配置
WSS_LOG_FILE="/var/log/wss.log" 
CONFIG_PATH="$PANEL_DIR/config.json"
UDP_CUSTOM_CONFIG_PATH="$UDP_CUSTOM_DIR/config.json"
XRAY_CONFIG_PATH="$XRAY_DIR/config.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" 
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"
NGINX_CONF_PATH="/etc/nginx/sites-available/wss_gateway.conf"
NGINX_CONF_SYMLINK="/etc/nginx/sites-enabled/wss_gateway.conf"
NGINX_ROOT_CERTBOT="/var/www/certbot"
mkdir -p "$NGINX_ROOT_CERTBOT"

# 二进制文件路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
UDP_CUSTOM_BIN_PATH="/usr/local/bin/udp-custom" 
XRAY_BIN_PATH="/usr/local/bin/xray" # Xray 二进制文件

# 面板文件路径
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"

# SSHD Stunnel 路径
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"

# BadVPN 路径
BADVPN_SRC_DIR="/root/badvpn"

# Systemd 服务路径 (Target)
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
UDP_CUSTOM_SERVICE_PATH="/etc/systemd/system/wss-udp-custom.service"
XRAY_SERVICE_PATH="/etc/systemd/system/xray.service" # Xray 服务文件

# Systemd 模板路径 (Source)
WSS_TEMPLATE="$REPO_ROOT/wss.service.template"
PANEL_TEMPLATE="$REPO_ROOT/wss_panel.service.template"
UDPGW_TEMPLATE="$REPO_ROOT/udpgw.service.template"
UDP_CUSTOM_TEMPLATE="$REPO_ROOT/wss-udp-custom.service.template"
XRAY_TEMPLATE="$REPO_ROOT/xray.service.template" # Xray 模板 (假设存在)
NGINX_TEMPLATE="$REPO_ROOT/nginx.conf.template" # Nginx 模板 (假设存在)

# 创建日志目录
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V3.1) ===="
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

# --- IPC (进程间通信) 端口配置 ---
INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"
WSS_HTTP_PORT=80 # Nginx 监听，但保留配置项
WSS_TLS_PORT=443 # Nginx 监听，但保留配置项

echo "---------------------------------"
echo "配置确认："
echo "Nginx 域名: $NGINX_DOMAIN"
echo "Nginx (80/443) -> Panel/Xray/WSS Proxy"
echo "WSS Proxy (内部) -> $WSS_PROXY_PORT_INTERNAL"
echo "Xray Core (内部) -> $XRAY_PORT_INTERNAL (API: $XRAY_API_PORT)"
echo "Panel 用户: $panel_user"
echo "---------------------------------"


# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。"
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
echo "==== 3. 系统清理与依赖安装 ===="
systemctl stop wss stunnel4 udpgw wss-udp-custom wss_panel sshd_stunnel nginx xray || true

# 核心依赖安装 (新增 nginx, curl)
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

echo "安装 Node.js 依赖..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
if ! npm install --production; then
    echo "警告: Node.js 依赖安装失败，但这可能是网络问题。"
fi

# 处理密钥
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    PANEL_ROOT_PASS_HASH=$(node -e "const bcrypt = require('bcrypt'); const hash = bcrypt.hashSync('$PANEL_ROOT_PASS_RAW', 12); console.log(hash);")
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
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

chmod 600 "$ROOT_HASH_FILE" "$SECRET_KEY_FILE" "$INTERNAL_SECRET_PATH"

# 生成主配置文件 (config.json)
echo "正在创建 config.json..."
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

# 生成 UDP Custom 专属配置文件
echo "正在创建 UDP Custom 配置文件..."
tee "$UDP_CUSTOM_CONFIG_PATH" > /dev/null <<EOF
{
  "listen": ":$UDP_CUSTOM_PORT",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"

echo "----------------------------------"


# =============================
# 4. 配置 Sudoers
# =============================
echo "==== 配置 Sudoers ===="
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
CMD_CERTBOT=$(command -v certbot || echo "/usr/bin/certbot") # Certbot/acme.sh 路径

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
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart xray
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL start nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL stop nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active xray
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
# [V6.0 NEW] Certbot 和文件操作权限，用于证书申请和 Nginx 配置
$panel_user ALL=(ALL) NOPASSWD: $CMD_CERTBOT
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/mkdir -p $NGINX_ROOT_CERTBOT
$panel_user ALL=(ALL) NOPASSWD: /bin/chown -R $panel_user:$panel_user $XRAY_DIR
$panel_user ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/sites-enabled/default
EOF

chmod 440 "$SUDOERS_FILE"
echo "Sudoers 配置完成。"
echo "----------------------------------"


# =============================
# 5. 内核调优
# =============================
echo "==== 配置内核参数 ===="
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
# BadVPN UDPGW & UDP Custom Buffer Tuning
net.core.rmem_max = 83886080
net.core.wmem_max = 83886080
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
# WSS_NET_END
EOF
sysctl -p > /dev/null
echo "----------------------------------"

# =============================
# 6. 部署代码文件
# =============================
echo "==== 部署代码文件 ===="
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

# [FIX] 部署 UDP Custom (使用 GitHub Raw 直链)
echo "正在下载 UDP Custom 二进制文件..."
if wget "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64" -O "$UDP_CUSTOM_BIN_PATH"; then
    chmod +x "$UDP_CUSTOM_BIN_PATH"
    echo "UDP Custom 下载成功。"
else
    echo "严重错误：无法下载 UDP Custom。请检查网络。"
    touch "$UDP_CUSTOM_BIN_PATH"
    chmod +x "$UDP_CUSTOM_BIN_PATH"
fi
echo "----------------------------------"

# =============================
# 7. Xray 部署 (V6.0 NEW)
# =============================
echo "==== 部署 Xray Core ===="
XRAY_VERSION="1.8.6" # 使用一个稳定版本
if [ ! -f "$XRAY_BIN_PATH" ]; then
    echo "正在下载 Xray Core $XRAY_VERSION..."
    XRAY_TEMP_FILE=$(mktemp)
    curl -L "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip" -o "$XRAY_TEMP_FILE"
    unzip -j "$XRAY_TEMP_FILE" "xray" -d /tmp/ > /dev/null
    mv /tmp/xray "$XRAY_BIN_PATH"
    chmod +x "$XRAY_BIN_PATH"
    rm "$XRAY_TEMP_FILE"
    echo "Xray Core $XRAY_VERSION 部署成功。"
fi

# 部署 Xray 配置文件 (使用预设模板，假设 VLESS+WS+TLS)
if [ ! -f "$XRAY_CONFIG_PATH" ]; then
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
    "port": $XRAY_API_PORT,
    "stats": true
  },
  "inbounds": [
    {
      "port": $XRAY_PORT_INTERNAL,
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
          "headers": {
            "Host": "$NGINX_DOMAIN"
          }
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
    chown "$panel_user:$panel_user" "$XRAY_CONFIG_PATH" # Panel 需要权限来修改用户列表
fi

# 部署 Xray Systemd 服务
tee "$XRAY_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=Xray Service (Axiom V6.0)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=$XRAY_BIN_PATH run -c $XRAY_CONFIG_PATH
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable xray || true
systemctl restart xray || true
echo "----------------------------------"

# =============================
# 8. 安装 Stunnel4 (保持不变)
# =============================
echo "==== 重新安装 Stunnel4 ===="
if ! getent group shell_users >/dev/null; then groupadd shell_users; fi

openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem

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
# 9. 安装 BadVPN UDPGW (保持不变)
# =============================
echo "==== 编译并部署 BadVPN UDPGW ===="
if [ ! -d "$BADVPN_SRC_DIR" ]; then
    echo "正在拉取 BadVPN 源码..."
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_SRC_DIR" > /dev/null 2>&1
fi

mkdir -p "$BADVPN_SRC_DIR/badvpn-build"
cd "$BADVPN_SRC_DIR/badvpn-build"
echo "正在配置编译..."
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
echo "正在编译 (请耐心等待)..."
make -j$(nproc) > /dev/null 2>&1

cd - > /dev/null
# 部署 udpgw service
if [ ! -f "$UDPGW_TEMPLATE" ]; then
    echo "错误: 找不到 udpgw.service.template。"
    exit 1
fi
cp "$UDPGW_TEMPLATE" "$UDPGW_SERVICE_PATH"
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"

systemctl daemon-reload
systemctl enable udpgw
systemctl restart udpgw
echo "BadVPN UDPGW 已启动 (端口: $UDPGW_PORT)。"
echo "----------------------------------"

# =============================
# 10. 部署 Node.js Systemd 服务
# =============================
echo "==== 部署 Node.js Systemd 服务 ===="

# wss service
if [ ! -f "$WSS_TEMPLATE" ]; then
    echo "错误: 找不到 wss.service.template ($WSS_TEMPLATE)"
    exit 1
fi
cp "$WSS_TEMPLATE" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_PATH|g" "$WSS_SERVICE_PATH"

# wss_panel service
if [ ! -f "$PANEL_TEMPLATE" ]; then
    echo "错误: 找不到 wss_panel.service.template ($PANEL_TEMPLATE)"
    exit 1
fi
cp "$PANEL_TEMPLATE" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_USER@|$panel_user|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_FILE|g" "$PANEL_SERVICE_PATH"

# udp custom service
if [ ! -f "$UDP_CUSTOM_TEMPLATE" ]; then
    echo "错误: 找不到 wss-udp-custom.service.template。"
    exit 1
fi
cp "$UDP_CUSTOM_TEMPLATE" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_DIR@|$UDP_CUSTOM_DIR|g" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_BIN_PATH@|$UDP_CUSTOM_BIN_PATH|g" "$UDP_CUSTOM_SERVICE_PATH"

chown -R "$panel_user:$panel_user" "$PANEL_DIR"
chown "$panel_user:$panel_user" "$WSS_LOG_FILE"
chown "$panel_user:$panel_user" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"

systemctl daemon-reload
systemctl enable wss_panel
systemctl enable wss
systemctl enable wss-udp-custom

# 重启服务
systemctl restart wss_panel
systemctl restart wss
systemctl restart wss-udp-custom
echo "----------------------------------"

# =============================
# 11. Nginx Gateway 配置 (V6.0 NEW - Fixed SSL)
# =============================
echo "==== 配置 Nginx 网关 ===="

# 1. SSL 证书预检与自动生成 (CRITICAL FIX)
CERT_DIR="/etc/letsencrypt/live/$NGINX_DOMAIN"
CERT_PATH="$CERT_DIR/fullchain.pem"
KEY_PATH="$CERT_DIR/privkey.pem"

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "警告: 未检测到域名 $NGINX_DOMAIN 的 SSL 证书。"
    echo "正在生成自签名证书以确保 Nginx 可以启动..."
    
    mkdir -p "$CERT_DIR"
    
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -days 365 \
        -subj "/CN=$NGINX_DOMAIN" > /dev/null 2>&1
        
    echo "自签名证书已生成: $CERT_DIR"
fi

# 2. 部署 Nginx 配置文件
if [ ! -f "$NGINX_TEMPLATE" ]; then
    echo "错误: 找不到 nginx.conf.template ($NGINX_TEMPLATE)。跳过 Nginx 配置。"
else
    cp "$NGINX_TEMPLATE" "$NGINX_CONF_PATH"
    
    HOSTS_REGEX=$(cat "$PANEL_DIR/hosts.json" | grep -v '^\s*$' | tr '\n' '|')
    # [FIX] Ensure valid regex even if hosts list is empty
    if [ -z "$HOSTS_REGEX" ]; then
        # Default to match nothing if list is empty, preventing empty regex error
        HOSTS_REGEX="^$"
    else
        # Remove trailing pipe
        HOSTS_REGEX="${HOSTS_REGEX%|}"
    fi

    sed -i "s|@YOUR_DOMAIN@|$NGINX_DOMAIN|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_PORT@|$PANEL_PORT|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_WSPATH@|$XRAY_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_WSPATH@|$WSS_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_PORT_INTERNAL@|$XRAY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_PROXY_PORT_INTERNAL@|$WSS_PROXY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$NGINX_CONF_PATH"
    
    # 替换证书路径
    sed -i "s|@CERT_PATH@|$CERT_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@KEY_PATH@|$KEY_PATH|g" "$NGINX_CONF_PATH"
    
    sed -i "s|@HOST_WHITELIST_REGEX@|$HOSTS_REGEX|g" "$NGINX_CONF_PATH"

    # 3. 启用站点并清理旧配置
    ln -sf "$NGINX_CONF_PATH" "$NGINX_CONF_SYMLINK"
    rm -f /etc/nginx/sites-enabled/default

    # 4. 检查配置并重启 Nginx
    nginx -t || echo "警告: Nginx 配置测试失败，但将尝试重启。"
    systemctl restart nginx || true
fi
echo "Nginx 网关配置完成。"
echo "----------------------------------"


# =============================
# 12. IPTABLES & 全端口转发 (核心逻辑)
# =============================
echo "==== 配置 IPTABLES (全端口 UDP 劫持 -> $UDP_CUSTOM_PORT) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
UDP_REDIR_CHAIN="WSS_UDP_REDIR" 

# 1. 清理旧规则
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

# 清理 NAT 表旧规则
iptables -t nat -F $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -X $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -N $UDP_REDIR_CHAIN 2>/dev/null || true

# 2. 注入 NAT 规则 (PREROUTING)
iptables -t nat -D PREROUTING -p udp -j $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp -j $UDP_REDIR_CHAIN

# 3. [排除规则] 保护关键服务端口
echo "  - 排除 BadVPN UDPGW ($UDPGW_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDPGW_PORT -j RETURN

echo "  - 排除 UDP Custom 自身 ($UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDP_CUSTOM_PORT -j RETURN

echo "  - 排除 DNS (53)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 53 -j RETURN

# 排除其他潜在的 UDP 监听端口 (TCP端口也排除以防协议误判)
# [V6.0 FIX] 移除 80/443 的排除，因为 Nginx 负责 80/443 TCP。
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $PANEL_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 22 -j RETURN

# 4. [核心] 实施重定向
echo "  - 启用全端口劫持 (REDIRECT -> $UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp -j REDIRECT --to-ports $UDP_CUSTOM_PORT

# 5. 放行规则
# [V6.0 FIX] 仅放行 Nginx (80/443) 和 Stunnel/UDP 网关
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
# 13. SSHD 配置 (保持不变)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
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

# Stunnel SSHD
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
systemctl restart sshd
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel

# Final Restart
systemctl restart stunnel4 udpgw wss_panel wss wss-udp-custom nginx xray

echo "=================================================="
echo "✅ 部署完成！(Axiom V6.0 - Xray/Nginx Multi-Protocol)"
echo "   - Nginx 网关: 0.0.0.0:80/443 (已生成自签名证书)"
echo "   - Web Panel: 0.0.0.0:$PANEL_PORT"
echo "   - Xray Core: 127.0.0.1:$XRAY_PORT_INTERNAL (API: $XRAY_API_PORT)"
echo "   - SSH WSS Proxy: 127.0.0.1:$WSS_PROXY_PORT_INTERNAL"
echo "=================================================="
