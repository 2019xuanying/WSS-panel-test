#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V3.8 (Axiom V6.0 - Fix Xray Deployment & Assets)
#
# [CHANGELOG]
# - [FIX] 修复 Xray 部署逻辑：现在正确使用 xray.service.template 模板。
# - [FIX] 修复 Xray 资源缺失：现在会安装 geoip.dat 和 geosite.dat。
# - [FIX] 移除 Systemd LogsDirectory 指令，避免权限冲突。
# - [FIX] 手动创建日志文件并赋予 666 权限 (rw-rw-rw-) 以确保绝对可写。
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
XRAY_TEMPLATE="$REPO_ROOT/xray.service.template" 
NGINX_TEMPLATE="$REPO_ROOT/nginx.conf.template" 

# 创建日志目录
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
# [FIX] 显式创建 Xray 日志目录
mkdir -p /var/log/xray
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V3.8) ===="
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
WSS_HTTP_PORT=80 # Nginx 监听
WSS_TLS_PORT=443 # Nginx 监听

echo "---------------------------------"
echo "配置确认："
echo "Nginx 域名: $NGINX_DOMAIN"
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

# 核心依赖安装
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
# 4. 配置 Sudoers (FIXED)
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
CMD_CERTBOT=$(command -v certbot || echo "/usr/bin/certbot") 

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
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active xray
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
$panel_user ALL=(ALL) NOPASSWD: $CMD_CERTBOT
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/mkdir -p $NGINX_ROOT_CERTBOT
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

# [FIX] 部署 UDP Custom
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
XRAY_VERSION="1.8.6" 
if [ ! -f "$XRAY_BIN_PATH" ]; then
    echo "正在下载 Xray Core $XRAY_VERSION..."
    XRAY_TEMP_FILE=$(mktemp)
    curl -L "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip" -o "$XRAY_TEMP_FILE"
    
    # [FIX] 解压 binary 和 assets
    echo "正在解压 Xray Core 和资源文件..."
    unzip -j "$XRAY_TEMP_FILE" "xray" "geoip.dat" "geosite.dat" -d /tmp/ > /dev/null
    
    mv /tmp/xray "$XRAY_BIN_PATH"
    # [FIX] 安装 GeoIP/GeoSite 资源到 /usr/local/bin (Xray 默认查找路径之一)
    mv /tmp/geoip.dat /usr/local/bin/
    mv /tmp/geosite.dat /usr/local/bin/
    
    chmod +x "$XRAY_BIN_PATH"
    rm "$XRAY_TEMP_FILE"
    echo "Xray Core $XRAY_VERSION 部署成功 (含资源文件)。"
fi

# 部署 Xray 配置文件
# [FIX] 强制确保端口变量已定义
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

# [CRITICAL FIX] 预先创建 Xray 日志目录并赋予最高权限
# 这是一个暴力修复，确保无论 systemd 如何降权，文件都是可写的
mkdir -p /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
# 赋予全局读写权限 (666)，这是解决 "permission denied" 的最快方法
chmod -R 777 /var/log/xray 
# 同时确保所有者为 root (Xray user)
chown -R root:root /var/log/xray

# Panel 需要读取配置，保留配置目录权限
chown "$panel_user:$panel_user" "$XRAY_CONFIG_PATH"
chown -R "$panel_user:$panel_user" "$XRAY_DIR"

# 部署 Xray Systemd 服务
# [FIX] 修复: 正确使用 xray.service.template，而不是内联生成
echo "部署 Xray 服务文件..."
if [ ! -f "$XRAY_TEMPLATE" ]; then
    echo "严重错误: 找不到 xray.service.template ($XRAY_TEMPLATE)。"
    # Fallback (仅当模板丢失时使用内联生成)
    tee "$XRAY_SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=Xray Service (Fallback)
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
ExecStart=$XRAY_BIN_PATH run -c $XRAY_CONFIG_PATH
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
else
    # 正常流程: 复制模板并替换变量
    cp "$XRAY_TEMPLATE" "$XRAY_SERVICE_PATH"
    # 替换模板中的路径变量 (如果有) - 模板中硬编码了 /usr/local/bin/xray，这里以防万一做个替换
    sed -i "s|/usr/local/bin/xray|$XRAY_BIN_PATH|g" "$XRAY_SERVICE_PATH"
    # 模板中硬编码了 /etc/xray/config.json，这里也做个替换
    sed -i "s|/etc/xray/config.json|$XRAY_CONFIG_PATH|g" "$XRAY_SERVICE_PATH"
fi

systemctl daemon-reload
systemctl enable xray || true
systemctl restart xray || true
echo "----------------------------------"

# =============================
# 8. 安装 Stunnel4
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
# 9. 安装 BadVPN UDPGW
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
# 11. Nginx Gateway 配置
# =============================
echo "==== 配置 Nginx 网关 ===="

# 1. SSL 证书预检与自动生成
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
    
    # [FIX] 使用 Node.js 安全生成 Regex
    echo "正在生成 Nginx Host 匹配规则..."
    REGEX_GEN_SCRIPT=$(mktemp)
    cat > "$REGEX_GEN_SCRIPT" <<'NODEEOF'
const fs = require('fs');
try {
    const data = fs.readFileSync(process.argv[2], 'utf8');
    const hosts = JSON.parse(data);
    if (!Array.isArray(hosts) || hosts.length === 0) {
        console.log(".*"); 
    } else {
        const validHosts = hosts.filter(h => h && h.trim().length > 0).map(h => h.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        if (validHosts.length === 0) {
             console.log(".*");
        } else {
             console.log(validHosts.join('|'));
        }
    }
} catch (e) {
    console.error("Error parsing hosts.json:", e.message);
    console.log(".*"); // Fallback
}
NODEEOF
    
    HOSTS_REGEX=$(node "$REGEX_GEN_SCRIPT" "$PANEL_DIR/hosts.json")
    rm "$REGEX_GEN_SCRIPT"
    
    echo "生成的 Host Regex: $HOSTS_REGEX"

    sed -i "s|@YOUR_DOMAIN@|$NGINX_DOMAIN|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_PORT@|$PANEL_PORT|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_WSPATH@|$XRAY_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_WSPATH@|$WSS_WS_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@XRAY_PORT_INTERNAL@|$_XRAY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@WSS_PROXY_PORT_INTERNAL@|$WSS_PROXY_PORT_INTERNAL|g" "$NGINX_CONF_PATH"
    sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$NGINX_CONF_PATH"
    
    sed -i "s|@CERT_PATH@|$CERT_PATH|g" "$NGINX_CONF_PATH"
    sed -i "s|@KEY_PATH@|$KEY_PATH|g" "$NGINX_CONF_PATH"
    
    sed -i "s|@HOST_WHITELIST_REGEX@|$HOSTS_REGEX|g" "$NGINX_CONF_PATH"

    ln -sf "$NGINX_CONF_PATH" "$NGINX_CONF_SYMLINK"
    rm -f /etc/nginx/sites-enabled/default

    nginx -t || echo "警告: Nginx 配置测试失败，但将尝试重启。"
    systemctl restart nginx || true
fi
echo "Nginx 网关配置完成。"
echo "----------------------------------"


# =============================
# 12. IPTABLES & 全端口转发
# =============================
echo "==== 配置 IPTABLES (全端口 UDP 劫持 -> $UDP_CUSTOM_PORT) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
UDP_REDIR_CHAIN="WSS_UDP_REDIR" 

iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

iptables -t nat -F $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -X $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -N $UDP_REDIR_CHAIN 2>/dev/null || true

iptables -t nat -D PREROUTING -p udp -j $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp -j $UDP_REDIR_CHAIN

iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDPGW_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDP_CUSTOM_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 53 -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $PANEL_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 22 -j RETURN

echo "  - 启用全端口劫持 (REDIRECT -> $UDP_CUSTOM_PORT)"
iptables -t nat -A $UDP_REDIR_CHAIN -p udp -j REDIRECT --to-ports $UDP_CUSTOM_PORT

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
# 13. SSHD 配置
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
echo "✅ 部署完成！(Axiom V6.0 - Final Fixes)"
echo "   - Sudoers: 语法已修复"
echo "   - Xray: 配置已重置并强制默认端口"
echo "=================================================="
