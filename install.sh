#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 综合流量管理面板部署脚本
# V6.0 (Axiom Architecture - Nginx Gateway + Xray Core)
#
# [V6.0 CHANGELOG]
# - [ARCH] 引入 Nginx 作为 80/443 网关和 SNI/Path 看门狗。
# - [CORE] 集成 Xray Core (VLESS/VMess) 支持。
# - [DEPS] 增加 GeoIP 数据库和 UUID 支持。
# - [NET] WSS Proxy 移至本地端口 (10080)，Xray 移至 (10081)。
# ==========================================================

# =============================
# 1. 文件路径定义 (全局变量)
# =============================
REPO_ROOT=$(dirname "$0")

# 核心目录
PANEL_DIR="/etc/wss-panel"
UDP_CUSTOM_DIR="$PANEL_DIR/udp-custom"
XRAY_DIR="$PANEL_DIR/xray"
NGINX_CONF_DIR="/etc/nginx/conf.d"
WEB_ROOT="/var/www/html"

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

# 二进制文件路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
UDP_CUSTOM_BIN_PATH="/usr/local/bin/udp-custom" 
XRAY_BIN_PATH="/usr/local/bin/xray"
XRAY_GEO_DIR="/usr/local/share/xray" # geosite.dat, geoip.dat

# 面板文件路径
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"

# Nginx 模板
NGINX_TEMPLATE_SRC="$REPO_ROOT/nginx_watchdog.conf.template"
NGINX_TEMPLATE_DEST="$PANEL_DIR/nginx_watchdog.conf.template" # 保存模板供 Panel 生成使用

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
XRAY_SERVICE_PATH="/etc/systemd/system/xray.service"

# Systemd 模板路径 (Source)
WSS_TEMPLATE="$REPO_ROOT/wss.service.template"
PANEL_TEMPLATE="$REPO_ROOT/wss_panel.service.template"
UDPGW_TEMPLATE="$REPO_ROOT/udpgw.service.template"
UDP_CUSTOM_TEMPLATE="$REPO_ROOT/wss-udp-custom.service.template"
XRAY_TEMPLATE="$REPO_ROOT/xray.service.template"

# 创建日志目录
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
mkdir -p /var/log/xray
mkdir -p "$XRAY_GEO_DIR"
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式配置 (V6.0)
# =============================
echo "----------------------------------"
echo "==== WSS 全栈流量管理平台配置 (V6.0) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

# 1. 核心域名 (用于 Nginx / Xray)
read -p "  1. 您的域名 (例如: demo.example.com): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    echo "错误: 域名不能为空。Nginx 需要域名来申请证书。"
    exit 1
fi

# 2. 端口 (Nginx 接管 80/443)
echo "  [INFO] Nginx 将自动接管端口 80 和 443。"
read -p "  2. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

# 内部端口 (Localhost Only)
WSS_PROXY_PORT=10080    # SSH WebSocket 本地监听
XRAY_PORT=10081         # Xray VLESS/VMess 本地监听
echo "  [INFO] 内部服务端口已固定: WSS Proxy ($WSS_PROXY_PORT), Xray ($XRAY_PORT)"

# 其他端口
read -p "  3. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "  4. BadVPN UDPGW 端口 (本地回环) [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  5. UDP Custom 端口 (劫持目标) [7400]: " UDP_CUSTOM_PORT
UDP_CUSTOM_PORT=${UDP_CUSTOM_PORT:-7400}

read -p "  6. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p "  7. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

# 3. 服务用户
read -p "  8. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}

# --- IPC 配置 ---
INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"

# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。"
else
    echo "==== 管理面板配置 (首次或重置) ===="
    echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
    while true; do
      read -s -p "面板密码: " pw1 && echo
      read -s -p "请再次确认密码: " pw2 && echo
      if [ -z "$pw1" ]; then echo "密码不能为空。"; continue; fi
      if [ "$pw1" != "$pw2" ]; then echo "两次输入不一致。"; continue; fi
      PANEL_ROOT_PASS_RAW="$pw1"
      break
    done
fi

echo "----------------------------------"
echo "==== 3. 系统环境准备 ===="
# 停止旧服务
systemctl stop wss stunnel4 udpgw wss-udp-custom wss_panel sshd_stunnel xray nginx || true

apt update -y
# 安装基础依赖 + Nginx
apt install -y wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo nginx unzip socat tar || echo "警告: 依赖安装部分失败，尝试继续..."

# 安装 Node.js (如果不存在)
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js LTS..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# 安装 Xray Core
echo "正在安装/更新 Xray Core..."
XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep "tag_name" | cut -d : -f 2,3 | tr -d \",\ )
XRAY_ZIP_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
wget -O /tmp/xray.zip "$XRAY_ZIP_URL"
unzip -o /tmp/xray.zip -d /tmp/xray_dist
mv /tmp/xray_dist/xray "$XRAY_BIN_PATH"
mv /tmp/xray_dist/geoip.dat "$XRAY_GEO_DIR/"
mv /tmp/xray_dist/geosite.dat "$XRAY_GEO_DIR/"
chmod +x "$XRAY_BIN_PATH"
rm -rf /tmp/xray.zip /tmp/xray_dist
echo "Xray Core 安装完成。"

# 创建服务用户
if ! id -u "$panel_user" >/dev/null 2>&1; then
    adduser --system --no-create-home "$panel_user"
fi

# Node 依赖
echo "安装 Node.js 依赖 (包括 GeoIP, UUID)..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
# [V6.0] 强制安装，确保 geoip-lite 等新依赖就位
npm install --production

# 密钥处理
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    PANEL_ROOT_PASS_HASH=$(node -e "const bcrypt = require('bcrypt'); const hash = bcrypt.hashSync('$PANEL_ROOT_PASS_RAW', 12); console.log(hash);")
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
fi
if [ ! -f "$SECRET_KEY_FILE" ]; then
    echo "$(openssl rand -hex 32)" > "$SECRET_KEY_FILE"
fi
if [ ! -f "$INTERNAL_SECRET_PATH" ]; then
    echo "$(openssl rand -hex 32)" > "$INTERNAL_SECRET_PATH"
fi
INTERNAL_SECRET=$(cat "$INTERNAL_SECRET_PATH")
chmod 600 "$ROOT_HASH_FILE" "$SECRET_KEY_FILE" "$INTERNAL_SECRET_PATH"

# =============================
# 4. 生成配置文件
# =============================

# 主 Config.json (V6.0 更新结构)
echo "正在创建 config.json..."
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "domain": "$DOMAIN_NAME",
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_proxy_port": $WSS_PROXY_PORT,
  "xray_port": $XRAY_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "udp_custom_port": $UDP_CUSTOM_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL",
  "features": {
    "nginx_watchdog": true,
    "xray_core": true,
    "geoip_analysis": true,
    "dynamic_qos": true
  },
  "qos": {
    "global_limit_mbps": 500,
    "congestion_threshold": 0.90
  }
}
EOF
chmod 600 "$CONFIG_PATH"
chown "$panel_user:$panel_user" "$CONFIG_PATH"

# UDP Custom Config
echo "正在创建 UDP Custom 配置文件..."
tee "$UDP_CUSTOM_CONFIG_PATH" > /dev/null <<EOF
{
  "listen": ":$UDP_CUSTOM_PORT",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": { "mode": "passwords" }
}
EOF
chmod 600 "$UDP_CUSTOM_CONFIG_PATH"

# Nginx 模板复制
if [ -f "$NGINX_TEMPLATE_SRC" ]; then
    cp "$NGINX_TEMPLATE_SRC" "$NGINX_TEMPLATE_DEST"
    chown "$panel_user:$panel_user" "$NGINX_TEMPLATE_DEST"
else
    echo "警告：找不到 nginx_watchdog.conf.template，Panel 可能无法生成 Nginx 配置。"
fi

# =============================
# 5. 配置 Sudoers (扩权)
# =============================
echo "==== 配置 Sudoers ===="
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
# 命令路径探测
CMD_USERADD=$(command -v useradd)
CMD_USERMOD=$(command -v usermod)
CMD_USERDEL=$(command -v userdel)
CMD_PKILL=$(command -v pkill)
CMD_IPTABLES=$(command -v iptables)
CMD_IPTABLES_SAVE=$(command -v iptables-save)
CMD_JOURNALCTL=$(command -v journalctl)
CMD_SYSTEMCTL=$(command -v systemctl)
CMD_GETENT=$(command -v getent)
CMD_SED=$(command -v sed)
CMD_NGINX=$(command -v nginx)

tee "$SUDOERS_FILE" > /dev/null <<EOF
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERADD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERMOD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERDEL
$panel_user ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd
$panel_user ALL=(ALL) NOPASSWD: /usr/bin/gpasswd
$panel_user ALL=(ALL) NOPASSWD: $CMD_PKILL
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES_SAVE
$panel_user ALL=(ALL) NOPASSWD: $CMD_JOURNALCTL
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
# 允许管理所有 WSS 相关服务
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss-udp-custom
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart xray
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL reload nginx
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active *
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
# Nginx 配置检查
$panel_user ALL=(ALL) NOPASSWD: $CMD_NGINX -t
EOF
chmod 440 "$SUDOERS_FILE"

# =============================
# 6. 内核调优
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
net.core.rmem_max = 83886080
net.core.wmem_max = 83886080
# WSS_NET_END
EOF
sysctl -p > /dev/null

# =============================
# 7. 部署代码与二进制
# =============================
echo "==== 部署代码 ===="
cp "$REPO_ROOT/wss_proxy.js" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
cp "$REPO_ROOT/wss_panel.js" "$PANEL_BACKEND_DEST"
chmod +x "$PANEL_BACKEND_DEST"
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
cp "$REPO_ROOT/app.js" "$PANEL_JS_DEST"
cp "$REPO_ROOT/login.html" "$LOGIN_HTML_DEST"

# UDP Custom Binary
if [ ! -f "$UDP_CUSTOM_BIN_PATH" ]; then
    echo "下载 UDP Custom..."
    wget -q "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64" -O "$UDP_CUSTOM_BIN_PATH" || echo "下载 UDP Custom 失败，请检查网络。"
    chmod +x "$UDP_CUSTOM_BIN_PATH"
fi

# =============================
# 8. 编译 BadVPN UDPGW
# =============================
if [ ! -f "$BADVPN_SRC_DIR/badvpn-build/udpgw/badvpn-udpgw" ]; then
    echo "==== 编译 BadVPN UDPGW ===="
    if [ ! -d "$BADVPN_SRC_DIR" ]; then
        git clone https://github.com/ambrop72/badvpn.git "$BADVPN_SRC_DIR" > /dev/null 2>&1
    fi
    mkdir -p "$BADVPN_SRC_DIR/badvpn-build"
    cd "$BADVPN_SRC_DIR/badvpn-build"
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j$(nproc) > /dev/null 2>&1
    cd - > /dev/null
fi
cp "$UDPGW_TEMPLATE" "$UDPGW_SERVICE_PATH"
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"
systemctl enable udpgw
systemctl restart udpgw

# =============================
# 9. 部署 Systemd 服务
# =============================
echo "==== 部署 Systemd 服务 ===="

# WSS Proxy (Data Plane)
cp "$WSS_TEMPLATE" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_PATH|g" "$WSS_SERVICE_PATH"

# Panel (Control Plane)
cp "$PANEL_TEMPLATE" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_USER@|$panel_user|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_FILE|g" "$PANEL_SERVICE_PATH"

# UDP Custom
cp "$UDP_CUSTOM_TEMPLATE" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_DIR@|$UDP_CUSTOM_DIR|g" "$UDP_CUSTOM_SERVICE_PATH"
sed -i "s|@UDP_CUSTOM_BIN_PATH@|$UDP_CUSTOM_BIN_PATH|g" "$UDP_CUSTOM_SERVICE_PATH"

# Xray
cp "$XRAY_TEMPLATE" "$XRAY_SERVICE_PATH"
sed -i "s|@XRAY_BIN_PATH@|$XRAY_BIN_PATH|g" "$XRAY_SERVICE_PATH"
sed -i "s|@XRAY_DIR@|$XRAY_DIR|g" "$XRAY_SERVICE_PATH"

# 权限修正
chown -R "$panel_user:$panel_user" "$PANEL_DIR"
chown "$panel_user:$panel_user" "$WSS_LOG_FILE"

# 重载 Daemon
systemctl daemon-reload
systemctl enable wss_panel wss wss-udp-custom xray nginx

# =============================
# 10. IPTABLES (UDP 劫持)
# =============================
echo "==== 配置 IPTABLES (UDP -> $UDP_CUSTOM_PORT) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
UDP_REDIR_CHAIN="WSS_UDP_REDIR" 

# 清理旧链
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

iptables -t nat -F $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -X $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -N $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp -j $UDP_REDIR_CHAIN 2>/dev/null || true
iptables -t nat -I PREROUTING -p udp -j $UDP_REDIR_CHAIN

# 排除规则
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDPGW_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $UDP_CUSTOM_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 53 -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport $PANEL_PORT -j RETURN
iptables -t nat -A $UDP_REDIR_CHAIN -p udp --dport 22 -j RETURN

# 核心重定向
iptables -t nat -A $UDP_REDIR_CHAIN -p udp -j REDIRECT --to-ports $UDP_CUSTOM_PORT

# 放行规则
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport $PANEL_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT
iptables -I INPUT -p tcp --dport $UDPGW_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $UDPGW_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $UDP_CUSTOM_PORT -j ACCEPT

# 持久化
if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES"
    systemctl enable netfilter-persistent || true
    systemctl start netfilter-persistent || true
fi

# =============================
# 11. SSHD 配置
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
chmod 600 "$SSHD_STUNNEL_CONFIG"
systemctl daemon-reload
systemctl restart sshd
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel

# =============================
# 12. Stunnel4 配置
# =============================
if ! getent group shell_users >/dev/null; then groupadd shell_users; fi
# 确保证书目录存在，即使 Nginx 接管了 443，Stunnel (444) 仍需自签名证书
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 3650 \
-subj "/CN=$DOMAIN_NAME" > /dev/null 2>&1
cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem
chmod 600 /etc/stunnel/certs/*.pem

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
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

# =============================
# 13. 启动所有核心服务
# =============================
echo "==== 启动核心服务 ===="
systemctl restart wss_panel
systemctl restart wss
systemctl restart xray
systemctl restart wss-udp-custom
systemctl restart nginx

echo "=================================================="
echo "✅ WSS V6.0 全栈部署完成!"
echo "   - Web 面板: http://$DOMAIN_NAME:$PANEL_PORT"
echo "   - Nginx 网关: 端口 80 / 443 (自动配置中...)"
echo "   - WSS Proxy: 监听本地 10080"
echo "   - Xray Core: 监听本地 10081"
echo "   请登录面板检查 Nginx 状态并生成证书。"
echo "=================================================="
