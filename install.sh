#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V2.4.2 (Axiom - Final Release)
# ==========================================================

# =============================
# 1. 基础变量与路径定义
# =============================
REPO_ROOT=$(dirname "$0")
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log" 
CONFIG_PATH="$PANEL_DIR/config.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" 
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"

# 源文件路径
WSS_PROXY_SRC="$REPO_ROOT/wss_proxy.js"
PANEL_BACKEND_SRC="$REPO_ROOT/wss_panel.js"
PANEL_HTML_SRC="$REPO_ROOT/index.html"
PANEL_JS_SRC="$REPO_ROOT/app.js"
LOGIN_HTML_SRC="$REPO_ROOT/login.html"
PACKAGE_JSON_SRC="$REPO_ROOT/package.json"
UDP_SERVER_SRC="$REPO_ROOT/udp_server.js"
SSH_UDP_SRC="$REPO_ROOT/ssh_udp.js"

# 目标文件路径
WSS_PROXY_DEST="/usr/local/bin/wss_proxy.js"
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"
UDP_SERVER_DEST="$PANEL_DIR/udp_server.js"
SSH_UDP_DEST="$PANEL_DIR/ssh_udp.js"

# Systemd 服务模板
WSS_TEMPLATE="$REPO_ROOT/wss.service.template"
PANEL_TEMPLATE="$REPO_ROOT/wss_panel.service.template"
UDPGW_TEMPLATE="$REPO_ROOT/udpgw.service.template"
SSH_UDP_TEMPLATE="$REPO_ROOT/ssh_udp.service.template"

# Systemd 服务目标路径
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
SSH_UDP_SERVICE_PATH="/etc/systemd/system/ssh_udp.service"

BADVPN_SRC_DIR="/root/badvpn"
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"

mkdir -p "$PANEL_DIR" 
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# 2. 交互式端口配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V2.4) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

read -p "  1. WSS HTTP 端口 [80]: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "  2. WSS TLS 端口 [443]: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "  3. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "  4. BadVPN UDPGW 端口 (本地) [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  5. SSH-UDP 公网端口 (核心服务) [7400]: " SSH_UDP_PORT
SSH_UDP_PORT=${SSH_UDP_PORT:-7400}

read -p "  6. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

read -p "  7. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p "  8. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

read -p "  9. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}

INTERNAL_API_PORT=54322 
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"

echo "---------------------------------"
echo "配置确认："
echo "Panel 用户: $panel_user"
echo "WSS (80/443) -> $WSS_HTTP_PORT/$WSS_TLS_PORT"
echo "Stunnel (444) -> $STUNNEL_PORT"
echo "BadVPN UDPGW (127.0.0.1) -> $UDPGW_PORT"
echo "SSH-UDP Auth (0.0.0.0) -> $SSH_UDP_PORT (1-65535 流量汇聚点)"
echo "Web Panel (HTTP) & IPC -> $PANEL_PORT"
echo "---------------------------------"

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

# =============================
# 3. 系统清理与依赖检查
# =============================
echo "----------------------------------"
echo "==== 系统清理与依赖检查 ===="
systemctl stop wss stunnel4 udpgw ssh_udp wss_panel sshd_stunnel || true
systemctl disable udp_server 2>/dev/null || true 
rm -f /etc/systemd/system/udp_server.service

apt update -y
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

apt install -y wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo || echo "警告: 部分依赖安装失败。"

if ! id -u "$panel_user" >/dev/null 2>&1; then
    adduser --system --no-create-home "$panel_user"
fi

echo "安装 Node.js 依赖..."
cp "$PACKAGE_JSON_SRC" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
if ! npm install --production; then
    echo "严重警告: Node.js 核心依赖安装失败。"
    exit 1
fi
cd "$REPO_ROOT"

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

echo "正在创建 config.json..."
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_http_port": $WSS_HTTP_PORT,
  "wss_tls_port": $WSS_TLS_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "ssh_udp_port": $SSH_UDP_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL"
}
EOF
chmod 600 "$CONFIG_PATH"


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
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart ssh_udp
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active ssh_udp
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
$panel_user ALL=(ALL) NOPASSWD: $CMD_SED
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL daemon-reload
EOF
chmod 440 "$SUDOERS_FILE"

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
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
# WSS_NET_END
EOF
sysctl -p > /dev/null

# =============================
# 6. 部署文件
# =============================
echo "==== 部署代码文件 ===="
cp "$WSS_PROXY_SRC" "$WSS_PROXY_DEST"
cp "$PANEL_BACKEND_SRC" "$PANEL_BACKEND_DEST"
cp "$PANEL_HTML_SRC" "$PANEL_HTML_DEST"
cp "$PANEL_JS_SRC" "$PANEL_JS_DEST"
cp "$LOGIN_HTML_SRC" "$LOGIN_HTML_DEST"
cp "$UDP_SERVER_SRC" "$UDP_SERVER_DEST" 

# [NEW] 部署 SSH-UDP JS
if [ -f "$SSH_UDP_SRC" ]; then
    cp "$SSH_UDP_SRC" "$SSH_UDP_DEST"
    chmod +x "$SSH_UDP_DEST"
else
    echo "警告: $SSH_UDP_SRC 未找到，SSH-UDP 服务将无法运行。"
fi

chmod +x "$WSS_PROXY_DEST" "$PANEL_BACKEND_DEST"

if [ ! -f "$DB_PATH" ]; then echo "Database will be initialized on start."; fi
[ ! -f "$PANEL_DIR/audit.log" ] && touch "$PANEL_DIR/audit.log"
[ ! -f "$PANEL_DIR/hosts.json" ] && echo '[]' > "$PANEL_DIR/hosts.json"
chown -R "$panel_user:$panel_user" "$PANEL_DIR"

# =============================
# 7. 安装 Stunnel4
# =============================
echo "==== 配置 Stunnel4 ===="
if ! getent group shell_users >/dev/null; then groupadd shell_users; fi
openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/stunnel/certs/stunnel.key -out /etc/stunnel/certs/stunnel.crt -days 1095 -subj "/CN=example.com" > /dev/null 2>&1
cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem
chmod 600 /etc/stunnel/certs/*.key /etc/stunnel/certs/*.pem

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

# =============================
# 8. 编译并部署 BadVPN (C++ Version)
# =============================
echo "==== 编译部署 BadVPN UDPGW (C++) ===="
if [ ! -d "$BADVPN_SRC_DIR" ]; then
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_SRC_DIR" > /dev/null 2>&1
fi
mkdir -p "$BADVPN_SRC_DIR/badvpn-build"
cd "$BADVPN_SRC_DIR/badvpn-build"
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
cd "$REPO_ROOT" 

# =============================
# 9. 部署 Systemd 服务
# =============================
echo "==== 部署 Systemd 服务 ===="

# 1. udpgw (BadVPN C++)
if [ -f "$UDPGW_TEMPLATE" ]; then
    cp "$UDPGW_TEMPLATE" "$UDPGW_SERVICE_PATH"
    sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"
    systemctl enable udpgw
else
    echo "错误: udpgw 模板未找到。"
fi

# 2. ssh_udp (Node.js Auth)
if [ -f "$SSH_UDP_TEMPLATE" ]; then
    cp "$SSH_UDP_TEMPLATE" "$SSH_UDP_SERVICE_PATH"
    systemctl enable ssh_udp
else
    echo "错误: ssh_udp 模板未找到。"
fi

# 3. wss
if [ -f "$WSS_TEMPLATE" ]; then
    cp "$WSS_TEMPLATE" "$WSS_SERVICE_PATH"
    sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
    sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_DEST|g" "$WSS_SERVICE_PATH"
else
    echo "错误: wss 模板未找到。"
fi

# 4. wss_panel
if [ -f "$PANEL_TEMPLATE" ]; then
    cp "$PANEL_TEMPLATE" "$PANEL_SERVICE_PATH"
    sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
    sed -i "s|@PANEL_USER@|$panel_user|g" "$PANEL_SERVICE_PATH"
    sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_FILE|g" "$PANEL_SERVICE_PATH"
else
    echo "错误: wss_panel 模板未找到。"
fi

systemctl daemon-reload
systemctl enable wss_panel wss udpgw ssh_udp

# =============================
# 10. IPTABLES 全端口转发 (1-65535)
# =============================
echo "==== 配置 IPTABLES (全端口转发 -> SSH_UDP) ===="
iptables -t nat -F
iptables -D INPUT -j WSS_IP_BLOCK 2>/dev/null || true
iptables -F INPUT
iptables -I INPUT 1 -j WSS_IP_BLOCK 2>/dev/null || true
if ! iptables -L WSS_IP_BLOCK >/dev/null 2>&1; then
    iptables -N WSS_IP_BLOCK
    iptables -I INPUT 1 -j WSS_IP_BLOCK
fi

# --- 1. 排除关键端口 (不转发) ---
iptables -t nat -A PREROUTING -p tcp --dport 22 -j RETURN
iptables -t nat -A PREROUTING -p tcp --dport $WSS_HTTP_PORT -j RETURN
iptables -t nat -A PREROUTING -p tcp --dport $WSS_TLS_PORT -j RETURN
iptables -t nat -A PREROUTING -p tcp --dport $STUNNEL_PORT -j RETURN
iptables -t nat -A PREROUTING -p tcp --dport $PANEL_PORT -j RETURN
iptables -t nat -A PREROUTING -p tcp --dport $SSH_UDP_PORT -j RETURN

# --- 2. 重定向其余流量 -> SSH_UDP ---
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port $SSH_UDP_PORT

# --- 3. 放行规则 ---
iptables -A INPUT -p tcp --dport $SSH_UDP_PORT -j ACCEPT
iptables -A INPUT -p tcp -j ACCEPT 
iptables -A INPUT -p udp --dport $UDPGW_PORT -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES"
    systemctl enable netfilter-persistent || true
    systemctl start netfilter-persistent || true
fi

# =============================
# 11. 最终重启
# =============================
echo "==== 重启所有服务 ===="
systemctl restart sshd
systemctl restart sshd_stunnel
systemctl restart stunnel4
systemctl restart udpgw
systemctl restart ssh_udp
systemctl restart wss_panel
systemctl restart wss

echo "=================================================="
echo "✅ 部署完成！(Axiom V2.4 - Full Port Forwarding)"
echo "SSH-UDP 监听端口: $SSH_UDP_PORT (已接管 1-65535 空闲端口)"
echo "BadVPN UDPGW 监听: 127.0.0.1:$UDPGW_PORT"
echo "=================================================="
