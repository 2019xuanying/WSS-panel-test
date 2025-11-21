#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板 一键卸载脚本 (Axiom V2.0 清理)
#
# [AXIOM V2.0 CHANGELOG]
# - 新增清理: config.json (外部化配置文件)
# - 新增清理: app.js (分离的前端 JS)
#
# [AXIOM V1.7.0 CHANGELOG]
# - 智能卸载: 脚本现在会自动从 wss_panel.service 
#   文件中读取 Panel 用户名，以实现完全清理。
# - 完整清理...
# ==========================================================

echo "----------------------------------"
echo "==== WSS 基础设施一键卸载程序 ===="
echo "----------------------------------"

# =============================
# 文件路径定义 (与 install.sh 保持一致)
# =============================
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log"
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_PATH="$PANEL_DIR/$PANEL_BACKEND_FILE"
# [AXIOM V2.0] 新增文件
CONFIG_PATH="$PANEL_DIR/config.json"
PANEL_APP_JS_PATH="$PANEL_DIR/app.js"
# ------------------------------
UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
STUNNEL_CONF="/etc/stunnel/ssh-tls.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"
IPTABLES_RULES="/etc/iptables/rules.v4"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"

# [AXIOM V1.7.0] 新增清理路径
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
SHELL_GROUP="shell_users"
BLOCK_CHAIN="WSS_IP_BLOCK"

# =============================
# [AXIOM V1.7.0] 智能检测 Panel 用户
# =============================
PANEL_USER=""
if [ -f "$PANEL_SERVICE_PATH" ]; then
    # 从服务文件中提取 User=...
    PANEL_USER=$(grep -E "^User=" "$PANEL_SERVICE_PATH" | cut -d'=' -f2)
    echo "检测到 Panel 服务用户: $PANEL_USER"
else
    echo "警告: 找不到 $PANEL_SERVICE_PATH，无法自动检测 Panel 用户。"
    echo "将尝试使用默认值 'admin'..."
    PANEL_USER="admin"
fi

if [ -z "$PANEL_USER" ]; then
    echo "错误: 无法确定 Panel 服务用户。"
    exit 1
fi

# =============================
# 1. 停止并禁用 Systemd 服务
# =============================
echo "1. 停止并禁用 Systemd 服务..."
# 尝试停止所有 WSS 相关的服务
systemctl stop wss_panel || true
systemctl disable wss_panel || true
systemctl stop wss || true
systemctl disable wss || true
systemctl stop udpgw || true
systemctl disable udpgw || true
systemctl stop stunnel4 || true
systemctl disable stunnel4 || true
systemctl stop sshd_stunnel || true # [AXIOM V1.7.0]
systemctl disable sshd_stunnel || true # [AXIOM V1.7.0]

# 重新加载 daemon，确保服务文件可以被删除
systemctl daemon-reload

# 移除服务文件
rm -f "$PANEL_SERVICE_PATH"
rm -f "$WSS_SERVICE_PATH"
rm -f "$UDPGW_SERVICE_PATH"
rm -f "$SSHD_STUNNEL_SERVICE" # [AXIOM V1.7.0]
echo "Systemd 服务已停止并移除。"
echo "----------------------------------"

# =============================
# 2. 清理 IPTABLES 规则
# =============================
echo "2. 清理 IPTABLES 规则链 ($BLOCK_CHAIN)..."
# 移除 IPTABLES jump 规则
while iptables -D INPUT -j "$BLOCK_CHAIN" 2>/dev/null; do
    echo "移除 $BLOCK_CHAIN 钩子..."
done

# 清理并删除自定义链
iptables -t filter -F "$BLOCK_CHAIN" 2>/dev/null || true
iptables -t filter -X "$BLOCK_CHAIN" 2>/dev/null || true

# 尝试删除 IPTABLES 规则持久化文件 (注意：这会删除系统其他规则，需要恢复)
if [ -f "$IPTABLES_RULES" ]; then
    echo "警告：IPTABLES 规则持久化文件存在，建议手动检查。"
    # 避免直接删除，但强制保存一次空规则以清除 BLOCK_CHAIN 引用
    /sbin/iptables-save | grep -v "$BLOCK_CHAIN" | /sbin/iptables-restore || true
fi


# 尝试重启持久化服务以加载干净的规则
if command -v netfilter-persistent >/dev/null; then
    echo "尝试重启 netfilter-persistent 以应用清理后的规则..."
    systemctl restart netfilter-persistent || true
fi
echo "IPTABLES 规则清理完成。"
echo "----------------------------------"

# =============================
# 3. 清理 Traffic Control (tc) 配置
# =============================
echo "3. 清理 Traffic Control (tc) 配置..."
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -n "$IP_DEV" ]; then
    tc qdisc del dev "$IP_DEV" root 2>/dev/null || true
    echo "Traffic Control (tc) 已在 $IP_DEV 上移除。"
else
    echo "警告: 无法找到主网络接口，跳过 tc 清理。"
fi
echo "----------------------------------"

# =============================
# 4. 还原 SSHD 配置 (删除 WSS 匹配块)
# =============================
echo "4. 还原 SSHD 配置..."
# 删除主 SSHD (Port 22/CUSTOM) 上的 WSS 块
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
# 删除 Stunnel SSHD (Port 2222/CUSTOM) 上的 WSS 块
if [ -f "$SSHD_STUNNEL_CONFIG" ]; then
    sed -i '/# WSS_STUNNEL_BLOCK_START/,/# WSS_STUNNEL_BLOCK_END/d' "$SSHD_STUNNEL_CONFIG"
fi

SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")
systemctl restart "$SSHD_SERVICE" || true
echo "SSHD 配置已还原，并重启 $SSHD_SERVICE 服务。"
echo "----------------------------------"

# =============================
# 5. 还原 Sysctl 网络调优配置
# =============================
echo "5. 还原 Sysctl 网络调优配置..."
# 删除 WSS_NET 块
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
sysctl -p > /dev/null
echo "Sysctl 配置已还原。"
echo "----------------------------------"


# =============================
# 6. [AXIOM V1.7.0] 清理 Sudoers、用户和组
# =============================
echo "6. 清理 Sudoers、用户和组..."

# 1. 移除 Sudoers 文件
rm -f "$SUDOERS_FILE"
echo "Sudoers 文件 ($SUDOERS_FILE) 已移除。"

# 2. 移除 'shell_users' 组
if getent group "$SHELL_GROUP" >/dev/null; then
    groupdel "$SHELL_GROUP"
    echo "用户组 '$SHELL_GROUP' 已移除。"
else
    echo "用户组 '$SHELL_GROUP' 不存在。"
fi

# 3. 移除 Panel 服务用户
if id -u "$PANEL_USER" >/dev/null 2>&1; then
    userdel "$PANEL_USER"
    echo "Panel 服务用户 '$PANEL_USER' 已移除。"
else
    echo "Panel 服务用户 '$PANEL_USER' 不存在。"
fi

echo "----------------------------------"

# =============================
# 7. 删除文件和目录
# =============================
echo "7. 删除 WSS 相关的文件和目录..."
# 删除脚本文件
rm -f "$WSS_PROXY_PATH"
rm -f "$PANEL_BACKEND_PATH"
# [AXIOM V2.0] 清理新文件
rm -f "$PANEL_APP_JS_PATH"
rm -f "$CONFIG_PATH"
# ------------------------------
rm -f "$WSS_LOG_FILE"
rm -f "$STUNNEL_CONF"
rm -f "$SECRET_KEY_FILE"
rm -f "$ROOT_HASH_FILE"
rm -f "$SSHD_STUNNEL_CONFIG" # [AXIOM V1.7.0]

# 删除目录及其内容
rm -rf "$PANEL_DIR"         # WSS Panel 数据和模板 (包括用户数据)
rm -rf /root/badvpn         # UDPGW 源代码 (如果是通过 git clone 到 /root/badvpn)
rm -rf /etc/stunnel/certs   # Stunnel 证书
rm -rf /var/log/stunnel4    # Stunnel 日志目录

echo "文件和目录清理完成。"
echo "----------------------------------"


echo "=================================================="
echo "✅ WSS 隧道管理面板 (Axiom V2.0) 已成功卸载！"
echo "=================================================="
echo ""
echo "🔥 后续操作提示:"
echo "1. 如果您使用该面板创建了系统用户，请手动使用 'userdel -r <username>' 删除这些用户。"
echo "2. 如果您需要恢复 Stunnel4 配置或默认 SSHD 设置，可能需要重新安装相关软件包。"
echo "=================================================="
