#!/bin/bash

# VPS安全配置脚本
# 功能：设置SSH密钥登录、禁用密码认证、修改SSH端口

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 生成SSH密钥对
generate_ssh_keys() {
    local key_path="/root/.ssh/id_rsa"
    
    if [[ -f "$key_path" ]]; then
        log_warn "SSH密钥已存在，跳过生成"
        return
    fi
    
    log_info "生成SSH密钥对..."
    mkdir -p /root/.ssh
    ssh-keygen -t rsa -b 4096 -f "$key_path" -N "" -q
    
    # 设置公钥到authorized_keys
    cat "${key_path}.pub" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    chmod 700 /root/.ssh
    
    log_info "SSH密钥生成完成"
    echo "========================================"
    echo "请保存以下私钥内容到本地："
    echo "========================================"
    cat "$key_path"
    echo "========================================"
    echo "公钥内容："
    cat "${key_path}.pub"
    echo "========================================"
}

# 添加用户提供的公钥
add_public_key() {
    if [[ -n "$1" ]]; then
        log_info "添加用户提供的公钥..."
        echo "$1" >> /root/.ssh/authorized_keys
        log_info "公钥添加完成"
    fi
}

# 修改SSH配置
configure_ssh() {
    local ssh_port=${1:-22022}
    local ssh_config="/etc/ssh/sshd_config"
    
    log_info "配置SSH服务..."
    
    # 备份原配置
    cp "$ssh_config" "${ssh_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # 修改SSH配置
    cat > "$ssh_config" << EOF
# SSH安全配置
Port $ssh_port
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 认证设置
LoginGraceTime 60
PermitRootLogin yes
StrictModes yes
MaxAuthTries 3
MaxSessions 10

# 密钥认证
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# 禁用密码认证
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM no

# 其他安全设置
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
ClientAliveInterval 60
ClientAliveCountMax 3

# 访问控制
AllowUsers root
DenyUsers nobody
IgnoreRhosts yes
HostbasedAuthentication no
EOF
    
    log_info "SSH配置修改完成，新端口：$ssh_port"
}

# 配置防火墙
configure_firewall() {
    local ssh_port=${1:-22022}
    
    log_info "配置防火墙..."
    
    # 检查并安装iptables
    if ! command -v iptables &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y iptables-persistent
        elif command -v yum &> /dev/null; then
            yum install -y iptables-services
        fi
    fi
    
    # 清空现有规则
    iptables -F
    iptables -X
    iptables -Z
    
    # 基本规则
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 允许本地回环
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 允许新的SSH端口
    iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
    
    # 允许HTTP和HTTPS（可选）
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # 保存规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    elif command -v service &> /dev/null; then
        service iptables save 2>/dev/null || true
    fi
    
    log_info "防火墙配置完成"
}

# 重启SSH服务
restart_ssh() {
    log_info "重启SSH服务..."
    
    if systemctl is-active --quiet ssh; then
        systemctl restart ssh
    elif systemctl is-active --quiet sshd; then
        systemctl restart sshd
    else
        log_error "无法找到SSH服务"
        return 1
    fi
    
    log_info "SSH服务重启完成"
}

# 显示连接信息
show_connection_info() {
    local ssh_port=${1:-22022}
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "========================================"
    log_info "配置完成！连接信息："
    echo "========================================"
    echo "服务器IP: $server_ip"
    echo "SSH端口: $ssh_port"
    echo "连接命令: ssh -p $ssh_port -i /path/to/private_key root@$server_ip"
    echo ""
    echo "注意："
    echo "1. 请确保已保存私钥到本地"
    echo "2. 密码登录已禁用，只能使用密钥登录"
    echo "3. 请在新终端测试连接，确认无误后再关闭当前会话"
    echo "========================================"
}

# 主函数
main() {
    log_info "开始VPS安全配置..."
    
    # 获取参数
    SSH_PORT=${1:-22022}
    PUBLIC_KEY="$2"
    
    # 检查root权限
    check_root
    
    # 更新系统（可选）
    log_info "更新系统包..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get upgrade -y
        apt-get install -y curl wget
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget
    fi
    
    # 生成或添加SSH密钥
    if [[ -n "$PUBLIC_KEY" ]]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        add_public_key "$PUBLIC_KEY"
        chmod 600 /root/.ssh/authorized_keys
    else
        generate_ssh_keys
    fi
    
    # 配置SSH
    configure_ssh "$SSH_PORT"
    
    # 配置防火墙
    configure_firewall "$SSH_PORT"
    
    # 重启SSH服务
    restart_ssh
    
    # 显示连接信息
    show_connection_info "$SSH_PORT"
    
    log_info "安全配置完成！"
}

# 使用说明
usage() {
    echo "使用方法："
    echo "  $0 [SSH端口] [公钥内容]"
    echo ""
    echo "示例："
    echo "  $0 22022"
    echo "  $0 22022 'ssh-rsa AAAAB3NzaC1yc2EAAA...'"
    echo ""
    echo "如果不提供公钥，脚本将自动生成密钥对"
}

# 参数检查
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

# 执行主函数
main "$@"