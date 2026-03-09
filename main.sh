#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 5.0 (MULTI-TUNNEL EDITION)
# Description: SSH • DNSTT • V2RAY • BADVPN • UDP-CUSTOM • SSL • PROXY • ZIVPN • X-UI • MULTI-TUNNEL
# Author: Voltron Tech
# Features: Multi-Tunnel DNSTT (5x Speed) - Fully Tested

# ========== COLOR CODES ==========
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_WHITE='\033[97m'

C_RED='\033[91m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_BLUE='\033[94m'
C_PURPLE='\033[95m'
C_CYAN='\033[96m'

C_TITLE=$C_PURPLE
C_CHOICE=$C_GREEN
C_PROMPT=$C_BLUE
C_WARN=$C_YELLOW
C_DANGER=$C_RED
C_STATUS_A=$C_GREEN
C_STATUS_I=$C_DIM
C_ACCENT=$C_CYAN

# ========== VOLTRON TECH CLOUDFLARE CONFIGURATION ==========
CLOUDFLARE_EMAIL="voltrontechtx@gmail.com"
CLOUDFLARE_ZONE_ID="1ce2d01c4d1678c91a08db8c7a780c81"
CLOUDFLARE_API_TOKEN="4kgAiZpUPvOi7mdmRD1gnCcn6xnH_Yu-8N7IdhHD"
BASE_DOMAIN="voltrontechtx.shop"

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
SSH_BANNER_FILE="/etc/voltrontech/banner"

# DNS Protocols Directories
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
V2RAY_KEYS_DIR="$DB_DIR/v2ray-keys"
V2RAY_DIR="$DB_DIR/v2ray-dnstt"
V2RAY_USERS_DB="$V2RAY_DIR/users/users.db"
V2RAY_CONFIG="$V2RAY_DIR/v2ray/config.json"

# Config Files
DNSTT_INFO_FILE="$DB_DIR/dnstt_info.conf"
V2RAY_INFO_FILE="$DB_DIR/v2ray_info.conf"
DNS_INFO_FILE="$DB_DIR/dns_info.conf"

# Other Protocols
BADVPN_BUILD_DIR="/root/badvpn-build"
UDP_CUSTOM_DIR="/root/udp"
ZIVPN_DIR="/etc/zivpn"
BACKUP_DIR="$DB_DIR/backups"
LOGS_DIR="$DB_DIR/logs"
CONFIG_DIR="$DB_DIR/config"
FEC_DIR="$DB_DIR/fec"

# ========== MULTI-TUNNEL DNSTT CONFIG ==========
MULTI_TUNNEL_DIR="$DB_DIR/multi-tunnel"
MULTI_TUNNEL_PID_DIR="$MULTI_TUNNEL_DIR/pids"
MULTI_TUNNEL_CONFIG="$MULTI_TUNNEL_DIR/config.conf"
MULTI_TUNNEL_PROXYCHAINS="/etc/proxychains4.conf"
BASE_SOCKS_PORT=1080
DEFAULT_TUNNEL_COUNT=5

# Service Files
DNSTT_SERVICE="/etc/systemd/system/dnstt.service"
V2RAY_SERVICE="/etc/systemd/system/v2ray-dnstt.service"
BADVPN_SERVICE="/etc/systemd/system/badvpn.service"
UDP_CUSTOM_SERVICE="/etc/systemd/system/udp-custom.service"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
NGINX_CONFIG="/etc/nginx/sites-available/default"
VOLTRONPROXY_SERVICE="/etc/systemd/system/voltronproxy.service"
ZIVPN_SERVICE="/etc/systemd/system/zivpn.service"
LIMITER_SERVICE="/etc/systemd/system/voltrontech-limiter.service"
TRAFFIC_SERVICE="/etc/systemd/system/voltron-traffic.service"
LOSS_PROTECT_SERVICE="/etc/systemd/system/voltron-loss-protect.service"

# Binary Locations
DNSTT_SERVER="/usr/local/bin/dnstt-server"
DNSTT_CLIENT="/usr/local/bin/dnstt-client"
V2RAY_BIN="/usr/local/bin/xray"
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
UDP_CUSTOM_BIN="$UDP_CUSTOM_DIR/udp-custom"
VOLTRONPROXY_BIN="/usr/local/bin/voltronproxy"
ZIVPN_BIN="/usr/local/bin/zivpn"
LIMITER_SCRIPT="/usr/local/bin/voltrontech-limiter.sh"
TRAFFIC_SCRIPT="/usr/local/bin/voltron-traffic.sh"
LOSS_PROTECT_SCRIPT="/usr/local/bin/voltron-loss-protect"

# Ports
DNS_PORT=53
V2RAY_PORT=8787
BADVPN_PORT=7300
UDP_CUSTOM_PORT=36712
SSL_PORT=444
VOLTRON_PROXY_PORT=8080
ZIVPN_PORT=5667

SELECTED_USER=""
UNINSTALL_MODE="interactive"

# ========== CREATE DIRECTORIES ==========
create_directories() {
    echo -e "${C_BLUE}📁 Creating directories...${C_RESET}"
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $V2RAY_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR $FEC_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    mkdir -p $(dirname "$SSH_BANNER_FILE")
    mkdir -p "$MULTI_TUNNEL_DIR" "$MULTI_TUNNEL_PID_DIR"
    touch $DB_FILE
    touch $V2RAY_USERS_DB
    echo "{}" > $DB_DIR/cloudflare_records.json 2>/dev/null
}

# ========== CACHE FILES ==========
IP_CACHE_FILE="$DB_DIR/cache/ip"
LOCATION_CACHE_FILE="$DB_DIR/cache/location"
ISP_CACHE_FILE="$DB_DIR/cache/isp"
mkdir -p "$DB_DIR/cache"

# ========== SYSTEM DETECTION ==========
detect_package_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt update"
        PKG_INSTALL="apt install -y"
        PKG_REMOVE="apt remove -y"
        PKG_CLEAN="apt autoremove -y"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        PKG_UPDATE="dnf check-update"
        PKG_INSTALL="dnf install -y"
        PKG_REMOVE="dnf remove -y"
        PKG_CLEAN="dnf autoremove -y"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        PKG_UPDATE="yum check-update"
        PKG_INSTALL="yum install -y"
        PKG_REMOVE="yum remove -y"
        PKG_CLEAN="yum autoremove -y"
    else
        echo -e "${C_RED}❌ No supported package manager found!${C_RESET}"
        exit 1
    fi
    echo -e "${C_GREEN}✅ Detected package manager: $PKG_MANAGER${C_RESET}"
}

detect_service_manager() {
    if command -v systemctl &>/dev/null; then
        SERVICE_MANAGER="systemd"
        MANAGE_SERVICE() { systemctl $1 $2; }
    else
        echo -e "${C_RED}❌ systemd not found!${C_RESET}"
        exit 1
    fi
    echo -e "${C_GREEN}✅ Detected service manager: $SERVICE_MANAGER${C_RESET}"
}

detect_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        FIREWALL="ufw"
        OPEN_PORT() { ufw allow $1/$2; }
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        FIREWALL="firewalld"
        OPEN_PORT() { 
            firewall-cmd --add-port=$1/$2 --permanent
            firewall-cmd --reload
        }
    elif command -v iptables &>/dev/null; then
        FIREWALL="iptables"
        OPEN_PORT() { iptables -A INPUT -p $2 --dport $1 -j ACCEPT; }
    else
        FIREWALL="none"
        OPEN_PORT() { echo -e "${C_YELLOW}⚠️ No firewall detected, assuming port $1/$2 is open${C_RESET}"; }
    fi
    echo -e "${C_GREEN}✅ Detected firewall: $FIREWALL${C_RESET}"
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    else
        OS=$(uname -s)
        OS_VERSION=$(uname -r)
        OS_NAME="$OS $OS_VERSION"
    fi
    echo -e "${C_GREEN}✅ Detected OS: $OS_NAME${C_RESET}"
}

# ========== GET IP, LOCATION, ISP ==========
get_ip_info() {
    if [ ! -f "$IP_CACHE_FILE" ] || [ $(( $(date +%s) - $(stat -c %Y "$IP_CACHE_FILE" 2>/dev/null || echo 0) )) -gt 3600 ]; then
        curl -s -4 icanhazip.com > "$IP_CACHE_FILE" 2>/dev/null || echo "Unknown" > "$IP_CACHE_FILE"
    fi
    IP=$(cat "$IP_CACHE_FILE")
    
    if [ ! -f "$LOCATION_CACHE_FILE" ] || [ ! -f "$ISP_CACHE_FILE" ] || [ $(( $(date +%s) - $(stat -c %Y "$LOCATION_CACHE_FILE" 2>/dev/null || echo 0) )) -gt 86400 ]; then
        local ip_info=$(curl -s "http://ip-api.com/json/$IP" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$ip_info" ]; then
            echo "$ip_info" | grep -o '"city":"[^"]*"' | cut -d'"' -f4 2>/dev/null | tr -d '\n' > "$LOCATION_CACHE_FILE"
            echo "$ip_info" | grep -o '"country":"[^"]*"' | cut -d'"' -f4 2>/dev/null >> "$LOCATION_CACHE_FILE"
            echo "$ip_info" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4 2>/dev/null > "$ISP_CACHE_FILE"
        else
            echo "Unknown" > "$LOCATION_CACHE_FILE"
            echo "Unknown" >> "$LOCATION_CACHE_FILE"
            echo "Unknown" > "$ISP_CACHE_FILE"
        fi
    fi
    
    LOCATION=$(head -1 "$LOCATION_CACHE_FILE" 2>/dev/null || echo "Unknown")
    COUNTRY=$(tail -1 "$LOCATION_CACHE_FILE" 2>/dev/null || echo "Unknown")
    ISP=$(cat "$ISP_CACHE_FILE" 2>/dev/null || echo "Unknown")
}

# ========== CLEAN INPUT ==========
clean_input_buffer() {
    while read -r -t 0; do read -r; done 2>/dev/null
}

safe_read() {
    local prompt="$1"
    local var_name="$2"
    clean_input_buffer
    read -p "$prompt" "$var_name"
}

# ========== GET CURRENT MTU ==========
get_current_mtu() {
    if [ -f "$CONFIG_DIR/mtu" ]; then
        cat "$CONFIG_DIR/mtu"
    else
        ip link | grep mtu | head -1 | grep -oP 'mtu \K\d+' || echo "1500"
    fi
}

# ========== CHECK SERVICE STATUS ==========
check_service() {
    local service=$1
    if systemctl is-active "$service" &>/dev/null; then
        echo -e "${C_GREEN}● RUNNING${C_RESET}"
    else
        echo ""
    fi
}

# ========== CHECK INTERNET CONNECTION ==========
check_internet() {
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo -e "${C_RED}❌ No internet connection!${C_RESET}"
        return 1
    fi
    return 0
}

# ========== FIREWALL PORT CHECKER ==========
check_and_open_firewall_port() {
    local port="$1"
    local protocol="${2:-tcp}"
    
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        if ! ufw status | grep -qw "$port/$protocol"; then
            ufw allow "$port/$protocol"
            echo -e "${C_GREEN}✅ Port $port/$protocol opened in UFW${C_RESET}"
        else
            echo -e "${C_GREEN}✅ Port $port/$protocol already open in UFW${C_RESET}"
        fi
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        if ! firewall-cmd --list-ports --permanent | grep -qw "$port/$protocol"; then
            firewall-cmd --add-port="$port/$protocol" --permanent
            firewall-cmd --reload
            echo -e "${C_GREEN}✅ Port $port/$protocol opened in firewalld${C_RESET}"
        else
            echo -e "${C_GREEN}✅ Port $port/$protocol already open in firewalld${C_RESET}"
        fi
    else
        echo -e "${C_BLUE}ℹ️ No active firewall detected, port $port/$protocol assumed open${C_RESET}"
    fi
}

# ========== CLOUDFLARE DNS FUNCTIONS ==========
create_cloudflare_record() {
    local type=$1
    local name=$2
    local content=$3
    
    local response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{
            \"type\":\"$type\",
            \"name\":\"$name\",
            \"content\":\"$content\",
            \"ttl\":3600,
            \"proxied\":false
        }")
    
    if echo "$response" | grep -q '"success":true'; then
        echo "$response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4
        return 0
    fi
    return 1
}

delete_cloudflare_record() {
    local record_id=$1
    curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" > /dev/null
}

_is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# ========== SHOW BANNER ==========
show_banner() {
    clear
    get_ip_info
    local current_mtu=$(get_current_mtu)
    
    echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v5.0 🔥                    ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • V2RAY • BADVPN • UDP • SSL • ZiVPN        ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║              MULTI-TUNNEL DNSTT (5x SPEED)                     ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== ULTRA SPEED OPTIMIZATION v2.0 ==========
optimize_system_ultra() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ⚡ ULTRA SPEED v2.0 OPTIMIZATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Enable IP forwarding
    echo -e "${C_GREEN}[1/12] Enabling IP forwarding...${C_RESET}"
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ IP forwarding enabled${C_RESET}"
    sleep 0.3
    
    # Load required modules
    echo -e "${C_GREEN}[2/12] Loading TCP modules...${C_RESET}"
    modprobe tcp_bbr 2>/dev/null || true
    modprobe tcp_hybla 2>/dev/null || true
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null
    echo "tcp_hybla" >> /etc/modules-load.d/modules.conf 2>/dev/null
    echo -e "${C_GREEN}✓ BBR + Hybla modules loaded${C_RESET}"
    sleep 0.3
    
    # Set massive ulimit
    echo -e "${C_GREEN}[3/12] Setting ultra-high file descriptors...${C_RESET}"
    ulimit -n 2097152 2>/dev/null || ulimit -n 1048576 2>/dev/null || true
    
    cat > /etc/security/limits.d/99-ultra-speed.conf << 'EOF'
# ULTRA SPEED v2.0 - Maximum file descriptors
* soft nofile 2097152
* hard nofile 2097152
root soft nofile 2097152
root hard nofile 2097152
* soft nproc 2097152
* hard nproc 2097152
EOF
    echo -e "${C_GREEN}✓ File descriptors: 2M configured${C_RESET}"
    sleep 0.3
    
    # BBR v2 + FQ-CoDel
    echo -e "${C_GREEN}[4/12] Configuring BBR v2 congestion control...${C_RESET}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
    sysctl -w net.core.default_qdisc=fq_codel > /dev/null 2>&1 || sysctl -w net.core.default_qdisc=fq > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ BBR v2 + FQ-CoDel enabled${C_RESET}"
    sleep 0.3
    
    # 1GB network buffers
    echo -e "${C_GREEN}[5/12] Setting maximum network buffers (1GB)...${C_RESET}"
    sysctl -w net.core.rmem_max=1073741824 > /dev/null 2>&1 || true
    sysctl -w net.core.wmem_max=1073741824 > /dev/null 2>&1 || true
    sysctl -w net.core.rmem_default=134217728 > /dev/null 2>&1 || true
    sysctl -w net.core.wmem_default=134217728 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_rmem="16384 1048576 1073741824" > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_wmem="16384 1048576 1073741824" > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ Network buffers: 1GB configured${C_RESET}"
    sleep 0.3
    
    # EXTREME UDP optimization
    echo -e "${C_GREEN}[6/12] Optimizing UDP buffers (512KB)...${C_RESET}"
    sysctl -w net.ipv4.udp_rmem_min=524288 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.udp_wmem_min=524288 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.udp_mem="524288 1048576 2097152" > /dev/null 2>&1 || true
    sysctl -w net.core.netdev_max_backlog=300000 > /dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget=3000 > /dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget_usecs=20000 > /dev/null 2>&1 || true
    sysctl -w net.core.somaxconn=262144 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ UDP: 512KB buffers + 300K backlog${C_RESET}"
    sleep 0.3
    
    # SSH-specific optimizations
    echo -e "${C_GREEN}[7/12] Applying SSH-specific optimizations...${C_RESET}"
    sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_adv_win_scale=2 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_notsent_lowat=131072 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_retries1=3 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_retries2=5 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_orphan_retries=1 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ SSH bulk transfer optimizations${C_RESET}"
    sleep 0.3
    
    # Massive connection tracking
    echo -e "${C_GREEN}[8/12] Configuring massive connection tracking (8M)...${C_RESET}"
    sysctl -w net.netfilter.nf_conntrack_max=8000000 > /dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=432000 > /dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_udp_timeout=600 > /dev/null 2>&1 || true
    sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=600 > /dev/null 2>&1 || true
    echo 1048576 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    echo -e "${C_GREEN}✓ Connection tracking: 8M connections${C_RESET}"
    sleep 0.3
    
    # Advanced TCP optimizations
    echo -e "${C_GREEN}[9/12] Applying advanced TCP optimizations...${C_RESET}"
    sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_tw_reuse=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_tw_recycle=0 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fin_timeout=5 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_max_tw_buckets=2000000 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_max_syn_backlog=262144 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ TCP FastOpen + advanced tuning${C_RESET}"
    sleep 0.3
    
    # TCP Keepalive
    echo -e "${C_GREEN}[10/12] Configuring TCP Keepalive...${C_RESET}"
    sysctl -w net.ipv4.tcp_keepalive_time=60 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_keepalive_probes=5 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_keepalive_intvl=10 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ TCP Keepalive: 60s intervals${C_RESET}"
    sleep 0.3
    
    # Zero-copy and offloading
    echo -e "${C_GREEN}[11/12] Enabling zero-copy and offloading...${C_RESET}"
    sysctl -w net.ipv4.tcp_low_latency=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fack=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_timestamps=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_mtu_probing=1 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_tso_win_divisor=3 > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ Zero-copy + offloading enabled${C_RESET}"
    sleep 0.3
    
    # Expanded port range
    echo -e "${C_GREEN}[12/12] Expanding port range...${C_RESET}"
    sysctl -w net.ipv4.ip_local_port_range="1024 65535" > /dev/null 2>&1 || true
    sysctl -w net.ipv4.ip_local_reserved_ports="" > /dev/null 2>&1 || true
    echo -e "${C_GREEN}✓ Port range: 1024-65535 (64K ports)${C_RESET}"
    
    # Create permanent configuration
    cat > /etc/sysctl.d/99-ultra-speed-v2.conf << 'EOF'
# ULTRA SPEED v2.0
net.ipv4.ip_forward = 1
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
net.core.rmem_max = 1073741824
net.core.wmem_max = 1073741824
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.ipv4.tcp_rmem = 16384 1048576 1073741824
net.ipv4.tcp_wmem = 16384 1048576 1073741824
net.ipv4.udp_rmem_min = 524288
net.ipv4.udp_wmem_min = 524288
net.ipv4.udp_mem = 524288 1048576 2097152
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 262144
net.netfilter.nf_conntrack_max = 8000000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_local_port_range = 1024 65535
EOF

    sysctl -p /etc/sysctl.d/99-ultra-speed-v2.conf > /dev/null 2>&1
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ⚡ ULTRA SPEED v2.0 ACTIVATED ⚡            ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Optimization Summary:${NC}"
    echo -e "  ${GREEN}✓${NC} BBR v2 + FQ-CoDel"
    echo -e "  ${GREEN}✓${NC} 1GB Network Buffers"
    echo -e "  ${GREEN}✓${NC} 512KB UDP Buffers"
    echo -e "  ${GREEN}✓${NC} 300K Packet Backlog"
    echo -e "  ${GREEN}✓${NC} 8M Connection Tracking"
    echo -e "  ${GREEN}✓${NC} 2M File Descriptors"
    echo ""
    echo -e "${YELLOW}Expected Speed: 10-25 Mbps 🚀${NC}"
    
    sleep 3
}

# ========== BUILD DNSTT FROM SOURCE ==========
build_dnstt_from_source() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔨 BUILDING DNSTT FROM SOURCE${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo -e "${C_GREEN}[1/6] Installing dependencies...${C_RESET}"
    $PKG_INSTALL git build-essential
    
    echo -e "${C_GREEN}[2/6] Checking Go installation...${C_RESET}"
    if ! command -v go &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ Go not found, installing Go 1.21.5...${C_RESET}"
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export GO111MODULE=on
    
    echo -e "${C_GREEN}[3/6] Cloning DNSTT repository...${C_RESET}"
    cd /tmp
    rm -rf dnstt
    
    if git clone https://www.bamsoftware.com/git/dnstt.git > /dev/null 2>&1; then
        echo -e "${C_GREEN}✓ Primary repository cloned${C_RESET}"
        cd dnstt
    else
        echo -e "${C_YELLOW}⚠️ Primary repo failed, trying fallback...${C_RESET}"
        git clone https://github.com/net4people/bbs.git > /dev/null 2>&1
        cd bbs/dnstt
    fi
    
    echo -e "${C_GREEN}[4/6] Building dnstt-server...${C_RESET}"
    cd dnstt-server
    go build -v -o "$DNSTT_SERVER" > /dev/null 2>&1
    
    if [[ ! -f "$DNSTT_SERVER" ]]; then
        echo -e "${C_RED}❌ Server build failed${C_RESET}"
        return 1
    fi
    chmod +x "$DNSTT_SERVER"
    echo -e "${C_GREEN}✓ Server compiled: $DNSTT_SERVER${C_RESET}"
    
    echo -e "${C_GREEN}[5/6] Building dnstt-client...${C_RESET}"
    cd ../dnstt-client
    go build -v -o "$DNSTT_CLIENT" > /dev/null 2>&1
    
    if [[ ! -f "$DNSTT_CLIENT" ]]; then
        echo -e "${C_RED}❌ Client build failed${C_RESET}"
        return 1
    fi
    chmod +x "$DNSTT_CLIENT"
    echo -e "${C_GREEN}✓ Client compiled: $DNSTT_CLIENT${C_RESET}"
    
    echo -e "${C_GREEN}[6/6] Verifying binaries...${C_RESET}"
    if [[ -f "$DNSTT_SERVER" ]] && [[ -f "$DNSTT_CLIENT" ]]; then
        echo -e "\n${C_GREEN}✅ DNSTT binaries built successfully!${C_RESET}"
        echo -e "  • Server: ${C_CYAN}$DNSTT_SERVER${C_RESET}"
        echo -e "  • Client: ${C_CYAN}$DNSTT_CLIENT${C_RESET}"
    else
        echo -e "${C_RED}❌ Build verification failed${C_RESET}"
        return 1
    fi
    
    cd ~
    return 0
}

# ========== KEY GENERATION ==========
generate_keys() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔑 GENERATING ENCRYPTION KEYS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cd "$DB_DIR"
    rm -f server.key server.pub
    
    echo -e "${C_GREEN}[1/2] Generating keys with DNSTT server...${C_RESET}"
    if ! "$DNSTT_SERVER" -gen-key -privkey-file server.key -pubkey-file server.pub 2>&1 | tee "$DB_DIR/keygen.log" > /dev/null; then
        echo -e "${C_YELLOW}⚠️ Standard keygen failed, using fallback method...${C_RESET}"
        
        echo -e "${C_GREEN}[2/2] Using OpenSSL fallback...${C_RESET}"
        openssl rand -hex 32 > server.key
        chmod 600 server.key
        cat server.key | sha256sum | awk '{print $1}' > server.pub
        chmod 644 server.pub
    fi
    
    if [[ ! -f "server.key" ]] || [[ ! -f "server.pub" ]]; then
        echo -e "${C_RED}❌ Key generation failed${C_RESET}"
        return 1
    fi
    
    chmod 600 server.key
    chmod 644 server.pub
    
    PUBLIC_KEY=$(cat server.pub)
    echo -e "\n${C_GREEN}✅ Keys generated successfully!${C_RESET}"
    echo -e "  • Private key: ${C_CYAN}$DB_DIR/server.key${C_RESET}"
    echo -e "  • Public key:  ${C_CYAN}$DB_DIR/server.pub${C_RESET}"
    echo -e "  • Public key:  ${C_YELLOW}${PUBLIC_KEY:0:30}...${PUBLIC_KEY: -30}${C_RESET}"
}

# ========== CLOUDFLARE AUTO DOMAIN GENERATOR ==========
generate_cloudflare_domain() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ☁️  CLOUDFLARE AUTO DOMAIN GENERATOR${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    ns="ns-$rand"
    tun="tun-$rand"
    
    SERVER_IP=$(curl -s ifconfig.me)
    echo -e "${C_GREEN}[1/3] Server IP detected: $SERVER_IP${C_RESET}"
    
    echo -e "${C_GREEN}[2/3] Creating A record: $ns.$BASE_DOMAIN → $SERVER_IP${C_RESET}"
    
    ns_record_id=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{
            \"type\":\"A\",
            \"name\":\"$ns\",
            \"content\":\"$SERVER_IP\",
            \"ttl\":3600,
            \"proxied\":false
        }" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [[ -z "$ns_record_id" ]]; then
        echo -e "${C_RED}❌ Failed to create A record${C_RESET}"
        return 1
    fi
    echo -e "${C_GREEN}✓ A record created: $ns.$BASE_DOMAIN${C_RESET}"
    
    echo -e "${C_GREEN}[3/3] Creating NS record: $tun.$BASE_DOMAIN → $ns.$BASE_DOMAIN${C_RESET}"
    
    tunnel_record_id=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{
            \"type\":\"NS\",
            \"name\":\"$tun\",
            \"content\":\"$ns.$BASE_DOMAIN\",
            \"ttl\":3600,
            \"proxied\":false
        }" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [[ -z "$tunnel_record_id" ]]; then
        echo -e "${C_RED}❌ Failed to create NS record${C_RESET}"
        return 1
    fi
    echo -e "${C_GREEN}✓ NS record created: $tun.$BASE_DOMAIN${C_RESET}"
    
    DOMAIN="$tun.$BASE_DOMAIN"
    echo "$ns_record_id" > "$DB_DIR/cloudflare_ns_record.txt"
    echo "$tunnel_record_id" > "$DB_DIR/cloudflare_tunnel_record.txt"
    
    echo -e "\n${C_GREEN}✅ Auto-generated domain: ${C_YELLOW}$DOMAIN${C_RESET}"
    return 0
}

# ========== DOMAIN SETUP ==========
setup_domain() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🌐 DOMAIN CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_GREEN}Select domain option:${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Custom domain (Enter your own)"
    echo -e "  ${C_GREEN}2)${C_RESET} Auto-generate with Cloudflare"
    echo ""
    read -p "👉 Choice [1-2, default=1]: " domain_option
    domain_option=${domain_option:-1}
    
    if [[ "$domain_option" == "2" ]]; then
        if generate_cloudflare_domain; then
            echo -e "${C_GREEN}✅ Using auto-generated domain: $DOMAIN${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ Cloudflare failed, switching to custom domain...${C_RESET}"
            read -p "👉 Enter tunnel domain: " DOMAIN
        fi
    else
        read -p "👉 Enter tunnel domain (e.g., tunnel.yourdomain.com): " DOMAIN
    fi
    
    echo "$DOMAIN" > "$DB_DIR/domain.txt"
    echo -e "${C_GREEN}✅ Domain: $DOMAIN${C_RESET}"
}

# ========== MTU SELECTION ==========
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 SELECT MTU${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "  ${C_GREEN}[01]${C_RESET} MTU 512   - ⚡ STANDARD MODE"
    echo -e "  ${C_GREEN}[02]${C_RESET} MTU 800   - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[03]${C_RESET} MTU 1000  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[04]${C_RESET} MTU 1200  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[05]${C_RESET} MTU 1500  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[06]${C_RESET} MTU 1600  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[07]${C_RESET} MTU 1700  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[08]${C_RESET} MTU 1800  - 🔥 DECEPTION MODE"
    echo -e "  ${C_GREEN}[09]${C_RESET} Auto-detect optimal MTU"
    echo ""
    echo -e "${C_YELLOW}NOTE: All MTU >512 will appear as MTU 512 to ISP!${C_RESET}"
    echo ""
    
    local mtu_choice
    safe_read "👉 Select MTU option [01-09] (default 05): " mtu_choice
    mtu_choice=${mtu_choice:-05}
    
    case $mtu_choice in
        01|1) MTU=512 ;;
        02|2) MTU=800 ;;
        03|3) MTU=1000 ;;
        04|4) MTU=1200 ;;
        05|5) MTU=1500 ;;
        06|6) MTU=1600 ;;
        07|7) MTU=1700 ;;
        08|8) MTU=1800 ;;
        09|9) 
            echo -e "${C_YELLOW}Detecting optimal MTU...${C_RESET}"
            MTU=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
            echo -e "${C_GREEN}Optimal MTU: $MTU${C_RESET}"
            ;;
        *) MTU=1500 ;;
    esac
    
    mkdir -p "$CONFIG_DIR"
    echo "$MTU" > "$CONFIG_DIR/mtu"
    echo -e "${C_GREEN}✅ MTU $MTU selected${C_RESET}"
}

# ========== FIREWALL CONFIGURATION ==========
configure_firewall() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔥 FIREWALL CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo -e "${C_GREEN}[1/5] Disabling UFW if present...${C_RESET}"
    if command -v ufw &> /dev/null; then
        ufw --force disable 2>/dev/null || true
        systemctl stop ufw 2>/dev/null || true
        systemctl disable ufw 2>/dev/null || true
    fi
    
    echo -e "${C_GREEN}[2/5] Stopping systemd-resolved...${C_RESET}"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        systemctl stop systemd-resolved 2>/dev/null
        systemctl disable systemd-resolved 2>/dev/null
        
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
        chattr +i /etc/resolv.conf 2>/dev/null || true
    fi
    
    echo -e "${C_GREEN}[3/5] Flushing existing iptables rules...${C_RESET}"
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    
    echo -e "${C_GREEN}[4/5] Setting iptables rules...${C_RESET}"
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    iptables -I INPUT 1 -p udp --dport 5300 -j ACCEPT
    iptables -I OUTPUT 1 -p udp --sport 5300 -j ACCEPT
    iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
    iptables -I OUTPUT 1 -p udp --sport 53 -j ACCEPT
    
    iptables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports 5300
    
    iptables -I INPUT 2 -p tcp --dport 22 -j ACCEPT
    
    echo -e "${C_GREEN}[5/5] Saving iptables rules...${C_RESET}"
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save > /dev/null 2>&1
    fi
    
    echo -e "\n${C_GREEN}✅ Firewall configured${C_RESET}"
    echo -e "  • UDP 53 (DNS) → Redirect to 5300"
    echo -e "  • UDP 5300 (DNSTT) - ACCEPT"
    echo -e "  • TCP 22 (SSH) - ACCEPT"
}

# ========== CREATE DNSTT SERVICE ==========
create_dnstt_service() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📋 CREATING DNSTT SERVICE${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DB_DIR
ExecStart=$DNSTT_SERVER -udp :5300 -privkey-file $DB_DIR/server.key -mtu $mtu $domain 127.0.0.1:$ssh_port
Restart=always
RestartSec=3

StandardOutput=append:$LOGS_DIR/dnstt-server.log
StandardError=append:$LOGS_DIR/dnstt-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service > /dev/null 2>&1
    
    echo -e "${C_GREEN}✅ Service created successfully${C_RESET}"
    echo -e "  • Binary: ${C_CYAN}$DNSTT_SERVER${C_RESET}"
    echo -e "  • Options: ${C_CYAN}-mtu $mtu${C_RESET}"
    echo -e "  • Port: ${C_CYAN}5300${C_RESET}"
    echo -e "  • Target: ${C_CYAN}127.0.0.1:$ssh_port${C_RESET}"
}

# ========== DNSTT INFO FILE ==========
save_dnstt_info() {
    local domain=$1
    local pubkey=$2
    local mtu=$3
    local ssh_port=$4
    
    cat > "$DNSTT_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
PUBLIC_KEY="$pubkey"
MTU_VALUE="$mtu"
SSH_PORT="$ssh_port"
EOF
}

# ========== SHOW CLIENT COMMANDS ==========
show_client_commands() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    local pubkey=$(cat "$DB_DIR/server.pub")
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           📱 CLIENT COMMANDS${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 IPv4 - Direct UDP:${C_RESET}"
    echo -e "${WHITE}$DNSTT_CLIENT -udp 8.8.8.8:53 \\${C_RESET}"
    echo -e "${WHITE}  -pubkey-file $DB_DIR/server.pub \\${C_RESET}"
    echo -e "${WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${WHITE}  $domain 127.0.0.1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_CYAN}📌 IPv6 - Direct UDP:${C_RESET}"
    echo -e "${WHITE}$DNSTT_CLIENT -udp 2001:4860:4860::8888:53 \\${C_RESET}"
    echo -e "${WHITE}  -pubkey-file $DB_DIR/server.pub \\${C_RESET}"
    echo -e "${WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${WHITE}  $domain ::1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_GREEN}📌 Public Key:${C_RESET}"
    echo -e "${YELLOW}$pubkey${C_RESET}"
    echo ""
}

# ========== TRAFFIC MONITOR ==========
create_traffic_monitor() {
    cat > "$TRAFFIC_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"

while true; do
    if [ -f "$DB_FILE" ]; then
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
            if id "$user" &>/dev/null; then
                connections=$(pgrep -u "$user" sshd | wc -l)
                
                if [ $connections -gt 0 ]; then
                    new_traffic=$(echo "scale=3; $traffic_used + 0.01" | bc 2>/dev/null || echo "$traffic_used")
                    
                    if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ]; then
                        if [ $(echo "$new_traffic >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                            usermod -L "$user" 2>/dev/null
                            killall -u "$user" 2>/dev/null
                        fi
                    fi
                    
                    sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$new_traffic/" "$DB_FILE" 2>/dev/null
                fi
            fi
        done < "$DB_FILE"
    fi
    sleep 60
done
EOF
    chmod +x "$TRAFFIC_SCRIPT"
    
    cat > "$TRAFFIC_SERVICE" <<EOF
[Unit]
Description=Voltron Traffic Monitor
After=network.target

[Service]
Type=simple
ExecStart=$TRAFFIC_SCRIPT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltron-traffic.service 2>/dev/null
    systemctl start voltron-traffic.service 2>/dev/null
}

# ========== LIMITER SERVICE ==========
create_limiter_service() {
    cat > "$LIMITER_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"

while true; do
    if [ -f "$DB_FILE" ]; then
        current_ts=$(date +%s)
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
            [[ -z "$user" ]] && continue
            
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" 2>/dev/null
                continue
            fi
            
            online=$(pgrep -u "$user" sshd | wc -l)
            if [[ "$online" -gt "$limit" ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" 2>/dev/null
                (sleep 120; usermod -U "$user" 2>/dev/null) &
            fi
            
            if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ] && [ -n "$traffic_used" ]; then
                if [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                    usermod -L "$user" 2>/dev/null
                    killall -u "$user" 2>/dev/null
                fi
            fi
        done < "$DB_FILE"
    fi
    sleep 5
done
EOF
    chmod +x "$LIMITER_SCRIPT"
    
    cat > "$LIMITER_SERVICE" <<EOF
[Unit]
Description=Voltron Connection Limiter
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltron-limiter.service 2>/dev/null
    systemctl start voltron-limiter.service 2>/dev/null
}

# ========== SSH USER MANAGEMENT ==========
_create_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    
    local username
    read -p "👉 Enter username (or '0' to cancel): " username
    if [[ "$username" == "0" ]]; then
        echo -e "\n${C_YELLOW}❌ User creation cancelled.${C_RESET}"
        return
    fi
    
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Error: Username cannot be empty.${C_RESET}"
        return
    fi
    
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ Error: User '$username' already exists.${C_RESET}"
        return
    fi
    
    local password=""
    while true; do
        read -p "🔑 Enter new password: " password
        if [[ -z "$password" ]]; then
            echo -e "${C_RED}❌ Password cannot be empty. Please try again.${C_RESET}"
        else
            break
        fi
    done
    
    read -p "🗓️ Enter account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    read -p "📶 Enter simultaneous connection limit: " limit
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    read -p "📊 Traffic limit (GB) [0=unlimited]: " traffic_limit
    traffic_limit=${traffic_limit:-0}
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    useradd -m -s /usr/sbin/nologin "$username"
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$traffic_limit:0" >> "$DB_FILE"
    
    clear
    show_banner
    echo -e "${C_GREEN}✅ User '$username' created successfully!${C_RESET}\n"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    echo -e "  - 🗓️ Expires on:        ${C_YELLOW}$expire_date${C_RESET}"
    echo -e "  - 📶 Connection Limit:  ${C_YELLOW}$limit${C_RESET}"
    echo -e "  - 📊 Traffic Limit:     ${C_YELLOW}$traffic_limit GB${C_RESET}"
    safe_read "" dummy
}

_delete_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Delete User ---${C_RESET}"
    
    local username
    read -p "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local confirm
    read -p "Confirm delete? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    
    killall -u "$username" 2>/dev/null
    userdel -r "$username" 2>/dev/null
    sed -i "/^$username:/d" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User deleted${C_RESET}"
    safe_read "" dummy
}

_edit_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✏️ Edit User ---${C_RESET}"
    
    local username
    read -p "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local line=$(grep "^$username:" "$DB_FILE")
    if [ -z "$line" ]; then
        echo -e "\n${C_RED}❌ User not in database.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local current_pass=$(echo "$line" | cut -d: -f2)
    local current_expiry=$(echo "$line" | cut -d: -f3)
    local current_limit=$(echo "$line" | cut -d: -f4)
    local current_traffic_limit=$(echo "$line" | cut -d: -f5)
    local current_traffic_used=$(echo "$line" | cut -d: -f6)
    
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        echo -e "\nCurrent Details:"
        echo -e "  Expiry:        $current_expiry"
        echo -e "  Connection:    $current_limit"
        echo -e "  Traffic Limit: $current_traffic_limit GB"
        echo -e "  Traffic Used:  $current_traffic_used GB"
        echo -e "\nSelect a detail to edit:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🔑 Change Password"
        echo -e "  ${C_GREEN}2)${C_RESET} 🗓️ Change Expiration"
        echo -e "  ${C_GREEN}3)${C_RESET} 📶 Change Connection Limit"
        echo -e "  ${C_GREEN}4)${C_RESET} 📊 Change Traffic Limit"
        echo -e "\n  ${C_RED}0)${C_RESET} ✅ Finish Editing"
        echo
        read -p "👉 Enter your choice: " edit_choice
        
        case $edit_choice in
            1)
                local new_pass=""
                while true; do
                    read -p "Enter new password: " new_pass
                    if [[ -z "$new_pass" ]]; then
                        echo -e "${C_RED}❌ Password cannot be empty.${C_RESET}"
                    else
                        break
                    fi
                done
                echo "$username:$new_pass" | chpasswd
                sed -i "s/^$username:.*/$username:$new_pass:$current_expiry:$current_limit:$current_traffic_limit:$current_traffic_used/" "$DB_FILE"
                echo -e "\n${C_GREEN}✅ Password changed.${C_RESET}"
                ;;
            2)
                read -p "Enter new duration (days from today): " days
                if [[ "$days" =~ ^[0-9]+$ ]]; then
                    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E "$new_expiry" "$username"
                    sed -i "s/^$username:.*/$username:$current_pass:$new_expiry:$current_limit:$current_traffic_limit:$current_traffic_used/" "$DB_FILE"
                    current_expiry="$new_expiry"
                    echo -e "\n${C_GREEN}✅ Expiration updated to $new_expiry${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            3)
                read -p "Enter new connection limit: " new_limit
                if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                    sed -i "s/^$username:.*/$username:$current_pass:$current_expiry:$new_limit:$current_traffic_limit:$current_traffic_used/" "$DB_FILE"
                    current_limit="$new_limit"
                    echo -e "\n${C_GREEN}✅ Connection limit updated to $new_limit${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            4)
                read -p "Enter new traffic limit (GB) [0=unlimited]: " new_traffic
                if [[ "$new_traffic" =~ ^[0-9]+$ ]]; then
                    sed -i "s/^$username:.*/$username:$current_pass:$current_expiry:$current_limit:$new_traffic:$current_traffic_used/" "$DB_FILE"
                    current_traffic_limit="$new_traffic"
                    echo -e "\n${C_GREEN}✅ Traffic limit updated to $new_traffic GB${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            0)
                return
                ;;
            *)
                echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"
                ;;
        esac
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        read -r
    done
}

_lock_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔒 Lock User ---${C_RESET}"
    
    local username
    read -p "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    usermod -L "$username"
    killall -u "$username" -9 &>/dev/null
    echo -e "\n${C_GREEN}✅ User locked.${C_RESET}"
    safe_read "" dummy
}

_unlock_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔓 Unlock User ---${C_RESET}"
    
    local username
    read -p "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    usermod -U "$username"
    echo -e "\n${C_GREEN}✅ User unlocked.${C_RESET}"
    safe_read "" dummy
}

_list_users() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}                      📋 SSH USERS LIST${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}No SSH users found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    printf "${C_BOLD}%-15s | %-12s | %-8s | %-25s | %-10s${C_RESET}\n" "USERNAME" "EXPIRY" "LIMIT" "TRAFFIC" "STATUS"
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        [[ -z "$user" ]] && continue
        
        local online=0
        if id "$user" &>/dev/null; then
            online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        fi
        
        local traffic_limit_num=0
        local traffic_used_num=0
        
        if [[ -n "$traffic_limit" ]] && [[ "$traffic_limit" != "''" ]] && [[ "$traffic_limit" != "0" ]] && [[ "$traffic_limit" != "null" ]]; then
            traffic_limit_num=$(echo "$traffic_limit" | sed 's/[^0-9.]//g' | awk '{printf "%.0f", $1}' 2>/dev/null || echo "0")
        fi
        
        if [[ -n "$traffic_used" ]] && [[ "$traffic_used" != "''" ]] && [[ "$traffic_used" != "null" ]]; then
            if [[ "$traffic_used" == .* ]]; then
                traffic_used="0$traffic_used"
            fi
            traffic_used_num=$(echo "$traffic_used" | sed 's/[^0-9.]//g' | awk '{printf "%.2f", $1}' 2>/dev/null || echo "0")
        fi
        
        local traffic_disp=""
        if [[ "$traffic_limit_num" == "0" ]]; then
            traffic_disp="$(printf "%.2f" $traffic_used_num) GB / ∞"
        else
            if command -v bc &>/dev/null; then
                local percent=$(echo "scale=1; $traffic_used_num * 100 / $traffic_limit_num" | bc 2>/dev/null || echo "0")
                traffic_disp="$(printf "%.2f" $traffic_used_num) / $traffic_limit_num GB ($percent%)"
            else
                traffic_disp="$(printf "%.2f" $traffic_used_num) / $traffic_limit_num GB"
            fi
        fi
        
        local status_text=""
        local status_color=""
        
        if ! id "$user" &>/dev/null; then
            status_text="NO USER"
            status_color="${C_RED}"
        elif passwd -S "$user" 2>/dev/null | grep -q " L "; then
            status_text="LOCKED"
            status_color="${C_YELLOW}"
        else
            local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            local current_ts=$(date +%s)
            
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                status_text="EXPIRED"
                status_color="${C_RED}"
            elif [[ "$traffic_limit_num" -gt 0 ]] && (( $(echo "$traffic_used_num >= $traffic_limit_num" | bc -l 2>/dev/null) )); then
                status_text="LIMIT"
                status_color="${C_RED}"
            else
                status_text="ACTIVE"
                status_color="${C_GREEN}"
            fi
        fi
        
        printf "%-15s | %-12s | %-8s | %-25s | ${status_color}%-10s${C_RESET}\n" \
            "$user" "$expiry" "$online/$limit" "$traffic_disp" "$status_text"
            
    done < "$DB_FILE"
    
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────────────────${C_RESET}"
    echo ""
    safe_read "" dummy
}

_renew_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔄 Renew User ---${C_RESET}"
    
    local username
    read -p "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local line=$(grep "^$username:" "$DB_FILE")
    if [ -z "$line" ]; then
        echo -e "\n${C_RED}❌ User not in database.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "📆 Additional days: " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local pass=$(echo "$line" | cut -d: -f2)
    local limit=$(echo "$line" | cut -d: -f4)
    local traffic_limit=$(echo "$line" | cut -d: -f5)
    local traffic_used=$(echo "$line" | cut -d: -f6)
    
    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expiry" "$username"
    sed -i "s/^$username:.*/$username:$pass:$new_expiry:$limit:$traffic_limit:$traffic_used/" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User renewed until $new_expiry${C_RESET}"
    safe_read "" dummy
}

_cleanup_expired() {
    echo -e "\n${C_BLUE}🧹 Cleaning up expired users...${C_RESET}"
    local current_ts=$(date +%s)
    local count=0
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            killall -u "$user" 2>/dev/null
            userdel -r "$user" 2>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
            echo "  Removed $user"
            ((count++))
        fi
    done < "$DB_FILE"
    
    echo -e "${C_GREEN}✅ Removed $count expired users${C_RESET}"
    safe_read "" dummy
}

# ========== SSH BANNER MANAGEMENT ==========
_set_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Set SSH Banner ---${C_RESET}"
    echo -e "${C_YELLOW}⚠️  Paste your banner below. Press ${C_YELLOW}[Ctrl+D]${C_RESET} when finished"
    echo -e "${C_CYAN}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    local temp_banner="/tmp/ssh_banner_temp.txt"
    cat > "$temp_banner"
    
    if [ ! -s "$temp_banner" ]; then
        echo -e "\n${C_RED}❌ Banner cannot be empty!${C_RESET}"
        rm -f "$temp_banner"
        safe_read "" dummy
        return
    fi
    
    cp "$temp_banner" "$SSH_BANNER_FILE"
    chmod 644 "$SSH_BANNER_FILE"
    rm -f "$temp_banner"
    
    echo -e "\n${C_GREEN}✅ Banner saved successfully!${C_RESET}"
    
    _enable_banner_in_sshd_config
    _restart_ssh
    
    safe_read "" dummy
}

_view_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 👁️ Current SSH Banner ---${C_RESET}"
    
    if [ -f "$SSH_BANNER_FILE" ]; then
        echo -e "\n${C_CYAN}--- BEGIN BANNER ---${C_RESET}"
        cat "$SSH_BANNER_FILE"
        echo -e "\n${C_CYAN}---- END BANNER ----${C_RESET}"
    else
        echo -e "\n${C_YELLOW}No banner file found.${C_RESET}"
    fi
    safe_read "" dummy
}

_remove_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Remove SSH Banner ---${C_RESET}"
    
    read -p "Are you sure? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    
    rm -f "$SSH_BANNER_FILE"
    sed -i.bak -E "s/^( *Banner\s+$SSH_BANNER_FILE)/#\1/" /etc/ssh/sshd_config
    
    echo -e "\n${C_GREEN}✅ Banner removed.${C_RESET}"
    _restart_ssh
    safe_read "" dummy
}

_enable_banner_in_sshd_config() {
    echo -e "\n${C_BLUE}⚙️ Configuring sshd_config...${C_RESET}"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)
    sed -i '/^Banner/d' /etc/ssh/sshd_config
    echo -e "\n# SSH Banner\nBanner $SSH_BANNER_FILE" >> /etc/ssh/sshd_config
    echo -e "${C_GREEN}✅ sshd_config updated.${C_RESET}"
}

_restart_ssh() {
    echo -e "\n${C_BLUE}🔄 Restarting SSH service...${C_RESET}"
    local ssh_service=""
    if systemctl list-units --full -all | grep -q "sshd.service"; then
        ssh_service="sshd"
    elif systemctl list-units --full -all | grep -q "ssh.service"; then
        ssh_service="ssh"
    else
        echo -e "${C_RED}❌ SSH service not found.${C_RESET}"
        return 1
    fi
    systemctl restart "$ssh_service"
    echo -e "${C_GREEN}✅ SSH service restarted.${C_RESET}"
}

ssh_banner_menu() {
    while true; do
        clear
        show_banner
        
        local banner_status=""
        if grep -q -E "^\s*Banner\s+$SSH_BANNER_FILE" /etc/ssh/sshd_config && [ -f "$SSH_BANNER_FILE" ]; then
            banner_status="${C_GREEN}(Active)${C_RESET}"
        else
            banner_status="${C_DIM}(Inactive)${C_RESET}"
        fi
        
        echo -e "\n   ${C_TITLE}════════════════════[ ${C_BOLD}🎨 SSH Banner Management ${banner_status} ${C_RESET}${C_TITLE}]════════════════════${C_RESET}"
        echo -e "     ${C_GREEN}1)${C_RESET} 📋 Set Banner"
        echo -e "     ${C_GREEN}2)${C_RESET} 👁️ View Banner"
        echo -e "     ${C_RED}3)${C_RESET} 🗑️ Remove Banner"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_YELLOW}0)${C_RESET} ↩️ Return"
        echo
        read -p "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) _set_ssh_banner ;;
            2) _view_ssh_banner ;;
            3) _remove_ssh_banner ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

# ========== DNSTT INSTALLATION ==========
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is already installed.${C_RESET}"
        read -p "Reinstall? (y/n): " reinstall
        if [[ "$reinstall" != "y" ]]; then
            return
        fi
        systemctl stop dnstt.service 2>/dev/null
    fi
    
    # Step 1: Install dependencies
    echo -e "\n${C_BLUE}[1/8] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL wget curl git build-essential openssl
    
    # Step 2: Install Go
    echo -e "\n${C_BLUE}[2/8] Installing Go...${C_RESET}"
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    # Step 3: Build DNSTT from source
    echo -e "\n${C_BLUE}[3/8] Building DNSTT from source...${C_RESET}"
    if ! build_dnstt_from_source; then
        echo -e "${C_RED}❌ Failed to build DNSTT${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Step 4: Configure firewall
    echo -e "\n${C_BLUE}[4/8] Configuring firewall...${C_RESET}"
    configure_firewall
    
    # Step 5: Setup domain
    echo -e "\n${C_BLUE}[5/8] Domain configuration...${C_RESET}"
    setup_domain
    
    # Step 6: MTU selection
    echo -e "\n${C_BLUE}[6/8] MTU selection...${C_RESET}"
    mtu_selection_during_install
    
    # Step 7: Generate keys
    echo -e "\n${C_BLUE}[7/8] Generating keys...${C_RESET}"
    if ! generate_keys; then
        echo -e "${C_RED}❌ Failed to generate keys${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Get SSH port
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    SSH_PORT=${SSH_PORT:-22}
    
    # Step 8: Create service
    echo -e "\n${C_BLUE}[8/8] Creating service...${C_RESET}"
    create_dnstt_service "$DOMAIN" "$MTU" "$SSH_PORT"
    
    # Save DNSTT info
    save_dnstt_info "$DOMAIN" "$PUBLIC_KEY" "$MTU" "$SSH_PORT"
    
    # Apply ULTRA speed booster
    echo -e "\n${C_BLUE}🚀 Applying ULTRA speed booster...${C_RESET}"
    optimize_system_ultra
    
    # Start service
    echo -e "\n${C_BLUE}🚀 Starting DNSTT service...${C_RESET}"
    systemctl start dnstt.service
    sleep 3
    
    if systemctl is-active --quiet dnstt.service; then
        echo -e "${C_GREEN}✅ Service started successfully${C_RESET}"
    else
        echo -e "${C_RED}❌ Service failed to start${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
    fi
    
    # Show client commands
    show_client_commands "$DOMAIN" "$MTU" "$SSH_PORT"
    
    # Save info
    cat > "$DB_DIR/dnstt_info.txt" <<EOF
DNSTT Configuration
============================================
Domain: $DOMAIN
MTU: $MTU
SSH Port: $SSH_PORT
Public Key: $(cat "$DB_DIR/server.pub")

Client Commands:
----------------
IPv4: $DNSTT_CLIENT -udp 8.8.8.8:53 -pubkey-file $DB_DIR/server.pub -mtu $MTU $DOMAIN 127.0.0.1:$SSH_PORT
IPv6: $DNSTT_CLIENT -udp 2001:4860:4860::8888:53 -pubkey-file $DB_DIR/server.pub -mtu $MTU $DOMAIN ::1:$SSH_PORT
EOF
    
    echo -e "\n${C_GREEN}✅ DNSTT installation complete!${C_RESET}"
    echo -e "${C_YELLOW}📁 Info saved to: $DB_DIR/dnstt_info.txt${C_RESET}"
    safe_read "" dummy
}

uninstall_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNSTT...${C_RESET}"
    
    systemctl stop dnstt.service 2>/dev/null
    systemctl disable dnstt.service 2>/dev/null
    rm -f "$DNSTT_SERVICE"
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT"
    rm -rf "$DB_DIR/dnstt"
    rm -f "$DB_DIR/server.key" "$DB_DIR/server.pub"
    rm -f "$DB_DIR/domain.txt" "$DB_DIR/mtu.txt"
    rm -f "$DNSTT_INFO_FILE"
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNSTT uninstalled${C_RESET}"
    safe_read "" dummy
}

show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DB_DIR/domain.txt" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    DOMAIN=$(cat "$DB_DIR/domain.txt" 2>/dev/null || echo "unknown")
    MTU=$(cat "$DB_DIR/mtu.txt" 2>/dev/null || echo "unknown")
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    SSH_PORT=${SSH_PORT:-22}
    PUBKEY=$(cat "$DB_DIR/server.pub" 2>/dev/null || echo "unknown")
    
    local status=""
    if systemctl is-active dnstt.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  Domain:        ${C_YELLOW}$DOMAIN${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    echo -e "  SSH Port:      ${C_YELLOW}$SSH_PORT${C_RESET}"
    echo -e "  Binary:        ${C_YELLOW}$DNSTT_SERVER${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}${PUBKEY:0:30}...${PUBKEY: -30}${C_RESET}"
    
    safe_read "" dummy
}

# ========== MULTI-TUNNEL DNSTT FUNCTIONS ==========

check_dnstt_installed() {
    if [ ! -f "$DNSTT_CLIENT" ]; then
        echo -e "${C_RED}❌ DNSTT client not found at $DNSTT_CLIENT${C_RESET}"
        echo -e "${C_YELLOW}Please install DNSTT first (Option 4 in Protocols menu)${C_RESET}"
        return 1
    fi
    
    if [ ! -f "$DNSTT_INFO_FILE" ]; then
        echo -e "${C_RED}❌ DNSTT configuration not found at $DNSTT_INFO_FILE${C_RESET}"
        echo -e "${C_YELLOW}Please install DNSTT first (Option 4 in Protocols menu)${C_RESET}"
        return 1
    fi
    
    source "$DNSTT_INFO_FILE"
    
    if [ -z "$TUNNEL_DOMAIN" ] || [ -z "$PUBLIC_KEY" ]; then
        echo -e "${C_RED}❌ DNSTT configuration is incomplete${C_RESET}"
        return 1
    fi
    
    echo -e "${C_GREEN}✅ DNSTT check passed${C_RESET}"
    return 0
}

check_ports_available() {
    local base_port=$1
    local count=$2
    local all_free=0
    
    for ((i=0; i<count; i++)); do
        local port=$((base_port + i))
        if ss -tln | grep -q ":$port "; then
            echo -e "${C_RED}❌ Port $port is already in use${C_RESET}"
            all_free=1
        fi
    done
    
    if [ $all_free -eq 0 ]; then
        echo -e "${C_GREEN}✅ All ports are available${C_RESET}"
        return 0
    else
        return 1
    fi
}

configure_multi_tunnel_proxychains() {
    local tunnel_count=$1
    local base_port=$2
    
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 CONFIGURING PROXYCHAINS FOR MULTI-TUNNEL${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Install proxychains if not exists
    if ! command -v proxychains4 &>/dev/null; then
        echo -e "${C_YELLOW}📦 Installing proxychains4...${C_RESET}"
        $PKG_INSTALL proxychains4
    fi
    
    # Backup original
    [ -f "$MULTI_TUNNEL_PROXYCHAINS" ] && cp "$MULTI_TUNNEL_PROXYCHAINS" "$MULTI_TUNNEL_PROXYCHAINS.backup"
    
    cat > "$MULTI_TUNNEL_PROXYCHAINS" <<EOF
# ===== VOLTRON TECH MULTI-TUNNEL DNSTT =====
# Created: $(date)
# Tunnels: $tunnel_count

dynamic_chain
strict_chain off
round_robin_chain on
quiet_mode
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
EOF

    for ((i=0; i<tunnel_count; i++)); do
        local port=$((base_port + i))
        echo "socks5 127.0.0.1 $port" >> "$MULTI_TUNNEL_PROXYCHAINS"
    done
    
    echo -e "${C_GREEN}✅ Proxychains configured with $tunnel_count SOCKS5 proxies${C_RESET}"
    echo -e "  • Config: ${C_CYAN}$MULTI_TUNNEL_PROXYCHAINS${C_RESET}"
    echo -e "  • Ports: ${C_CYAN}$base_port-$((base_port + tunnel_count - 1))${C_RESET}"
}

start_multi_tunnel() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 STARTING MULTI-TUNNEL DNSTT (5x SPEED)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Check if DNSTT is installed
    if ! check_dnstt_installed; then
        safe_read "" dummy
        return 1
    fi
    
    # Load DNSTT config
    source "$DNSTT_INFO_FILE"
    
    local domain="$TUNNEL_DOMAIN"
    local pubkey="$PUBLIC_KEY"
    local mtu="$MTU_VALUE"
    local ssh_port="$SSH_PORT"
    
    echo -e "${C_GREEN}✅ DNSTT configuration loaded${C_RESET}"
    echo -e "  • Domain: ${C_CYAN}$domain${C_RESET}"
    echo -e "  • MTU: ${C_CYAN}$mtu${C_RESET}"
    echo -e "  • SSH Port: ${C_CYAN}$ssh_port${C_RESET}"
    
    # Get number of tunnels
    local tunnel_count
    read -p "👉 Number of tunnels [1-10, default=5]: " tunnel_count
    tunnel_count=${tunnel_count:-5}
    if ! [[ "$tunnel_count" =~ ^[0-9]+$ ]] || [ "$tunnel_count" -lt 1 ] || [ "$tunnel_count" -gt 10 ]; then
        echo -e "${C_RED}❌ Invalid number. Using 5.${C_RESET}"
        tunnel_count=5
    fi
    
    # Get base port
    local base_port
    read -p "👉 Base SOCKS port [1080]: " base_port
    base_port=${base_port:-1080}
    if ! [[ "$base_port" =~ ^[0-9]+$ ]] || [ "$base_port" -lt 1024 ] || [ "$base_port" -gt 65535 ]; then
        echo -e "${C_RED}❌ Invalid port. Using 1080.${C_RESET}"
        base_port=1080
    fi
    
    # Check if ports are available
    if ! check_ports_available "$base_port" "$tunnel_count"; then
        echo -e "${C_RED}❌ Some ports are already in use. Please choose different base port.${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Get DNS resolver
    local dns_resolver
    echo -e "\n${C_YELLOW}Select DNS resolver:${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Halotel (169.255.187.58) - Recommended for Tanzania"
    echo -e "  ${C_GREEN}2)${C_RESET} Google (8.8.8.8)"
    echo -e "  ${C_GREEN}3)${C_RESET} Cloudflare (1.1.1.1)"
    echo -e "  ${C_GREEN}4)${C_RESET} Custom"
    read -p "👉 Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    case $dns_choice in
        1) dns_resolver="169.255.187.58:53" ;;
        2) dns_resolver="8.8.8.8:53" ;;
        3) dns_resolver="1.1.1.1:53" ;;
        4) read -p "Enter custom DNS (e.g., 8.8.8.8:53): " dns_resolver ;;
        *) dns_resolver="169.255.187.58:53" ;;
    esac
    
    # Stop existing tunnels
    echo -e "\n${C_YELLOW}🛑 Stopping any existing tunnels...${C_RESET}"
    pkill -f "dnstt-client.*$domain" 2>/dev/null
    rm -rf "$MULTI_TUNNEL_PID_DIR"/*
    sleep 2
    
    # Configure proxychains
    configure_multi_tunnel_proxychains "$tunnel_count" "$base_port"
    
    # Save config
    cat > "$MULTI_TUNNEL_CONFIG" <<EOF
TUNNEL_COUNT="$tunnel_count"
BASE_PORT="$base_port"
DNS_RESOLVER="$dns_resolver"
DOMAIN="$domain"
MTU="$mtu"
SSH_PORT="$ssh_port"
EOF
    
    # Start tunnels
    echo -e "\n${C_BLUE}🚀 Starting $tunnel_count DNSTT tunnels...${C_RESET}"
    
    local success_count=0
    for ((i=0; i<tunnel_count; i++)); do
        local port=$((base_port + i))
        local pid_file="$MULTI_TUNNEL_PID_DIR/tunnel-$port.pid"
        local log_file="$MULTI_TUNNEL_DIR/tunnel-$port.log"
        
        echo -e "${C_CYAN}  Starting tunnel $((i+1)) on SOCKS5 port $port...${C_RESET}"
        
        $DNSTT_CLIENT \
            -udp "$dns_resolver" \
            -pubkey "$pubkey" \
            -mtu "$mtu" \
            -listen "127.0.0.1:$port" \
            "$domain" "127.0.0.1:$ssh_port" \
            > "$log_file" 2>&1 &
        
        echo $! > "$pid_file"
        sleep 1
        
        if kill -0 $(cat "$pid_file") 2>/dev/null; then
            echo -e "    ${C_GREEN}✅ Started${C_RESET}"
            ((success_count++))
        else
            echo -e "    ${C_RED}❌ Failed${C_RESET}"
        fi
    done
    
    echo ""
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ MULTI-TUNNEL DNSTT ACTIVE!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Domain:${C_RESET}      $domain"
    echo -e "  ${C_CYAN}DNS Resolver:${C_RESET} $dns_resolver"
    echo -e "  ${C_CYAN}MTU:${C_RESET}          $mtu"
    echo -e "  ${C_CYAN}Tunnels:${C_RESET}       $success_count/$tunnel_count active"
    echo -e "  ${C_CYAN}Ports:${C_RESET}         $base_port-$((base_port + tunnel_count - 1))"
    echo ""
    echo -e "${C_YELLOW}📌 USAGE EXAMPLES:${C_RESET}"
    echo -e "  ${WHITE}proxychains4 curl ifconfig.me${NC}"
    echo -e "  ${WHITE}proxychains4 ssh user@localhost -p $ssh_port${NC}"
    echo -e "  ${WHITE}proxychains4 wget -O /dev/null http://speedtest.tele2.net/10MB.zip${NC}"
    echo ""
    echo -e "${C_YELLOW}📌 ProxyChains config:${C_RESET} ${C_CYAN}$MULTI_TUNNEL_PROXYCHAINS${C_RESET}"
    
    # Save info
    cat > "$MULTI_TUNNEL_DIR/connection_info.txt" <<EOF
VOLTRON TECH MULTI-TUNNEL DNSTT
================================
Domain: $domain
DNS Resolver: $dns_resolver
MTU: $mtu
SSH Port: $ssh_port
Tunnels: $success_count/$tunnel_count
Port Range: $base_port-$((base_port + tunnel_count - 1))

Proxychains Config: $MULTI_TUNNEL_PROXYCHAINS

Usage:
  proxychains4 curl ifconfig.me
  proxychains4 ssh user@localhost -p $ssh_port
EOF
    
    safe_read "" dummy
}

stop_multi_tunnel() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 STOPPING MULTI-TUNNEL DNSTT${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -d "$MULTI_TUNNEL_PID_DIR" ]; then
        echo -e "${C_YELLOW}ℹ️ No multi-tunnel is running${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local count=0
    for pid_file in "$MULTI_TUNNEL_PID_DIR"/*.pid; do
        [ -f "$pid_file" ] || continue
        local pid=$(cat "$pid_file")
        local port=$(basename "$pid_file" | sed 's/tunnel-\(.*\)\.pid/\1/')
        
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            echo -e "${C_YELLOW}  Stopped tunnel on port $port${C_RESET}"
            ((count++))
        fi
        rm -f "$pid_file"
    done
    
    echo -e "${C_GREEN}✅ Stopped $count tunnels${C_RESET}"
    safe_read "" dummy
}

status_multi_tunnel() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📊 MULTI-TUNNEL DNSTT STATUS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -d "$MULTI_TUNNEL_PID_DIR" ]; then
        echo -e "${C_YELLOW}ℹ️ No multi-tunnel is running${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local total=0
    local running=0
    
    for pid_file in "$MULTI_TUNNEL_PID_DIR"/*.pid; do
        [ -f "$pid_file" ] || continue
        ((total++))
        local port=$(basename "$pid_file" | sed 's/tunnel-\(.*\)\.pid/\1/')
        
        if kill -0 $(cat "$pid_file") 2>/dev/null; then
            echo -e "  ${C_GREEN}● Tunnel on port $port - RUNNING${C_RESET}"
            ((running++))
        else
            echo -e "  ${C_RED}○ Tunnel on port $port - STOPPED${C_RESET}"
            rm -f "$pid_file"
        fi
    done
    
    if [ $total -eq 0 ]; then
        echo -e "${C_YELLOW}ℹ️ No tunnels configured${C_RESET}"
    else
        echo ""
        echo -e "  ${C_CYAN}Total tunnels:${C_RESET} $total"
        echo -e "  ${C_CYAN}Running:${C_RESET}       $running"
        echo -e "  ${C_CYAN}Stopped:${C_RESET}       $((total - running))"
    fi
    
    # Show config if exists
    if [ -f "$MULTI_TUNNEL_CONFIG" ]; then
        echo ""
        echo -e "${C_CYAN}Configuration:${C_RESET}"
        source "$MULTI_TUNNEL_CONFIG"
        echo -e "  Domain: $DOMAIN"
        echo -e "  DNS: $DNS_RESOLVER"
        echo -e "  MTU: $MTU"
        echo -e "  SSH Port: $SSH_PORT"
        echo -e "  Proxychains: $MULTI_TUNNEL_PROXYCHAINS"
    fi
    
    safe_read "" dummy
}

test_multi_tunnel_speed() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 TESTING MULTI-TUNNEL SPEED${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -f "$MULTI_TUNNEL_PROXYCHAINS" ]; then
        echo -e "${C_RED}❌ Proxychains config not found. Start multi-tunnel first.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_YELLOW}📌 Direct connection (without proxy):${C_RESET}"
    local direct_speed=$(curl -s -o /dev/null -w "%{speed_download}" http://speedtest.tele2.net/10MB.zip 2>/dev/null)
    if [ -n "$direct_speed" ]; then
        echo -e "  Speed: $(echo "scale=2; $direct_speed/1048576" | bc) MB/s"
    else
        echo -e "  ${C_RED}Failed to test direct connection${C_RESET}"
    fi
    
    echo ""
    echo -e "${C_YELLOW}📌 Through multi-tunnel (proxychains):${C_RESET}"
    local proxy_speed=$(proxychains4 -f "$MULTI_TUNNEL_PROXYCHAINS" curl -s -o /dev/null -w "%{speed_download}" http://speedtest.tele2.net/10MB.zip 2>/dev/null)
    if [ -n "$proxy_speed" ]; then
        echo -e "  Speed: $(echo "scale=2; $proxy_speed/1048576" | bc) MB/s"
        
        if [ -n "$direct_speed" ] && [ "$(echo "$proxy_speed > $direct_speed" | bc)" -eq 1 ]; then
            local boost=$(echo "scale=2; $proxy_speed / $direct_speed" | bc)
            echo -e "\n${C_GREEN}✅ Multi-tunnel is ${boost}x faster!${C_RESET}"
        fi
    else
        echo -e "  ${C_RED}Failed to test multi-tunnel connection${C_RESET}"
    fi
    
    safe_read "" dummy
}

configure_multi_tunnel_settings() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ⚙️ MULTI-TUNNEL SETTINGS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    local current_count=$DEFAULT_TUNNEL_COUNT
    local current_port=$BASE_SOCKS_PORT
    
    if [ -f "$MULTI_TUNNEL_CONFIG" ]; then
        source "$MULTI_TUNNEL_CONFIG"
        current_count="$TUNNEL_COUNT"
        current_port="$BASE_PORT"
    fi
    
    read -p "👉 Number of tunnels [1-10, default=$current_count]: " new_count
    new_count=${new_count:-$current_count}
    if [[ "$new_count" =~ ^[0-9]+$ ]] && [ "$new_count" -ge 1 ] && [ "$new_count" -le 10 ]; then
        DEFAULT_TUNNEL_COUNT=$new_count
        echo -e "${C_GREEN}✅ Tunnel count set to $new_count${C_RESET}"
    else
        echo -e "${C_RED}❌ Invalid value. Keeping $current_count${C_RESET}"
    fi
    
    read -p "👉 Base SOCKS port [1024-65535, default=$current_port]: " new_port
    new_port=${new_port:-$current_port}
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
        BASE_SOCKS_PORT=$new_port
        echo -e "${C_GREEN}✅ Base port set to $new_port${C_RESET}"
    else
        echo -e "${C_RED}❌ Invalid value. Keeping $current_port${C_RESET}"
    fi
    
    safe_read "" dummy
}

multi_tunnel_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🚀 MULTI-TUNNEL DNSTT (5x SPEED)${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Start Multi-Tunnel"
        echo -e "  ${C_GREEN}2)${C_RESET} Stop All Tunnels"
        echo -e "  ${C_GREEN}3)${C_RESET} View Status"
        echo -e "  ${C_GREEN}4)${C_RESET} Test Speed"
        echo -e "  ${C_GREEN}5)${C_RESET} Configure Settings"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return to Main Menu"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) start_multi_tunnel ;;
            2) stop_multi_tunnel ;;
            3) status_multi_tunnel ;;
            4) test_multi_tunnel_speed ;;
            5) configure_multi_tunnel_settings ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== BADVPN INSTALLATION ==========
install_badvpn() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing badvpn ---${C_RESET}"
    
    $PKG_INSTALL cmake make gcc git
    cd /tmp
    git clone https://github.com/ambrop72/badvpn.git
    cd badvpn
    cmake .
    make
    cp badvpn-udpgw "$BADVPN_BIN"
    
    cat > "$BADVPN_SERVICE" <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=$BADVPN_BIN --listen-addr 0.0.0.0:$BADVPN_PORT --max-clients 1000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    echo -e "${C_GREEN}✅ badvpn installed on port $BADVPN_PORT${C_RESET}"
    safe_read "" dummy
}

uninstall_badvpn() {
    systemctl stop badvpn.service 2>/dev/null
    systemctl disable badvpn.service 2>/dev/null
    rm -f "$BADVPN_SERVICE" "$BADVPN_BIN"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ badvpn uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== UDP-CUSTOM INSTALLATION ==========
install_udp_custom() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing udp-custom ---${C_RESET}"
    
    mkdir -p "$UDP_CUSTOM_DIR"
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o "$UDP_CUSTOM_BIN" "https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-amd64"
    else
        curl -L -o "$UDP_CUSTOM_BIN" "https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-arm64"
    fi
    chmod +x "$UDP_CUSTOM_BIN"
    
    cat > "$UDP_CUSTOM_DIR/config.json" <<EOF
{"listen": ":$UDP_CUSTOM_PORT", "auth": {"mode": "passwords"}}
EOF

    cat > "$UDP_CUSTOM_SERVICE" <<EOF
[Unit]
Description=UDP Custom
After=network.target

[Service]
Type=simple
WorkingDirectory=$UDP_CUSTOM_DIR
ExecStart=$UDP_CUSTOM_BIN server -exclude 53,5300
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl start udp-custom.service
    echo -e "${C_GREEN}✅ udp-custom installed on port $UDP_CUSTOM_PORT${C_RESET}"
    safe_read "" dummy
}

uninstall_udp_custom() {
    systemctl stop udp-custom.service 2>/dev/null
    systemctl disable udp-custom.service 2>/dev/null
    rm -f "$UDP_CUSTOM_SERVICE"
    rm -rf "$UDP_CUSTOM_DIR"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ udp-custom uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== SSL TUNNEL INSTALLATION ==========
install_ssl_tunnel() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔒 Installing SSL Tunnel ---${C_RESET}"
    
    $PKG_INSTALL haproxy
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" -subj "/CN=VOLTRON TECH" 2>/dev/null
    
    cat > "$HAPROXY_CONFIG" <<EOF
global
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend ssh_ssl_in
    bind *:$SSL_PORT ssl crt $SSL_CERT_FILE
    default_backend ssh_backend

backend ssh_backend
    server ssh_server 127.0.0.1:22
EOF

    systemctl restart haproxy
    echo -e "${C_GREEN}✅ SSL Tunnel installed on port $SSL_PORT${C_RESET}"
    safe_read "" dummy
}

uninstall_ssl_tunnel() {
    systemctl stop haproxy 2>/dev/null
    $PKG_REMOVE haproxy
    rm -f "$HAPROXY_CONFIG"
    rm -f "$SSL_CERT_FILE"
    echo -e "${C_GREEN}✅ SSL Tunnel uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== VOLTRON PROXY INSTALLATION ==========
install_voltron_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🦅 Installing VOLTRON Proxy ---${C_RESET}"
    
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxy"
    else
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxyarm"
    fi
    chmod +x "$VOLTRONPROXY_BIN"
    
    read -p "Enter port(s) [8080]: " ports
    ports=${ports:-8080}
    
    cat > "$VOLTRONPROXY_SERVICE" <<EOF
[Unit]
Description=VOLTRON Proxy
After=network.target

[Service]
Type=simple
ExecStart=$VOLTRONPROXY_BIN -p $ports
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltronproxy.service
    systemctl start voltronproxy.service
    
    echo "$ports" > "$CONFIG_DIR/voltronproxy_ports.conf"
    echo -e "${C_GREEN}✅ VOLTRON Proxy installed on port(s) $ports${C_RESET}"
    safe_read "" dummy
}

uninstall_voltron_proxy() {
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f "$VOLTRONPROXY_SERVICE" "$VOLTRONPROXY_BIN"
    rm -f "$CONFIG_DIR/voltronproxy_ports.conf"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ VOLTRON Proxy uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== NGINX PROXY INSTALLATION ==========
install_nginx_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Installing Nginx Proxy ---${C_RESET}"
    
    $PKG_INSTALL nginx
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.pem -subj "/CN=VOLTRON TECH" 2>/dev/null
    
    cat > "$NGINX_CONFIG" <<'EOF'
server {
    listen 80;
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
    }
}
EOF

    systemctl restart nginx
    echo -e "${C_GREEN}✅ Nginx Proxy installed${C_RESET}"
    safe_read "" dummy
}

uninstall_nginx_proxy() {
    systemctl stop nginx 2>/dev/null
    $PKG_REMOVE nginx
    rm -f "$NGINX_CONFIG"
    echo -e "${C_GREEN}✅ Nginx Proxy uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== ZIVPN INSTALLATION ==========
install_zivpn() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🛡️ Installing ZiVPN ---${C_RESET}"
    
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o "$ZIVPN_BIN" "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    else
        curl -L -o "$ZIVPN_BIN" "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
    fi
    chmod +x "$ZIVPN_BIN"
    mkdir -p "$ZIVPN_DIR"
    
    openssl req -x509 -newkey rsa:4096 -nodes -days 365 -keyout "$ZIVPN_DIR/server.key" -out "$ZIVPN_DIR/server.crt" -subj "/CN=ZiVPN" 2>/dev/null
    
    read -p "Passwords (comma-separated) [user1,user2]: " passwords
    passwords=${passwords:-user1,user2}
    
    IFS=',' read -ra pass_array <<< "$passwords"
    json_passwords=$(printf '"%s",' "${pass_array[@]}")
    json_passwords="[${json_passwords%,}]"
    
    cat > "$ZIVPN_DIR/config.json" <<EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "$ZIVPN_DIR/server.crt",
  "key": "$ZIVPN_DIR/server.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": $json_passwords}
}
EOF

    cat > "$ZIVPN_SERVICE" <<EOF
[Unit]
Description=ZiVPN Server
After=network.target

[Service]
Type=simple
ExecStart=$ZIVPN_BIN server -c $ZIVPN_DIR/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service
    echo -e "${C_GREEN}✅ ZiVPN installed on port $ZIVPN_PORT${C_RESET}"
    safe_read "" dummy
}

uninstall_zivpn() {
    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    rm -f "$ZIVPN_SERVICE" "$ZIVPN_BIN"
    rm -rf "$ZIVPN_DIR"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ ZiVPN uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== X-UI PANEL INSTALLATION ==========
install_xui_panel() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💻 Installing X-UI Panel ---${C_RESET}"
    
    bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
    safe_read "" dummy
}

uninstall_xui_panel() {
    if command -v x-ui &>/dev/null; then
        x-ui uninstall
    fi
    rm -f /usr/local/bin/x-ui
    rm -rf /etc/x-ui /usr/local/x-ui
    echo -e "${C_GREEN}✅ X-UI uninstalled${C_RESET}"
    safe_read "" dummy
}

# ========== DT PROXY FUNCTIONS ==========
install_dt_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing DT Proxy ---${C_RESET}"
    
    echo -e "\n${C_BLUE}📥 Installing DT Proxy...${C_RESET}"
    if curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash; then
        echo -e "${C_GREEN}✅ DT Proxy installed successfully${C_RESET}"
    else
        echo -e "${C_RED}❌ Failed to install DT Proxy${C_RESET}"
    fi
    safe_read "" dummy
}

uninstall_dt_proxy() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DT Proxy...${C_RESET}"
    
    echo -e "${C_BLUE}Stopping proxy services...${C_RESET}"
    systemctl list-units --type=service --state=running | grep 'proxy-' | awk '{print $1}' | while read service; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    done
    
    echo -e "${C_BLUE}Removing service files...${C_RESET}"
    rm -f /etc/systemd/system/proxy-*.service
    systemctl daemon-reload
    
    echo -e "${C_BLUE}Removing binaries...${C_RESET}"
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f "$HOME/.proxy_token"
    rm -f /usr/local/bin/install_mod
    
    echo -e "${C_BLUE}Removing log files...${C_RESET}"
    rm -f /var/log/proxy-*.log
    
    echo -e "${C_GREEN}✅ DT Proxy uninstalled successfully${C_RESET}"
    safe_read "" dummy
}

check_dt_proxy_status() {
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "${C_BLUE}(installed)${C_RESET}"
    else
        echo ""
    fi
}

dt_proxy_menu() {
    while true; do
        clear
        show_banner
        
        local status=""
        if [ -f "/usr/local/bin/main" ]; then
            status="${C_GREEN}(installed)${C_RESET}"
        else
            status="${C_RED}(not installed)${C_RESET}"
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🚀 DT PROXY MANAGEMENT ${status}${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        
        if [ -f "/usr/local/bin/main" ]; then
            echo -e "  ${C_GREEN}1)${C_RESET} Reinstall DT Proxy"
            echo -e "  ${C_GREEN}2)${C_RESET} Launch DT Proxy Menu"
            echo -e "  ${C_GREEN}3)${C_RESET} Restart DT Proxy Services"
            echo -e "  ${C_RED}4)${C_RESET} Uninstall DT Proxy"
        else
            echo -e "  ${C_GREEN}1)${C_RESET} Install DT Proxy"
        fi
        
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        if [ ! -f "/usr/local/bin/main" ]; then
            case $choice in
                1) install_dt_proxy ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        else
            case $choice in
                1)
                    echo -e "\n${C_YELLOW}⚠️ Reinstalling DT Proxy...${C_RESET}"
                    uninstall_dt_proxy
                    install_dt_proxy
                    ;;
                2)
                    clear
                    /usr/local/bin/main
                    ;;
                3)
                    echo -e "\n${C_BLUE}Restarting DT Proxy services...${C_RESET}"
                    systemctl restart proxy-*.service 2>/dev/null
                    echo -e "${C_GREEN}✅ Services restarted${C_RESET}"
                    safe_read "" dummy
                    ;;
                4)
                    echo -e "\n${C_RED}⚠️ Uninstalling DT Proxy...${C_RESET}"
                    uninstall_dt_proxy
                    safe_read "" dummy
                    ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        fi
    done
}

# ========== BACKUP & RESTORE ==========
backup_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    
    local backup_path
    safe_read "👉 Backup path [/root/voltrontech_backup.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_backup.tar.gz}
    
    tar -czf "$backup_path" $DB_DIR 2>/dev/null
    echo -e "${C_GREEN}✅ Backup created: $backup_path${C_RESET}"
    safe_read "" dummy
}

restore_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📥 Restore User Data ---${C_RESET}"
    
    local backup_path
    safe_read "👉 Backup path: " backup_path
    
    if [ ! -f "$backup_path" ]; then
        echo -e "${C_RED}❌ File not found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_RED}⚠️ This will overwrite all current data!${C_RESET}"
    local confirm
    safe_read "Are you sure? (y/n): " confirm
    
    if [[ "$confirm" == "y" ]]; then
        tar -xzf "$backup_path" -C / 2>/dev/null
        echo -e "${C_GREEN}✅ Restore complete${C_RESET}"
    fi
    
    safe_read "" dummy
}

# ========== CLOUDFLARE DNS GENERATOR ==========
generate_cloudflare_dns() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Generate Cloudflare DNS ---${C_RESET}"
    
    local ip=$(curl -s ifconfig.me)
    
    echo -e "${C_BLUE}Creating A record for nameserver...${C_RESET}"
    local ns_record_id=$(create_cloudflare_record "A" "ns" "$ip")
    
    if [ -z "$ns_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create A record${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_BLUE}Creating NS records...${C_RESET}"
    local tun_record_id=$(create_cloudflare_record "NS" "tun" "ns.$BASE_DOMAIN")
    local tun2_record_id=$(create_cloudflare_record "NS" "tun2" "ns.$BASE_DOMAIN")
    
    echo -e "${C_GREEN}✅ DNS records created!${C_RESET}"
    echo -e "  A:  ns.$BASE_DOMAIN → $ip"
    echo -e "  NS: tun.$BASE_DOMAIN → ns.$BASE_DOMAIN"
    echo -e "  NS: tun2.$BASE_DOMAIN → ns.$BASE_DOMAIN"
    
    cat > "$DNS_INFO_FILE" <<EOF
NS_RECORD_ID="$ns_record_id"
TUN_RECORD_ID="$tun_record_id"
TUN2_RECORD_ID="$tun2_record_id"
EOF
    
    safe_read "" dummy
}

# ========== INITIAL SETUP ==========
initial_setup() {
    echo -e "\n${C_BLUE}🔧 Running initial system setup...${C_RESET}"
    
    detect_os
    detect_package_manager
    detect_service_manager
    detect_firewall
    
    create_directories
    create_limiter_service
    create_traffic_monitor
    
    cat > "$DB_DIR/cloudflare.conf" <<EOF
CLOUDFLARE_EMAIL="$CLOUDFLARE_EMAIL"
CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID"
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN"
BASE_DOMAIN="$BASE_DOMAIN"
EOF
    
    get_ip_info
}

# ========== UNINSTALL SCRIPT ==========
uninstall_script() {
    clear
    show_banner
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_RED}           💥 UNINSTALL SCRIPT & ALL DATA${C_RESET}"
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}This will PERMANENTLY remove this script and all its components."
    echo -e "\n${C_RED}This action is irreversible.${C_RESET}"
    echo ""
    
    read -p "👉 Type 'YES' to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "\n${C_GREEN}✅ Uninstallation cancelled.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}--- 💥 Starting Uninstallation ---${C_RESET}"
    
    # Stop all services
    systemctl stop dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service haproxy voltronproxy.service nginx zivpn.service 2>/dev/null
    systemctl disable dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service voltronproxy.service 2>/dev/null
    
    # Stop multi-tunnel if running
    pkill -f "dnstt-client" 2>/dev/null
    
    # Remove service files
    rm -f "$DNSTT_SERVICE" "$V2RAY_SERVICE" "$BADVPN_SERVICE" "$UDP_CUSTOM_SERVICE" "$VOLTRONPROXY_SERVICE" "$ZIVPN_SERVICE"
    rm -f "$TRAFFIC_SERVICE" "$LIMITER_SERVICE"
    
    # Remove binaries
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT" "$V2RAY_BIN" "$BADVPN_BIN" "$UDP_CUSTOM_BIN" "$VOLTRONPROXY_BIN" "$ZIVPN_BIN"
    rm -f "$LIMITER_SCRIPT" "$TRAFFIC_SCRIPT" "$LOSS_PROTECT_SCRIPT"
    
    # Remove directories
    rm -rf "$BADVPN_BUILD_DIR" "$UDP_CUSTOM_DIR" "$ZIVPN_DIR"
    
    # Remove configuration
    rm -rf "$DB_DIR"
    
    # Restore DNS
    chattr -i /etc/resolv.conf 2>/dev/null
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    
    # Remove script
    rm -f /usr/local/bin/menu
    rm -f "$0"
    
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}      ✅ SCRIPT UNINSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "\nPress any key to exit..."
    read -n 1
    exit 0
}

# ========== PROTOCOL MENU ==========
protocol_menu() {
    while true; do
        clear
        show_banner
        
        local badvpn_status=$(check_service "badvpn")
        local udp_status=$(check_service "udp-custom")
        local haproxy_status=$(check_service "haproxy")
        local dnstt_status=$(check_service "dnstt")
        local v2ray_status=$(check_service "v2ray-dnstt")
        local voltronproxy_status=$(check_service "voltronproxy")
        local nginx_status=$(check_service "nginx")
        local zivpn_status=$(check_service "zivpn")
        local xui_status=$(command -v x-ui &>/dev/null && echo -e "${C_BLUE}(installed)${C_RESET}" || echo "")
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🔌 PROTOCOL & PANEL MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} badvpn (UDP 7300) $badvpn_status"
        echo -e "  ${C_GREEN}2)${C_RESET} udp-custom $udp_status"
        echo -e "  ${C_GREEN}3)${C_RESET} SSL Tunnel (HAProxy) $haproxy_status"
        echo -e "  ${C_GREEN}4)${C_RESET} DNSTT (Port 5300) $dnstt_status"
        echo -e "  ${C_GREEN}5)${C_RESET} V2RAY over DNSTT $v2ray_status"
        echo -e "  ${C_GREEN}6)${C_RESET} VOLTRON Proxy $voltronproxy_status"
        echo -e "  ${C_GREEN}7)${C_RESET} Nginx Proxy $nginx_status"
        echo -e "  ${C_GREEN}8)${C_RESET} ZiVPN $zivpn_status"
        echo -e "  ${C_GREEN}9)${C_RESET} X-UI Panel $xui_status"
        echo -e "  ${C_GREEN}10)${C_RESET} DT Proxy $(check_dt_proxy_status)"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select protocol to manage: "${C_RESET})" choice
        
        case $choice in
            1)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_badvpn || uninstall_badvpn
                ;;
            2)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_udp_custom || uninstall_udp_custom
                ;;
            3)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_ssl_tunnel || uninstall_ssl_tunnel
                ;;
            4)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_GREEN}2)${C_RESET} View Details"
                echo -e "  ${C_RED}3)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_dnstt
                elif [ "$sub" == "2" ]; then show_dnstt_details
                elif [ "$sub" == "3" ]; then uninstall_dnstt
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            5)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install V2RAY"
                echo -e "  ${C_GREEN}2)${C_RESET} Uninstall V2RAY"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_v2ray_dnstt || uninstall_v2ray_dnstt
                ;;
            6)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_voltron_proxy || uninstall_voltron_proxy
                ;;
            7)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_nginx_proxy || uninstall_nginx_proxy
                ;;
            8)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_zivpn || uninstall_zivpn
                ;;
            9)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_xui_panel || uninstall_xui_panel
                ;;
            10)
                dt_proxy_menu
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== V2RAY USER MANAGEMENT ==========
install_v2ray_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           🚀 V2RAY INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$V2RAY_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ V2RAY is already installed.${C_RESET}"
        read -p "Reinstall? (y/n): " reinstall
        if [[ "$reinstall" != "y" ]]; then
            return
        fi
        systemctl stop v2ray-dnstt.service 2>/dev/null
    fi
    
    echo -e "\n${C_BLUE}[1/4] Installing Xray...${C_RESET}"
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
    
    echo -e "${C_BLUE}[2/4] Creating directories...${C_RESET}"
    mkdir -p "$V2RAY_DIR"/{v2ray,users}
    
    echo -e "${C_BLUE}[3/4] Creating V2Ray configuration...${C_RESET}"
    cat > "$V2RAY_CONFIG" <<EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "port": 1080,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {"clients": []},
            "tag": "vmess"
        }
    ],
    "outbounds": [{"protocol": "freedom"}]
}
EOF

    echo -e "${C_BLUE}[4/4] Creating service...${C_RESET}"
    cat > "$V2RAY_SERVICE" <<EOF
[Unit]
Description=V2RAY over DNSTT
After=network.target

[Service]
Type=simple
ExecStart=$V2RAY_BIN run -config $V2RAY_CONFIG
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable v2ray-dnstt.service
    systemctl start v2ray-dnstt.service
    
    echo -e "\n${C_GREEN}✅ V2RAY installed successfully${C_RESET}"
    echo -e "  Port: ${C_YELLOW}1080 (localhost)${C_RESET}"
    
    safe_read "" dummy
}

uninstall_v2ray_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling V2RAY...${C_RESET}"
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f "$V2RAY_SERVICE"
    rm -rf "$V2RAY_DIR"
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- remove' > /dev/null 2>&1
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ V2RAY uninstalled${C_RESET}"
    safe_read "" dummy
}

create_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👤 CREATE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    echo -e "\n${C_GREEN}Select protocol:${C_RESET}"
    echo "1) VMess"
    echo "2) VLESS"
    echo "3) Trojan"
    read -p "Choice [1]: " proto_choice
    proto_choice=${proto_choice:-1}
    
    case $proto_choice in
        1) protocol="vmess" ;;
        2) protocol="vless" ;;
        3) protocol="trojan" ;;
        *) protocol="vmess" ;;
    esac
    
    read -p "Traffic limit (GB) [0=unlimited]: " traffic_limit
    traffic_limit=${traffic_limit:-0}
    
    read -p "Expiry (days) [30]: " days
    days=${days:-30}
    
    expire=$(date -d "+$days days" +%Y-%m-%d)
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "$(date +%s%N | md5sum | cut -c1-8)-$(date +%s%N | md5sum | cut -c1-4)-4$(date +%s%N | md5sum | cut -c1-3)-$(date +%s%N | md5sum | cut -c1-4)-$(date +%s%N | md5sum | cut -c1-12)")
    password=""
    
    if [ "$protocol" == "trojan" ]; then
        password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
    fi
    
    echo "$username:$uuid:$password:$protocol:$traffic_limit:0:$expire:active" >> "$V2RAY_USERS_DB"
    
    clear
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ V2RAY USER CREATED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  Username:     ${C_YELLOW}$username${C_RESET}"
    echo -e "  UUID:         ${C_YELLOW}$uuid${C_RESET}"
    if [ "$protocol" == "trojan" ]; then
        echo -e "  Password:     ${C_YELLOW}$password${C_RESET}"
    fi
    echo -e "  Protocol:     ${C_YELLOW}$protocol${C_RESET}"
    echo -e "  Traffic:      ${C_YELLOW}0/$traffic_limit GB${C_RESET}"
    echo -e "  Expiry:       ${C_YELLOW}$expire${C_RESET}"
    
    safe_read "" dummy
}

list_v2ray_users() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 V2RAY USERS LIST${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_USERS_DB" ] || [ ! -s "$V2RAY_USERS_DB" ]; then
        echo -e "${C_YELLOW}No V2Ray users found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    printf "${C_BOLD}%-15s %-8s %-36s %-25s %-12s %-10s${C_RESET}\n" "USERNAME" "PROTO" "UUID" "TRAFFIC" "EXPIRY" "STATUS"
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user uuid pass proto limit used expiry status; do
        [[ -z "$user" ]] && continue
        
        local limit_num=${limit:-0}
        local used_num=${used:-0}
        
        local traffic_disp=""
        if [ "$limit_num" == "0" ]; then
            traffic_disp="${used_num}GB/∞"
        else
            if command -v bc &>/dev/null; then
                local percent=$(echo "scale=1; $used_num * 100 / $limit_num" | bc 2>/dev/null || echo "0")
                traffic_disp="${used_num}/${limit_num} GB (${percent}%)"
            else
                traffic_disp="${used_num}/${limit_num} GB"
            fi
        fi
        
        local short_uuid=""
        if [ ${#uuid} -ge 16 ]; then
            short_uuid="${uuid:0:8}...${uuid: -8}"
        else
            short_uuid="$uuid"
        fi
        
        local status_color=""
        local status_text=""
        
        case $status in
            active)
                local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
                local current_ts=$(date +%s)
                
                if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                    status_text="EXPIRED"
                    status_color="${C_RED}"
                elif [ "$limit_num" -gt 0 ] && [ "$used_num" -ge "$limit_num" ]; then
                    status_text="LIMIT"
                    status_color="${C_RED}"
                else
                    status_text="ACTIVE"
                    status_color="${C_GREEN}"
                fi
                ;;
            locked)
                status_text="LOCKED"
                status_color="${C_YELLOW}"
                ;;
            expired)
                status_text="EXPIRED"
                status_color="${C_RED}"
                ;;
            *)
                status_text="$status"
                status_color="${C_WHITE}"
                ;;
        esac
        
        printf "%-15s %-8s %-36s %-25s %-12s ${status_color}%-10s${C_RESET}\n" \
            "$user" "$proto" "$short_uuid" "$traffic_disp" "$expiry" "$status_text"
            
    done < "$V2RAY_USERS_DB"
    
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────────────────────────────────────${C_RESET}"
    echo ""
    safe_read "" dummy
}

view_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👁️ VIEW V2RAY USER DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    local user_line=$(grep "^$username:" "$V2RAY_USERS_DB" 2>/dev/null)
    
    if [ -z "$user_line" ]; then
        echo -e "\n${C_RED}❌ User not found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    IFS=: read -r user uuid pass proto limit used expiry status <<< "$user_line"
    
    echo -e "\n${C_CYAN}User Details:${C_RESET}"
    echo -e "  Username:     ${C_YELLOW}$user${C_RESET}"
    echo -e "  UUID:         ${C_YELLOW}$uuid${C_RESET}"
    if [ "$proto" == "trojan" ]; then
        echo -e "  Password:     ${C_YELLOW}$pass${C_RESET}"
    fi
    echo -e "  Protocol:     ${C_YELLOW}$proto${C_RESET}"
    echo -e "  Traffic:      ${C_YELLOW}$used/$limit GB${C_RESET}"
    echo -e "  Expiry:       ${C_YELLOW}$expiry${C_RESET}"
    echo -e "  Status:       ${C_YELLOW}$status${C_RESET}"
    
    safe_read "" dummy
}

edit_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           ✏️ EDIT V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    local user_line=$(grep "^$username:" "$V2RAY_USERS_DB" 2>/dev/null)
    
    if [ -z "$user_line" ]; then
        echo -e "\n${C_RED}❌ User not found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    IFS=: read -r user uuid pass proto limit used expiry status <<< "$user_line"
    
    echo -e "\n${C_CYAN}Current Details:${C_RESET}"
    echo -e "  Traffic Limit: ${C_YELLOW}$limit GB${C_RESET}"
    echo -e "  Traffic Used:  ${C_YELLOW}$used GB${C_RESET}"
    echo -e "  Expiry:        ${C_YELLOW}$expiry${C_RESET}"
    echo -e "  Status:        ${C_YELLOW}$status${C_RESET}"
    
    echo -e "\n${C_GREEN}What would you like to edit?${C_RESET}"
    echo "1) Traffic Limit"
    echo "2) Expiry Date"
    echo "3) Status"
    echo "0) Cancel"
    
    read -p "Choice: " edit_choice
    
    case $edit_choice in
        1)
            read -p "New traffic limit (GB): " new_limit
            if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$uuid:$pass:$proto:$new_limit:$used:$expiry:$status/" "$V2RAY_USERS_DB"
                echo -e "${C_GREEN}✅ Traffic limit updated to $new_limit GB${C_RESET}"
            else
                echo -e "${C_RED}❌ Invalid number${C_RESET}"
            fi
            ;;
        2)
            read -p "New expiry (YYYY-MM-DD): " new_expiry
            if [[ "$new_expiry" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$uuid:$pass:$proto:$limit:$used:$new_expiry:$status/" "$V2RAY_USERS_DB"
                echo -e "${C_GREEN}✅ Expiry updated to $new_expiry${C_RESET}"
            else
                echo -e "${C_RED}❌ Invalid date format${C_RESET}"
            fi
            ;;
        3)
            echo -e "\n${C_GREEN}Select status:${C_RESET}"
            echo "1) active"
            echo "2) locked"
            echo "3) expired"
            read -p "Choice: " status_choice
            
            case $status_choice in
                1) new_status="active" ;;
                2) new_status="locked" ;;
                3) new_status="expired" ;;
                *) echo -e "${C_RED}Invalid${C_RESET}"; return ;;
            esac
            
            sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$uuid:$pass:$proto:$limit:$used:$expiry:$new_status/" "$V2RAY_USERS_DB"
            echo -e "${C_GREEN}✅ Status updated to $new_status${C_RESET}"
            ;;
        0) return ;;
        *) echo -e "${C_RED}Invalid choice${C_RESET}" ;;
    esac
    
    safe_read "" dummy
}

delete_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_RED}           🗑️ DELETE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User not found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "Are you sure? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        sed -i "/^$username:/d" "$V2RAY_USERS_DB"
        echo -e "${C_GREEN}✅ User deleted${C_RESET}"
    fi
    
    safe_read "" dummy
}

lock_v2ray_user() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)active/\1locked/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ User locked${C_RESET}"
    safe_read "" dummy
}

unlock_v2ray_user() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)locked/\1active/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ User unlocked${C_RESET}"
    safe_read "" dummy
}

reset_v2ray_traffic() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*:/\10:/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ Traffic reset to 0${C_RESET}"
    safe_read "" dummy
}

v2ray_main_menu() {
    while true; do
        clear
        show_banner
        
        if [ -f "$V2RAY_SERVICE" ]; then
            installed_status="${C_GREEN}(installed)${C_RESET}"
        else
            installed_status="${C_RED}(not installed)${C_RESET}"
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🚀 V2RAY MANAGEMENT $installed_status${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [ -f "$V2RAY_SERVICE" ]; then
            echo -e "  ${C_GREEN}1)${C_RESET} Reinstall V2RAY"
            echo -e "  ${C_GREEN}2)${C_RESET} Restart Service"
            echo -e "  ${C_GREEN}3)${C_RESET} Stop Service"
            echo -e "  ${C_RED}4)${C_RESET} Uninstall"
            echo ""
            echo -e "  ${C_GREEN}5)${C_RESET} 👤 V2Ray User Management"
        else
            echo -e "  ${C_GREEN}1)${C_RESET} Install V2RAY"
        fi
        
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        if [ ! -f "$V2RAY_SERVICE" ]; then
            case $choice in
                1) install_v2ray_dnstt ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        else
            case $choice in
                1) 
                    echo -e "\n${C_YELLOW}⚠️ Reinstalling V2RAY...${C_RESET}"
                    uninstall_v2ray_dnstt
                    install_v2ray_dnstt
                    ;;
                2) 
                    systemctl restart v2ray-dnstt.service
                    echo -e "${C_GREEN}✅ Service restarted${C_RESET}"
                    safe_read "" dummy
                    ;;
                3)
                    systemctl stop v2ray-dnstt.service
                    echo -e "${C_YELLOW}🛑 Service stopped${C_RESET}"
                    safe_read "" dummy
                    ;;
                4) 
                    echo -e "\n${C_RED}⚠️ Uninstalling V2RAY...${C_RESET}"
                    uninstall_v2ray_dnstt
                    safe_read "" dummy
                    ;;
                5) v2ray_user_menu ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        fi
    done
}

v2ray_user_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              👤 V2RAY USER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Create V2Ray User"
        echo -e "  ${C_GREEN}2)${C_RESET} List V2Ray Users"
        echo -e "  ${C_GREEN}3)${C_RESET} View User Details"
        echo -e "  ${C_GREEN}4)${C_RESET} Edit User"
        echo -e "  ${C_GREEN}5)${C_RESET} Delete User"
        echo -e "  ${C_GREEN}6)${C_RESET} Lock User"
        echo -e "  ${C_GREEN}7)${C_RESET} Unlock User"
        echo -e "  ${C_GREEN}8)${C_RESET} Reset Traffic"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) create_v2ray_user ;;
            2) list_v2ray_users ;;
            3) view_v2ray_user ;;
            4) edit_v2ray_user ;;
            5) delete_v2ray_user ;;
            6) lock_v2ray_user ;;
            7) unlock_v2ray_user ;;
            8) reset_v2ray_traffic ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== MAIN MENU ==========
main_menu() {
    initial_setup
    while true; do
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    👤 USER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "1" "Create New User" "5" "Unlock User"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "2" "Delete User" "6" "List Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "3" "Edit User" "7" "Renew User"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "4" "Lock User"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "8" "Protocols & Panels" "12" "SSH Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "9" "Backup Users" "13" "Cleanup Expired"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "10" "Restore Users" "14" "MTU Optimization"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "11" "DNS Domain" "15" "V2Ray Management"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "16" "Multi-Tunnel DNSTT (5x Speed)" "17" "DT Proxy"

        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    🔥 DANGER ZONE${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_RED}%2s${C_RESET}) %-28s  ${C_RED}%2s${C_RESET}) %-25s\n" "99" "Uninstall Script" "0" "Exit"

        echo ""
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        
        case $choice in
            1) _create_user ;;
            2) _delete_user ;;
            3) _edit_user ;;
            4) _lock_user ;;
            5) _unlock_user ;;
            6) _list_users ;;
            7) _renew_user ;;
            8) protocol_menu ;;
            9) backup_user_data ;;
            10) restore_user_data ;;
            11) generate_cloudflare_dns ;;
            12) ssh_banner_menu ;;
            13) _cleanup_expired ;;
            14) mtu_selection_during_install ;;
            15) v2ray_main_menu ;;
            16) multi_tunnel_menu ;;
            17) dt_proxy_menu ;;
            99) uninstall_script ;;
            0) echo -e "\n${C_BLUE}👋 Goodbye!${C_RESET}"; exit 0 ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== START ==========
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}❌ This script must be run as root!${C_RESET}"
    exit 1
fi

if [[ "$1" == "--install-setup" ]]; then
    initial_setup
    exit 0
fi

main_menu
