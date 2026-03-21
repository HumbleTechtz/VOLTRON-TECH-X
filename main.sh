#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 10.0 (FALCON STYLE)
# Description: SSH • DNSTT • V2RAY • BADVPN • UDP-CUSTOM • SSL • PROXY • ZIVPN • X-UI
# Author: Voltron Tech
# Features: DNSTT with Falcon Style, Auto HTML Banner, User Manager

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

# ========== DESEC DNS CONFIGURATION ==========
DESEC_TOKEN="3WxD4Hkiu5VYBLWVizVhf1rzyKbz"
DESEC_DOMAIN="voltrontechtx.shop"

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
SSH_BANNER_FILE="/etc/voltrontech/banner"
TRAFFIC_DIR="$DB_DIR/traffic"
BANNER_DIR="$DB_DIR/banners"

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

# ========== CONNECTION FORCER CONFIG ==========
FORCER_DIR="$DB_DIR/forcer"
FORCER_CONFIG="$FORCER_DIR/config.conf"
FORCER_HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
FORCER_BACKUP_DIR="$FORCER_DIR/backups"

# ========== CACHE CLEANER CONFIG ==========
CACHE_CRON_FILE="/etc/cron.d/voltron-cache-clean"
CACHE_LOG_FILE="/var/log/voltron-cache.log"
CACHE_STATUS_FILE="$DB_DIR/cache/status"
CACHE_SCRIPT="/usr/local/bin/voltron-cache-clean"

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
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $V2RAY_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR $FEC_DIR $TRAFFIC_DIR $BANNER_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    mkdir -p $(dirname "$SSH_BANNER_FILE")
    mkdir -p "$FORCER_DIR" "$FORCER_BACKUP_DIR"
    mkdir -p "$DB_DIR/cache"
    touch $DB_FILE
    touch $V2RAY_USERS_DB
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
    else
        echo -e "${C_RED}❌ systemd not found!${C_RESET}"
        exit 1
    fi
    echo -e "${C_GREEN}✅ Detected service manager: $SERVICE_MANAGER${C_RESET}"
}

detect_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        FIREWALL="ufw"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        FIREWALL="firewalld"
    elif command -v iptables &>/dev/null; then
        FIREWALL="iptables"
    else
        FIREWALL="none"
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
        echo "512"
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
        fi
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        if ! firewall-cmd --list-ports --permanent | grep -qw "$port/$protocol"; then
            firewall-cmd --add-port="$port/$protocol" --permanent
            firewall-cmd --reload
            echo -e "${C_GREEN}✅ Port $port/$protocol opened in firewalld${C_RESET}"
        fi
    else
        echo -e "${C_BLUE}ℹ️ No active firewall detected, port $port/$protocol assumed open${C_RESET}"
    fi
}

# ========== DESEC DNS VALIDATION ==========
_is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

_is_valid_ipv6() {
    local ip=$1
    if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
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
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v10.0 🔥                    ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • V2RAY • BADVPN • UDP • SSL • ZiVPN        ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║                   FALCON STYLE EDITION                         ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ULTRA BOOST: ${C_GREEN}ACTIVE (10x speed mode)${C_PURPLE}${C_RESET}"
    
    if [ -f "$FORCER_CONFIG" ]; then
        source "$FORCER_CONFIG"
        echo -e "${C_BOLD}${C_PURPLE}║  Forcer:     ${C_GREEN}ACTIVE (${CONNECTIONS_PER_IP} conn/IP)${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  Forcer:     ${C_YELLOW}INACTIVE (1 conn/IP)${C_PURPLE}${C_RESET}"
    fi
    
    if [ -f "$CACHE_CRON_FILE" ]; then
        echo -e "${C_BOLD}${C_PURPLE}║  Cache:      ${C_GREEN}AUTO CLEAN ACTIVE (12:00 AM daily)${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  Cache:      ${C_YELLOW}AUTO CLEAN DISABLED${C_PURPLE}${C_RESET}"
    fi
    
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== DNSTT BINARY (FALCON STYLE) ==========
download_dnstt_binary() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📥 DOWNLOADING DNSTT BINARY (FALCON STYLE)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    local arch
    arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://dnstt.network/dnstt-server-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://dnstt.network/dnstt-server-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install DNSTT.${C_RESET}"
        return 1
    fi
    
    echo -e "${C_YELLOW}📥 Downloading DNSTT binary from: $binary_url${C_RESET}"
    
    curl -sL "$binary_url" -o "$DNSTT_SERVER"
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download the DNSTT binary.${C_RESET}"
        return 1
    fi
    
    chmod +x "$DNSTT_SERVER"
    
    # Verify binary
    if [ ! -f "$DNSTT_SERVER" ]; then
        echo -e "${C_RED}❌ Binary download failed${C_RESET}"
        return 1
    fi
    
    local binary_size=$(stat -c%s "$DNSTT_SERVER" 2>/dev/null || echo "0")
    if [ "$binary_size" -lt 1000000 ]; then
        echo -e "${C_RED}❌ Binary size too small ($binary_size bytes) - download may have failed${C_RESET}"
        return 1
    fi
    
    echo -e "${C_GREEN}✅ DNSTT binary downloaded successfully!${C_RESET}"
    echo -e "  • Location: ${C_CYAN}$DNSTT_SERVER${C_RESET}"
    echo -e "  • Size: ${C_CYAN}$binary_size bytes${C_RESET}"
    
    return 0
}

# ========== DNSTT ULTRA BOOSTER (FALCON STYLE) ==========
apply_dnstt_ultra_booster() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 DNSTT ULTRA BOOSTER (FALCON STYLE)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # 1. BBR v2 + fq_codel
    echo -e "${C_CYAN}[1/6]${C_RESET} Enabling BBR v2..."
    modprobe tcp_bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1
    echo -e "${C_GREEN}✓ BBR v2 + FQ-CoDel enabled${C_RESET}"
    
    # 2. Ultra Network Buffers (32MB)
    echo -e "${C_CYAN}[2/6]${C_RESET} Setting ultra network buffers..."
    sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1
    sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1
    sysctl -w net.core.rmem_default=16777216 >/dev/null 2>&1
    sysctl -w net.core.wmem_default=16777216 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Ultra buffers: 32MB${C_RESET}"
    
    # 3. UDP Optimization for DNS
    echo -e "${C_CYAN}[3/6]${C_RESET} Optimizing UDP for DNS..."
    sysctl -w net.ipv4.udp_rmem_min=524288 >/dev/null 2>&1
    sysctl -w net.ipv4.udp_wmem_min=524288 >/dev/null 2>&1
    sysctl -w net.ipv4.udp_mem="524288 1048576 2097152" >/dev/null 2>&1
    echo -e "${C_GREEN}✓ UDP: 512KB buffers (EDNS0 ready)${C_RESET}"
    
    # 4. Packet Backlog
    echo -e "${C_CYAN}[4/6]${C_RESET} Setting packet backlog..."
    sysctl -w net.core.netdev_max_backlog=300000 >/dev/null 2>&1
    sysctl -w net.core.somaxconn=262144 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Backlog: 300K packets${C_RESET}"
    
    # 5. Connection Tracking
    echo -e "${C_CYAN}[5/6]${C_RESET} Increasing connection tracking..."
    sysctl -w net.netfilter.nf_conntrack_max=2000000 >/dev/null 2>&1
    sysctl -w net.netfilter.nf_conntrack_udp_timeout=600 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Connection tracking: 2M${C_RESET}"
    
    # 6. File Descriptors
    echo -e "${C_CYAN}[6/6]${C_RESET} Setting file descriptors..."
    ulimit -n 524288 2>/dev/null
    echo -e "${C_GREEN}✓ File descriptors: 512K${C_RESET}"
    
    # Save config
    cat > /etc/sysctl.d/99-dnstt-ultra.conf << 'EOF'
# DNSTT ULTRA BOOSTER - Falcon Style
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.ipv4.udp_rmem_min = 524288
net.ipv4.udp_wmem_min = 524288
net.ipv4.udp_mem = 524288 1048576 2097152
net.core.netdev_max_backlog = 300000
net.core.somaxconn = 262144
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_udp_timeout = 600
EOF
    
    sysctl -p /etc/sysctl.d/99-dnstt-ultra.conf >/dev/null 2>&1
    
    echo -e "\n${C_GREEN}✅ DNSTT ULTRA BOOSTER APPLIED!${C_RESET}"
    echo -e "  • BBR v2: Active"
    echo -e "  • Ultra Buffers: 32MB"
    echo -e "  • UDP Buffers: 512KB (EDNS0 ready)"
    echo -e "  • Packet Backlog: 300K"
    echo -e "  • Connection Tracking: 2M"
    echo -e "  • File Descriptors: 512K"
    echo -e "  • Expected Speed: 15-25 Mbps 🚀"
    
    sleep 2
}

# ========== DNSTT SPEED BOOSTER (STANDARD) ==========
apply_dnstt_speed_booster() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ⚡ DNSTT SPEED BOOSTER (STANDARD)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # 1. BBR Congestion Control
    echo -e "${C_CYAN}[1/4]${C_RESET} Enabling BBR congestion control..."
    modprobe tcp_bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1
    echo -e "${C_GREEN}✓ BBR + FQ-CoDel enabled${C_RESET}"
    
    # 2. UDP Buffers (512KB)
    echo -e "${C_CYAN}[2/4]${C_RESET} Optimizing UDP buffers..."
    sysctl -w net.ipv4.udp_rmem_min=524288 >/dev/null 2>&1
    sysctl -w net.ipv4.udp_wmem_min=524288 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ UDP buffers: 512KB${C_RESET}"
    
    # 3. Network Buffers (32MB)
    echo -e "${C_CYAN}[3/4]${C_RESET} Setting network buffers..."
    sysctl -w net.core.rmem_max=33554432 >/dev/null 2>&1
    sysctl -w net.core.wmem_max=33554432 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Network buffers: 32MB${C_RESET}"
    
    # 4. Packet Backlog
    echo -e "${C_CYAN}[4/4]${C_RESET} Setting packet backlog..."
    sysctl -w net.core.netdev_max_backlog=100000 >/dev/null 2>&1
    echo -e "${C_GREEN}✓ Packet backlog: 100K${C_RESET}"
    
    # Save config
    cat > /etc/sysctl.d/99-dnstt-speed.conf << 'EOF'
# DNSTT Speed Booster - Falcon Style
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
net.ipv4.udp_rmem_min = 524288
net.ipv4.udp_wmem_min = 524288
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 100000
EOF
    
    sysctl -p /etc/sysctl.d/99-dnstt-speed.conf >/dev/null 2>&1
    
    echo -e "\n${C_GREEN}✅ DNSTT Speed Booster applied!${C_RESET}"
    echo -e "  • BBR: Active"
    echo -e "  • UDP Buffers: 512KB"
    echo -e "  • Network Buffers: 32MB"
    echo -e "  • Expected Speed: 10-15 Mbps"
    
    sleep 2
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
}

# ========== DESEC DNS AUTO DOMAIN GENERATOR ==========
generate_desec_domain() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ☁️  DESEC DNS AUTO DOMAIN GENERATOR${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    ns="ns-$rand"
    tun="tun-$rand"
    
    SERVER_IPV4=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IPV4" ] || ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "${C_YELLOW}⚠️ Could not detect IPv4 address${C_RESET}"
        SERVER_IPV4=""
    fi
    
    SERVER_IPV6=$(curl -s -6 ifconfig.me 2>/dev/null || curl -s -6 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IPV6" ] || ! _is_valid_ipv6 "$SERVER_IPV6"; then
        echo -e "${C_YELLOW}⚠️ Could not detect IPv6 address${C_RESET}"
        SERVER_IPV6=""
    fi
    
    local API_DATA="["
    local first=true
    
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${C_GREEN}[1/3] Creating IPv4 A record: $ns.$DESEC_DOMAIN → $SERVER_IPV4${C_RESET}"
        if [ "$first" = true ]; then
            API_DATA="${API_DATA}{\"subname\":\"$ns\",\"type\":\"A\",\"ttl\":3600,\"records\":[\"$SERVER_IPV4\"]}"
            first=false
        else
            API_DATA="${API_DATA},{\"subname\":\"$ns\",\"type\":\"A\",\"ttl\":3600,\"records\":[\"$SERVER_IPV4\"]}"
        fi
    fi
    
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${C_GREEN}[2/3] Creating IPv6 AAAA record: $ns.$DESEC_DOMAIN → $SERVER_IPV6${C_RESET}"
        if [ "$first" = true ]; then
            API_DATA="${API_DATA}{\"subname\":\"$ns\",\"type\":\"AAAA\",\"ttl\":3600,\"records\":[\"$SERVER_IPV6\"]}"
            first=false
        else
            API_DATA="${API_DATA},{\"subname\":\"$ns\",\"type\":\"AAAA\",\"ttl\":3600,\"records\":[\"$SERVER_IPV6\"]}"
        fi
    fi
    
    local ns_target="$ns.$DESEC_DOMAIN."
    echo -e "${C_GREEN}[3/3] Creating NS record: $tun.$DESEC_DOMAIN → $ns.$DESEC_DOMAIN${C_RESET}"
    if [ "$first" = true ]; then
        API_DATA="${API_DATA}{\"subname\":\"$tun\",\"type\":\"NS\",\"ttl\":3600,\"records\":[\"$ns_target\"]}"
    else
        API_DATA="${API_DATA},{\"subname\":\"$tun\",\"type\":\"NS\",\"ttl\":3600,\"records\":[\"$ns_target\"]}"
    fi
    
    API_DATA="${API_DATA}]"
    
    local RESPONSE
    RESPONSE=$(curl -s -w "%{http_code}" -X POST "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/" \
        -H "Authorization: Token $DESEC_TOKEN" \
        -H "Content-Type: application/json" \
        --data "$API_DATA")
    
    local HTTP_CODE=${RESPONSE: -3}
    local RESPONSE_BODY=${RESPONSE:0:${#RESPONSE}-3}
    
    if [[ "$HTTP_CODE" -eq 201 ]]; then
        DOMAIN="$tun.$DESEC_DOMAIN"
        echo "$ns" > "$DB_DIR/desec_ns_subdomain.txt"
        echo "$tun" > "$DB_DIR/desec_tun_subdomain.txt"
        
        echo -e "\n${C_GREEN}✅ Auto-generated domain: ${C_YELLOW}$DOMAIN${C_RESET}"
        
        if [ -n "$SERVER_IPV4" ]; then
            echo -e "  • IPv4: ${C_GREEN}$SERVER_IPV4${C_RESET}"
        fi
        if [ -n "$SERVER_IPV6" ]; then
            echo -e "  • IPv6: ${C_GREEN}$SERVER_IPV6${C_RESET}"
        fi
        return 0
    else
        echo -e "${C_RED}❌ Failed to create DNS records. API returned HTTP $HTTP_CODE.${C_RESET}"
        return 1
    fi
}

# ========== DELETE DESEC DNS RECORDS ==========
delete_desec_dns_records() {
    echo -e "\n${C_BLUE}🗑️ Deleting auto-generated DNS records...${C_RESET}"
    
    local ns_subdomain=""
    local tun_subdomain=""
    
    if [ -f "$DB_DIR/desec_ns_subdomain.txt" ]; then
        ns_subdomain=$(cat "$DB_DIR/desec_ns_subdomain.txt")
    fi
    if [ -f "$DB_DIR/desec_tun_subdomain.txt" ]; then
        tun_subdomain=$(cat "$DB_DIR/desec_tun_subdomain.txt")
    fi
    
    if [ -n "$ns_subdomain" ]; then
        curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$ns_subdomain/A/" \
            -H "Authorization: Token $DESEC_TOKEN" > /dev/null
        curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$ns_subdomain/AAAA/" \
            -H "Authorization: Token $DESEC_TOKEN" > /dev/null
        echo -e "${C_GREEN}✓ A/AAAA records deleted${C_RESET}"
    fi
    
    if [ -n "$tun_subdomain" ]; then
        curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$tun_subdomain/NS/" \
            -H "Authorization: Token $DESEC_TOKEN" > /dev/null
        echo -e "${C_GREEN}✓ NS record deleted${C_RESET}"
    fi
    
    rm -f "$DB_DIR/desec_ns_subdomain.txt" "$DB_DIR/desec_tun_subdomain.txt"
    echo -e "${C_GREEN}✅ DNS records deleted${C_RESET}"
}

# ========== DOMAIN SETUP ==========
setup_domain() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🌐 DOMAIN CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_GREEN}Select domain option:${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Custom domain (Enter your own)"
    echo -e "  ${C_GREEN}2)${C_RESET} Auto-generate with deSEC DNS (IPv4 + IPv6)"
    echo ""
    read -p "👉 Choice [1-2, default=2]: " domain_option
    domain_option=${domain_option:-2}
    
    if [[ "$domain_option" == "2" ]]; then
        if generate_desec_domain; then
            echo -e "${C_GREEN}✅ Using auto-generated domain: $DOMAIN${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ deSEC failed, switching to custom domain...${C_RESET}"
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
    echo -e "${C_BLUE}           📡 MTU CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    MTU=512
    echo -e "${C_GREEN}✅ MTU set to $MTU (ULTRA BOOST mode)${C_RESET}"
    
    mkdir -p "$CONFIG_DIR"
    echo "$MTU" > "$CONFIG_DIR/mtu"
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
}

# ========== DNSTT SERVICE (LIVE MODE - NO AUTO-RESTART) ==========
create_dnstt_service_live() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DB_DIR
ExecStart=$DNSTT_SERVER -udp :5300 -privkey-file $DB_DIR/server.key -mtu $mtu $domain 127.0.0.1:$ssh_port
Restart=no

StandardOutput=append:$LOGS_DIR/dnstt-server.log
StandardError=append:$LOGS_DIR/dnstt-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service > /dev/null 2>&1
    
    echo -e "${C_GREEN}✅ DNSTT service created (live mode, no auto-restart)${C_RESET}"
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
show_client_commands_falcon_style() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    local pubkey=$(cat "$DB_DIR/server.pub")
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           📱 CLIENT CONNECTION DETAILS${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_WHITE}Your connection details:${C_RESET}"
    echo -e "  - ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$domain${C_RESET}"
    echo -e "  - ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$pubkey${C_RESET}"
    echo -e "  - ${C_CYAN}SSH Port:${C_RESET}      ${C_YELLOW}$ssh_port${C_RESET}"
    echo -e "  - ${C_CYAN}MTU Value:${C_RESET}     ${C_YELLOW}$mtu${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 DNS Records:${C_RESET}"
    echo -e "  • NS Record: ${C_GREEN}$domain${C_RESET}"
    echo -e "  • A Record:  ${C_GREEN}$domain → $(curl -s -4 icanhazip.com)${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 Client Command:${C_RESET}"
    echo -e "${C_WHITE}$DNSTT_CLIENT -udp 8.8.8.8:53 \\${C_RESET}"
    echo -e "${C_WHITE}  -pubkey-file $DB_DIR/server.pub \\${C_RESET}"
    echo -e "${C_WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${C_WHITE}  $domain 127.0.0.1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 SSH Connection:${C_RESET}"
    echo -e "${C_WHITE}  ssh username@127.0.0.1 -p $ssh_port${C_RESET}"
}

# ========== AUTO HTML BANNER FUNCTIONS ==========
_enable_auto_banner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🎨 ENABLING AUTO HTML BANNER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    touch "/etc/voltrontech/banners_enabled"
    mkdir -p "/etc/voltrontech/banners"
    
    echo -e "${C_GREEN}✅ Auto HTML Banner enabled!${C_RESET}"
    echo -e "${C_CYAN}📌 Users will see account status when connecting via SSH tunnel${C_RESET}"
    safe_read "" dummy
}

_disable_auto_banner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING AUTO HTML BANNER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    rm -f "/etc/voltrontech/banners_enabled"
    
    echo -e "${C_GREEN}✅ Auto HTML Banner disabled!${C_RESET}"
    safe_read "" dummy
}

_view_auto_banner_status() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🎨 Auto HTML Banner Status ---${C_RESET}"
    
    if [ -f "/etc/voltrontech/banners_enabled" ]; then
        echo -e "\n${C_GREEN}✅ Auto HTML Banner: ENABLED${C_RESET}"
        
        local first_user=$(head -1 "$DB_FILE" 2>/dev/null | cut -d: -f1)
        if [ -n "$first_user" ] && [ -f "/etc/voltrontech/banners/${first_user}.txt" ]; then
            echo -e "\n${C_CYAN}📌 Sample banner for user '$first_user':${C_RESET}"
            echo -e "${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
            cat "/etc/voltrontech/banners/${first_user}.txt"
            echo -e "${C_YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        fi
    else
        echo -e "\n${C_RED}❌ Auto HTML Banner: DISABLED${C_RESET}"
    fi
    
    safe_read "" dummy
}

auto_banner_menu() {
    while true; do
        clear
        show_banner
        
        local banner_status=""
        if [ -f "/etc/voltrontech/banners_enabled" ]; then
            banner_status="${C_GREEN}ENABLED${C_RESET}"
        else
            banner_status="${C_RED}DISABLED${C_RESET}"
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🎨 AUTO HTML BANNER (FALCON STYLE)${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           📱 For HTTP Custom / HTTP Injector${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_CYAN}Current Status:${C_RESET} $banner_status"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Auto HTML Banner"
        echo -e "  ${C_RED}2)${C_RESET} Disable Auto HTML Banner"
        echo -e "  ${C_GREEN}3)${C_RESET} View Status & Sample Banner"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) _enable_auto_banner ;;
            2) _disable_auto_banner ;;
            3) _view_auto_banner_status ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== AUTO REBOOT FUNCTIONS ==========
_enable_auto_reboot() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔄 ENABLING AUTO REBOOT${C_RESET}"
    echo -e "${C_BLUE}           ⏰ Schedule: Daily at 00:00 (Midnight)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab - 2>/dev/null
    (crontab -l 2>/dev/null; echo "0 0 * * * /usr/sbin/systemctl reboot") | crontab - 2>/dev/null
    
    echo -e "${C_GREEN}✅ Auto reboot scheduled for every day at 00:00 (Midnight)${C_RESET}"
    safe_read "" dummy
}

_disable_auto_reboot() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING AUTO REBOOT${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab - 2>/dev/null
    
    echo -e "${C_GREEN}✅ Auto reboot disabled${C_RESET}"
    safe_read "" dummy
}

_view_auto_reboot_status() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔄 Auto Reboot Status ---${C_RESET}"
    
    local cron_check=$(crontab -l 2>/dev/null | grep "systemctl reboot")
    if [[ -n "$cron_check" ]]; then
        echo -e "\n${C_GREEN}✅ Auto Reboot: ENABLED${C_RESET}"
        echo -e "${C_CYAN}📌 Schedule: Daily at 00:00 (Midnight)${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Auto Reboot: DISABLED${C_RESET}"
    fi
    
    safe_read "" dummy
}

auto_reboot_menu() {
    while true; do
        clear
        show_banner
        
        local reboot_status=""
        local cron_check=$(crontab -l 2>/dev/null | grep "systemctl reboot")
        if [[ -n "$cron_check" ]]; then
            reboot_status="${C_GREEN}ENABLED (Daily at 00:00)${C_RESET}"
        else
            reboot_status="${C_RED}DISABLED${C_RESET}"
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🔄 AUTO REBOOT MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_CYAN}Current Status:${C_RESET} $reboot_status"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Auto Reboot (Daily at 00:00)"
        echo -e "  ${C_RED}2)${C_RESET} Disable Auto Reboot"
        echo -e "  ${C_GREEN}3)${C_RESET} View Status"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) _enable_auto_reboot ;;
            2) _disable_auto_reboot ;;
            3) _view_auto_reboot_status ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== SSH BANNER (PLAIN TEXT) - FALCON STYLE ==========
_set_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Paste SSH Banner ---${C_RESET}"
    echo -e "Paste your banner code below. Press ${C_YELLOW}[Ctrl+D]${C_RESET} when finished."
    echo -e "${C_DIM}The current banner will be overwritten.${C_RESET}"
    echo -e "--------------------------------------------------"
    
    cat > "$SSH_BANNER_FILE"
    chmod 644 "$SSH_BANNER_FILE"
    
    echo -e "\n--------------------------------------------------"
    echo -e "\n${C_GREEN}✅ Banner saved!${C_RESET}"
    
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
        echo -e "${C_CYAN}---- END BANNER ----${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ No banner found.${C_RESET}"
    fi
    
    safe_read "" dummy
}

_remove_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Remove SSH Banner ---${C_RESET}"
    
    read -p "👉 Are you sure? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}Cancelled.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    rm -f "$SSH_BANNER_FILE"
    rm -f "/etc/ssh/sshd_config.d/voltrontech-banner.conf"
    
    echo -e "\n${C_GREEN}✅ Banner removed.${C_RESET}"
    _restart_ssh
    safe_read "" dummy
}

_enable_banner_in_sshd_config() {
    echo -e "\n${C_BLUE}⚙️ Configuring sshd_config...${C_RESET}"
    
    mkdir -p /etc/ssh/sshd_config.d
    
    cat > /etc/ssh/sshd_config.d/voltrontech-banner.conf <<EOF
# Voltron Tech SSH Banner
Banner $SSH_BANNER_FILE
EOF

    if ! grep -q "Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config 2>/dev/null; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi
    
    echo -e "${C_GREEN}✅ sshd_config updated.${C_RESET}"
}

_restart_ssh() {
    echo -e "\n${C_BLUE}🔄 Restarting SSH service...${C_RESET}"
    
    if systemctl list-units --full -all | grep -q "sshd.service"; then
        systemctl restart sshd
    elif systemctl list-units --full -all | grep -q "ssh.service"; then
        systemctl restart ssh
    else
        echo -e "${C_RED}❌ SSH service not found.${C_RESET}"
        return 1
    fi
    
    echo -e "${C_GREEN}✅ SSH service restarted.${C_RESET}"
}

ssh_banner_menu() {
    while true; do
        clear
        show_banner
        
        local banner_status=""
        if [ -f "$SSH_BANNER_FILE" ] && [ -f "/etc/ssh/sshd_config.d/voltrontech-banner.conf" ]; then
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

# ========== USER MANAGEMENT ==========
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
            echo -e "${C_RED}❌ Password cannot be empty.${C_RESET}"
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
    echo "$username:$password:$expire_date:$limit:$traffic_limit:0:ACTIVE" >> "$DB_FILE"
    
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
    rm -f "$TRAFFIC_DIR/$username" 2>/dev/null
    
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
    
    IFS=: read -r user pass expiry limit traffic_limit traffic_used status <<< "$line"
    status=${status:-ACTIVE}
    
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        echo -e "\nCurrent Details:"
        echo -e "  Expiry:        $expiry"
        echo -e "  Connection:    $limit"
        echo -e "  Traffic Limit: $traffic_limit GB"
        echo -e "  Traffic Used:  $traffic_used GB"
        echo -e "  Status:        $status"
        echo -e "\nSelect a detail to edit:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🔑 Change Password"
        echo -e "  ${C_GREEN}2)${C_RESET} 🗓️ Change Expiration"
        echo -e "  ${C_GREEN}3)${C_RESET} 📶 Change Connection Limit"
        echo -e "  ${C_GREEN}4)${C_RESET} 📊 Change Traffic Limit"
        echo -e "  ${C_GREEN}5)${C_RESET} 🔓 Unlock User (if locked)"
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
                sed -i "s/^$username:.*/$username:$new_pass:$expiry:$limit:$traffic_limit:$traffic_used:$status/" "$DB_FILE"
                echo -e "\n${C_GREEN}✅ Password changed.${C_RESET}"
                ;;
            2)
                read -p "Enter new duration (days from today): " days
                if [[ "$days" =~ ^[0-9]+$ ]]; then
                    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E "$new_expiry" "$username"
                    sed -i "s/^$username:.*/$username:$pass:$new_expiry:$limit:$traffic_limit:$traffic_used:$status/" "$DB_FILE"
                    expiry="$new_expiry"
                    echo -e "\n${C_GREEN}✅ Expiration updated to $new_expiry${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            3)
                read -p "Enter new connection limit: " new_limit
                if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                    sed -i "s/^$username:.*/$username:$pass:$expiry:$new_limit:$traffic_limit:$traffic_used:$status/" "$DB_FILE"
                    limit="$new_limit"
                    echo -e "\n${C_GREEN}✅ Connection limit updated to $new_limit${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            4)
                read -p "Enter new traffic limit (GB) [0=unlimited]: " new_traffic
                if [[ "$new_traffic" =~ ^[0-9]+$ ]]; then
                    sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$new_traffic:$traffic_used:$status/" "$DB_FILE"
                    traffic_limit="$new_traffic"
                    echo -e "\n${C_GREEN}✅ Traffic limit updated to $new_traffic GB${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            5)
                if [[ "$status" == "LIMIT" ]] || [[ "$status" == "LOCKED" ]]; then
                    usermod -U "$username" 2>/dev/null
                    sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$traffic_limit:$traffic_used:ACTIVE/" "$DB_FILE"
                    echo -e "\n${C_GREEN}✅ User unlocked${C_RESET}"
                    status="ACTIVE"
                else
                    echo -e "\n${C_YELLOW}⚠️ User is not locked${C_RESET}"
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
    
    local line=$(grep "^$username:" "$DB_FILE")
    if [ -n "$line" ]; then
        IFS=: read -r user pass expiry limit traffic_limit traffic_used status <<< "$line"
        sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$traffic_limit:$traffic_used:LOCKED/" "$DB_FILE"
    fi
    
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
    
    local line=$(grep "^$username:" "$DB_FILE")
    if [ -n "$line" ]; then
        IFS=: read -r user pass expiry limit traffic_limit traffic_used status <<< "$line"
        sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$traffic_limit:$traffic_used:ACTIVE/" "$DB_FILE"
    fi
    
    echo -e "\n${C_GREEN}✅ User unlocked.${C_RESET}"
    safe_read "" dummy
}

_list_users() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}                      📋 SSH USERS LIST                        ${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}No SSH users found${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    printf "${C_BOLD}%-15s | %-12s | %-8s | %-25s | %-10s${C_RESET}\n" "USERNAME" "EXPIRY" "LIMIT" "TRAFFIC" "STATUS"
    echo -e "${C_CYAN}──────────────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
        [[ -z "$user" ]] && continue
        status=${status:-ACTIVE}
        
        local online=0
        if id "$user" &>/dev/null; then
            online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        fi
        
        local traffic_disp=""
        if [[ "$traffic_limit" == "0" ]] || [[ -z "$traffic_limit" ]]; then
            traffic_disp="$(printf "%.2f" $traffic_used) GB / ∞"
        else
            traffic_disp="$(printf "%.2f" $traffic_used) / $traffic_limit GB"
        fi
        
        local status_color=""
        case $status in
            ACTIVE) status_color="${C_GREEN}" ;;
            LOCKED|LIMIT) status_color="${C_YELLOW}" ;;
            EXPIRED) status_color="${C_RED}" ;;
            *) status_color="${C_WHITE}" ;;
        esac
        
        printf "%-15s | ${C_YELLOW}%-12s${C_RESET} | ${C_CYAN}%s/%s${C_RESET} | %-25s | ${status_color}%-10s${C_RESET}\n" \
            "$user" "$expiry" "$online" "$limit" "$traffic_disp" "$status"
            
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
    
    IFS=: read -r user pass expiry limit traffic_limit traffic_used status <<< "$line"
    status=${status:-ACTIVE}
    
    read -p "📆 Additional days: " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expiry" "$username"
    sed -i "s/^$username:.*/$username:$pass:$new_expiry:$limit:$traffic_limit:$traffic_used:$status/" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User renewed until $new_expiry${C_RESET}"
    safe_read "" dummy
}

_cleanup_expired() {
    echo -e "\n${C_BLUE}🧹 Cleaning up expired users...${C_RESET}"
    local current_ts=$(date +%s)
    local count=0
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            killall -u "$user" 2>/dev/null
            userdel -r "$user" 2>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
            rm -f "$TRAFFIC_DIR/$user" 2>/dev/null
            echo "  Removed $user"
            ((count++))
        fi
    done < "$DB_FILE"
    
    echo -e "${C_GREEN}✅ Removed $count expired users${C_RESET}"
    safe_read "" dummy
}

# ========== FALCON-STYLE USER MANAGEMENT ==========
_bulk_create_users() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 👥 Bulk Create Users ---${C_RESET}"
    
    read -p "👉 Enter username prefix (e.g., 'user'): " prefix
    if [[ -z "$prefix" ]]; then 
        echo -e "\n${C_RED}❌ Prefix cannot be empty.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "🔢 How many users to create? " count
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [[ "$count" -lt 1 ]] || [[ "$count" -gt 100 ]]; then
        echo -e "\n${C_RED}❌ Invalid count (1-100).${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "🗓️ Account duration (in days) [30]: " days
    days=${days:-30}
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then 
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "📶 Connection limit per user [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then 
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "📦 Bandwidth limit in GB per user (0 = unlimited) [0]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-0}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then 
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    local bw_display="Unlimited"
    [[ "$bandwidth_gb" != "0" ]] && bw_display="${bandwidth_gb} GB"
    
    echo -e "\n${C_BLUE}⚙️ Creating $count users with prefix '${prefix}'...${C_RESET}\n"
    echo -e "${C_YELLOW}================================================================${C_RESET}"
    printf "${C_BOLD}${C_WHITE}%-20s | %-15s | %-12s${C_RESET}\n" "USERNAME" "PASSWORD" "EXPIRES"
    echo -e "${C_YELLOW}----------------------------------------------------------------${C_RESET}"
    
    local created=0
    for ((i=1; i<=count; i++)); do
        local username="${prefix}${i}"
        if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
            echo -e "${C_RED}  ⚠️ Skipping '$username' — already exists${C_RESET}"
            continue
        fi
        local password=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
        useradd -m -s /usr/sbin/nologin "$username"
        usermod -aG ffusers "$username" 2>/dev/null
        echo "$username:$password" | chpasswd
        chage -E "$expire_date" "$username"
        echo "$username:$password:$expire_date:$limit:$bandwidth_gb:0:ACTIVE" >> "$DB_FILE"
        printf "  ${C_GREEN}%-20s${C_RESET} | ${C_YELLOW}%-15s${C_RESET} | ${C_CYAN}%-12s${C_RESET}\n" "$username" "$password" "$expire_date"
        created=$((created + 1))
    done
    
    echo -e "${C_YELLOW}================================================================${C_RESET}"
    echo -e "\n${C_GREEN}✅ Created $created users. Conn Limit: ${limit} | BW: ${bw_display}${C_RESET}"
    safe_read "" dummy
}

_view_user_bandwidth() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📊 View User Bandwidth ---${C_RESET}"
    
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
    
    IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status <<< "$line"
    bandwidth_gb=${bandwidth_gb:-0}
    traffic_used=${traffic_used:-0}
    
    echo -e "\n  ${C_CYAN}Data Used:${C_RESET}        ${C_WHITE}${traffic_used} GB${C_RESET}"
    
    if [[ "$bandwidth_gb" == "0" ]]; then
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_GREEN}Unlimited${C_RESET}"
        echo -e "  ${C_CYAN}Status:${C_RESET}           ${C_GREEN}No quota restrictions${C_RESET}"
    else
        local percentage=$(echo "scale=1; $traffic_used * 100 / $bandwidth_gb" | bc 2>/dev/null || echo "0")
        local remaining_gb=$(echo "scale=2; $bandwidth_gb - $traffic_used" | bc 2>/dev/null || echo "0")
        
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_YELLOW}${bandwidth_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Remaining:${C_RESET}        ${C_WHITE}${remaining_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Usage:${C_RESET}            ${C_WHITE}${percentage}%${C_RESET}"
        
        # Progress bar
        local bar_width=30
        local filled=$(echo "scale=0; $percentage * $bar_width / 100" | bc 2>/dev/null || echo "0")
        if [[ "$filled" -gt "$bar_width" ]]; then filled=$bar_width; fi
        local empty=$((bar_width - filled))
        local bar_color="$C_GREEN"
        if (( $(echo "$percentage > 80" | bc -l 2>/dev/null) )); then bar_color="$C_RED"
        elif (( $(echo "$percentage > 50" | bc -l 2>/dev/null) )); then bar_color="$C_YELLOW"
        fi
        printf "  ${C_CYAN}Progress:${C_RESET}         ${bar_color}["
        for ((i=0; i<filled; i++)); do printf "█"; done
        for ((i=0; i<empty; i++)); do printf "░"; done
        printf "]${C_RESET} ${percentage}%%\n"
        
        if (( $(echo "$traffic_used >= $bandwidth_gb" | bc -l 2>/dev/null) )); then
            echo -e "\n  ${C_RED}⚠️ USER HAS EXCEEDED BANDWIDTH QUOTA — ACCOUNT LOCKED${C_RESET}"
        fi
    fi
    
    safe_read "" dummy
}

# ========== GENERATE CLIENT CONFIG ==========
generate_client_config() {
    local user=$1
    local pass=$2
    
    local host_ip=$(curl -s -4 icanhazip.com)
    local host_domain="$host_ip"
    
    if [ -f "$DB_DIR/domain.txt" ]; then
        local managed_domain=$(cat "$DB_DIR/domain.txt" 2>/dev/null)
        if [[ -n "$managed_domain" ]]; then 
            host_domain="$managed_domain"
        fi
    fi

    echo -e "\n${C_BOLD}${C_PURPLE}--- 📱 Client Connection Configuration ---${C_RESET}"
    echo -e "${C_CYAN}Copy the details below to your clipboard:${C_RESET}\n"

    echo -e "${C_YELLOW}========================================${C_RESET}"
    echo -e "👤 ${C_BOLD}User Details${C_RESET}"
    echo -e "   • Username: ${C_WHITE}$user${C_RESET}"
    echo -e "   • Password: ${C_WHITE}$pass${C_RESET}"
    echo -e "   • Host/IP : ${C_WHITE}$host_domain${C_RESET}"
    echo -e "${C_YELLOW}========================================${C_RESET}"
    
    # 1. SSH Direct
    echo -e "\n🔹 ${C_BOLD}SSH Direct${C_RESET}:"
    echo -e "   • Host: $host_domain"
    echo -e "   • Port: 22"
    echo -e "   • Username: $user"
    echo -e "   • Password: $pass"

    # 2. SSL/TLS Tunnel
    if systemctl is-active --quiet haproxy 2>/dev/null; then
        local haproxy_port=$(grep -oP 'bind \*:(\d+)' /etc/haproxy/haproxy.cfg 2>/dev/null | awk -F: '{print $2}' | head -1)
        if [[ -n "$haproxy_port" ]]; then
            echo -e "\n🔹 ${C_BOLD}SSL/TLS Tunnel (HAProxy)${C_RESET}:"
            echo -e "   • Host: $host_domain"
            echo -e "   • Port: $haproxy_port"
            echo -e "   • Username: $user"
            echo -e "   • Password: $pass"
        fi
    fi

    # 3. UDP Custom
    if systemctl is-active --quiet udp-custom 2>/dev/null; then
        echo -e "\n🔹 ${C_BOLD}UDP Custom${C_RESET}:"
        echo -e "   • IP: $host_ip (Must use numeric IP)"
        echo -e "   • Port: 1-65535 (Exclude 53, 5300)"
        echo -e "   • Username: $user"
        echo -e "   • Password: $pass"
    fi

    # 4. DNSTT
    if systemctl is-active --quiet dnstt 2>/dev/null; then
        if [ -f "$DNSTT_INFO_FILE" ]; then
            source "$DNSTT_INFO_FILE"
            echo -e "\n🔹 ${C_BOLD}DNSTT (SlowDNS)${C_RESET}:"
            echo -e "   • Nameserver: $TUNNEL_DOMAIN"
            echo -e "   • PubKey: $PUBLIC_KEY"
            echo -e "   • DNS IP: 1.1.1.1 / 8.8.8.8"
            echo -e "   • Username: $user"
            echo -e "   • Password: $pass"
        fi
    fi
    
    # 5. ZiVPN
    if systemctl is-active --quiet zivpn 2>/dev/null; then
        echo -e "\n🔹 ${C_BOLD}ZiVPN${C_RESET}:"
        echo -e "   • UDP Port: 5667"
        echo -e "   • Forwarded Ports: 6000-19999"
        echo -e "   • Username: $user"
        echo -e "   • Password: $pass"
    fi
    
    echo -e "${C_YELLOW}========================================${C_RESET}"
    safe_read "" dummy
}

client_config_menu() {
    _select_user_interface "--- 📱 Generate Client Config ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" || -z "$u" ]]; then return; fi
    
    local pass=$(grep "^$u:" "$DB_FILE" | cut -d: -f2)
    generate_client_config "$u" "$pass"
}

# ========== SELECT USER INTERFACE ==========
_select_user_interface() {
    local title="$1"
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}${title}${C_RESET}\n"
    if [[ ! -s $DB_FILE ]]; then
        echo -e "${C_YELLOW}ℹ️ No users found in the database.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    
    mapfile -t all_users < <(cut -d: -f1 "$DB_FILE" | sort)
    
    if [ ${#all_users[@]} -ge 15 ]; then
        read -p "👉 Enter a search term (or press Enter to list all): " search_term
        if [[ -n "$search_term" ]]; then
            mapfile -t users < <(printf "%s\n" "${all_users[@]}" | grep -i "$search_term")
        else
            users=("${all_users[@]}")
        fi
    else
        users=("${all_users[@]}")
    fi

    if [ ${#users[@]} -eq 0 ]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found matching your criteria.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    echo -e "\nPlease select a user:\n"
    for i in "${!users[@]}"; do
        printf "  ${C_GREEN}[%2d]${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_RED} [ 0]${C_RESET} ↩️ Cancel and return to main menu"
    echo
    local choice
    while true; do
        read -p "👉 Enter the number of the user: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -le "${#users[@]}" ]; then
            if [ "$choice" -eq 0 ]; then
                SELECTED_USER=""; return
            else
                SELECTED_USER="${users[$((choice-1))]}"; return
            fi
        else
            echo -e "${C_RED}❌ Invalid selection. Please try again.${C_RESET}"
        fi
    done
}

_select_multi_user_interface() {
    local title="$1"
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}${title}${C_RESET}\n"
    SELECTED_USERS=()
    if [[ ! -s $DB_FILE ]]; then
        echo -e "${C_YELLOW}ℹ️ No users found in the database.${C_RESET}"
        SELECTED_USERS=("NO_USERS"); return
    fi
    
    mapfile -t all_users < <(cut -d: -f1 "$DB_FILE" | sort)
    
    if [ ${#all_users[@]} -ge 15 ]; then
        read -p "👉 Enter a search term (or press Enter to list all): " search_term
        if [[ -n "$search_term" ]]; then
            mapfile -t users < <(printf "%s\n" "${all_users[@]}" | grep -i "$search_term")
        else
            users=("${all_users[@]}")
        fi
    else
        users=("${all_users[@]}")
    fi

    if [ ${#users[@]} -eq 0 ]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found matching your criteria.${C_RESET}"
        SELECTED_USERS=("NO_USERS"); return
    fi
    echo -e "\nPlease select users:\n"
    for i in "${!users[@]}"; do
        printf "  ${C_GREEN}[%2d]${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_GREEN}[all]${C_RESET} Select ALL listed users"
    echo -e "  ${C_RED}  [0]${C_RESET} ↩️ Cancel and return to main menu"
    echo -e "\n${C_CYAN}💡 You can select multiple! (e.g. '1 3 5' or '1,3' or '1-4')${C_RESET}"
    echo
    local choice
    while true; do
        read -p "👉 Enter user numbers: " choice
        choice=$(echo "$choice" | tr ',' ' ')
        
        if [[ -z "$choice" ]]; then
            echo -e "${C_RED}❌ Invalid selection. Please try again.${C_RESET}"
            continue
        fi

        if [[ "$choice" == "0" ]]; then
            SELECTED_USERS=(); return
        fi
        
        if [[ "${choice,,}" == "all" ]]; then
            SELECTED_USERS=("${users[@]}")
            return
        fi
        
        local valid=true
        local selected_indices=()
        for token in $choice; do
            if [[ "$token" =~ ^[0-9]+-[0-9]+$ ]]; then
                local start=${token%-*}
                local end=${token#*-}
                if [ "$start" -le "$end" ]; then
                    for (( idx=start; idx<=end; idx++ )); do
                        if [ "$idx" -ge 1 ] && [ "$idx" -le "${#users[@]}" ]; then
                            selected_indices+=($idx)
                        else
                            valid=false; break
                        fi
                    done
                else
                    valid=false; break
                fi
            elif [[ "$token" =~ ^[0-9]+$ ]]; then
                if [ "$token" -ge 1 ] && [ "$token" -le "${#users[@]}" ]; then
                    selected_indices+=($token)
                else
                    valid=false; break
                fi
            else
                valid=false; break
            fi
        done
        
        if [[ "$valid" == true && ${#selected_indices[@]} -gt 0 ]]; then
            mapfile -t unique_indices < <(printf "%s\n" "${selected_indices[@]}" | sort -u -n)
            for idx in "${unique_indices[@]}"; do
                SELECTED_USERS+=("${users[$((idx-1))]}")
            done
            return
        else
            echo -e "${C_RED}❌ Invalid selection. Please check your numbers.${C_RESET}"
            SELECTED_USERS=()
            selected_indices=()
        fi
    done
}

# ========== PROTOCOLS ==========
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

# ========== DT PROXY ==========
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
    
    systemctl list-units --type=service --state=running | grep 'proxy-' | awk '{print $1}' | while read service; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    done
    
    rm -f /etc/systemd/system/proxy-*.service
    systemctl daemon-reload
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f "$HOME/.proxy_token"
    rm -f /usr/local/bin/install_mod
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

# ========== V2RAY FUNCTIONS ==========
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
        
        local traffic_disp=""
        if [ "$limit" == "0" ]; then
            traffic_disp="${used}GB/∞"
        else
            traffic_disp="${used}/${limit} GB"
        fi
        
        local short_uuid=""
        if [ ${#uuid} -ge 16 ]; then
            short_uuid="${uuid:0:8}...${uuid: -8}"
        else
            short_uuid="$uuid"
        fi
        
        local status_color=""
        case $status in
            active) status_color="${C_GREEN}" ;;
            locked) status_color="${C_YELLOW}" ;;
            expired) status_color="${C_RED}" ;;
            *) status_color="${C_WHITE}" ;;
        esac
        
        printf "%-15s %-8s %-36s %-25s %-12s ${status_color}%-10s${C_RESET}\n" \
            "$user" "$proto" "$short_uuid" "$traffic_disp" "$expiry" "$status"
            
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

# ========== BACKUP & RESTORE ==========
backup_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    
    local backup_path
    safe_read "👉 Backup path [/root/voltrontech_backup.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_backup.tar.gz}
    
    tar -czf "$backup_path" $DB_DIR $TRAFFIC_DIR 2>/dev/null
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

# ========== CACHE CLEANER ==========
enable_cache_cleaner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 ENABLING ADVANCED AUTO CACHE CLEANER${C_RESET}"
    echo -e "${C_BLUE}           ⏰ Schedule: Daily at 12:00 AM (Midnight)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    touch "$CACHE_LOG_FILE" 2>/dev/null
    
    cat > "$CACHE_SCRIPT" << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/voltron-cache.log"

log() { echo "$(date): $1" >> "$LOG_FILE"; }

log "Starting advanced cache clean..."
apt clean >> "$LOG_FILE" 2>&1
apt autoclean >> "$LOG_FILE" 2>&1
apt autoremove -y >> "$LOG_FILE" 2>&1
journalctl --vacuum-time=3d >> "$LOG_FILE" 2>&1
rm -f /var/log/*.gz /var/log/*.old 2>/dev/null
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null
log "Advanced cache clean completed"
EOF

    chmod +x "$CACHE_SCRIPT"
    
    cat > "$CACHE_CRON_FILE" << EOF
0 0 * * * root $CACHE_SCRIPT
EOF

    (crontab -l 2>/dev/null | grep -v "voltron-cache-clean"; echo "0 0 * * * $CACHE_SCRIPT") | crontab - 2>/dev/null

    echo -e "${C_GREEN}✅ Advanced auto cache cleaner enabled!${C_RESET}"
    safe_read "" dummy
}

disable_cache_cleaner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING AUTO CACHE CLEANER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    rm -f "$CACHE_CRON_FILE" 2>/dev/null
    crontab -l 2>/dev/null | grep -v "voltron-cache-clean" | crontab - 2>/dev/null
    
    echo -e "${C_GREEN}✅ Auto cache cleaner disabled${C_RESET}"
    safe_read "" dummy
}

check_cache_status() {
    if [ -f "$CACHE_CRON_FILE" ]; then
        echo -e "${C_GREEN}ENABLED${C_RESET}"
        return 0
    else
        echo -e "${C_RED}DISABLED${C_RESET}"
        return 1
    fi
}

cache_cleaner_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🧹 ADVANCED AUTO CACHE CLEANER${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_CYAN}Current Status:${C_RESET} $(check_cache_status)"
        echo -e "  ${C_CYAN}Schedule:${C_RESET} ${C_YELLOW}Daily at 12:00 AM (Midnight)${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Auto Clean"
        echo -e "  ${C_RED}2)${C_RESET} Disable Auto Clean"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) enable_cache_cleaner ;;
            2) disable_cache_cleaner ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== CONNECTION FORCER ==========
connection_forcer_menu() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔗 CONNECTION FORCER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ Coming soon...${C_RESET}"
    safe_read "" dummy
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
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install DNSTT"
                echo -e "  ${C_GREEN}2)${C_RESET} View Details"
                echo -e "  ${C_RED}3)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_dnstt_falcon
                elif [ "$sub" == "2" ]; then show_dnstt_details
                elif [ "$sub" == "3" ]; then uninstall_dnstt
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            5)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install V2RAY"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall V2RAY"
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

# ========== DNSTT INSTALLATION (FALCON STYLE) ==========
install_dnstt_falcon() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION (FALCON STYLE)${C_RESET}"
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
    echo -e "\n${C_BLUE}[1/7] Installing dependencies...${C_RESET}"
    $PKG_INSTALL wget curl openssl
    
    # Step 2: Download binary (Falcon style)
    echo -e "\n${C_BLUE}[2/7] Downloading DNSTT binary...${C_RESET}"
    if ! download_dnstt_binary; then
        echo -e "${C_RED}❌ Failed to download DNSTT binary${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Step 3: Configure firewall
    echo -e "\n${C_BLUE}[3/7] Configuring firewall...${C_RESET}"
    configure_firewall
    
    # Step 4: Setup domain
    echo -e "\n${C_BLUE}[4/7] Domain configuration...${C_RESET}"
    setup_domain
    
    # Step 5: MTU selection
    echo -e "\n${C_BLUE}[5/7] MTU configuration...${C_RESET}"
    mtu_selection_during_install
    
    # Step 6: Generate keys
    echo -e "\n${C_BLUE}[6/7] Generating keys...${C_RESET}"
    generate_keys
    
    # Step 7: Create service (LIVE MODE - no auto-restart)
    echo -e "\n${C_BLUE}[7/7] Creating service...${C_RESET}"
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    SSH_PORT=${SSH_PORT:-22}
    
    create_dnstt_service_live "$DOMAIN" "$MTU" "$SSH_PORT"
    save_dnstt_info "$DOMAIN" "$PUBLIC_KEY" "$MTU" "$SSH_PORT"
    
    # Apply Speed Booster
    echo -e "\n${C_BLUE}⚡ Apply Speed Booster?${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Standard Speed Booster (10-15 Mbps)"
    echo -e "  ${C_GREEN}2)${C_RESET} ULTRA Speed Booster (15-25 Mbps)"
    echo -e "  ${C_GREEN}3)${C_RESET} Skip (No booster)"
    echo ""
    read -p "👉 Choose [1-3, default=2]: " booster_choice
    booster_choice=${booster_choice:-2}
    
    case $booster_choice in
        1) apply_dnstt_speed_booster ;;
        2) apply_dnstt_ultra_booster ;;
        3) echo -e "${C_YELLOW}⚠️ Skipping speed booster${C_RESET}" ;;
        *) apply_dnstt_ultra_booster ;;
    esac
    
    echo -e "\n${C_BLUE}🚀 Starting DNSTT service...${C_RESET}"
    systemctl start dnstt.service
    sleep 2
    
    if systemctl is-active --quiet dnstt.service; then
        echo -e "${C_GREEN}✅ Service started successfully${C_RESET}"
    else
        echo -e "${C_RED}❌ Service failed to start${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
    fi
    
    show_client_commands_falcon_style "$DOMAIN" "$MTU" "$SSH_PORT"
    
    echo -e "\n${C_GREEN}✅ DNSTT installation complete (Falcon style - Live mode)!${C_RESET}"
    safe_read "" dummy
}

uninstall_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNSTT...${C_RESET}"
    
    systemctl stop dnstt.service 2>/dev/null
    systemctl disable dnstt.service 2>/dev/null
    rm -f "$DNSTT_SERVICE"
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT"
    rm -f "$DB_DIR/server.key" "$DB_DIR/server.pub"
    rm -f "$DB_DIR/domain.txt"
    rm -f "$DNSTT_INFO_FILE"
    rm -f /etc/sysctl.d/99-dnstt-*.conf
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNSTT uninstalled${C_RESET}"
    safe_read "" dummy
}

show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNSTT DETAILS (FALCON STYLE)${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DB_DIR/domain.txt" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    DOMAIN=$(cat "$DB_DIR/domain.txt" 2>/dev/null || echo "unknown")
    MTU=$(cat "$CONFIG_DIR/mtu" 2>/dev/null || echo "512")
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
    echo -e "  Public Key:    ${C_YELLOW}${PUBKEY:0:30}...${PUBKEY: -30}${C_RESET}"
    
    safe_read "" dummy
}

# ========== LEGACY CLOUDFLARE DNS ==========
generate_cloudflare_dns() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Generate Cloudflare DNS ---${C_RESET}"
    echo -e "${C_YELLOW}⚠️ This is legacy. Use auto-generated with deSEC instead.${C_RESET}"
    safe_read "" dummy
}

# ========== LIMITER SERVICE ==========
create_limiter_service() {
    cat > "$LIMITER_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
TRAFFIC_DIR="/etc/voltrontech/traffic"
BANNER_DIR="/etc/voltrontech/banners"
mkdir -p "$TRAFFIC_DIR" "$BANNER_DIR"

while true; do
    if [ -f "$DB_FILE" ]; then
        current_ts=$(date +%s)
        
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
            [[ -z "$user" ]] && continue
            status=${status:-ACTIVE}
            
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" -9 2>/dev/null
                sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$traffic_used:EXPIRED/" "$DB_FILE" 2>/dev/null
                continue
            fi
            
            online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
            
            if [[ "$online" -gt "$limit" && "$limit" -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" -9 2>/dev/null
                sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$traffic_used:LIMIT/" "$DB_FILE" 2>/dev/null
                (sleep 120; usermod -U "$user" 2>/dev/null) &
                continue
            fi
            
            # ========== AUTO HTML BANNER GENERATION ==========
            if [ -f "/etc/voltrontech/banners_enabled" ]; then
                # Calculate days left
                days_left="N/A"
                if [[ "$expiry" != "Never" && -n "$expiry" ]]; then
                    if [[ $expiry_ts -gt 0 ]]; then
                        diff_secs=$((expiry_ts - current_ts))
                        if [[ $diff_secs -le 0 ]]; then
                            days_left="EXPIRED"
                        else
                            d_l=$(( diff_secs / 86400 ))
                            h_l=$(( (diff_secs % 86400) / 3600 ))
                            if [[ $d_l -eq 0 ]]; then days_left="${h_l}h left"
                            else days_left="${d_l}d ${h_l}h"; fi
                        fi
                    fi
                fi
                
                # Calculate bandwidth info
                bw_info="Unlimited"
                if [[ "$traffic_limit" != "0" && -n "$traffic_limit" ]]; then
                    used_gb=$traffic_used
                    remain_gb=$(echo "scale=2; $traffic_limit - $used_gb" | bc 2>/dev/null || echo "0")
                    bw_info="${used_gb}/${traffic_limit} GB used | ${remain_gb} GB left"
                fi
                
                # YOUR BANNER (TOP)
                cat > "$BANNER_DIR/${user}.txt" <<BANNER_EOF
<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px; width: 180px;">
    ===============================
  </span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;"></span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;">
    WELCOME TO VOLTRON TECH
  </span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px; width: 180px;">
    ===============================
  </span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;"></span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;">
    🇿🇦 SOUTH AFRICA SERVER 🇿🇦
  </span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;">
    📱 HALOTEL UNLIMITED
  </span>
</H3>

<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px;"></span>
</H3>
BANNER_EOF

                # FALCON ORIGINAL BANNER (CENTER)
                echo -e "<div style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
                echo -e "<br><font color=\"yellow\"><b>      ✨ ACCOUNT STATUS ✨      </b></font><br><br>" >> "$BANNER_DIR/${user}.txt"
                echo -e "<font color=\"white\">👤 <b>Username   :</b> $user</font><br>" >> "$BANNER_DIR/${user}.txt"
                echo -e "<font color=\"white\">📅 <b>Expiration :</b> $expiry ($days_left)</font><br>" >> "$BANNER_DIR/${user}.txt"
                echo -e "<font color=\"white\">📊 <b>Bandwidth  :</b> $bw_info</font><br>" >> "$BANNER_DIR/${user}.txt"
                echo -e "<font color=\"white\">🔌 <b>Sessions   :</b> $online/$limit</font><br><br>" >> "$BANNER_DIR/${user}.txt"
                echo -e "</div>" >> "$BANNER_DIR/${user}.txt"
                
                # YOUR BANNER (FOOTER)
                cat >> "$BANNER_DIR/${user}.txt" <<BANNER_EOF
<H3 style="text-align:center">
  <span style="padding: 8px 15px; display: inline-block; margin: 3px; width: 180px;">
    ===============================
  </span>
</H3>
BANNER_EOF
            fi
            
            traffic_file="$TRAFFIC_DIR/$user"
            if [ -f "$traffic_file" ]; then
                current_bytes=$(cat "$traffic_file" 2>/dev/null || echo "0")
                current_gb=$(echo "scale=2; $current_bytes / 1073741824" | bc 2>/dev/null || echo "0")
            else
                current_gb=0
            fi
            
            if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ]; then
                if (( $(echo "$current_gb >= $traffic_limit" | bc -l 2>/dev/null) )); then
                    usermod -L "$user" 2>/dev/null
                    killall -u "$user" -9 2>/dev/null
                    sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$current_gb:LIMIT/" "$DB_FILE" 2>/dev/null
                    continue
                fi
            fi
            
            sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$current_gb:ACTIVE/" "$DB_FILE" 2>/dev/null
            
        done < "$DB_FILE"
    fi
    sleep 5
done
EOF
    chmod +x "$LIMITER_SCRIPT"
    
    cat > "$LIMITER_SERVICE" <<EOF
[Unit]
Description=Voltron Connection & Traffic Limiter with Auto Banner
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
    systemctl restart voltron-limiter.service 2>/dev/null
}

# ========== TRAFFIC MONITOR ==========
create_traffic_monitor() {
    cat > "$TRAFFIC_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
TRAFFIC_DIR="/etc/voltrontech/traffic"
mkdir -p "$TRAFFIC_DIR"

while true; do
    if [ -f "$DB_FILE" ]; then
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
            [[ -z "$user" ]] && continue
            if id "$user" &>/dev/null; then
                traffic_file="$TRAFFIC_DIR/$user"
                if [ -f "$traffic_file" ]; then
                    current_bytes=$(cat "$traffic_file" 2>/dev/null || echo "0")
                    current_gb=$(echo "scale=3; $current_bytes / 1073741824" | bc 2>/dev/null || echo "0")
                    sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$current_gb:$status/" "$DB_FILE" 2>/dev/null
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
    systemctl restart voltron-traffic.service 2>/dev/null
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
    
    # Delete deSEC DNS records
    delete_desec_dns_records
    
    # Disable Auto Reboot
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab - 2>/dev/null
    
    # Disable Cache Cleaner
    rm -f "$CACHE_CRON_FILE" 2>/dev/null
    crontab -l 2>/dev/null | grep -v "voltron-cache-clean" | crontab - 2>/dev/null
    
    # Stop all services
    systemctl stop dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service haproxy voltronproxy.service nginx zivpn.service 2>/dev/null
    systemctl disable dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service voltronproxy.service 2>/dev/null
    systemctl stop voltron-limiter.service voltron-traffic.service 2>/dev/null
    systemctl disable voltron-limiter.service voltron-traffic.service 2>/dev/null
    
    # Remove service files
    rm -f "$DNSTT_SERVICE" "$V2RAY_SERVICE" "$BADVPN_SERVICE" "$UDP_CUSTOM_SERVICE" "$VOLTRONPROXY_SERVICE" "$ZIVPN_SERVICE"
    rm -f "$TRAFFIC_SERVICE" "$LIMITER_SERVICE"
    
    # Remove binaries
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT" "$V2RAY_BIN" "$BADVPN_BIN" "$UDP_CUSTOM_BIN" "$VOLTRONPROXY_BIN" "$ZIVPN_BIN"
    rm -f "$LIMITER_SCRIPT" "$TRAFFIC_SCRIPT" "$LOSS_PROTECT_SCRIPT"
    rm -f "$CACHE_SCRIPT"
    
    # Remove directories
    rm -rf "$BADVPN_BUILD_DIR" "$UDP_CUSTOM_DIR" "$ZIVPN_DIR"
    
    # Remove configuration
    rm -rf "$DB_DIR" "$TRAFFIC_DIR"
    
    # Restore DNS
    chattr -i /etc/resolv.conf 2>/dev/null
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    
    # Restart SSH
    systemctl restart sshd
    
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

# ========== MAIN MENU ==========
main_menu() {
    initial_setup
    while true; do
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    👤 USER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "1" "Create New User" "6" "Unlock User"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "2" "Delete User" "7" "List Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "3" "Edit User" "8" "Renew User"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "4" "Lock User" "9" "Cleanup Expired"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "5" "Bulk Create Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "10" "📊 View Bandwidth"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "11" "📱 Generate Client Config"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "12" "Protocols & Panels" "16" "SSH Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "13" "Backup Users" "17" "Auto HTML Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "14" "Restore Users" "18" "Auto Reboot"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "15" "DNS Domain" "19" "Cache Cleaner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "20" "V2Ray Management" "21" "Connection Forcer"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "22" "DT Proxy"

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
            5) _bulk_create_users ;;
            6) _unlock_user ;;
            7) _list_users ;;
            8) _renew_user ;;
            9) _cleanup_expired ;;
            10) _view_user_bandwidth ;;
            11) client_config_menu ;;
            
            12) protocol_menu ;;
            13) backup_user_data ;;
            14) restore_user_data ;;
            15) generate_cloudflare_dns ;;
            16) ssh_banner_menu ;;
            17) auto_banner_menu ;;
            18) auto_reboot_menu ;;
            19) cache_cleaner_menu ;;
            20) v2ray_main_menu ;;
            21) connection_forcer_menu ;;
            22) dt_proxy_menu ;;
            
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
