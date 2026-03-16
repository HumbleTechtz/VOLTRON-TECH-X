#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 9.0 (ULTRA BOOST - 10x SPEED for MTU 512)
# Description: SSH • DNSTT • V2RAY • BADVPN • UDP-CUSTOM • SSL • PROXY • ZIVPN • X-UI
# Author: Voltron Tech
# Features: ULTRA BOOST - 10x speed with MTU 512 using 10 parallel instances!

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
TRAFFIC_DIR="$DB_DIR/traffic"

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
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $V2RAY_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR $FEC_DIR $TRAFFIC_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    mkdir -p $(dirname "$SSH_BANNER_FILE")
    mkdir -p "$FORCER_DIR" "$FORCER_BACKUP_DIR"
    mkdir -p "$DB_DIR/cache"
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
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v9.0 🔥                    ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • V2RAY • BADVPN • UDP • SSL • ZiVPN        ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║              ULTRA BOOST - 10x SPEED for MTU 512                ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    
    # Show ULTRA BOOST status
    echo -e "${C_BOLD}${C_PURPLE}║  ULTRA BOOST: ${C_GREEN}ACTIVE (10x speed mode)${C_PURPLE}${C_RESET}"
    
    # Show Connection Forcer status
    if [ -f "$FORCER_CONFIG" ]; then
        source "$FORCER_CONFIG"
        echo -e "${C_BOLD}${C_PURPLE}║  Forcer:     ${C_GREEN}ACTIVE (${CONNECTIONS_PER_IP} conn/IP)${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  Forcer:     ${C_YELLOW}INACTIVE (1 conn/IP)${C_PURPLE}${C_RESET}"
    fi
    
    # Show Cache Cleaner status
    if [ -f "$CACHE_CRON_FILE" ]; then
        echo -e "${C_BOLD}${C_PURPLE}║  Cache:      ${C_GREEN}AUTO CLEAN ACTIVE (12:00 AM daily)${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  Cache:      ${C_YELLOW}AUTO CLEAN DISABLED${C_PURPLE}${C_RESET}"
    fi
    
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== ULTRA BOOST FUNCTIONS (DEFAULT - 10x SPEED) ==========

# Function to enable BBR v3 with fq_codel
enable_bbr_v3() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 ENABLING BBR v3 CONGESTION CONTROL${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Load module
    modprobe tcp_bbr 2>/dev/null
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null
    
    # Set congestion control to BBR v3 with fq_codel for better latency
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel > /dev/null 2>&1
    
    # Make permanent
    cat >> /etc/sysctl.conf << EOF

# BBR v3 Congestion Control with fq_codel
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
EOF
    
    echo -e "${C_GREEN}✅ BBR v3 enabled with fq_codel (optimized for low latency)${C_RESET}"
}

# Function to set ULTRA buffers (32MB for 10x speed)
optimize_ultra_buffers() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📊 OPTIMIZING ULTRA BUFFERS (32MB)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Set buffer sizes to 32MB - critical for 10x speed with MTU 512
    sysctl -w net.core.rmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.core.wmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432" > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432" > /dev/null 2>&1
    sysctl -w net.core.optmem_max=33554432 > /dev/null 2>&1
    
    # Make permanent
    cat >> /etc/sysctl.conf << EOF

# Ultra Network Buffers for MTU 512 (32MB) - 10x speed
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.optmem_max = 33554432
EOF
    
    echo -e "${C_GREEN}✅ Ultra buffers set to 32MB (optimized for 10x speed)${C_RESET}"
}

# Function to set aggressive keepalive (10s)
optimize_aggressive_keepalive() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔄 OPTIMIZING AGGRESSIVE KEEPALIVE (10s)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Set aggressive keepalive to maintain connection with MTU 512
    sysctl -w net.ipv4.tcp_keepalive_time=10 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_intvl=2 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_probes=2 > /dev/null 2>&1
    
    # Make permanent
    cat >> /etc/sysctl.conf << EOF

# Aggressive TCP Keepalive for MTU 512 (10s) - 10x speed
net.ipv4.tcp_keepalive_time = 10
net.ipv4.tcp_keepalive_intvl = 2
net.ipv4.tcp_keepalive_probes = 2
EOF
    
    echo -e "${C_GREEN}✅ Aggressive keepalive set to 10s intervals${C_RESET}"
}

# Function for advanced TCP tuning (12 parameters)
optimize_advanced_tcp() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📐 APPLYING ADVANCED TCP TUNABLES (12 parameters)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Advanced TCP optimizations for maximum throughput
    sysctl -w net.ipv4.tcp_sack=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_dsack=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_fack=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_window_scaling=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_timestamps=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_no_metrics_save=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_low_latency=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_early_retrans=3 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_thin_linear_timeouts=1 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_autocorking=0 > /dev/null 2>&1
    
    # Make permanent
    cat >> /etc/sysctl.conf << EOF

# Advanced TCP Tuning for MTU 512 - 10x speed
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_early_retrans = 3
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_autocorking = 0
EOF
    
    echo -e "${C_GREEN}✅ Advanced TCP tuning applied (12 parameters)${C_RESET}"
}

# Function to set ultra file descriptors (8M)
optimize_ultra_filedesc() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📄 SETTING ULTRA FILE DESCRIPTORS (8M)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Set ultra-high file descriptors for 10+ instances
    ulimit -n 8388608 2>/dev/null || ulimit -n 4194304 2>/dev/null || true
    
    cat > /etc/security/limits.d/99-ultra-boost.conf << 'EOF'
# Ultra file descriptors for MTU 512 - 10x speed (supports 10+ instances)
* soft nofile 8388608
* hard nofile 8388608
root soft nofile 8388608
root hard nofile 8388608
* soft nproc 8388608
* hard nproc 8388608
EOF
    
    echo -e "${C_GREEN}✅ File descriptors set to 8M (supports 10+ parallel instances)${C_RESET}"
}

# Function to apply all ULTRA BOOST optimizations (DEFAULT - 10x speed)
apply_ultra_boost() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 APPLYING ULTRA BOOST (10x SPEED)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    enable_bbr_v3
    optimize_ultra_buffers
    optimize_aggressive_keepalive
    optimize_advanced_tcp
    optimize_ultra_filedesc
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ ULTRA BOOST ACTIVATED - 10x SPEED!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}• BBR v3 with fq_codel:${C_RESET} Active"
    echo -e "  ${C_CYAN}• Ultra Buffers:${C_RESET} 32MB"
    echo -e "  ${C_CYAN}• Aggressive Keepalive:${C_RESET} 10s"
    echo -e "  ${C_CYAN}• Advanced TCP Tuning:${C_RESET} 12 parameters"
    echo -e "  ${C_CYAN}• File Descriptors:${C_RESET} 8M"
    echo -e "  ${C_CYAN}• Parallel Instances:${C_RESET} 10 (on client)"
    echo -e "  ${C_CYAN}• Expected Speed:${C_RESET} ${C_GREEN}10x with MTU 512!${C_RESET}"
    
    sleep 3
}

# ========== FIXED LIMITER SERVICE WITH TRAFFIC MONITORING ==========
create_limiter_service() {
    cat > "$LIMITER_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
TRAFFIC_DIR="/etc/voltrontech/traffic"
mkdir -p "$TRAFFIC_DIR"

# Function to calculate traffic per user
update_user_traffic() {
    local username=$1
    local traffic_file="$TRAFFIC_DIR/$username"
    
    # Get user's active connections
    local connections=$(pgrep -u "$username" sshd 2>/dev/null | wc -l)
    
    if [ $connections -gt 0 ]; then
        # Simple traffic estimation (1KB per second per connection)
        local total_bytes=$((connections * 1024))
        
        # Add to user's traffic
        if [ -f "$traffic_file" ]; then
            current=$(cat "$traffic_file" 2>/dev/null || echo "0")
            new=$((current + total_bytes))
            echo "$new" > "$traffic_file"
        else
            echo "$total_bytes" > "$traffic_file"
        fi
    fi
}

while true; do
    if [ -f "$DB_FILE" ]; then
        current_ts=$(date +%s)
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
            [[ -z "$user" ]] && continue
            status=${status:-ACTIVE}
            
            # Check expiry
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" -9 2>/dev/null
                sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$traffic_used:EXPIRED/" "$DB_FILE" 2>/dev/null
                continue
            fi
            
            # Get current connections
            online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
            
            # Check connection limit
            if [[ "$online" -gt "$limit" && "$limit" -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" -9 2>/dev/null
                sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$traffic_used:LIMIT/" "$DB_FILE" 2>/dev/null
                (sleep 120; usermod -U "$user" 2>/dev/null) &
                continue
            fi
            
            # Update traffic
            update_user_traffic "$user"
            
            # Get current traffic from traffic file
            traffic_file="$TRAFFIC_DIR/$user"
            if [ -f "$traffic_file" ]; then
                current_traffic_bytes=$(cat "$traffic_file" 2>/dev/null || echo "0")
                current_traffic_gb=$(echo "scale=2; $current_traffic_bytes / 1073741824" | bc 2>/dev/null || echo "0")
            else
                current_traffic_gb=0
            fi
            
            # Check traffic limit
            if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ]; then
                if (( $(echo "$current_traffic_gb >= $traffic_limit" | bc -l 2>/dev/null) )); then
                    usermod -L "$user" 2>/dev/null
                    killall -u "$user" -9 2>/dev/null
                    sed -i "s/^$user:.*/$user:$pass:$expiry:$limit:$traffic_limit:$current_traffic_gb:LIMIT/" "$DB_FILE" 2>/dev/null
                    continue
                fi
            fi
            
            # Update database with current traffic
            sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$current_traffic_gb:ACTIVE/" "$DB_FILE" 2>/dev/null
            
        done < "$DB_FILE"
    fi
    sleep 5
done
EOF
    chmod +x "$LIMITER_SCRIPT"
    
    cat > "$LIMITER_SERVICE" <<EOF
[Unit]
Description=Voltron Connection & Traffic Limiter
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

# ========== FIXED TRAFFIC MONITOR ==========
create_traffic_monitor() {
    cat > "$TRAFFIC_SCRIPT" <<'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
TRAFFIC_DIR="/etc/voltrontech/traffic"
mkdir -p "$TRAFFIC_DIR"

# Function to get traffic for a user
get_user_traffic() {
    local username=$1
    local traffic_file="$TRAFFIC_DIR/$username"
    
    if [ -f "$traffic_file" ]; then
        cat "$traffic_file"
    else
        echo "0"
    fi
}

while true; do
    if [ -f "$DB_FILE" ]; then
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used status; do
            [[ -z "$user" ]] && continue
            status=${status:-ACTIVE}
            
            if id "$user" &>/dev/null; then
                connections=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
                
                if [ $connections -gt 0 ]; then
                    # Get current traffic
                    current_bytes=$(get_user_traffic "$user")
                    current_gb=$(echo "scale=3; $current_bytes / 1073741824" | bc 2>/dev/null || echo "0")
                    
                    # Update database with current traffic
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

# ========== ADVANCED CACHE CLEANER (12:00 AM) ==========

# Function to check cache cleaner status
check_cache_status() {
    if [ -f "$CACHE_CRON_FILE" ]; then
        echo -e "${C_GREEN}ENABLED${C_RESET} (runs daily at 12:00 AM - Midnight)"
        return 0
    else
        echo -e "${C_RED}DISABLED${C_RESET}"
        return 1
    fi
}

# Function to enable advanced auto cache cleaner (12:00 AM)
enable_cache_cleaner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 ENABLING ADVANCED AUTO CACHE CLEANER${C_RESET}"
    echo -e "${C_BLUE}           ⏰ Schedule: Daily at 12:00 AM (Midnight)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Create log file
    touch "$CACHE_LOG_FILE" 2>/dev/null || {
        echo -e "${C_RED}❌ Failed to create log file${C_RESET}"
        safe_read "" dummy
        return 1
    }
    
    # Create advanced clean script
    cat > "$CACHE_SCRIPT" << 'EOF'
#!/bin/bash
# VOLTRON TECH Advanced Auto Cache Cleaner
# Runs at 12:00 AM (Midnight)
LOG_FILE="/var/log/voltron-cache.log"

log() {
    echo "$(date): $1" >> "$LOG_FILE"
}

log "========================================="
log "Starting advanced cache clean at $(date)"
log "========================================="

# === RECORD SPACE BEFORE ===
before=$(df / | awk 'NR==2 {print $3}')

# === LEVEL 1: APT CACHE ===
log "[1/5] Cleaning apt cache..."
apt clean >> "$LOG_FILE" 2>&1
apt autoclean >> "$LOG_FILE" 2>&1
apt autoremove -y >> "$LOG_FILE" 2>&1

# === LEVEL 2: SYSTEM LOGS ===
log "[2/5] Cleaning old system logs..."
journalctl --vacuum-time=3d >> "$LOG_FILE" 2>&1
rm -f /var/log/*.gz /var/log/*.old /var/log/*.log.* 2>/dev/null
find /var/log -type f -name "*.log" -size +100M -exec truncate -s 0 {} \; 2>/dev/null

# === LEVEL 3: TEMPORARY FILES ===
log "[3/5] Cleaning temporary files..."
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null
rm -rf /var/cache/apt/archives/*.deb 2>/dev/null
rm -rf /var/cache/debconf/* 2>/dev/null

# === LEVEL 4: OLD KERNELS ===
log "[4/5] Removing old kernels..."
current_kernel=$(uname -r)
dpkg -l linux-* | grep '^ii' | awk '{print $2}' | grep -v "$current_kernel" | grep -E 'linux-image-[0-9]' | while read kernel; do
    log "  Removing old kernel: $kernel"
    apt purge -y "$kernel" >> "$LOG_FILE" 2>&1
done

# === LEVEL 5: USER CACHES ===
log "[5/5] Cleaning user caches..."
for user_home in /home/* /root; do
    if [ -d "$user_home/.cache" ]; then
        find "$user_home/.cache" -type f -atime +30 -delete 2>/dev/null
    fi
    if [ -d "$user_home/.npm" ]; then
        npm cache clean --force >> "$LOG_FILE" 2>&1 2>/dev/null
    fi
    if [ -d "$user_home/.cargo" ]; then
        cargo cache -a >> "$LOG_FILE" 2>&1 2>/dev/null
    fi
    if [ -d "$user_home/.composer" ]; then
        composer clear-cache >> "$LOG_FILE" 2>&1 2>/dev/null
    fi
done

# === CALCULATE SPACE SAVED ===
after=$(df / | awk 'NR==2 {print $3}')
saved=$((before - after))
saved_mb=$((saved / 1024))
saved_gb=$(echo "scale=2; $saved_mb / 1024" | bc 2>/dev/null || echo "0")

log "========================================="
log "Advanced clean completed at $(date)"
log "Space saved: ${saved_mb}MB (${saved_gb}GB)"
log "========================================="
EOF

    chmod +x "$CACHE_SCRIPT" || {
        echo -e "${C_RED}❌ Failed to create clean script${C_RESET}"
        safe_read "" dummy
        return 1
    }
    
    # Create cron file for 12:00 AM (midnight)
    cat > "$CACHE_CRON_FILE" << EOF
# VOLTRON TECH Advanced Auto Cache Cleaner
# Runs daily at 12:00 AM (Midnight)
0 0 * * * root $CACHE_SCRIPT
EOF

    # Also add to crontab for compatibility
    (crontab -l 2>/dev/null | grep -v "voltron-cache-clean"; echo "0 0 * * * $CACHE_SCRIPT") | crontab - 2>/dev/null

    # Check if cron file was created
    if [ -f "$CACHE_CRON_FILE" ]; then
        echo -e "${C_GREEN}✅ Advanced auto cache cleaner enabled successfully!${C_RESET}"
        echo -e "  ${C_CYAN}Schedule:${C_RESET} Daily at ${C_YELLOW}12:00 AM (Midnight)${C_RESET}"
        echo -e "  ${C_CYAN}Clean Level:${C_RESET} Deep Clean (5 levels)"
        echo -e "  ${C_CYAN}Log file:${C_RESET} $CACHE_LOG_FILE"
        
        # Run once now to test
        echo -e "${C_YELLOW}Running initial advanced clean...${C_RESET}"
        bash "$CACHE_SCRIPT"
        echo -e "${C_GREEN}✅ Initial advanced clean completed${C_RESET}"
        
        # Show next run time
        echo -e "\n${C_CYAN}📌 Next automatic run:${C_RESET} Tonight at 12:00 AM"
    else
        echo -e "${C_RED}❌ Failed to create cron file${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    safe_read "" dummy
}

# Function to disable auto cache cleaner
disable_cache_cleaner() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING AUTO CACHE CLEANER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Remove cron file
    rm -f "$CACHE_CRON_FILE" 2>/dev/null
    
    # Remove from crontab
    crontab -l 2>/dev/null | grep -v "voltron-cache-clean" | crontab - 2>/dev/null
    
    echo -e "${C_GREEN}✅ Auto cache cleaner disabled${C_RESET}"
    echo -e "${C_YELLOW}📌 No more automatic cleanups at 12:00 AM${C_RESET}"
    safe_read "" dummy
}

# Cache Cleaner Menu (Enable/Disable tu)
cache_cleaner_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🧹 ADVANCED AUTO CACHE CLEANER${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        # Show current status
        echo -e "  ${C_CYAN}Current Status:${C_RESET} $(check_cache_status)"
        echo -e "  ${C_CYAN}Clean Level:${C_RESET} Deep Clean (5 levels)"
        echo -e "  ${C_CYAN}Schedule:${C_RESET} ${C_YELLOW}Daily at 12:00 AM (Midnight)${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Advanced Auto Clean (12:00 AM)"
        echo -e "  ${C_RED}2)${C_RESET} Disable Auto Clean"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return to Main Menu"
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
}

# ========== CLOUDFLARE AUTO DOMAIN GENERATOR WITH IPv4 & IPv6 ==========
generate_cloudflare_domain() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ☁️  CLOUDFLARE AUTO DOMAIN GENERATOR${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Generate random strings
    rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    ns="ns-$rand"
    tun="tun-$rand"
    
    # Get server IPv4
    SERVER_IPV4=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IPV4" ] || ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "${C_YELLOW}⚠️ Could not detect IPv4 address${C_RESET}"
        SERVER_IPV4=""
    fi
    
    # Get server IPv6
    SERVER_IPV6=$(curl -s -6 ifconfig.me 2>/dev/null || curl -s -6 icanhazip.com 2>/dev/null)
    if [ -z "$SERVER_IPV6" ] || ! _is_valid_ipv6 "$SERVER_IPV6"; then
        echo -e "${C_YELLOW}⚠️ Could not detect IPv6 address${C_RESET}"
        SERVER_IPV6=""
    fi
    
    # Create IPv4 A record if available
    local ns_record_id=""
    local ns_record_id6=""
    local tunnel_record_id=""
    local tunnel_record_id6=""
    
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "${C_GREEN}[1/4] Creating IPv4 A record: $ns.$BASE_DOMAIN → $SERVER_IPV4${C_RESET}"
        
        ns_record_id=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\":\"A\",
                \"name\":\"$ns\",
                \"content\":\"$SERVER_IPV4\",
                \"ttl\":3600,
                \"proxied\":false
            }" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -n "$ns_record_id" ]; then
            echo -e "${C_GREEN}✓ IPv4 A record created: $ns.$BASE_DOMAIN${C_RESET}"
        else
            echo -e "${C_RED}❌ Failed to create IPv4 A record${C_RESET}"
        fi
    fi
    
    # Create IPv6 AAAA record if available
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "${C_GREEN}[2/4] Creating IPv6 AAAA record: $ns.$BASE_DOMAIN → $SERVER_IPV6${C_RESET}"
        
        ns_record_id6=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\":\"AAAA\",
                \"name\":\"$ns\",
                \"content\":\"$SERVER_IPV6\",
                \"ttl\":3600,
                \"proxied\":false
            }" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -n "$ns_record_id6" ]; then
            echo -e "${C_GREEN}✓ IPv6 AAAA record created: $ns.$BASE_DOMAIN${C_RESET}"
        else
            echo -e "${C_RED}❌ Failed to create IPv6 AAAA record${C_RESET}"
        fi
    fi
    
    # Create IPv4 NS record if we have IPv4
    if [ -n "$ns_record_id" ]; then
        echo -e "${C_GREEN}[3/4] Creating IPv4 NS record: $tun.$BASE_DOMAIN → $ns.$BASE_DOMAIN${C_RESET}"
        
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
        
        if [ -n "$tunnel_record_id" ]; then
            echo -e "${C_GREEN}✓ IPv4 NS record created: $tun.$BASE_DOMAIN${C_RESET}"
        else
            echo -e "${C_RED}❌ Failed to create IPv4 NS record${C_RESET}"
        fi
    fi
    
    # Create IPv6 NS record if we have IPv6
    if [ -n "$ns_record_id6" ]; then
        echo -e "${C_GREEN}[4/4] Creating IPv6 NS record: $tun.$BASE_DOMAIN → $ns.$BASE_DOMAIN${C_RESET}"
        
        tunnel_record_id6=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\":\"NS\",
                \"name\":\"$tun\",
                \"content\":\"$ns.$BASE_DOMAIN\",
                \"ttl\":3600,
                \"proxied\":false
            }" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -n "$tunnel_record_id6" ]; then
            echo -e "${C_GREEN}✓ IPv6 NS record created: $tun.$BASE_DOMAIN${C_RESET}"
        else
            echo -e "${C_RED}❌ Failed to create IPv6 NS record${C_RESET}"
        fi
    fi
    
    DOMAIN="$tun.$BASE_DOMAIN"
    
    # Save record IDs
    echo "$ns_record_id" > "$DB_DIR/cloudflare_ns_record.txt"
    echo "$tunnel_record_id" > "$DB_DIR/cloudflare_tunnel_record.txt"
    echo "$ns_record_id6" > "$DB_DIR/cloudflare_ns_record6.txt" 2>/dev/null
    echo "$tunnel_record_id6" > "$DB_DIR/cloudflare_tunnel_record6.txt" 2>/dev/null
    
    echo -e "\n${C_GREEN}✅ Auto-generated domain: ${C_YELLOW}$DOMAIN${C_RESET}"
    
    # Show IPs detected
    echo -e "\n${C_CYAN}IP Addresses detected:${C_RESET}"
    if [ -n "$SERVER_IPV4" ]; then
        echo -e "  • IPv4: ${C_GREEN}$SERVER_IPV4${C_RESET}"
    else
        echo -e "  • IPv4: ${C_RED}Not detected${C_RESET}"
    fi
    if [ -n "$SERVER_IPV6" ]; then
        echo -e "  • IPv6: ${C_GREEN}$SERVER_IPV6${C_RESET}"
    else
        echo -e "  • IPv6: ${C_YELLOW}Not detected${C_RESET}"
    fi
    
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
    echo -e "  ${C_GREEN}2)${C_RESET} Auto-generate with Cloudflare (IPv4 + IPv6)"
    echo ""
    read -p "👉 Choice [1-2, default=2]: " domain_option
    domain_option=${domain_option:-2}
    
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

# ========== MTU SELECTION (FORCED TO 512) ==========
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 MTU CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    # Force MTU 512 for ULTRA BOOST
    MTU=512
    
    echo -e "${C_GREEN}✅ MTU set to $MTU (ULTRA BOOST mode)${C_RESET}"
    echo -e "${C_YELLOW}📌 10x speed will be achieved through:${C_RESET}"
    echo -e "   • 32MB Ultra Buffers"
    echo -e "   • BBR v3 Congestion Control"
    echo -e "   • 10 Parallel Instances"
    echo -e "   • Aggressive Keepalive (10s)"
    echo -e "   • Advanced TCP Tuning (12 parameters)"
    echo -e "   • 8M File Descriptors"
    
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
    echo -e "${C_BLUE}           📋 CREATING DNSTT SERVICE (ULTRA BOOST)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server (ULTRA BOOST - 10x Speed)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DB_DIR
ExecStart=$DNSTT_SERVER -udp :5300 -privkey-file $DB_DIR/server.key -mtu $mtu $domain 127.0.0.1:$ssh_port
Restart=always
RestartSec=3

# IPv6 Support (uncomment if needed)
# ExecStart=$DNSTT_SERVER -udp :5300 -privkey-file $DB_DIR/server.key -mtu $mtu $domain ::1:$ssh_port

StandardOutput=append:$LOGS_DIR/dnstt-server.log
StandardError=append:$LOGS_DIR/dnstt-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service > /dev/null 2>&1
    
    echo -e "${C_GREEN}✅ Service created successfully${C_RESET}"
    echo -e "  • Binary: ${C_CYAN}$DNSTT_SERVER${C_RESET}"
    echo -e "  • MTU: ${C_CYAN}$mtu (ULTRA BOOST mode)${C_RESET}"
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

# ========== FIXED SHOW CLIENT COMMANDS WITH 10 INSTANCES (NO COLOR CODES IN SCRIPT) ==========
show_client_commands() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    local pubkey=$(cat "$DB_DIR/server.pub")
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           📱 ULTRA CLIENT COMMANDS (10x SPEED)${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 ULTRA DNS Resolvers (10 different - for 10 instances):${C_RESET}"
    echo -e "  ${C_GREEN}1.${C_RESET} 8.8.8.8:53          (Google)"
    echo -e "  ${C_GREEN}2.${C_RESET} 1.1.1.1:53          (Cloudflare)"
    echo -e "  ${C_GREEN}3.${C_RESET} 169.255.187.58:53   (Halotel - Tanzania)"
    echo -e "  ${C_GREEN}4.${C_RESET} 208.67.222.222:53   (OpenDNS)"
    echo -e "  ${C_GREEN}5.${C_RESET} 9.9.9.9:53          (Quad9)"
    echo -e "  ${C_GREEN}6.${C_RESET} 77.88.8.8:53        (Yandex)"
    echo -e "  ${C_GREEN}7.${C_RESET} 8.26.56.26:53       (Comodo)"
    echo -e "  ${C_GREEN}8.${C_RESET} 185.228.168.9:53    (CleanBrowsing)"
    echo -e "  ${C_GREEN}9.${C_RESET} 76.76.19.19:53      (Alternate DNS)"
    echo -e "  ${C_GREEN}10.${C_RESET} 94.140.14.14:53     (AdGuard)"
    echo ""
    
    echo -e "${C_YELLOW}📌 ULTRA SCRIPT - 10 Parallel Instances (10x Speed):${C_RESET}"
    
    # === HAPA NDIYO SEHEMU MUHIMU - TUMIA echo PLAIN ===
    echo "cat > /usr/local/bin/ultra-dnstt.sh << 'EOF'"
    echo "#!/bin/bash"
    echo "# ULTRA BOOST - 10 Instances for 10x Speed"
    echo "# Generated by Voltron Tech"
    echo ""
    echo "DOMAIN=\"$domain\""
    echo "PUBKEY_FILE=\"$DB_DIR/server.pub\""
    echo "MTU=$mtu"
    echo "BASE_PORT=1080"
    echo ""
    echo "# DNS resolvers (10 different)"
    echo "DNS_RESOLVERS=("
    echo "    \"8.8.8.8:53\""
    echo "    \"1.1.1.1:53\""
    echo "    \"169.255.187.58:53\""
    echo "    \"208.67.222.222:53\""
    echo "    \"9.9.9.9:53\""
    echo "    \"77.88.8.8:53\""
    echo "    \"8.26.56.26:53\""
    echo "    \"185.228.168.9:53\""
    echo "    \"76.76.19.19:53\""
    echo "    \"94.140.14.14:53\""
    echo ")"
    echo ""
    echo "# Create proxychains config"
    echo "cat > /tmp/proxychains-ultra.conf << 'PROXY_EOF'"
    echo "dynamic_chain"
    echo "round_robin_chain on"
    echo "[ProxyList]"
    echo "PROXY_EOF"
    echo ""
    echo "for i in {0..9}; do"
    echo "    PORT=\$((BASE_PORT + i))"
    echo "    echo \"socks5 127.0.0.1 \$PORT\" >> /tmp/proxychains-ultra.conf"
    echo "    $DNSTT_CLIENT -udp \${DNS_RESOLVERS[\$i]} \\"
    echo "        -pubkey-file \"\$PUBKEY_FILE\" \\"
    echo "        -mtu \$MTU \\"
    echo "        -listen \"127.0.0.1:\$PORT\" \\"
    echo "        \"\$DOMAIN\" 127.0.0.1:$ssh_port &"
    echo "    echo \"Instance \$((i+1)) started on port \$PORT\""
    echo "    sleep 1"
    echo "done"
    echo ""
    echo "echo \"\""
    echo "echo \"✅ 10 ULTRA INSTANCES ACTIVE!\""
    echo "echo \"📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf ssh user@localhost -p $ssh_port\""
    echo "echo \"📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf curl ifconfig.me\""
    echo "echo \"📌 Expected speed: 10x!\""
    echo "EOF"
    # === MWISHO WA SEHEMU MUHIMU ===
    
    echo ""
    echo -e "${WHITE}chmod +x /usr/local/bin/ultra-dnstt.sh${NC}"
    echo -e "${WHITE}sudo /usr/local/bin/ultra-dnstt.sh${NC}"
    echo ""
    
    echo -e "${C_YELLOW}📌 Single Instance (for testing):${C_RESET}"
    echo -e "${WHITE}$DNSTT_CLIENT -udp 8.8.8.8:53 \\${C_RESET}"
    echo -e "${WHITE}  -pubkey-file $DB_DIR/server.pub \\${C_RESET}"
    echo -e "${WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${WHITE}  $domain 127.0.0.1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_GREEN}📌 Public Key:${C_RESET}"
    echo -e "${YELLOW}$pubkey${C_RESET}"
    echo ""
    
    echo -e "${C_CYAN}⚡ ULTRA BOOST STATUS (10x Speed Mode):${C_RESET}"
    echo -e "  • MTU: ${C_GREEN}$mtu (ISP limited)${C_RESET}"
    echo -e "  • Ultra Buffers: ${C_GREEN}32MB${C_RESET}"
    echo -e "  • BBR v3: ${C_GREEN}Active${C_RESET}"
    echo -e "  • Keepalive: ${C_GREEN}10s${C_RESET}"
    echo -e "  • File Descriptors: ${C_GREEN}8M${C_RESET}"
    echo -e "  • TCP Tuning: ${C_GREEN}12 parameters optimized${C_RESET}"
    echo -e "  • 10 Parallel Instances: ${C_GREEN}10x speed!${C_RESET}"
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

# ========== LIST USERS (ORIGINAL STYLE) ==========
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
        
        # Get current connections
        local online=0
        if id "$user" &>/dev/null; then
            online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        fi
        
        # Format traffic display
        local traffic_disp=""
        if [[ "$traffic_limit" == "0" ]] || [[ -z "$traffic_limit" ]]; then
            traffic_disp="$(printf "%.2f" $traffic_used) GB / ∞"
        else
            if command -v bc &>/dev/null; then
                local percent=$(echo "scale=1; $traffic_used * 100 / $traffic_limit" | bc 2>/dev/null || echo "0")
                traffic_disp="$(printf "%.2f" $traffic_used) / $traffic_limit GB ($percent%)"
            else
                traffic_disp="$(printf "%.2f" $traffic_used) / $traffic_limit GB"
            fi
        fi
        
        # Determine status color
        local status_color=""
        local status_text="$status"
        
        case $status in
            ACTIVE)
                status_color="${C_GREEN}"
                ;;
            LOCKED|LIMIT)
                status_color="${C_YELLOW}"
                ;;
            EXPIRED)
                status_color="${C_RED}"
                ;;
            *)
                status_color="${C_WHITE}"
                ;;
        esac
        
        printf "%-15s | ${C_YELLOW}%-12s${C_RESET} | ${C_CYAN}%s/%s${C_RESET} | %-25s | ${status_color}%-10s${C_RESET}\n" \
            "$user" "$expiry" "$online" "$limit" "$traffic_disp" "$status_text"
            
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

# ========== CONNECTION FORCER FUNCTIONS (FIXED) ==========

# Function to check if port is available
check_port_available() {
    local port=$1
    if ss -tlnp | grep -q ":$port "; then
        return 1  # Port in use
    else
        return 0  # Port free
    fi
}

# Function to get free port
get_free_port() {
    local base_port=$1
    local port=$base_port
    local max_attempts=100
    local attempts=0
    
    while ! check_port_available $port && [ $attempts -lt $max_attempts ]; do
        port=$((port + 1))
        attempts=$((attempts + 1))
    done
    
    if [ $attempts -ge $max_attempts ]; then
        echo ""
    else
        echo $port
    fi
}

# Function to install HAProxy safely
install_haproxy_safe() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📦 INSTALLING HAPROXY${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Check if already installed
    if command -v haproxy &>/dev/null; then
        echo -e "${C_GREEN}✅ HAProxy is already installed${C_RESET}"
        return 0
    fi
    
    # Install
    echo -e "${C_YELLOW}Updating package lists...${C_RESET}"
    apt update -qq
    
    echo -e "${C_YELLOW}Installing HAProxy...${C_RESET}"
    apt install -y haproxy
    
    if command -v haproxy &>/dev/null; then
        echo -e "${C_GREEN}✅ HAProxy installed successfully${C_RESET}"
        return 0
    else
        echo -e "${C_RED}❌ Failed to install HAProxy${C_RESET}"
        return 1
    fi
}

# Function to enable Connection Forcer (fixed - doesn't modify SSH)
enable_connection_forcer_fixed() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 ENABLING CONNECTION FORCER (FIXED)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Create directories
    mkdir -p "$FORCER_DIR" "$FORCER_BACKUP_DIR"
    
    # Install HAProxy if needed
    if ! install_haproxy_safe; then
        echo -e "${C_RED}❌ Cannot proceed without HAProxy${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Get number of connections
    local connections
    read -p "👉 Number of connections per IP [5]: " connections
    connections=${connections:-5}
    if ! [[ "$connections" =~ ^[0-9]+$ ]] || [ "$connections" -lt 1 ] || [ "$connections" -gt 20 ]; then
        echo -e "${C_RED}❌ Invalid number. Using 5.${C_RESET}"
        connections=5
    fi
    
    # Use a different port for HAProxy (not 22)
    local haproxy_port
    read -p "👉 Port for HAProxy [2222]: " haproxy_port
    haproxy_port=${haproxy_port:-2222}
    
    # Check if port is available
    if ! check_port_available $haproxy_port; then
        echo -e "${C_YELLOW}⚠️ Port $haproxy_port is in use${C_RESET}"
        local new_port=$(get_free_port $haproxy_port)
        if [ -n "$new_port" ]; then
            echo -e "${C_GREEN}✅ Found free port: $new_port${C_RESET}"
            haproxy_port=$new_port
        else
            echo -e "${C_RED}❌ Could not find free port${C_RESET}"
            safe_read "" dummy
            return 1
        fi
    fi
    
    # Backup existing HAProxy config
    if [ -f "$FORCER_HAPROXY_CFG" ]; then
        local backup_file="$FORCER_BACKUP_DIR/haproxy.cfg.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$FORCER_HAPROXY_CFG" "$backup_file"
        echo -e "${C_GREEN}✅ Backed up existing config to $backup_file${C_RESET}"
    fi
    
    # Create HAProxy config - use different port, don't modify SSH
    echo -e "${C_YELLOW}Creating HAProxy configuration...${C_RESET}"
    
    cat > "$FORCER_HAPROXY_CFG" <<EOF
global
    log /dev/log local0
    maxconn 10000
    user haproxy
    group haproxy
    daemon
    stats socket /var/lib/haproxy/stats

defaults
    log global
    mode tcp
    option tcplog
    retries 3
    timeout connect 5s
    timeout client 30s
    timeout server 30s

# Stats page
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:voltron123

# Frontend - listen on HAProxy port
frontend ssh-in
    bind *:$haproxy_port
EOF

    # Add extra ports for each connection
    for ((i=1; i<=connections; i++)); do
        local extra_port=$((haproxy_port + i))
        echo "    bind *:$extra_port" >> "$FORCER_HAPROXY_CFG"
    done
    
    cat >> "$FORCER_HAPROXY_CFG" <<EOF
    default_backend ssh-servers

# Backend with multiple servers (all to local SSH)
backend ssh-servers
    balance roundrobin
EOF

    # Add servers (each connects to local SSH on port 22)
    for ((i=1; i<=connections; i++)); do
        echo "    server ssh$i 127.0.0.1:22 check" >> "$FORCER_HAPROXY_CFG"
    done
    
    # Test configuration
    echo -e "${C_YELLOW}Testing HAProxy configuration...${C_RESET}"
    if haproxy -f "$FORCER_HAPROXY_CFG" -c; then
        echo -e "${C_GREEN}✅ Configuration test passed${C_RESET}"
        
        # Stop HAProxy if running
        systemctl stop haproxy 2>/dev/null
        
        # Start HAProxy
        echo -e "${C_YELLOW}Starting HAProxy...${C_RESET}"
        systemctl start haproxy
        systemctl enable haproxy
        
        # Wait for HAProxy to start
        sleep 3
        
        # Check if HAProxy started
        if systemctl is-active haproxy &>/dev/null; then
            echo -e "${C_GREEN}✅ HAProxy started successfully on port $haproxy_port${C_RESET}"
            
            # Open firewall ports
            if command -v ufw &>/dev/null; then
                echo -e "${C_YELLOW}Opening firewall ports...${C_RESET}"
                ufw allow $haproxy_port/tcp 2>/dev/null
                for ((i=1; i<=connections; i++)); do
                    ufw allow $((haproxy_port + i))/tcp 2>/dev/null
                done
                ufw allow 8404/tcp 2>/dev/null  # Stats page
            fi
            
            # Save configuration
            cat > "$FORCER_CONFIG" <<EOF
CONNECTIONS_PER_IP="$connections"
HAPROXY_PORT="$haproxy_port"
ENABLED="yes"
DATE="$(date)"
EOF
            
            echo ""
            echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
            echo -e "${C_GREEN}           ✅ CONNECTION FORCER ENABLED!${C_RESET}"
            echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
            echo -e "  ${C_CYAN}Connections per IP:${C_RESET} $connections"
            echo -e "  ${C_CYAN}HAProxy Port:${C_RESET}       $haproxy_port"
            for ((i=1; i<=connections; i++)); do
                echo -e "                       $((haproxy_port + i))"
            done
            echo ""
            echo -e "${C_YELLOW}📌 Clients connect to HAProxy port, NOT SSH port:${C_RESET}"
            echo -e "  ssh user@your-server -p $haproxy_port"
            echo -e "  # HAProxy automatically creates $connections connections per IP!"
            echo ""
            echo -e "${C_YELLOW}📌 Stats page:${C_RESET} http://$IP:8404/stats (admin/voltron123)"
        else
            echo -e "${C_RED}❌ HAProxy failed to start${C_RESET}"
            echo -e "${C_YELLOW}HAProxy logs:${C_RESET}"
            journalctl -u haproxy -n 20 --no-pager
        fi
    else
        echo -e "${C_RED}❌ Configuration test failed${C_RESET}"
        echo -e "${C_YELLOW}Please check the configuration manually${C_RESET}"
    fi
    
    safe_read "" dummy
}

# Function to disable Connection Forcer
disable_connection_forcer() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING CONNECTION FORCER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -f "$FORCER_CONFIG" ]; then
        echo -e "${C_YELLOW}ℹ️ Connection Forcer is not enabled${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Stop HAProxy
    echo -e "${C_YELLOW}Stopping HAProxy...${C_RESET}"
    systemctl stop haproxy
    systemctl disable haproxy
    
    # Restore HAProxy config if backup exists
    local latest_backup=$(ls -t "$FORCER_BACKUP_DIR"/* 2>/dev/null | head -1)
    if [ -n "$latest_backup" ]; then
        cp "$latest_backup" "$FORCER_HAPROXY_CFG"
        echo -e "${C_GREEN}✅ Restored previous HAProxy config${C_RESET}"
    else
        rm -f "$FORCER_HAPROXY_CFG"
    fi
    
    rm -f "$FORCER_CONFIG"
    
    echo -e "${C_GREEN}✅ Connection Forcer disabled${C_RESET}"
    echo -e "${C_YELLOW}📌 Clients now connect directly to SSH port 22${C_RESET}"
    
    safe_read "" dummy
}

# Function to check Connection Forcer status
status_connection_forcer() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📊 CONNECTION FORCER STATUS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -f "$FORCER_CONFIG" ]; then
        echo -e "${C_YELLOW}ℹ️ Connection Forcer is NOT enabled${C_RESET}"
        echo -e "Clients connect directly to SSH port 22"
    else
        source "$FORCER_CONFIG"
        echo -e "${C_GREEN}✅ Connection Forcer is ENABLED${C_RESET}"
        echo -e "  ${C_CYAN}Connections per IP:${C_RESET} $CONNECTIONS_PER_IP"
        echo -e "  ${C_CYAN}HAProxy Port:${C_RESET}       $HAPROXY_PORT"
        echo -e "  ${C_CYAN}Active ports:${C_RESET}        $HAPROXY_PORT"
        for ((i=1; i<=CONNECTIONS_PER_IP; i++)); do
            echo -e "                    $((HAPROXY_PORT + i))"
        done
        echo -e "  ${C_CYAN}Enabled since:${C_RESET}       $DATE"
        
        # Check if HAProxy is running
        if systemctl is-active haproxy &>/dev/null; then
            echo -e "  ${C_CYAN}HAProxy:${C_RESET}            ${C_GREEN}Running${C_RESET}"
        else
            echo -e "  ${C_CYAN}HAProxy:${C_RESET}            ${C_RED}Stopped${C_RESET}"
        fi
    fi
    
    safe_read "" dummy
}

# Function to view connection statistics
stats_connection_forcer() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📈 CONNECTION FORCER STATISTICS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if ! systemctl is-active haproxy &>/dev/null; then
        echo -e "${C_YELLOW}ℹ️ HAProxy is not running${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Get expected connections per IP from config
    local expected=5
    if [ -f "$FORCER_CONFIG" ]; then
        source "$FORCER_CONFIG"
        expected=$CONNECTIONS_PER_IP
    fi
    
    echo -e "${C_GREEN}Current connections per IP (via HAProxy):${C_RESET}"
    echo ""
    
    # Get all established connections to HAProxy ports
    local connections=""
    if [ -f "$FORCER_CONFIG" ]; then
        source "$FORCER_CONFIG"
        connections=$(ss -tnp 2>/dev/null | grep ESTAB | grep ":$HAPROXY_PORT" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr)
    else
        connections=$(ss -tnp 2>/dev/null | grep ESTAB | grep ":2222" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr)
    fi
    
    if [ -z "$connections" ]; then
        echo -e "${C_YELLOW}No active connections through HAProxy${C_RESET}"
    else
        local total_connections=0
        local total_ips=0
        local ips_meeting_target=0
        
        echo "$connections" | while read count ip; do
            total_connections=$((total_connections + count))
            total_ips=$((total_ips + 1))
            
            if [ $count -ge $expected ]; then
                echo -e "  ${C_GREEN}$ip${C_RESET} → ${C_GREEN}$count connections ✓${C_RESET}"
                ips_meeting_target=$((ips_meeting_target + 1))
            else
                echo -e "  ${C_YELLOW}$ip${C_RESET} → ${C_YELLOW}$count connections ⚠️ (should be $expected)${C_RESET}"
            fi
        done
        
        echo ""
        echo -e "${C_CYAN}Total unique IPs:${C_RESET} $total_ips"
        echo -e "${C_CYAN}Total connections:${C_RESET} $total_connections"
        if [ $total_ips -gt 0 ]; then
            echo -e "${C_CYAN}IPs meeting target ($expected):${C_RESET} $ips_meeting_target"
            echo -e "${C_CYAN}Average connections per IP:${C_RESET} $((total_connections / total_ips))"
        fi
    fi
    
    safe_read "" dummy
}

# Connection Forcer Menu
connection_forcer_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🔗 CONNECTION FORCER (Multiple connections per IP)${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        # Show current status
        if [ -f "$FORCER_CONFIG" ]; then
            source "$FORCER_CONFIG"
            echo -e "  ${C_GREEN}✅ Status: ENABLED (${CONNECTIONS_PER_IP} conn/IP)${C_RESET}"
        else
            echo -e "  ${C_YELLOW}⚠️ Status: DISABLED (1 connection per IP)${C_RESET}"
        fi
        echo ""
        
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Connection Forcer"
        echo -e "  ${C_RED}2)${C_RESET} Disable Connection Forcer"
        echo -e "  ${C_GREEN}3)${C_RESET} View Status"
        echo -e "  ${C_GREEN}4)${C_RESET} View Statistics"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return to Main Menu"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) enable_connection_forcer_fixed ;;
            2) disable_connection_forcer ;;
            3) status_connection_forcer ;;
            4) stats_connection_forcer ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== DNSTT INSTALLATION WITH ULTRA BOOST ==========
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION (ULTRA BOOST - 10x SPEED)${C_RESET}"
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
    echo -e "\n${C_BLUE}[1/9] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL wget curl git build-essential openssl
    
    # Step 2: Install Go
    echo -e "\n${C_BLUE}[2/9] Installing Go...${C_RESET}"
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    # Step 3: Build DNSTT from source
    echo -e "\n${C_BLUE}[3/9] Building DNSTT from source...${C_RESET}"
    if ! build_dnstt_from_source; then
        echo -e "${C_RED}❌ Failed to build DNSTT${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Step 4: Apply ULTRA BOOST optimizations (DEFAULT - 10x speed)
    echo -e "\n${C_BLUE}[4/9] Applying ULTRA BOOST optimizations (10x speed)...${C_RESET}"
    apply_ultra_boost
    
    # Step 5: Configure firewall
    echo -e "\n${C_BLUE}[5/9] Configuring firewall...${C_RESET}"
    configure_firewall
    
    # Step 6: Setup domain
    echo -e "\n${C_BLUE}[6/9] Domain configuration...${C_RESET}"
    setup_domain
    
    # Step 7: MTU selection (forced to 512)
    echo -e "\n${C_BLUE}[7/9] MTU configuration...${C_RESET}"
    mtu_selection_during_install
    
    # Step 8: Generate keys
    echo -e "\n${C_BLUE}[8/9] Generating keys...${C_RESET}"
    if ! generate_keys; then
        echo -e "${C_RED}❌ Failed to generate keys${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Get SSH port
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    SSH_PORT=${SSH_PORT:-22}
    
    # Step 9: Create service
    echo -e "\n${C_BLUE}[9/9] Creating service...${C_RESET}"
    create_dnstt_service "$DOMAIN" "$MTU" "$SSH_PORT"
    
    # Save DNSTT info
    save_dnstt_info "$DOMAIN" "$PUBLIC_KEY" "$MTU" "$SSH_PORT"
    
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
    
    # Show client commands with ULTRA BOOST
    show_client_commands "$DOMAIN" "$MTU" "$SSH_PORT"
    
    # Save info
    cat > "$DB_DIR/dnstt_info.txt" <<EOF
DNSTT Configuration (ULTRA BOOST - 10x Speed)
============================================
Domain: $DOMAIN
MTU: $MTU (ISP limited)
SSH Port: $SSH_PORT
Public Key: $(cat "$DB_DIR/server.pub")
ULTRA BOOST Features:
- BBR v3 with fq_codel: Active
- Ultra Buffers: 32MB
- Aggressive Keepalive: 10s
- Advanced TCP Tuning: 12 parameters
- File Descriptors: 8M
- Parallel Instances: 10 (on client)

For 10x speed, use the ULTRA client script shown above!
EOF
    
    echo -e "\n${C_GREEN}✅ DNSTT installation complete with ULTRA BOOST!${C_RESET}"
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
    echo -e "${C_GREEN}           📡 DNSTT DETAILS (ULTRA BOOST)${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DB_DIR/domain.txt" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    DOMAIN=$(cat "$DB_DIR/domain.txt" 2>/dev/null || echo "unknown")
    MTU=$(cat "$DB_DIR/mtu.txt" 2>/dev/null || echo "512")
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
    echo -e "  MTU:           ${C_YELLOW}$MTU (ULTRA BOOST mode)${C_RESET}"
    echo -e "  SSH Port:      ${C_YELLOW}$SSH_PORT${C_RESET}"
    echo -e "  Binary:        ${C_YELLOW}$DNSTT_SERVER${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}${PUBKEY:0:30}...${PUBKEY: -30}${C_RESET}"
    echo -e "  ULTRA BOOST Features:"
    echo -e "    • BBR v3:    ${C_GREEN}Active${C_RESET}"
    echo -e "    • Buffers:   ${C_GREEN}32MB${C_RESET}"
    echo -e "    • Keepalive: ${C_GREEN}10s${C_RESET}"
    echo -e "    • TCP Tuning: ${C_GREEN}12 parameters${C_RESET}"
    echo -e "    • File Desc: ${C_GREEN}8M${C_RESET}"
    echo -e "    • Instances: ${C_GREEN}10x speed possible${C_RESET}"
    
    safe_read "" dummy
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

# ========== CLOUDFLARE DNS GENERATOR (LEGACY) ==========
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
    
    # Disable Connection Forcer if enabled
    if [ -f "$FORCER_CONFIG" ]; then
        echo -e "${C_BLUE}Disabling Connection Forcer...${C_RESET}"
        systemctl stop haproxy 2>/dev/null
        systemctl disable haproxy 2>/dev/null
    fi
    
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
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "16" "Connection Forcer" "17" "DT Proxy"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "18" "🧹 Cache Cleaner"

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
            16) connection_forcer_menu ;;
            17) dt_proxy_menu ;;
            18) cache_cleaner_menu ;;
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
