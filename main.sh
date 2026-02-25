#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 3.0 (MTU 1800 SPECIAL)
# Description: SSH • DNSTT • DNS2TCP • V2RAY over DNSTT • MTU 1800 ULTIMATE
# Author: Voltron Tech

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
DOMAIN="voltrontechtx.shop"

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"

# DNS Protocols Directories
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNS2TCP_KEYS_DIR="$DB_DIR/dns2tcp"
V2RAY_DIR="$DB_DIR/v2ray-dnstt"
V2RAY_USERS_DB="$V2RAY_DIR/users/users.db"
V2RAY_CONFIG="$V2RAY_DIR/v2ray/config.json"

# Config Files
DNSTT_INFO_FILE="$DB_DIR/dnstt_info.conf"
DNS2TCP_INFO_FILE="$DB_DIR/dns2tcp_info.conf"
V2RAY_INFO_FILE="$DB_DIR/v2ray_info.conf"
DNS_INFO_FILE="$DB_DIR/dns_info.conf"

# Other Protocols
BADVPN_BUILD_DIR="/root/badvpn-build"
UDP_CUSTOM_DIR="/root/udp"
ZIVPN_DIR="/etc/zivpn"
BACKUP_DIR="$DB_DIR/backups"
LOGS_DIR="$DB_DIR/logs"
CONFIG_DIR="$DB_DIR/config"

# Service Files
DNSTT_SERVICE="/etc/systemd/system/dnstt.service"
DNSTT5300_SERVICE="/etc/systemd/system/dnstt-5300.service"
DNS2TCP53_SERVICE="/etc/systemd/system/dns2tcp-53.service"
DNS2TCP5300_SERVICE="/etc/systemd/system/dns2tcp-5300.service"
V2RAY_SERVICE="/etc/systemd/system/v2ray-dnstt.service"
BADVPN_SERVICE="/etc/systemd/system/badvpn.service"
UDP_CUSTOM_SERVICE="/etc/systemd/system/udp-custom.service"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
NGINX_CONFIG="/etc/nginx/sites-available/default"
VOLTRONPROXY_SERVICE="/etc/systemd/system/voltronproxy.service"
ZIVPN_SERVICE="/etc/systemd/system/zivpn.service"
LIMITER_SERVICE="/etc/systemd/system/voltrontech-limiter.service"
TRAFFIC_SERVICE="/etc/systemd/system/voltron-traffic.service"

# Binary Locations
DNSTT_BIN="/usr/local/bin/dnstt-server"
DNS2TCP_BIN="/usr/local/bin/dns2tcp-server"
V2RAY_BIN="/usr/local/bin/xray"
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
UDP_CUSTOM_BIN="$UDP_CUSTOM_DIR/udp-custom"
VOLTRONPROXY_BIN="/usr/local/bin/voltronproxy"
ZIVPN_BIN="/usr/local/bin/zivpn"
LIMITER_SCRIPT="/usr/local/bin/voltrontech-limiter.sh"
TRAFFIC_SCRIPT="/usr/local/bin/voltron-traffic.sh"

# Ports
DNS_PORT=53
DNS2_PORT=5300
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
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $DNS2TCP_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
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
    # Get IP
    if [ ! -f "$IP_CACHE_FILE" ] || [ $(( $(date +%s) - $(stat -c %Y "$IP_CACHE_FILE" 2>/dev/null || echo 0) )) -gt 3600 ]; then
        curl -s -4 icanhazip.com > "$IP_CACHE_FILE" 2>/dev/null || echo "Unknown" > "$IP_CACHE_FILE"
    fi
    IP=$(cat "$IP_CACHE_FILE")
    
    # Get location and ISP
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
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v3.0 🔥                    ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • DNS2TCP • V2RAY • MTU 1800 ULTIMATE      ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    if [ "$current_mtu" -eq 1800 ]; then
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_YELLOW}⚡ MTU 1800 ULTIMATE ACTIVE - ISP sees 512!${C_PURPLE}${C_RESET}"
    fi
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== MTU 1800 ULTIMATE OPTIMIZATION ==========
apply_mtu_1800_optimization() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 MTU 1800 ULTIMATE OPTIMIZATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # ========== 1. TCP STACK OPTIMIZATION ==========
    echo -e "\n${C_GREEN}[1/7] Configuring TCP stack for MTU 1800...${C_RESET}"
    
    cat >> /etc/sysctl.conf <<EOF

# ===== VOLTRON TECH MTU 1800 ULTIMATE OPTIMIZATION =====
# TCP Window Scaling
net.ipv4.tcp_window_scaling = 1

# TCP Buffer Sizes (optimized for MTU 1800)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP Congestion Control (BBR for maximum throughput)
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# MTU Probing (essential for 1800)
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1760  # 1800 - 40
net.ipv4.tcp_mtu_probe_floor = 48

# TCP Advanced Settings for High MTU
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Network Limits (Ultra)
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
EOF

    sysctl -p >/dev/null 2>&1

    # ========== 2. INTERFACE OPTIMIZATION ==========
    echo -e "${C_GREEN}[2/7] Optimizing network interface for MTU 1800...${C_RESET}"
    
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$iface" ]; then
        # Set MTU on interface
        ip link set dev $iface mtu 1800 2>/dev/null
        
        # Increase queue length (essential for high MTU)
        ip link set dev $iface txqueuelen 50000 2>/dev/null
        
        # Disable offloading for better control
        ethtool -K $iface tx off sg off tso off gso off gro off lro off 2>/dev/null
        
        # Increase ring buffers
        ethtool -G $iface rx 8192 tx 8192 2>/dev/null
        
        echo -e "      • Interface: ${C_CYAN}$iface${C_RESET}"
        echo -e "      • MTU set: ${C_CYAN}1800${C_RESET}"
        echo -e "      • Queue length: ${C_CYAN}50000${C_RESET}"
        echo -e "      • Ring buffers: ${C_CYAN}8192${C_RESET}"
    fi

    # ========== 3. DNSTT SERVICE OPTIMIZATION ==========
    echo -e "${C_GREEN}[3/7] Optimizing DNSTT services for MTU 1800...${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        # Update DNSTT services to use MTU 1800
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" "$DNSTT_SERVICE"
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" "$DNSTT5300_SERVICE" 2>/dev/null
        
        systemctl daemon-reload
        systemctl restart dnstt.service dnstt-5300.service 2>/dev/null
        
        echo -e "      • DNSTT services updated to MTU 1800"
    fi

    # ========== 4. IPTABLES MSS CLAMPING ==========
    echo -e "${C_GREEN}[4/7] Adding iptables MSS clamping...${C_RESET}"
    
    # Clear existing rules
    iptables -t mangle -F 2>/dev/null
    
    # Add MSS clamping for all TCP traffic
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760
    iptables -t mangle -A INPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760
    
    echo -e "      • MSS clamped to 1760 (1800 - 40)"

    # ========== 5. BUFFER SIZE OPTIMIZATION ==========
    echo -e "${C_GREEN}[5/7] Setting ultra buffer size (512MB)...${C_RESET}"
    
    local buffer_size=536870912  # 512MB
    
    cat > /etc/sysctl.d/99-voltron-mtu1800.conf <<EOF
# VOLTRON TECH MTU 1800 ULTRA BUFFERS
net.core.rmem_max = $buffer_size
net.core.wmem_max = $buffer_size
net.ipv4.tcp_rmem = 4096 $((buffer_size / 4)) $buffer_size
net.ipv4.tcp_wmem = 4096 $((buffer_size / 4)) $buffer_size
EOF
    
    sysctl -p /etc/sysctl.d/99-voltron-mtu1800.conf 2>/dev/null

    # ========== 6. PERSISTENT RULES ==========
    echo -e "${C_GREEN}[6/7] Making iptables rules persistent...${C_RESET}"
    
    # Install iptables-persistent if available
    if command -v apt &>/dev/null; then
        apt install -y iptables-persistent 2>/dev/null
    fi
    
    # Save iptables rules
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.up.rules 2>/dev/null
    fi

    # ========== 7. VERIFICATION ==========
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ MTU 1800 ULTIMATE OPTIMIZATION COMPLETE!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_YELLOW}📌 ISP PERSPECTIVE:${C_RESET}"
    echo -e "     • ISP sees: ${C_GREEN}MTU 512${C_RESET} (via DNS queries)"
    echo -e "     • ISP allows: ${C_GREEN}✓${C_RESET}"
    echo ""
    echo -e "  ${C_YELLOW}📌 VPS PERSPECTIVE:${C_RESET}"
    echo -e "     • Actual MTU: ${C_GREEN}1800${C_RESET}"
    echo -e "     • MSS: ${C_GREEN}1760${C_RESET}"
    echo -e "     • Buffer: ${C_GREEN}512MB${C_RESET}"
    echo -e "     • Queue length: ${C_GREEN}50000${C_RESET}"
    echo -e "     • TCP Window Scaling: ${C_GREEN}Enabled${C_RESET}"
    echo -e "     • MSS Clamping: ${C_GREEN}Active (1760)${C_RESET}"
    echo ""
    echo -e "  ${C_YELLOW}📌 EXPECTED PERFORMANCE:${C_RESET}"
    echo -e "     • Speed: ${C_GREEN}30-40 Mbps${C_RESET}"
    echo -e "     • Packet loss: ${C_GREEN}Minimal${C_RESET}"
    echo -e "     • Stability: ${C_GREEN}High${C_RESET}"
    echo ""
    echo -e "  ${C_YELLOW}📌 VERIFICATION COMMANDS:${C_RESET}"
    echo -e "     • Check interface MTU: ${C_CYAN}ip link show $iface | grep mtu${C_RESET}"
    echo -e "     • Check TCP settings: ${C_CYAN}sysctl net.ipv4.tcp_base_mss${C_RESET}"
    echo -e "     • Check iptables MSS: ${C_CYAN}iptables -t mangle -L -v${C_RESET}"
    echo -e "     • Check DNSTT: ${C_CYAN}systemctl status dnstt.service${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
}

# ========== MTU SELECTION ==========
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 SELECT MTU${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "  ${C_GREEN}[01]${C_RESET} MTU 512   - ⚡⚡⚡ ULTRA BOOST MODE (512MB buffers)"
    echo -e "  ${C_GREEN}[02]${C_RESET} MTU 800   - ⚡⚡ HYPER BOOST MODE"
    echo -e "  ${C_GREEN}[03]${C_RESET} MTU 1000  - ⚡⚡ SUPER BOOST MODE"
    echo -e "  ${C_GREEN}[04]${C_RESET} MTU 1200  - ⚡⚡ MEGA BOOST MODE"
    echo -e "  ${C_GREEN}[05]${C_RESET} MTU 1500  - ⚡⚡ TURBO BOOST MODE"
    echo -e "  ${C_GREEN}[06]${C_RESET} MTU 1800  - 🔥 ULTIMATE MODE (FOOLS ISP! ISP sees 512)"
    echo -e "  ${C_GREEN}[07]${C_RESET} Auto-detect optimal MTU"
    echo ""
    echo -e "${C_YELLOW}NOTE: MTU 1800 SPECIAL MODE - ISP sees MTU 512, but VPS uses MTU 1800!${C_RESET}"
    echo ""
    
    local mtu_choice
    safe_read "👉 Select MTU option [01-07] (default 05): " mtu_choice
    mtu_choice=${mtu_choice:-05}
    
    case $mtu_choice in
        01|1) MTU=512 ;;
        02|2) MTU=800 ;;
        03|3) MTU=1000 ;;
        04|4) MTU=1200 ;;
        05|5) MTU=1500 ;;
        06|6) 
            MTU=1800
            apply_mtu_1800_optimization
            return
            ;;
        07|7) 
            echo -e "${C_YELLOW}Detecting optimal MTU...${C_RESET}"
            MTU=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
            echo -e "${C_GREEN}Optimal MTU: $MTU${C_RESET}"
            ;;
        *) MTU=1500 ;;
    esac
    
    # Save MTU to config file
    mkdir -p "$CONFIG_DIR"
    echo "$MTU" > "$CONFIG_DIR/mtu"
    echo -e "${C_GREEN}✅ MTU $MTU selected${C_RESET}"
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

# ========== VOLTRON TECH BOOSTER ==========
install_voltron_booster() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 VOLTRON TECH ULTIMATE BOOSTER${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"

    # Enable BBR
    echo -e "\n${C_GREEN}🔧 Enabling BBR Congestion Control...${C_RESET}"
    if ! lsmod | grep -q bbr; then
        modprobe tcp_bbr 2>/dev/null || echo -e "${C_YELLOW}⚠️ Could not load BBR module, continuing...${C_RESET}"
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null || true
    fi

    cat >> /etc/sysctl.conf <<EOF
# VOLTRON TECH ULTIMATE BOOSTER - BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p 2>/dev/null || echo -e "${C_YELLOW}⚠️ Could not apply sysctl settings, continuing...${C_RESET}"
    echo -e "${C_GREEN}✅ BBR enabled successfully${C_RESET}"

    # TCP Buffer Optimization
    echo -e "\n${C_GREEN}📊 Optimizing TCP Buffers for MAXIMUM SPEED...${C_RESET}"
    cat >> /etc/sysctl.conf <<EOF
# VOLTRON TECH ULTIMATE BOOSTER - TCP Buffers
net.core.rmem_max = 536870912
net.core.wmem_max = 536870912
net.ipv4.tcp_rmem = 4096 87380 536870912
net.ipv4.tcp_wmem = 4096 65536 536870912
net.core.netdev_max_backlog = 20000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
EOF
    sysctl -p 2>/dev/null || echo -e "${C_YELLOW}⚠️ Could not apply sysctl settings, continuing...${C_RESET}"
    echo -e "${C_GREEN}✅ TCP Buffers optimized!${C_RESET}"

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ VOLTRON TECH ULTIMATE BOOSTER INSTALLED!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
}

# ========== SSH USER MANAGEMENT ==========
create_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    
    local username
    safe_read "👉 Enter username: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ User already exists.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local password
    safe_read "🔑 Enter password: " password
    
    local days
    safe_read "🗓️ Expiry (days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local limit
    safe_read "📶 Connection limit: " limit
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local traffic_limit
    safe_read "📊 Traffic limit (GB) [0=unlimited]: " traffic_limit
    traffic_limit=${traffic_limit:-0}
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    useradd -m -s /usr/sbin/nologin "$username"
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$traffic_limit:0" >> "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User '$username' created successfully!${C_RESET}"
    echo -e "  Expires: $expire_date"
    echo -e "  Limit: $limit connections"
    echo -e "  Traffic: $traffic_limit GB"
    safe_read "" dummy
}

delete_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Delete User ---${C_RESET}"
    
    local username
    safe_read "👉 Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "\n${C_RED}❌ User not found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    local confirm
    safe_read "Confirm delete? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    
    killall -u "$username" 2>/dev/null
    userdel -r "$username" 2>/dev/null
    sed -i "/^$username:/d" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User deleted${C_RESET}"
    safe_read "" dummy
}

list_users() {
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
    
    printf "${C_BOLD}%-15s | %-12s | %-8s | %-20s | %-10s${C_RESET}\n" "USERNAME" "EXPIRY" "LIMIT" "TRAFFIC" "STATUS"
    echo -e "${C_CYAN}─────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        [[ -z "$user" ]] && continue
        
        online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        
        # Format traffic
        if [[ -z "$traffic_limit" ]] || [[ "$traffic_limit" == "0" ]]; then
            traffic_disp="${traffic_used}GB/∞"
        else
            percent=$(echo "scale=1; $traffic_used * 100 / $traffic_limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${traffic_used}/$traffic_limit GB ($percent%)"
        fi
        
        # Check status
        if ! id "$user" &>/dev/null; then
            status="${C_RED}NO USER${C_RESET}"
        elif passwd -S "$user" 2>/dev/null | grep -q " L "; then
            status="${C_YELLOW}LOCKED${C_RESET}"
        elif [[ "$(date -d "$expiry" +%s 2>/dev/null)" -lt "$(date +%s)" ]]; then
            status="${C_RED}EXPIRED${C_RESET}"
        elif [ "$traffic_limit" != "0" ] && [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
            status="${C_RED}LIMIT${C_RESET}"
        else
            status="${C_GREEN}ACTIVE${C_RESET}"
        fi
        
        printf "%-15s | %-12s | %-8s | %-20s | %s\n" \
            "$user" "$expiry" "$online/$limit" "$traffic_disp" "$status"
    done < "$DB_FILE"
    
    echo ""
    safe_read "" dummy
}

lock_user() {
    local username
    safe_read "👉 Username: " username
    usermod -L "$username"
    echo -e "\n${C_GREEN}✅ User locked${C_RESET}"
    safe_read "" dummy
}

unlock_user() {
    local username
    safe_read "👉 Username: " username
    usermod -U "$username"
    echo -e "\n${C_GREEN}✅ User unlocked${C_RESET}"
    safe_read "" dummy
}

renew_user() {
    local username
    safe_read "👉 Username: " username
    
    local days
    safe_read "📆 Additional days: " days
    
    local new_expiry=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expiry" "$username"
    
    local line=$(grep "^$username:" "$DB_FILE")
    local pass=$(echo "$line" | cut -d: -f2)
    local limit=$(echo "$line" | cut -d: -f4)
    local traffic_limit=$(echo "$line" | cut -d: -f5)
    local traffic_used=$(echo "$line" | cut -d: -f6)
    
    sed -i "s/^$username:.*/$username:$pass:$new_expiry:$limit:$traffic_limit:$traffic_used/" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User renewed until $new_expiry${C_RESET}"
    safe_read "" dummy
}

cleanup_expired() {
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

# ========== DNSTT FUNCTIONS ==========
download_dnstt_binary() {
    local arch=$(uname -m)
    local success=0
    
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o /tmp/dnstt.tar.gz "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-amd64-20240101.tar.gz"
        if [ -f /tmp/dnstt.tar.gz ] && [ -s /tmp/dnstt.tar.gz ]; then
            cd /tmp
            tar -xzf dnstt.tar.gz
            if [ -f /tmp/server_linux_amd64 ]; then
                cp /tmp/server_linux_amd64 "$DNSTT_BIN"
                success=1
            fi
            rm -f /tmp/dnstt.tar.gz
        fi
    elif [[ "$arch" == "aarch64" ]]; then
        curl -L -o /tmp/dnstt.tar.gz "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-arm64-20240101.tar.gz"
        if [ -f /tmp/dnstt.tar.gz ] && [ -s /tmp/dnstt.tar.gz ]; then
            cd /tmp
            tar -xzf dnstt.tar.gz
            if [ -f /tmp/server_linux_arm64 ]; then
                cp /tmp/server_linux_arm64 "$DNSTT_BIN"
                success=1
            fi
            rm -f /tmp/dnstt.tar.gz
        fi
    fi
    
    chmod +x "$DNSTT_BIN" 2>/dev/null
    return $success
}

install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is already installed.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Free port 53
    echo -e "\n${C_BLUE}[1/6] Freeing port 53...${C_RESET}"
    systemctl stop systemd-resolved 2>/dev/null
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    
    # Download binary
    echo -e "${C_BLUE}[2/6] Downloading DNSTT binary...${C_RESET}"
    if ! download_dnstt_binary; then
        echo -e "\n${C_RED}❌ Failed to download DNSTT binary${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Generate keys
    echo -e "${C_BLUE}[3/6] Generating keys...${C_RESET}"
    mkdir -p "$DNSTT_KEYS_DIR"
    "$DNSTT_BIN" -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null
    
    # Get MTU
    echo -e "${C_BLUE}[4/6] Selecting MTU...${C_RESET}"
    mtu_selection_during_install
    
    # DNS Configuration
    echo -e "\n${C_BLUE}[5/6] DNS Configuration:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    local ns_record_id=""
    local tunnel_record_id=""
    local public_key=$(cat "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null)
    
    if [ "$dns_choice" == "1" ]; then
        local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
        local ns="ns-$rand"
        local tun="tun-$rand"
        
        echo -e "${C_BLUE}Creating Cloudflare records...${C_RESET}"
        local ip=$(curl -s ifconfig.me)
        ns_record_id=$(create_cloudflare_record "A" "$ns" "$ip")
        
        if [ -n "$ns_record_id" ]; then
            tunnel_record_id=$(create_cloudflare_record "NS" "$tun" "$ns.$DOMAIN")
            domain="$tun.$DOMAIN"
            echo -e "${C_GREEN}✅ Domain created: $domain${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ Cloudflare failed. Using manual mode.${C_RESET}"
            dns_choice="2"
        fi
    fi
    
    if [ "$dns_choice" == "2" ] || [ -z "$domain" ]; then
        read -p "Enter tunnel domain: " domain
    fi
    
    # Create services
    echo -e "\n${C_BLUE}[6/6] Creating services...${C_RESET}"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
ExecStart=$DNSTT_BIN -udp :$DNS_PORT -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $domain 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    cat > "$DNSTT5300_SERVICE" <<EOF
[Unit]
Description=DNSTT Server (Port 5300)
After=network.target

[Service]
Type=simple
ExecStart=$DNSTT_BIN -udp :$DNS2_PORT -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $domain 127.0.0.1:22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service dnstt-5300.service
    systemctl start dnstt.service dnstt-5300.service
    
    # Save info
    cat > "$DNSTT_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
PUBLIC_KEY="$public_key"
MTU="$MTU"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$domain${C_RESET}"
    echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$public_key${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}        ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ SAVE THIS PUBLIC KEY! You'll need it for clients.${C_RESET}"
    safe_read "" dummy
}

uninstall_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNSTT...${C_RESET}"
    
    systemctl stop dnstt.service dnstt-5300.service 2>/dev/null
    systemctl disable dnstt.service dnstt-5300.service 2>/dev/null
    rm -f "$DNSTT_SERVICE" "$DNSTT5300_SERVICE"
    rm -f "$DNSTT_BIN"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_INFO_FILE"
    
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNSTT uninstalled${C_RESET}"
    safe_read "" dummy
}

show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNSTT_INFO_FILE" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    source "$DNSTT_INFO_FILE"
    
    if systemctl is-active dnstt.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Note:          ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    
    echo -e "\n  Services:"
    systemctl is-active dnstt.service &>/dev/null && echo -e "    • dnstt.service: ${C_GREEN}active${C_RESET}" || echo -e "    • dnstt.service: ${C_RED}inactive${C_RESET}"
    systemctl is-active dnstt-5300.service &>/dev/null && echo -e "    • dnstt-5300.service: ${C_GREEN}active${C_RESET}" || echo -e "    • dnstt-5300.service: ${C_RED}inactive${C_RESET}"
    
    safe_read "" dummy
}

# ========== DNS2TCP FUNCTIONS ==========
install_dns2tcp() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNS2TCP INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNS2TCP53_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNS2TCP is already installed.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Install dependencies
    echo -e "\n${C_BLUE}[1/6] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL dns2tcp screen lsof
    
    # Configure systemd-resolved
    echo -e "${C_BLUE}[2/6] Configuring systemd-resolved...${C_RESET}"
    cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup 2>/dev/null
    cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    
    # Create directories
    echo -e "${C_BLUE}[3/6] Creating directories...${C_RESET}"
    mkdir -p /root/dns2tcp
    mkdir -p /var/empty/dns2tcp
    
    # Create user
    if ! id "ashtunnel" &>/dev/null; then
        useradd -r -s /bin/false -d /var/empty/dns2tcp ashtunnel
    fi
    
    # Get MTU
    echo -e "${C_BLUE}[4/6] Selecting MTU...${C_RESET}"
    mtu_selection_during_install
    
    # DNS Configuration
    echo -e "\n${C_BLUE}[5/6] DNS Configuration:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    local key=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
    local ns_record_id=""
    local tunnel_record_id=""
    
    if [ "$dns_choice" == "1" ]; then
        local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
        local ns="ns2-$rand"
        local tun="tun2-$rand"
        
        echo -e "${C_BLUE}Creating Cloudflare records...${C_RESET}"
        local ip=$(curl -s ifconfig.me)
        ns_record_id=$(create_cloudflare_record "A" "$ns" "$ip")
        
        if [ -n "$ns_record_id" ]; then
            tunnel_record_id=$(create_cloudflare_record "NS" "$tun" "$ns.$DOMAIN")
            domain="$tun.$DOMAIN"
            echo -e "${C_GREEN}✅ Domain created: $domain${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ Cloudflare failed. Using manual mode.${C_RESET}"
            dns_choice="2"
        fi
    fi
    
    if [ "$dns_choice" == "2" ] || [ -z "$domain" ]; then
        read -p "Enter tunnel domain: " domain
    fi
    
    # Target port
    while true; do
        read -p "Target port (SSH default 22): " target_port
        target_port=${target_port:-22}
        if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
            break
        fi
    done
    
    # Create configs
    cat > /root/dns2tcp/dns2tcp-53.conf <<EOF
listen = 0.0.0.0
port = 53
user = ashtunnel
chroot = /var/empty/dns2tcp/
domain = $domain
key = $key
resources = ssh:127.0.0.1:$target_port
EOF

    cat > /root/dns2tcp/dns2tcp-5300.conf <<EOF
listen = 0.0.0.0
port = 5300
user = ashtunnel
chroot = /var/empty/dns2tcp/
domain = $domain
key = $key
resources = ssh:127.0.0.1:$target_port
EOF

    # Create services
    echo -e "${C_BLUE}[6/6] Creating services...${C_RESET}"
    
    cat > "$DNS2TCP53_SERVICE" <<EOF
[Unit]
Description=DNS2TCP Server (Port 53)
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/dns2tcp
ExecStart=/usr/bin/dns2tcpd -d 1 -F -f /root/dns2tcp/dns2tcp-53.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    cat > "$DNS2TCP5300_SERVICE" <<EOF
[Unit]
Description=DNS2TCP Server (Port 5300)
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/dns2tcp
ExecStart=/usr/bin/dns2tcpd -d 1 -F -f /root/dns2tcp/dns2tcp-5300.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Configure resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    
    systemctl daemon-reload
    systemctl enable dns2tcp-53.service dns2tcp-5300.service
    systemctl start dns2tcp-53.service dns2tcp-5300.service
    
    # Save info
    cat > "$DNS2TCP_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
KEY="$key"
TARGET_PORT="$target_port"
MTU="$MTU"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNS2TCP INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$domain${C_RESET}"
    echo -e "  ${C_CYAN}Key:${C_RESET}           ${C_YELLOW}$key${C_RESET}"
    echo -e "  ${C_CYAN}Target Port:${C_RESET}   ${C_YELLOW}$target_port${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}        ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ SAVE THIS KEY! You'll need it for clients.${C_RESET}"
    safe_read "" dummy
}

uninstall_dns2tcp() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNS2TCP...${C_RESET}"
    
    systemctl stop dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    systemctl disable dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    rm -f "$DNS2TCP53_SERVICE" "$DNS2TCP5300_SERVICE"
    rm -f "$DNS2TCP_BIN"
    rm -rf /root/dns2tcp
    rm -f "$DNS2TCP_INFO_FILE"
    
    # Restore resolv.conf
    if [ -f /etc/resolv.conf.backup ]; then
        cp /etc/resolv.conf.backup /etc/resolv.conf
    fi
    
    if [ -f "$DNS2TCP_INFO_FILE" ]; then
        source "$DNS2TCP_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNS2TCP uninstalled${C_RESET}"
    safe_read "" dummy
}

show_dns2tcp_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNS2TCP DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNS2TCP_INFO_FILE" ]; then
        echo -e "${C_YELLOW}DNS2TCP is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    source "$DNS2TCP_INFO_FILE"
    
    if systemctl is-active dns2tcp-53.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  Key:           ${C_YELLOW}$KEY${C_RESET}"
    echo -e "  Target Port:   ${C_YELLOW}$TARGET_PORT${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Note:          ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    
    echo -e "\n  Services:"
    systemctl is-active dns2tcp-53.service &>/dev/null && echo -e "    • dns2tcp-53.service: ${C_GREEN}active${C_RESET}" || echo -e "    • dns2tcp-53.service: ${C_RED}inactive${C_RESET}"
    systemctl is-active dns2tcp-5300.service &>/dev/null && echo -e "    • dns2tcp-5300.service: ${C_GREEN}active${C_RESET}" || echo -e "    • dns2tcp-5300.service: ${C_RED}inactive${C_RESET}"
    
    safe_read "" dummy
}

# ========== V2RAY over DNSTT FUNCTIONS ==========
generate_uuid() {
    uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s%N | md5sum | cut -c1-8)-$(date +%s%N | md5sum | cut -c1-4)-4$(date +%s%N | md5sum | cut -c1-3)-$(date +%s%N | md5sum | cut -c1-4)-$(date +%s%N | md5sum | cut -c1-12)"
}

generate_v2ray_json() {
    local username=$1
    local uuid=$2
    local protocol=$3
    local password=$4
    
    case $protocol in
        vmess)
            local vmess_json='{
  "v": "2",
  "ps": "'$username'",
  "add": "'$DOMAIN'",
  "port": "'$V2RAY_PORT'",
  "id": "'$uuid'",
  "aid": "0",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": ""
}'
            echo "$vmess_json" | jq . 2>/dev/null || echo "$vmess_json"
            echo ""
            echo -e "${C_CYAN}VMess Link:${C_RESET}"
            echo "vmess://$(echo -n "$vmess_json" | base64 -w 0 2>/dev/null || echo -n "$vmess_json" | base64)"
            ;;
        vless)
            echo -e "${C_CYAN}VLESS Config:${C_RESET}"
            echo "  Address: $DOMAIN"
            echo "  Port: $((V2RAY_PORT+1))"
            echo "  UUID: $uuid"
            echo "  Encryption: none"
            ;;
        trojan)
            echo -e "${C_CYAN}Trojan Config:${C_RESET}"
            echo "  Address: $DOMAIN"
            echo "  Port: $((V2RAY_PORT+2))"
            echo "  Password: $password"
            ;;
    esac
}

install_v2ray_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           🚀 V2RAY over DNSTT INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$V2RAY_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ V2RAY over DNSTT is already installed.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Check if DNSTT is installed
    if [ ! -f "$DNSTT_SERVICE" ]; then
        echo -e "\n${C_YELLOW}⚠️ DNSTT not found. Installing DNSTT first...${C_RESET}"
        install_dnstt
    fi
    
    # Install Xray
    echo -e "\n${C_BLUE}[1/4] Installing Xray...${C_RESET}"
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
    
    # Create directories
    echo -e "${C_BLUE}[2/4] Creating directories...${C_RESET}"
    mkdir -p "$V2RAY_DIR"/{v2ray,users}
    
    # Get MTU
    echo -e "${C_BLUE}[3/4] Selecting MTU...${C_RESET}"
    mtu_selection_during_install
    
    # Create V2Ray config
    echo -e "${C_BLUE}[4/4] Creating V2Ray configuration...${C_RESET}"
    cat > "$V2RAY_CONFIG" <<EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "port": $V2RAY_PORT,
            "protocol": "vmess",
            "settings": {"clients": []},
            "tag": "vmess"
        },
        {
            "port": $((V2RAY_PORT+1)),
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "tag": "vless"
        },
        {
            "port": $((V2RAY_PORT+2)),
            "protocol": "trojan",
            "settings": {"clients": []},
            "tag": "trojan"
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF

    # Create service
    cat > "$V2RAY_SERVICE" <<EOF
[Unit]
Description=V2RAY over DNSTT
After=network.target dnstt.service
Wants=dnstt.service

[Service]
Type=simple
ExecStart=$V2RAY_BIN run -config $V2RAY_CONFIG
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable v2ray-dnstt.service
    systemctl start v2ray-dnstt.service
    
    # Save info
    cat > "$V2RAY_INFO_FILE" <<EOF
VMESS_PORT="$V2RAY_PORT"
VLESS_PORT="$((V2RAY_PORT+1))"
TROJAN_PORT="$((V2RAY_PORT+2))"
MTU="$MTU"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ V2RAY over DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}VMess Port:${C_RESET}   ${C_YELLOW}$V2RAY_PORT${C_RESET}"
    echo -e "  ${C_CYAN}VLESS Port:${C_RESET}   ${C_YELLOW}$((V2RAY_PORT+1))${C_RESET}"
    echo -e "  ${C_CYAN}Trojan Port:${C_RESET}  ${C_YELLOW}$((V2RAY_PORT+2))${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}          ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}       ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}Use V2Ray User Management to add users${C_RESET}"
    safe_read "" dummy
}

uninstall_v2ray_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling V2RAY over DNSTT...${C_RESET}"
    
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f "$V2RAY_SERVICE"
    rm -rf "$V2RAY_DIR"
    rm -f "$V2RAY_INFO_FILE"
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ V2RAY over DNSTT uninstalled${C_RESET}"
    safe_read "" dummy
}

show_v2ray_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🚀 V2RAY over DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_INFO_FILE" ]; then
        echo -e "${C_YELLOW}V2RAY over DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    source "$V2RAY_INFO_FILE"
    
    if systemctl is-active v2ray-dnstt.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  VMess Port:    ${C_YELLOW}$VMESS_PORT${C_RESET}"
    echo -e "  VLESS Port:    ${C_YELLOW}$VLESS_PORT${C_RESET}"
    echo -e "  Trojan Port:   ${C_YELLOW}$TROJAN_PORT${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Note:          ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    
    local user_count=$(wc -l < "$V2RAY_USERS_DB" 2>/dev/null || echo 0)
    echo -e "  Total Users:   ${C_YELLOW}$user_count${C_RESET}"
    
    safe_read "" dummy
}

# ========== V2RAY USER MANAGEMENT ==========
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
    uuid=$(generate_uuid)
    password=""
    
    if [ "$protocol" == "trojan" ]; then
        password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
    fi
    
    # Save to database
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
    echo ""
    
    echo -e "${C_CYAN}JSON Configuration:${C_RESET}"
    generate_v2ray_json "$username" "$uuid" "$protocol" "$password"
    
    echo ""
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
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
    
    printf "${C_BOLD}%-15s %-8s %-36s %-20s %-12s %-10s${C_RESET}\n" "USERNAME" "PROTO" "UUID" "TRAFFIC" "EXPIRY" "STATUS"
    echo -e "${C_CYAN}─────────────────────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user uuid pass proto limit used expiry status; do
        [[ -z "$user" ]] && continue
        
        # Format traffic
        if [ "$limit" == "0" ]; then
            traffic_disp="${used}GB/∞"
        else
            percent=$(echo "scale=1; $used * 100 / $limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${used}/$limit GB ($percent%)"
        fi
        
        # Short UUID for display
        short_uuid="${uuid:0:8}...${uuid: -8}"
        
        # Status color
        case $status in
            active)  status_disp="${C_GREEN}ACTIVE${C_RESET}" ;;
            locked)  status_disp="${C_YELLOW}LOCKED${C_RESET}" ;;
            expired) status_disp="${C_RED}EXPIRED${C_RESET}" ;;
            *)       status_disp="$status" ;;
        esac
        
        printf "%-15s %-8s %-36s %-20s %-12s %s\n" \
            "$user" "$proto" "$short_uuid" "$traffic_disp" "$expiry" "$status_disp"
    done < "$V2RAY_USERS_DB"
    
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
    
    echo -e "\n${C_CYAN}JSON Configuration:${C_RESET}"
    generate_v2ray_json "$user" "$uuid" "$proto" "$pass"
    
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

# ========== V2RAY MAIN MENU ==========
v2ray_main_menu() {
    while true; do
        clear
        show_banner
        
        if [ -f "$V2RAY_SERVICE" ]; then
            installed_status="${C_GREEN}(installed)${C_RESET}"
        else
            installed_status=""
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🚀 V2RAY over DNSTT $installed_status${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [ -f "$V2RAY_SERVICE" ]; then
            echo -e "  ${C_GREEN}1)${C_RESET} Reinstall V2RAY over DNSTT"
            echo -e "  ${C_GREEN}2)${C_RESET} View Details"
            echo -e "  ${C_GREEN}3)${C_RESET} Restart Service"
            echo -e "  ${C_RED}4)${C_RESET} Uninstall"
            echo ""
            echo -e "  ${C_GREEN}5)${C_RESET} 👤 V2Ray User Management"
            echo -e "  ${C_GREEN}6)${C_RESET} ⚙️ Change MTU"
        else
            echo -e "  ${C_GREEN}1)${C_RESET} Install V2RAY over DNSTT"
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
                1) install_v2ray_dnstt ;;
                2) show_v2ray_details ;;
                3) systemctl restart v2ray-dnstt.service; echo "Restarted"; safe_read "" dummy ;;
                4) uninstall_v2ray_dnstt ;;
                5) v2ray_user_menu ;;
                6) mtu_selection_during_install ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        fi
    done
}

# ========== V2RAY USER MANAGEMENT MENU ==========
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

# ========== OTHER PROTOCOLS ==========
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
    
    echo "$ports" > "$VOLTRONPROXY_CONFIG_FILE"
    echo -e "${C_GREEN}✅ VOLTRON Proxy installed on port(s) $ports${C_RESET}"
    safe_read "" dummy
}

uninstall_voltron_proxy() {
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f "$VOLTRONPROXY_SERVICE" "$VOLTRONPROXY_BIN"
    rm -f "$VOLTRONPROXY_CONFIG_FILE"
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
    
    openssl req -x509 -newkey rsa:4096 -nodes -days 365 -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" -subj "/CN=ZiVPN" 2>/dev/null
    
    read -p "Passwords (comma-separated) [user1,user2]: " passwords
    passwords=${passwords:-user1,user2}
    
    IFS=',' read -ra pass_array <<< "$passwords"
    json_passwords=$(printf '"%s",' "${pass_array[@]}")
    json_passwords="[${json_passwords%,}]"
    
    cat > "$ZIVPN_CONFIG_FILE" <<EOF
{
  "listen": ":$ZIVPN_PORT",
  "cert": "$ZIVPN_CERT_FILE",
  "key": "$ZIVPN_KEY_FILE",
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
ExecStart=$ZIVPN_BIN server -c $ZIVPN_CONFIG_FILE
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

install_dt_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing DT Proxy ---${C_RESET}"
    
    curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash
    safe_read "" dummy
}

uninstall_dt_proxy() {
    rm -f /usr/local/bin/proxy /usr/local/bin/main /usr/local/bin/install_mod
    rm -f /etc/systemd/system/proxy-*.service 2>/dev/null
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DT Proxy uninstalled${C_RESET}"
    safe_read "" dummy
}

check_dt_proxy_status() {
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "${C_BLUE}(installed)${C_RESET}"
    else
        echo ""
    fi
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
    local tun_record_id=$(create_cloudflare_record "NS" "tun" "ns.$DOMAIN")
    local tun2_record_id=$(create_cloudflare_record "NS" "tun2" "ns.$DOMAIN")
    
    echo -e "${C_GREEN}✅ DNS records created!${C_RESET}"
    echo -e "  A:  ns.$DOMAIN → $ip"
    echo -e "  NS: tun.$DOMAIN → ns.$DOMAIN"
    echo -e "  NS: tun2.$DOMAIN → ns.$DOMAIN"
    
    cat > "$DNS_INFO_FILE" <<EOF
NS_RECORD_ID="$ns_record_id"
TUN_RECORD_ID="$tun_record_id"
TUN2_RECORD_ID="$tun2_record_id"
EOF
    
    safe_read "" dummy
}

# ========== PROTOCOL MENU ==========
protocol_menu() {
    while true; do
        clear
        show_banner
        
        local dnstt_status=$(check_service "dnstt")
        local dns2tcp_status=$(check_service "dns2tcp-53")
        local v2ray_status=$(check_service "v2ray-dnstt")
        local badvpn_status=$(check_service "badvpn")
        local udp_status=$(check_service "udp-custom")
        local haproxy_status=$(check_service "haproxy")
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
        echo -e "  ${C_GREEN}4)${C_RESET} DNSTT (Port 53) $dnstt_status"
        echo -e "  ${C_GREEN}5)${C_RESET} DNS2TCP (Port 53) ${C_BLUE}[NEW]${C_RESET} $dns2tcp_status"
        echo -e "  ${C_GREEN}6)${C_RESET} V2RAY over DNSTT ${C_BLUE}[NEW]${C_RESET} $v2ray_status"
        echo -e "  ${C_GREEN}7)${C_RESET} VOLTRON Proxy $voltronproxy_status"
        echo -e "  ${C_GREEN}8)${C_RESET} Nginx Proxy $nginx_status"
        echo -e "  ${C_GREEN}9)${C_RESET} ZiVPN $zivpn_status"
        echo -e "  ${C_GREEN}10)${C_RESET} X-UI Panel $xui_status"
        echo -e "  ${C_GREEN}11)${C_RESET} DT Proxy $(check_dt_proxy_status)"
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
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install DNS2TCP"
                echo -e "  ${C_GREEN}2)${C_RESET} View Details"
                echo -e "  ${C_RED}3)${C_RESET} Uninstall DNS2TCP"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_dns2tcp
                elif [ "$sub" == "2" ]; then show_dns2tcp_details
                elif [ "$sub" == "3" ]; then uninstall_dns2tcp
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            6)
                v2ray_main_menu
                ;;
            7)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_voltron_proxy || uninstall_voltron_proxy
                ;;
            8)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_nginx_proxy || uninstall_nginx_proxy
                ;;
            9)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_zivpn || uninstall_zivpn
                ;;
            10)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_xui_panel || uninstall_xui_panel
                ;;
            11)
                dt_proxy_menu
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== DT PROXY MENU ==========
dt_proxy_menu() {
    while true; do
        clear
        show_banner
        local status=""
        [ -f "/usr/local/bin/main" ] && status="${C_BLUE}(installed)${C_RESET}"
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🚀 DT PROXY MANAGEMENT ${status}${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} Install DT Proxy"
        echo -e "  ${C_GREEN}2)${C_RESET} Launch DT Proxy Menu"
        echo -e "  ${C_RED}3)${C_RESET} Uninstall DT Proxy"
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) install_dt_proxy ;;
            2) 
                if [ -f "/usr/local/bin/main" ]; then
                    clear
                    /usr/local/bin/main
                else
                    echo -e "\n${C_RED}❌ DT Proxy is not installed.${C_RESET}"
                    safe_read "" dummy
                fi
                ;;
            3) uninstall_dt_proxy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== LIMITER SERVICE SETUP ==========
setup_limiter_service() {
    # Already done in create_limiter_service
    :
}

# ========== INITIAL SETUP ==========
initial_setup() {
    echo -e "\n${C_BLUE}🔧 Running initial system setup...${C_RESET}"
    
    detect_os
    detect_package_manager
    detect_service_manager
    detect_firewall
    
    create_directories
    
    cat > "$DB_DIR/cloudflare.conf" <<EOF
CLOUDFLARE_EMAIL="$CLOUDFLARE_EMAIL"
CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID"
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN"
DOMAIN="$DOMAIN"
EOF
    
    create_limiter_service
    create_traffic_monitor
    install_voltron_booster
    
    if [ ! -f "$INSTALL_FLAG_FILE" ]; then
        touch "$INSTALL_FLAG_FILE"
    fi
    
    get_ip_info
}

# ========== UNINSTALL EVERYTHING ==========
uninstall_script() {
    clear
    show_banner
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_RED}           💥 UNINSTALL EVERYTHING${C_RESET}"
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    read -p "Type YES to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "${C_GREEN}Cancelled${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    # Uninstall all protocols
    uninstall_dnstt
    uninstall_dns2tcp
    uninstall_v2ray_dnstt
    uninstall_badvpn
    uninstall_udp_custom
    uninstall_ssl_tunnel
    uninstall_voltron_proxy
    uninstall_nginx_proxy
    uninstall_zivpn
    uninstall_xui_panel
    uninstall_dt_proxy
    
    # Stop services
    systemctl stop voltron-traffic.service voltron-limiter.service 2>/dev/null
    systemctl disable voltron-traffic.service voltron-limiter.service 2>/dev/null
    rm -f "$TRAFFIC_SERVICE" "$LIMITER_SERVICE"
    rm -f "$TRAFFIC_SCRIPT" "$LIMITER_SCRIPT"
    
    # Remove data directory
    rm -rf "$DB_DIR"
    
    # Remove script
    rm -f /usr/local/bin/menu
    
    systemctl daemon-reload
    
    echo -e "${C_GREEN}✅ Everything uninstalled${C_RESET}"
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
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "1" "Create New User" "5" "Unlock User Account"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "2" "Delete User" "6" "List All Managed Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "3" "Edit User Details" "7" "Renew User Account"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "4" "Lock User Account"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "8" "Protocols & Panels" "12" "SSH Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "9" "Backup Users" "13" "Cleanup Expired"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "10" "Restore Users" "14" "MTU Optimization"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "11" "DNS Domain" "15" "DT Proxy"

        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    🔥 DANGER ZONE${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_RED}%2s${C_RESET}) %-28s  ${C_RED}%2s${C_RESET}) %-25s\n" "99" "Uninstall Script" "0" "Exit"

        echo ""
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        
        case $choice in
            1) create_user ;;
            2) delete_user ;;
            3) edit_user ;;
            4) lock_user ;;
            5) unlock_user ;;
            6) list_users ;;
            7) renew_user ;;
            8) protocol_menu ;;
            9) backup_user_data ;;
            10) restore_user_data ;;
            11) generate_cloudflare_dns ;;
            12) 
                echo "SSH Banner menu - to be implemented"
                safe_read "" dummy
                ;;
            13) cleanup_expired ;;
            14) mtu_selection_during_install ;;
            15) dt_proxy_menu ;;
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

# Check for --install-setup flag
if [[ "$1" == "--install-setup" ]]; then
    initial_setup
    exit 0
fi

main_menu
