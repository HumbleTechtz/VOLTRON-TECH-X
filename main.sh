#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 3.1 (FULLY FIXED: All menus + DNS2TCP + V2RAY Localhost)
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
SSH_BANNER_FILE="/etc/voltrontech/banner"

# DNS Protocols Directories
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
V2RAY_KEYS_DIR="$DB_DIR/v2ray-keys"
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
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $V2RAY_KEYS_DIR $DNS2TCP_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    mkdir -p $(dirname "$SSH_BANNER_FILE")
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
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v3.1 🔥                    ║${C_RESET}"
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
    
    echo -e "\n${C_GREEN}[1/7] Configuring TCP stack for MTU 1800...${C_RESET}"
    
    cat >> /etc/sysctl.conf <<EOF

# ===== VOLTRON TECH MTU 1800 ULTIMATE OPTIMIZATION =====
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1760
net.ipv4.tcp_mtu_probe_floor = 48
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
EOF

    sysctl -p >/dev/null 2>&1

    echo -e "${C_GREEN}[2/7] Optimizing network interface for MTU 1800...${C_RESET}"
    
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$iface" ]; then
        ip link set dev $iface mtu 1800 2>/dev/null
        ip link set dev $iface txqueuelen 50000 2>/dev/null
        ethtool -K $iface tx off sg off tso off gso off gro off lro off 2>/dev/null
        ethtool -G $iface rx 8192 tx 8192 2>/dev/null
        
        echo -e "      • Interface: ${C_CYAN}$iface${C_RESET}"
        echo -e "      • MTU set: ${C_CYAN}1800${C_RESET}"
    fi

    echo -e "${C_GREEN}[3/7] Optimizing DNSTT services for MTU 1800...${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" "$DNSTT_SERVICE"
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" "$DNSTT5300_SERVICE" 2>/dev/null
        systemctl daemon-reload
        systemctl restart dnstt.service dnstt-5300.service 2>/dev/null
        echo -e "      • DNSTT services updated to MTU 1800"
    fi

    echo -e "${C_GREEN}[4/7] Adding iptables MSS clamping...${C_RESET}"
    iptables -t mangle -F 2>/dev/null
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760
    iptables -t mangle -A INPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1760

    echo -e "${C_GREEN}[5/7] Setting ultra buffer size (512MB)...${C_RESET}"
    local buffer_size=536870912
    cat > /etc/sysctl.d/99-voltron-mtu1800.conf <<EOF
net.core.rmem_max = $buffer_size
net.core.wmem_max = $buffer_size
net.ipv4.tcp_rmem = 4096 $((buffer_size / 4)) $buffer_size
net.ipv4.tcp_wmem = 4096 $((buffer_size / 4)) $buffer_size
EOF
    sysctl -p /etc/sysctl.d/99-voltron-mtu1800.conf 2>/dev/null

    echo -e "${C_GREEN}[6/7] Making iptables rules persistent...${C_RESET}"
    if command -v apt &>/dev/null; then
        apt install -y iptables-persistent 2>/dev/null
    fi
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.up.rules 2>/dev/null
    fi

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ MTU 1800 ULTIMATE OPTIMIZATION COMPLETE!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
}

# ========== MTU SELECTION ==========
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 SELECT MTU${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "  ${C_GREEN}[01]${C_RESET} MTU 512   - ⚡⚡⚡ ULTRA BOOST MODE"
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

# ========== SSH USER MANAGEMENT (FALCON STYLE) ==========

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
    
    # ========== TRAFFIC LIMIT ==========
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
        
        local traffic_limit_num=${traffic_limit:-0}
        local traffic_used_num=${traffic_used:-0}
        
        local traffic_disp=""
        if [[ "$traffic_limit_num" == "0" ]]; then
            traffic_disp="${traffic_used_num} GB / ∞"
        else
            if command -v bc &>/dev/null; then
                local percent=$(echo "scale=1; $traffic_used_num * 100 / $traffic_limit_num" | bc 2>/dev/null || echo "0")
                traffic_disp="${traffic_used_num} / ${traffic_limit_num} GB (${percent}%)"
            else
                traffic_disp="${traffic_used_num} / ${traffic_limit_num} GB"
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
            elif [[ "$traffic_limit_num" -gt 0 ]] && [[ "$traffic_used_num" -ge "$traffic_limit_num" ]]; then
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

# ========== FALCON DNSTT BINARY DOWNLOAD ==========
download_dnstt_binary() {
    local arch=$(uname -m)
    local success=0
    
    echo -e "${C_BLUE}📥 Downloading Falcon DNSTT binary for $arch...${C_RESET}"
    
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    
    if [[ "$arch" == "x86_64" ]]; then
        echo -e "${C_BLUE}Downloading from dnstt.network...${C_RESET}"
        curl -L -o "$DNSTT_BIN" "https://dnstt.network/dnstt-server-linux-amd64" || {
            echo -e "${C_RED}❌ Failed to download from dnstt.network${C_RESET}"
            return 1
        }
        
    elif [[ "$arch" == "aarch64" ]]; then
        echo -e "${C_BLUE}Downloading from dnstt.network (ARM)...${C_RESET}"
        curl -L -o "$DNSTT_BIN" "https://dnstt.network/dnstt-server-linux-arm64" || {
            echo -e "${C_RED}❌ Failed to download from dnstt.network${C_RESET}"
            return 1
        }
    else
        echo -e "${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return 1
    fi
    
    if [ -f "$DNSTT_BIN" ] && [ -s "$DNSTT_BIN" ]; then
        chmod +x "$DNSTT_BIN"
        success=1
        echo -e "${C_GREEN}✅ Falcon DNSTT binary downloaded successfully!${C_RESET}"
        echo -e "${C_YELLOW}Binary size: $(du -h $DNSTT_BIN | cut -f1)${C_RESET}"
    fi
    
    if [ $success -eq 0 ]; then
        echo -e "${C_RED}❌ Failed to download Falcon DNSTT binary${C_RESET}"
        return 1
    fi
    
    return 0
}

# ========== DNSTT INSTALLATION ==========
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION (SSH)${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is already installed.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}[1/6] Freeing port 53...${C_RESET}"
    systemctl stop systemd-resolved 2>/dev/null
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    
    echo -e "${C_BLUE}[2/6] Downloading Falcon DNSTT binary...${C_RESET}"
    if ! download_dnstt_binary; then
        echo -e "\n${C_RED}❌ Cannot proceed without DNSTT binary${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_BLUE}[3/6] 🔐 Generating cryptographic keys...${C_RESET}"
    mkdir -p "$DNSTT_KEYS_DIR"
    "$DNSTT_BIN" -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub"
    
    if [[ ! -f "$DNSTT_KEYS_DIR/server.key" ]]; then 
        echo -e "${C_RED}❌ Failed to generate keys.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    PUBLIC_KEY=$(cat "$DNSTT_KEYS_DIR/server.pub")
    echo -e "${C_GREEN}✅ Keys generated successfully!${C_RESET}"
    echo -e "${C_YELLOW}Public Key: ${PUBLIC_KEY}${C_RESET}"
    
    echo -e "${C_BLUE}[4/6] Selecting MTU...${C_RESET}"
    mtu_selection_during_install
    
    echo -e "\n${C_BLUE}[5/6] DNS Configuration:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    local ns_record_id=""
    local tunnel_record_id=""
    
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
    
    echo -e "\n${C_BLUE}[6/6] Creating services...${C_RESET}"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server (SSH)
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
Description=DNSTT Server (Port 5300) (SSH)
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
    
    cat > "$DNSTT_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
PUBLIC_KEY="$PUBLIC_KEY"
MTU="$MTU"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNSTT (SSH) INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$domain${C_RESET}"
    echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
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
    echo -e "${C_GREEN}           📡 DNSTT DETAILS (SSH)${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNSTT_INFO_FILE" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    source "$DNSTT_INFO_FILE" 2>/dev/null
    
    local status=""
    if systemctl is-active dnstt.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    
    safe_read "" dummy
}

# ========== DNS2TCP INSTALLATION ==========
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
    
    echo -e "\n${C_BLUE}[1/7] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL dns2tcp screen lsof net-tools
    
    echo -e "\n${C_BLUE}[2/7] Freeing port 53 and 5300...${C_RESET}"
    
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    fuser -k 53/udp 2>/dev/null
    fuser -k 5300/udp 2>/dev/null
    fuser -k 53/tcp 2>/dev/null
    fuser -k 5300/tcp 2>/dev/null
    
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    
    sleep 2
    if ss -lunp | grep -q ':53\s'; then
        echo -e "${C_RED}❌ Port 53 still in use! Please check manually.${C_RESET}"
        ss -lunp | grep ':53\s'
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_GREEN}✅ Ports 53 and 5300 are free${C_RESET}"
    
    echo -e "\n${C_BLUE}[3/7] Opening firewall ports...${C_RESET}"
    check_and_open_firewall_port 53 udp
    check_and_open_firewall_port 5300 udp
    
    echo -e "${C_BLUE}[4/7] Creating directories...${C_RESET}"
    mkdir -p /root/dns2tcp
    mkdir -p /var/empty/dns2tcp
    
    if ! id "ashtunnel" &>/dev/null; then
        useradd -r -s /bin/false -d /var/empty/dns2tcp ashtunnel
    fi
    
    echo -e "${C_BLUE}[5/7] Selecting MTU...${C_RESET}"
    mtu_selection_during_install
    
    echo -e "\n${C_BLUE}[6/7] DNS Configuration:${C_RESET}"
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
    
    while true; do
        read -p "Target port (SSH default 22): " target_port
        target_port=${target_port:-22}
        if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
            break
        fi
    done
    
    echo -e "\n${C_BLUE}[7/7] Creating configuration files...${C_RESET}"
    
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

    echo -e "${C_BLUE}Creating systemd services...${C_RESET}"
    
    cat > "$DNS2TCP53_SERVICE" <<EOF
[Unit]
Description=DNS2TCP Server (Port 53)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dns2tcp
ExecStart=/usr/bin/dns2tcpd -d 1 -F -f /root/dns2tcp/dns2tcp-53.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cat > "$DNS2TCP5300_SERVICE" <<EOF
[Unit]
Description=DNS2TCP Server (Port 5300)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dns2tcp
ExecStart=/usr/bin/dns2tcpd -d 1 -F -f /root/dns2tcp/dns2tcp-5300.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    
    echo -e "\n${C_BLUE}Starting DNS2TCP services...${C_RESET}"
    
    systemctl daemon-reload
    systemctl enable dns2tcp-53.service dns2tcp-5300.service
    
    systemctl start dns2tcp-53.service
    sleep 2
    systemctl start dns2tcp-5300.service
    sleep 2
    
    local status53=$(systemctl is-active dns2tcp-53.service)
    local status5300=$(systemctl is-active dns2tcp-5300.service)
    
    if [ "$status53" == "active" ]; then
        echo -e "${C_GREEN}✅ DNS2TCP (port 53) is RUNNING${C_RESET}"
    else
        echo -e "${C_RED}❌ DNS2TCP (port 53) FAILED to start${C_RESET}"
        echo -e "${C_YELLOW}📌 Error log:${C_RESET}"
        journalctl -u dns2tcp-53.service -n 10 --no-pager
    fi
    
    if [ "$status5300" == "active" ]; then
        echo -e "${C_GREEN}✅ DNS2TCP (port 5300) is RUNNING${C_RESET}"
    else
        echo -e "${C_RED}❌ DNS2TCP (port 5300) FAILED to start${C_RESET}"
        echo -e "${C_YELLOW}📌 Error log:${C_RESET}"
        journalctl -u dns2tcp-5300.service -n 10 --no-pager
    fi
    
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
    echo -e "  ${C_CYAN}Port 53:${C_RESET}        ${C_YELLOW}$status53${C_RESET}"
    echo -e "  ${C_CYAN}Port 5300:${C_RESET}      ${C_YELLOW}$status5300${C_RESET}"
    safe_read "" dummy
}

uninstall_dns2tcp() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNS2TCP...${C_RESET}"
    
    systemctl stop dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    systemctl disable dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    rm -f "$DNS2TCP53_SERVICE" "$DNS2TCP5300_SERVICE"
    rm -rf /root/dns2tcp
    rm -f "$DNS2TCP_INFO_FILE"
    
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
    
    local status53=$(systemctl is-active dns2tcp-53.service 2>/dev/null || echo "inactive")
    local status5300=$(systemctl is-active dns2tcp-5300.service 2>/dev/null || echo "inactive")
    
    echo -e "  ${C_CYAN}Status (53):${C_RESET}   $([ "$status53" == "active" ] && echo "${C_GREEN}● RUNNING${C_RESET}" || echo "${C_RED}● STOPPED${C_RESET}")"
    echo -e "  ${C_CYAN}Status (5300):${C_RESET} $([ "$status5300" == "active" ] && echo "${C_GREEN}● RUNNING${C_RESET}" || echo "${C_RED}● STOPPED${C_RESET}")"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}Key:${C_RESET}           ${C_YELLOW}$KEY${C_RESET}"
    echo -e "  ${C_CYAN}Target Port:${C_RESET}   ${C_YELLOW}$TARGET_PORT${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
    
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
  "add": "127.0.0.1",
  "port": "8000",
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
            echo "  Address: 127.0.0.1"
            echo "  Port: 8000"
            echo "  UUID: $uuid"
            echo "  Encryption: none"
            ;;
        trojan)
            echo -e "${C_CYAN}Trojan Config:${C_RESET}"
            echo "  Address: 127.0.0.1"
            echo "  Port: 8000"
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
    
    if [ ! -f "$DNSTT_BIN" ]; then
        echo -e "\n${C_RED}❌ DNSTT binary not found! Please install DNSTT first.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}[1/6] 🔐 Generating cryptographic keys for V2RAY tunnel...${C_RESET}"
    mkdir -p "$V2RAY_KEYS_DIR"
    "$DNSTT_BIN" -gen-key -privkey-file "$V2RAY_KEYS_DIR/server.key" -pubkey-file "$V2RAY_KEYS_DIR/server.pub"
    
    if [[ ! -f "$V2RAY_KEYS_DIR/server.key" ]]; then 
        echo -e "${C_RED}❌ Failed to generate keys.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    V2RAY_PUBLIC_KEY=$(cat "$V2RAY_KEYS_DIR/server.pub")
    echo -e "${C_GREEN}✅ Keys generated successfully!${C_RESET}"
    echo -e "${C_YELLOW}V2RAY Public Key: ${V2RAY_PUBLIC_KEY}${C_RESET}"
    
    echo -e "\n${C_BLUE}[2/6] DNS Configuration for V2RAY domain:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    local ns_record_id=""
    local tunnel_record_id=""
    
    if [ "$dns_choice" == "1" ]; then
        local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
        local ns="v2ns-$rand"
        local tun="v2tun-$rand"
        
        echo -e "${C_BLUE}Creating Cloudflare records for V2RAY...${C_RESET}"
        local ip=$(curl -s ifconfig.me)
        ns_record_id=$(create_cloudflare_record "A" "$ns" "$ip")
        
        if [ -n "$ns_record_id" ]; then
            tunnel_record_id=$(create_cloudflare_record "NS" "$tun" "$ns.$DOMAIN")
            domain="$tun.$DOMAIN"
            echo -e "${C_GREEN}✅ V2RAY domain created: $domain${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ Cloudflare failed. Using manual mode.${C_RESET}"
            dns_choice="2"
        fi
    fi
    
    if [ "$dns_choice" == "2" ] || [ -z "$domain" ]; then
        read -p "Enter V2RAY tunnel domain: " domain
    fi
    
    echo -e "\n${C_BLUE}[3/6] Selecting MTU for V2RAY tunnel...${C_RESET}"
    mtu_selection_during_install
    
    echo -e "\n${C_BLUE}[4/6] Installing Xray (V2RAY core)...${C_RESET}"
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
    
    echo -e "\n${C_BLUE}[5/6] Creating V2Ray directories...${C_RESET}"
    mkdir -p "$V2RAY_DIR"/{v2ray,users}
    
    echo -e "${C_BLUE}[6/6] Creating V2Ray configuration (localhost only)...${C_RESET}"
    cat > "$V2RAY_CONFIG" <<EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "port": 1080,
            "listen": "127.0.0.1",
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "tag": "vmess"
        },
        {
            "port": 1081,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "tag": "vless"
        },
        {
            "port": 1082,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "tag": "trojan"
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        }
    ]
}
EOF

    cat > "$V2RAY_SERVICE" <<EOF
[Unit]
Description=V2RAY over DNSTT
After=network.target

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
    
    cat > "$V2RAY_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
V2RAY_PUBLIC_KEY="$V2RAY_PUBLIC_KEY"
VMESS_PORT="1080"
VLESS_PORT="1081"
TROJAN_PORT="1082"
MTU="$MTU"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ V2RAY over DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}V2RAY Tunnel Domain:${C_RESET} ${C_YELLOW}$domain${C_RESET}"
    echo -e "  ${C_CYAN}V2RAY Public Key:${C_RESET}   ${C_YELLOW}$V2RAY_PUBLIC_KEY${C_RESET}"
    echo -e "  ${C_CYAN}VMess Port:${C_RESET}          ${C_YELLOW}1080${C_RESET} ${C_GREEN}(localhost)${C_RESET}"
    echo -e "  ${C_CYAN}VLESS Port:${C_RESET}          ${C_YELLOW}1081${C_RESET} ${C_GREEN}(localhost)${C_RESET}"
    echo -e "  ${C_CYAN}Trojan Port:${C_RESET}         ${C_YELLOW}1082${C_RESET} ${C_GREEN}(localhost)${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}                 ${C_YELLOW}$MTU${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    safe_read "" dummy
}

uninstall_v2ray_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling V2RAY over DNSTT...${C_RESET}"
    
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f "$V2RAY_SERVICE"
    rm -rf "$V2RAY_DIR"
    rm -rf "$V2RAY_KEYS_DIR"
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
    
    local status=""
    if systemctl is-active v2ray-dnstt.service &>/dev/null; then
        status="${C_GREEN}● RUNNING${C_RESET}"
    else
        status="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "  Status:        $status"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}$V2RAY_PUBLIC_KEY${C_RESET}"
    echo -e "  VMess Port:    ${C_YELLOW}1080${C_RESET} (localhost)"
    echo -e "  VLESS Port:    ${C_YELLOW}1081${C_RESET} (localhost)"
    echo -e "  Trojan Port:   ${C_YELLOW}1082${C_RESET} (localhost)"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    
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

# ========== V2RAY MAIN MENU ==========
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
        echo -e "${C_BOLD}${C_PURPLE}              🚀 V2RAY over DNSTT $installed_status${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [ -f "$V2RAY_SERVICE" ]; then
            echo -e "  ${C_GREEN}1)${C_RESET} Reinstall V2RAY over DNSTT"
            echo -e "  ${C_GREEN}2)${C_RESET} View Details"
            echo -e "  ${C_GREEN}3)${C_RESET} Restart Service"
            echo -e "  ${C_GREEN}4)${C_RESET} Stop Service"
            echo -e "  ${C_RED}5)${C_RESET} Uninstall"
            echo ""
            echo -e "  ${C_GREEN}6)${C_RESET} 👤 V2Ray User Management"
            echo -e "  ${C_GREEN}7)${C_RESET} ⚙️ Change MTU"
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
                1) 
                    echo -e "\n${C_YELLOW}⚠️ Reinstalling V2RAY over DNSTT...${C_RESET}"
                    uninstall_v2ray_dnstt
                    install_v2ray_dnstt
                    ;;
                2) show_v2ray_details ;;
                3) 
                    systemctl restart v2ray-dnstt.service
                    echo -e "${C_GREEN}✅ Service restarted${C_RESET}"
                    safe_read "" dummy
                    ;;
                4)
                    systemctl stop v2ray-dnstt.service
                    echo -e "${C_YELLOW}🛑 Service stopped${C_RESET}"
                    safe_read "" dummy
                    ;;
                5) 
                    echo -e "\n${C_RED}⚠️ Uninstalling V2RAY over DNSTT...${C_RESET}"
                    uninstall_v2ray_dnstt
                    safe_read "" dummy
                    ;;
                6) v2ray_user_menu ;;
                7) mtu_selection_during_install ;;
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

install_dt_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing DT Proxy ---${C_RESET}"
    
    curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash
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

# ========== DT PROXY MENU ==========
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
                1) 
                    install_dt_proxy
                    safe_read "" dummy
                    ;;
                0) return ;;
                *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
            esac
        else
            case $choice in
                1)
                    echo -e "\n${C_YELLOW}⚠️ Reinstalling DT Proxy...${C_RESET}"
                    uninstall_dt_proxy
                    install_dt_proxy
                    safe_read "" dummy
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
        
        local badvpn_status=$(check_service "badvpn")
        local udp_status=$(check_service "udp-custom")
        local haproxy_status=$(check_service "haproxy")
        local dnstt_status=$(check_service "dnstt")
        local dns2tcp_status=$(check_service "dns2tcp-53")
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
        echo -e "  ${C_GREEN}4)${C_RESET} DNSTT (Port 53) $dnstt_status"
        echo -e "  ${C_GREEN}5)${C_RESET} DNS2TCP (Port 53) $dns2tcp_status"
        echo -e "  ${C_GREEN}6)${C_RESET} V2RAY over DNSTT $v2ray_status"
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
    systemctl stop dnstt.service dnstt-5300.service 2>/dev/null
    systemctl stop dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl stop badvpn.service 2>/dev/null
    systemctl stop udp-custom.service 2>/dev/null
    systemctl stop haproxy 2>/dev/null
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl stop nginx 2>/dev/null
    systemctl stop zivpn.service 2>/dev/null
    systemctl stop voltron-traffic.service voltron-limiter.service 2>/dev/null
    
    # Disable all services
    systemctl disable dnstt.service dnstt-5300.service 2>/dev/null
    systemctl disable dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    systemctl disable badvpn.service 2>/dev/null
    systemctl disable udp-custom.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    systemctl disable voltron-traffic.service voltron-limiter.service 2>/dev/null
    
    # Remove service files
    echo -e "\n${C_BLUE}🗑️ Removing service files...${C_RESET}"
    rm -f "$DNSTT_SERVICE" "$DNSTT5300_SERVICE"
    rm -f "$DNS2TCP53_SERVICE" "$DNS2TCP5300_SERVICE"
    rm -f "$V2RAY_SERVICE"
    rm -f "$BADVPN_SERVICE"
    rm -f "$UDP_CUSTOM_SERVICE"
    rm -f "$VOLTRONPROXY_SERVICE"
    rm -f "$ZIVPN_SERVICE"
    rm -f "$TRAFFIC_SERVICE" "$LIMITER_SERVICE"
    
    # Remove binaries
    echo -e "\n${C_BLUE}🗑️ Removing binaries...${C_RESET}"
    rm -f "$DNSTT_BIN"
    rm -f "$V2RAY_BIN"
    rm -f "$BADVPN_BIN"
    rm -f "$UDP_CUSTOM_BIN"
    rm -f "$VOLTRONPROXY_BIN"
    rm -f "$ZIVPN_BIN"
    rm -f "$LIMITER_SCRIPT" "$TRAFFIC_SCRIPT"
    
    # Remove build directories
    echo -e "\n${C_BLUE}🗑️ Removing build directories...${C_RESET}"
    rm -rf "$BADVPN_BUILD_DIR"
    rm -rf "$UDP_CUSTOM_DIR"
    rm -rf "$ZIVPN_DIR"
    
    # Delete DNS records from Cloudflare
    echo -e "\n${C_BLUE}🗑️ Cleaning up DNS records...${C_RESET}"
    if [ -f "$DNSTT_INFO_FILE" ]; then
        source "$DNSTT_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    if [ -f "$DNS2TCP_INFO_FILE" ]; then
        source "$DNS2TCP_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
        [ -n "$TUN_RECORD_ID" ] && delete_cloudflare_record "$TUN_RECORD_ID"
        [ -n "$TUN2_RECORD_ID" ] && delete_cloudflare_record "$TUN2_RECORD_ID"
    fi
    
    # Remove config directory
    echo -e "\n${C_BLUE}🗑️ Removing configuration and user data...${C_RESET}"
    rm -rf "$DB_DIR"
    
    # Restore resolv.conf
    echo -e "\n${C_BLUE}🌐 Restoring DNS resolver...${C_RESET}"
    chattr -i /etc/resolv.conf 2>/dev/null
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    
    # Remove script
    echo -e "\n${C_BLUE}🗑️ Removing script...${C_RESET}"
    rm -f /usr/local/bin/menu
    rm -f "$0"
    
    # Reload systemd
    echo -e "\n${C_BLUE}🔄 Reloading systemd...${C_RESET}"
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}      ✅ SCRIPT UNINSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "\nPress any key to exit..."
    read -n 1
    exit 0
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

if [[ "$1" == "--install-setup" ]]; then
    initial_setup
    exit 0
fi

main_menu
