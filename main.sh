#!/bin/bash

# ========== VOLTRON TECH X ULTIMATE SCRIPT ==========
# Version: 2.0.3
# Description: Complete VPN Server Management
# Includes: DNSTT, DNS2TCP, V2RAY over DNSTT, Traffic Limits, MTU 1800 Ultimate Mode
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
VOLTRON_DB="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNS2TCP_KEYS_DIR="$DB_DIR/dns2tcp"
V2RAY_DIR="$DB_DIR/v2ray-dnstt"
V2RAY_USERS_DB="$V2RAY_DIR/users/users.db"
V2RAY_CONFIG="$V2RAY_DIR/v2ray/config.json"
DNSTT_INFO_FILE="$DB_DIR/dnstt_info.conf"
DNS2TCP_INFO_FILE="$DB_DIR/dns2tcp_info.conf"
V2RAY_INFO_FILE="$DB_DIR/v2ray_info.conf"
DNS_INFO_FILE="$DB_DIR/dns_info.conf"
UDP_CUSTOM_DIR="/root/udp"
BACKUP_DIR="$DB_DIR/backups"
LOGS_DIR="$DB_DIR/logs"
CONFIG_DIR="$DB_DIR/config"
ZIVPN_DIR="/etc/zivpn"

# ========== SERVICE FILES ==========
DNSTT_SERVICE="/etc/systemd/system/dnstt.service"
DNSTT5300_SERVICE="/etc/systemd/system/dnstt-5300.service"
DNS2TCP53_SERVICE="/etc/systemd/system/dns2tcp-53.service"
DNS2TCP5300_SERVICE="/etc/systemd/system/dns2tcp-5300.service"
V2RAY_SERVICE="/etc/systemd/system/v2ray-dnstt.service"
BADVPN_SERVICE="/etc/systemd/system/badvpn.service"
UDP_CUSTOM_SERVICE="/etc/systemd/system/udp-custom.service"
HAPROXY_SERVICE="/etc/systemd/system/haproxy.service"
VOLTRONPROXY_SERVICE="/etc/systemd/system/voltronproxy.service"
NGINX_SERVICE="/etc/systemd/system/nginx.service"
ZIVPN_SERVICE="/etc/systemd/system/zivpn.service"
LIMITER_SERVICE="/etc/systemd/system/voltron-limiter.service"
TRAFFIC_SERVICE="/etc/systemd/system/voltron-traffic.service"

# ========== BINARY LOCATIONS ==========
DNSTT_BIN="/usr/local/bin/dnstt-server"
DNS2TCP_BIN="/usr/local/bin/dns2tcp-server"
V2RAY_BIN="/usr/local/bin/xray"
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
UDP_CUSTOM_BIN="$UDP_CUSTOM_DIR/udp-custom"
VOLTRONPROXY_BIN="/usr/local/bin/voltronproxy"
ZIVPN_BIN="/usr/local/bin/zivpn"
LIMITER_SCRIPT="/usr/local/bin/voltron-limiter.sh"
TRAFFIC_SCRIPT="/usr/local/bin/voltron-traffic.sh"

# ========== PORTS ==========
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
    touch $VOLTRON_DB
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
        MANAGE_SERVICE() {
            local action=$1
            local service=$2
            systemctl $action $service
        }
    else
        echo -e "${C_RED}❌ systemd not found!${C_RESET}"
        exit 1
    fi
    echo -e "${C_GREEN}✅ Detected service manager: $SERVICE_MANAGER${C_RESET}"
}

detect_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        FIREWALL="ufw"
        OPEN_PORT() {
            ufw allow $1/$2
        }
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        FIREWALL="firewalld"
        OPEN_PORT() {
            firewall-cmd --add-port=$1/$2 --permanent
            firewall-cmd --reload
        }
    elif command -v iptables &>/dev/null; then
        FIREWALL="iptables"
        OPEN_PORT() {
            iptables -A INPUT -p $2 --dport $1 -j ACCEPT
        }
    else
        FIREWALL="none"
        OPEN_PORT() {
            echo -e "${C_YELLOW}⚠️ No firewall detected, assuming port $1/$2 is open${C_RESET}"
        }
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
    if [ -n "$prompt" ]; then
        read -p "$prompt" "$var_name"
    else
        read "$var_name"
    fi
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
        echo -e "${C_GREEN}RUNNING${C_RESET}"
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
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH X ULTIMATE v2.0.3 🔥               ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • DNS2TCP • V2RAY • MTU 1800 ULTIMATE     ║${C_RESET}"
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

# ========== MTU OPTIMIZATION (1800 SPECIAL) ==========
apply_mtu_optimization() {
    local mtu=$1
    echo -e "\n${C_BLUE}⚡ Applying MTU optimization for MTU $mtu...${C_RESET}"
    
    local mss=""
    local buffer_size=""
    
    if [ $mtu -eq 1800 ]; then
        echo -e "${C_YELLOW}   🔥 SPECIAL MODE: ISP sees 512, VPS uses 1800!${C_RESET}"
        mss=1760
        buffer_size=536870912  # 512MB
    else
        mss=$((mtu - 40))
        buffer_size=$((mtu * 40000))
    fi
    
    cat > /etc/sysctl.d/99-voltron.conf <<EOF
# VOLTRON TECH OPTIMIZATION - MTU $mtu
net.core.rmem_max = $buffer_size
net.core.wmem_max = $buffer_size
net.ipv4.tcp_rmem = 4096 87380 $buffer_size
net.ipv4.tcp_wmem = 4096 65536 $buffer_size
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = $mss
EOF
    sysctl -p /etc/sysctl.d/99-voltron.conf 2>/dev/null
    
    mkdir -p "$CONFIG_DIR"
    echo "$mtu" > "$CONFIG_DIR/mtu"
    
    echo -e "${C_GREEN}✅ MTU optimization applied${C_RESET}"
}

# ========== MTU SELECTION ==========
mtu_selection() {
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
    
    local choice
    safe_read "👉 Select MTU option [01-07] (default 05): " choice
    choice=${choice:-05}
    
    case $choice in
        01|1) MTU=512 ;;
        02|2) MTU=800 ;;
        03|3) MTU=1000 ;;
        04|4) MTU=1200 ;;
        05|5) MTU=1500 ;;
        06|6) MTU=1800 ;;
        07|7) 
            echo -e "${C_YELLOW}Detecting optimal MTU...${C_RESET}"
            MTU=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
            echo -e "${C_GREEN}Optimal MTU: $MTU${C_RESET}"
            ;;
        *) MTU=1500 ;;
    esac
    
    apply_mtu_optimization $MTU
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
                
                # Simulate traffic (0.01GB per connection per hour)
                if [ $connections -gt 0 ]; then
                    new_traffic=$(echo "scale=3; $traffic_used + 0.01" | bc 2>/dev/null || echo "$traffic_used")
                    
                    # Check traffic limit
                    if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ]; then
                        if [ $(echo "$new_traffic >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                            usermod -L "$user" 2>/dev/null
                            killall -u "$user" 2>/dev/null
                            logger "User $user locked - traffic limit exceeded"
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
            
            # Check expiry
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" 2>/dev/null
                continue
            fi
            
            # Check connection limit
            online=$(pgrep -u "$user" sshd | wc -l)
            if [[ "$online" -gt "$limit" ]]; then
                usermod -L "$user" 2>/dev/null
                killall -u "$user" 2>/dev/null
                (sleep 120; usermod -U "$user" 2>/dev/null) &
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
create_user() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👤 CREATE SSH USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    read -p "Password: " password
    read -p "Expiry (days): " days
    read -p "Connection limit: " limit
    read -p "Traffic limit (GB) [0=unlimited]: " traffic_limit
    
    traffic_limit=${traffic_limit:-0}
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    useradd -m -s /usr/sbin/nologin "$username" 2>/dev/null
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$traffic_limit:0" >> "$VOLTRON_DB"
    
    echo -e "${C_GREEN}✅ SSH user created: $username${C_RESET}"
    echo -e "  Traffic limit: $traffic_limit GB"
    read -p "Press Enter"
}

delete_user() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_RED}           🗑️ DELETE SSH USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    if ! id "$username" &>/dev/null; then
        echo -e "${C_RED}❌ User not found${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    read -p "Confirm delete? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    
    killall -u "$username" 2>/dev/null
    userdel -r "$username" 2>/dev/null
    sed -i "/^$username:/d" "$VOLTRON_DB"
    
    echo -e "${C_GREEN}✅ User deleted${C_RESET}"
    read -p "Press Enter"
}

list_users() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 SSH USERS LIST${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -s "$VOLTRON_DB" ]; then
        echo -e "${C_YELLOW}No SSH users found${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    printf "${C_BOLD}%-15s %-12s %-8s %-20s %-10s${C_RESET}\n" "USERNAME" "EXPIRY" "LIMIT" "TRAFFIC" "STATUS"
    echo -e "${C_CYAN}─────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        [[ -z "$user" ]] && continue
        
        online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        
        # Format traffic
        if [[ -z "$traffic_limit" ]] || [[ "$traffic_limit" == "0" ]]; then
            traffic_disp="${traffic_used}GB/∞"
            traffic_ok=1
        else
            percent=$(echo "scale=1; $traffic_used * 100 / $traffic_limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${traffic_used}/$traffic_limit GB ($percent%)"
            if [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                traffic_ok=0
            else
                traffic_ok=1
            fi
        fi
        
        # Check status
        if ! id "$user" &>/dev/null; then
            status="${C_RED}NO USER${C_RESET}"
        elif passwd -S "$user" 2>/dev/null | grep -q " L "; then
            status="${C_YELLOW}LOCKED${C_RESET}"
        elif [[ "$(date -d "$expiry" +%s 2>/dev/null)" -lt "$(date +%s)" ]]; then
            status="${C_RED}EXPIRED${C_RESET}"
        elif [ "$traffic_ok" -eq 0 ]; then
            status="${C_RED}LIMIT${C_RESET}"
        else
            status="${C_GREEN}ACTIVE${C_RESET}"
        fi
        
        printf "%-15s %-12s %-8s %-20s %s\n" "$user" "$expiry" "$online/$limit" "$traffic_disp" "$status"
    done < "$VOLTRON_DB"
    
    echo ""
    read -p "Press Enter"
}

lock_user() {
    read -p "Username: " username
    usermod -L "$username"
    echo -e "${C_GREEN}✅ User locked${C_RESET}"
    read -p "Press Enter"
}

unlock_user() {
    read -p "Username: " username
    usermod -U "$username"
    echo -e "${C_GREEN}✅ User unlocked${C_RESET}"
    read -p "Press Enter"
}

renew_user() {
    read -p "Username: " username
    read -p "Additional days: " days
    new_expiry=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expiry" "$username"
    
    local line=$(grep "^$username:" "$VOLTRON_DB")
    local pass=$(echo "$line" | cut -d: -f2)
    local limit=$(echo "$line" | cut -d: -f4)
    local traffic_limit=$(echo "$line" | cut -d: -f5)
    local traffic_used=$(echo "$line" | cut -d: -f6)
    
    sed -i "s/^$username:.*/$username:$pass:$new_expiry:$limit:$traffic_limit:$traffic_used/" "$VOLTRON_DB"
    
    echo -e "${C_GREEN}✅ User renewed until $new_expiry${C_RESET}"
    read -p "Press Enter"
}

cleanup_expired() {
    echo -e "${C_BLUE}Cleaning up expired users...${C_RESET}"
    current_ts=$(date +%s)
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            killall -u "$user" 2>/dev/null
            userdel -r "$user" 2>/dev/null
            sed -i "/^$user:/d" "$VOLTRON_DB"
            echo "  Removed $user"
        fi
    done < "$VOLTRON_DB"
    echo -e "${C_GREEN}✅ Cleanup complete${C_RESET}"
    read -p "Press Enter"
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
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 INSTALL DNSTT${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        echo -e "${C_YELLOW}DNSTT already installed${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    # Free port 53
    echo -e "${C_BLUE}[1/5] Freeing port 53...${C_RESET}"
    systemctl stop systemd-resolved 2>/dev/null
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    
    # Download binary
    echo -e "${C_BLUE}[2/5] Downloading DNSTT binary...${C_RESET}"
    if ! download_dnstt_binary; then
        echo -e "${C_RED}❌ Failed to download DNSTT binary${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    # Generate keys
    echo -e "${C_BLUE}[3/5] Generating keys...${C_RESET}"
    mkdir -p "$DNSTT_KEYS_DIR"
    "$DNSTT_BIN" -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null
    
    # Get MTU
    echo -e "${C_BLUE}[4/5] Selecting MTU...${C_RESET}"
    mtu_selection
    
    # DNS Configuration
    echo -e "\n${C_BLUE}[5/5] DNS Configuration:${C_RESET}"
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
    
    # Create services
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
PUBLIC_KEY="$(cat $DNSTT_KEYS_DIR/server.pub)"
MTU="$MTU"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  Tunnel Domain: ${C_YELLOW}$domain${C_RESET}"
    echo -e "  Public Key:    ${C_YELLOW}$(cat $DNSTT_KEYS_DIR/server.pub)${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Status:        ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    read -p "Press Enter"
}

uninstall_dnstt() {
    echo -e "${C_BLUE}🗑️ Uninstalling DNSTT...${C_RESET}"
    
    systemctl stop dnstt.service dnstt-5300.service 2>/dev/null
    systemctl disable dnstt.service dnstt-5300.service 2>/dev/null
    rm -f "$DNSTT_SERVICE" "$DNSTT5300_SERVICE"
    rm -f "$DNSTT_BIN"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_INFO_FILE"
    
    # Remove Cloudflare records
    if [ -f "$DNSTT_INFO_FILE" ]; then
        source "$DNSTT_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNSTT uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNSTT_INFO_FILE" ]; then
        echo -e "${C_YELLOW}DNSTT is not installed${C_RESET}"
        read -p "Press Enter"
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
    
    read -p "Press Enter"
}

# ========== DNS2TCP FUNCTIONS ==========
install_dns2tcp() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 INSTALL DNS2TCP${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "$DNS2TCP53_SERVICE" ]; then
        echo -e "${C_YELLOW}DNS2TCP already installed${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    # Install dependencies
    echo -e "${C_BLUE}[1/5] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL dns2tcp screen lsof
    
    # Configure systemd-resolved
    echo -e "${C_BLUE}[2/5] Configuring systemd-resolved...${C_RESET}"
    cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup 2>/dev/null
    cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    
    # Create directories
    echo -e "${C_BLUE}[3/5] Creating directories...${C_RESET}"
    mkdir -p /root/dns2tcp
    mkdir -p /var/empty/dns2tcp
    
    # Create user
    if ! id "ashtunnel" &>/dev/null; then
        useradd -r -s /bin/false -d /var/empty/dns2tcp ashtunnel
    fi
    
    # Get MTU
    echo -e "${C_BLUE}[4/5] Selecting MTU...${C_RESET}"
    mtu_selection
    
    # DNS Configuration
    echo -e "\n${C_BLUE}[5/5] DNS Configuration:${C_RESET}"
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
    
    # Create config for port 53
    cat > /root/dns2tcp/dns2tcp-53.conf <<EOF
listen = 0.0.0.0
port = 53
user = ashtunnel
chroot = /var/empty/dns2tcp/
domain = $domain
key = $key
resources = ssh:127.0.0.1:$target_port
EOF

    # Create config for port 5300
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
    echo -e "  Tunnel Domain: ${C_YELLOW}$domain${C_RESET}"
    echo -e "  Key:           ${C_YELLOW}$key${C_RESET}"
    echo -e "  Target Port:   ${C_YELLOW}$target_port${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Status:        ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    read -p "Press Enter"
}

uninstall_dns2tcp() {
    echo -e "${C_BLUE}🗑️ Uninstalling DNS2TCP...${C_RESET}"
    
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
    
    # Remove Cloudflare records
    if [ -f "$DNS2TCP_INFO_FILE" ]; then
        source "$DNS2TCP_INFO_FILE"
        [ -n "$TUNNEL_RECORD_ID" ] && delete_cloudflare_record "$TUNNEL_RECORD_ID"
        [ -n "$NS_RECORD_ID" ] && delete_cloudflare_record "$NS_RECORD_ID"
    fi
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNS2TCP uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_dns2tcp_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNS2TCP DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNS2TCP_INFO_FILE" ]; then
        echo -e "${C_YELLOW}DNS2TCP is not installed${C_RESET}"
        read -p "Press Enter"
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
    
    read -p "Press Enter"
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
            cat <<EOF
{
  "v": "2",
  "ps": "$username",
  "add": "$DOMAIN",
  "port": "8787",
  "id": "$uuid",
  "aid": "0",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": ""
}
EOF
            ;;
        vless)
            cat <<EOF
VLESS Config:
  Address: $DOMAIN
  Port: 8788
  UUID: $uuid
  Encryption: none
EOF
            ;;
        trojan)
            cat <<EOF
Trojan Config:
  Address: $DOMAIN
  Port: 8789
  Password: $password
EOF
            ;;
    esac
}

install_v2ray_dnstt() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🚀 INSTALL V2RAY over DNSTT${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "$V2RAY_SERVICE" ]; then
        echo -e "${C_YELLOW}V2RAY over DNSTT already installed${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    # Check if DNSTT is installed
    if [ ! -f "$DNSTT_SERVICE" ]; then
        echo -e "${C_YELLOW}⚠️ DNSTT not found. Installing DNSTT first...${C_RESET}"
        install_dnstt
    fi
    
    # Install Xray
    echo -e "${C_BLUE}[1/4] Installing Xray...${C_RESET}"
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
    
    # Create directories
    echo -e "${C_BLUE}[2/4] Creating directories...${C_RESET}"
    mkdir -p "$V2RAY_DIR"/{v2ray,users}
    
    # Get MTU
    echo -e "${C_BLUE}[3/4] Selecting MTU...${C_RESET}"
    mtu_selection
    
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
    echo -e "  VMess Port:    ${C_YELLOW}$V2RAY_PORT${C_RESET}"
    echo -e "  VLESS Port:    ${C_YELLOW}$((V2RAY_PORT+1))${C_RESET}"
    echo -e "  Trojan Port:   ${C_YELLOW}$((V2RAY_PORT+2))${C_RESET}"
    echo -e "  MTU:           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  Status:        ${C_GREEN}SPECIAL MODE - ISP sees 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}Use V2Ray User Management to add users${C_RESET}"
    read -p "Press Enter"
}

uninstall_v2ray_dnstt() {
    echo -e "${C_BLUE}🗑️ Uninstalling V2RAY over DNSTT...${C_RESET}"
    
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f "$V2RAY_SERVICE"
    rm -rf "$V2RAY_DIR"
    rm -f "$V2RAY_INFO_FILE"
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ V2RAY over DNSTT uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_v2ray_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🚀 V2RAY over DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_INFO_FILE" ]; then
        echo -e "${C_YELLOW}V2RAY over DNSTT is not installed${C_RESET}"
        read -p "Press Enter"
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
    echo -e "  Total Users:   ${C_YELLOW}$(wc -l < "$V2RAY_USERS_DB" 2>/dev/null || echo 0)${C_RESET}"
    
    read -p "Press Enter"
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
    read -p "Press Enter"
}

list_v2ray_users() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 V2RAY USERS LIST${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_USERS_DB" ] || [ ! -s "$V2RAY_USERS_DB" ]; then
        echo -e "${C_YELLOW}No V2Ray users found${C_RESET}"
        read -p "Press Enter"
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
    read -p "Press Enter"
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
        read -p "Press Enter"
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
    
    read -p "Press Enter"
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
        read -p "Press Enter"
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
    
    read -p "Press Enter"
}

delete_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_RED}           🗑️ DELETE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    read -p "Username: " username
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User not found${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    read -p "Are you sure? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        sed -i "/^$username:/d" "$V2RAY_USERS_DB"
        echo -e "${C_GREEN}✅ User deleted${C_RESET}"
    fi
    
    read -p "Press Enter"
}

lock_v2ray_user() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)active/\1locked/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ User locked${C_RESET}"
    read -p "Press Enter"
}

unlock_v2ray_user() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)locked/\1active/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ User unlocked${C_RESET}"
    read -p "Press Enter"
}

reset_v2ray_traffic() {
    read -p "Username: " username
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*:/\10:/" "$V2RAY_USERS_DB"
    echo -e "${C_GREEN}✅ Traffic reset to 0${C_RESET}"
    read -p "Press Enter"
}

# ========== V2RAY MAIN MENU ==========
v2ray_menu() {
    while true; do
        clear
        show_banner
        
        if [ -f "$V2RAY_SERVICE" ]; then
            installed_status="${C_GREEN}● INSTALLED${C_RESET}"
        else
            installed_status="${C_RED}● NOT INSTALLED${C_RESET}"
        fi
        
        echo -e "${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_PURPLE}              🚀 V2RAY over DNSTT MANAGEMENT $installed_status${C_RESET}"
        echo -e "${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [ -f "$V2RAY_SERVICE" ]; then
            echo -e "  ${C_GREEN}1)${C_RESET} Reinstall V2RAY over DNSTT"
            echo -e "  ${C_GREEN}2)${C_RESET} View Tunnel Details"
            echo -e "  ${C_GREEN}3)${C_RESET} Restart Tunnel"
            echo -e "  ${C_GREEN}4)${C_RESET} Uninstall V2RAY over DNSTT"
            echo ""
            echo -e "  ${C_GREEN}5)${C_RESET} 👤 Create V2Ray User"
            echo -e "  ${C_GREEN}6)${C_RESET} 📋 List V2Ray Users"
            echo -e "  ${C_GREEN}7)${C_RESET} 👁️ View User Details (with JSON)"
            echo -e "  ${C_GREEN}8)${C_RESET} ✏️ Edit User"
            echo -e "  ${C_GREEN}9)${C_RESET} 🗑️ Delete User"
            echo -e "  ${C_GREEN}10)${C_RESET} 🔒 Lock User"
            echo -e "  ${C_GREEN}11)${C_RESET} 🔓 Unlock User"
            echo -e "  ${C_GREEN}12)${C_RESET} 🔄 Reset Traffic"
            echo ""
            echo -e "  ${C_GREEN}13)${C_RESET} ⚙️ Change MTU"
            echo -e "  ${C_GREEN}14)${C_RESET} 📄 View V2Ray Config"
            echo -e "  ${C_GREEN}15)${C_RESET} 🔄 Restart V2Ray Service"
        else
            echo -e "  ${C_GREEN}1)${C_RESET} Install V2RAY over DNSTT"
        fi
        
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        read -p "Choice: " choice
        
        if [ ! -f "$V2RAY_SERVICE" ]; then
            case $choice in
                1) install_v2ray_dnstt ;;
                0) return ;;
                *) echo -e "${C_RED}Invalid${C_RESET}"; sleep 2 ;;
            esac
        else
            case $choice in
                1) install_v2ray_dnstt ;;
                2) show_v2ray_details ;;
                3) systemctl restart v2ray-dnstt.service; echo "Restarted"; read -p "Press Enter" ;;
                4) uninstall_v2ray_dnstt ;;
                5) create_v2ray_user ;;
                6) list_v2ray_users ;;
                7) view_v2ray_user ;;
                8) edit_v2ray_user ;;
                9) delete_v2ray_user ;;
                10) lock_v2ray_user ;;
                11) unlock_v2ray_user ;;
                12) reset_v2ray_traffic ;;
                13) mtu_selection ;;
                14) cat "$V2RAY_CONFIG" | jq . 2>/dev/null || cat "$V2RAY_CONFIG"; read -p "Press Enter" ;;
                15) systemctl restart v2ray-dnstt.service; echo "Restarted"; read -p "Press Enter" ;;
                0) return ;;
                *) echo -e "${C_RED}Invalid${C_RESET}"; sleep 2 ;;
            esac
        fi
    done
}

# ========== OTHER PROTOCOLS (SIMPLIFIED) ==========
install_badvpn() {
    echo -e "${C_BLUE}🚀 Installing badvpn...${C_RESET}"
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
    read -p "Press Enter"
}

uninstall_badvpn() {
    systemctl stop badvpn.service 2>/dev/null
    systemctl disable badvpn.service 2>/dev/null
    rm -f "$BADVPN_SERVICE" "$BADVPN_BIN"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ badvpn uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_udp_custom() {
    echo -e "${C_BLUE}🚀 Installing udp-custom...${C_RESET}"
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
    read -p "Press Enter"
}

uninstall_udp_custom() {
    systemctl stop udp-custom.service 2>/dev/null
    systemctl disable udp-custom.service 2>/dev/null
    rm -f "$UDP_CUSTOM_SERVICE"
    rm -rf "$UDP_CUSTOM_DIR"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ udp-custom uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_ssl_tunnel() {
    echo -e "${C_BLUE}🔒 Installing SSL Tunnel...${C_RESET}"
    $PKG_INSTALL haproxy
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" -subj "/CN=VOLTRON TECH" 2>/dev/null
    
    cat > /etc/haproxy/haproxy.cfg <<EOF
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
    read -p "Press Enter"
}

uninstall_ssl_tunnel() {
    systemctl stop haproxy 2>/dev/null
    $PKG_REMOVE haproxy
    rm -f /etc/haproxy/haproxy.cfg
    rm -f "$SSL_CERT_FILE"
    echo -e "${C_GREEN}✅ SSL Tunnel uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_voltron_proxy() {
    echo -e "${C_BLUE}🦅 Installing VOLTRON Proxy...${C_RESET}"
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxy"
    else
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxyarm"
    fi
    chmod +x "$VOLTRONPROXY_BIN"
    
    cat > "$VOLTRONPROXY_SERVICE" <<EOF
[Unit]
Description=VOLTRON Proxy
After=network.target

[Service]
Type=simple
ExecStart=$VOLTRONPROXY_BIN -p $VOLTRON_PROXY_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltronproxy.service
    systemctl start voltronproxy.service
    echo -e "${C_GREEN}✅ VOLTRON Proxy installed on port $VOLTRON_PROXY_PORT${C_RESET}"
    read -p "Press Enter"
}

uninstall_voltron_proxy() {
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f "$VOLTRONPROXY_SERVICE" "$VOLTRONPROXY_BIN"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ VOLTRON Proxy uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_nginx_proxy() {
    echo -e "${C_BLUE}🌐 Installing Nginx Proxy...${C_RESET}"
    $PKG_INSTALL nginx
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.pem -subj "/CN=VOLTRON TECH" 2>/dev/null
    
    cat > /etc/nginx/sites-available/default <<'EOF'
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
    read -p "Press Enter"
}

uninstall_nginx_proxy() {
    systemctl stop nginx 2>/dev/null
    $PKG_REMOVE nginx
    rm -f /etc/nginx/sites-available/default
    echo -e "${C_GREEN}✅ Nginx Proxy uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_zivpn() {
    echo -e "${C_BLUE}🛡️ Installing ZiVPN...${C_RESET}"
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
    read -p "Press Enter"
}

uninstall_zivpn() {
    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    rm -f "$ZIVPN_SERVICE" "$ZIVPN_BIN"
    rm -rf "$ZIVPN_DIR"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ ZiVPN uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_xui_panel() {
    echo -e "${C_BLUE}💻 Installing X-UI Panel...${C_RESET}"
    bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
    read -p "Press Enter"
}

uninstall_xui_panel() {
    if command -v x-ui &>/dev/null; then
        x-ui uninstall
    fi
    rm -f /usr/local/bin/x-ui
    rm -rf /etc/x-ui /usr/local/x-ui
    echo -e "${C_GREEN}✅ X-UI uninstalled${C_RESET}"
    read -p "Press Enter"
}

install_dt_proxy() {
    echo -e "${C_BLUE}🚀 Installing DT Proxy...${C_RESET}"
    curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash
    read -p "Press Enter"
}

uninstall_dt_proxy() {
    rm -f /usr/local/bin/proxy /usr/local/bin/main /usr/local/bin/install_mod
    rm -f /etc/systemd/system/proxy-*.service 2>/dev/null
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DT Proxy uninstalled${C_RESET}"
    read -p "Press Enter"
}

# ========== BACKUP & RESTORE ==========
backup_data() {
    echo -e "${C_BLUE}💾 Creating backup...${C_RESET}"
    backup_file="/root/voltrontech-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" $DB_DIR 2>/dev/null
    echo -e "${C_GREEN}✅ Backup created: $backup_file${C_RESET}"
    read -p "Press Enter"
}

restore_data() {
    echo -e "${C_BLUE}📥 Available backups:${C_RESET}"
    ls -la /root/voltrontech-backup-*.tar.gz 2>/dev/null
    echo ""
    read -p "Enter backup file path: " backup_file
    if [ -f "$backup_file" ]; then
        tar -xzf "$backup_file" -C / 2>/dev/null
        echo -e "${C_GREEN}✅ Restore complete${C_RESET}"
    else
        echo -e "${C_RED}❌ File not found${C_RESET}"
    fi
    read -p "Press Enter"
}

# ========== CLOUDFLARE DNS GENERATOR ==========
generate_cloudflare_dns() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🌐 GENERATE CLOUDFLARE DNS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local ip=$(curl -s ifconfig.me)
    
    echo -e "${C_BLUE}Creating A record for nameserver...${C_RESET}"
    local ns_record_id=$(create_cloudflare_record "A" "ns" "$ip")
    
    if [ -z "$ns_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create A record${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    echo -e "${C_BLUE}Creating NS records...${C_RESET}"
    local tun_record_id=$(create_cloudflare_record "NS" "tun" "ns.$DOMAIN")
    local tun2_record_id=$(create_cloudflare_record "NS" "tun2" "ns.$DOMAIN")
    
    echo -e "${C_GREEN}✅ DNS records created successfully!${C_RESET}"
    echo -e "  A record:  ns.$DOMAIN → $ip"
    echo -e "  NS record: tun.$DOMAIN → ns.$DOMAIN"
    echo -e "  NS record: tun2.$DOMAIN → ns.$DOMAIN"
    
    # Save record IDs
    cat > "$DNS_INFO_FILE" <<EOF
NS_RECORD_ID="$ns_record_id"
TUN_RECORD_ID="$tun_record_id"
TUN2_RECORD_ID="$tun2_record_id"
EOF
    
    read -p "Press Enter"
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
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🔌 PROTOCOL & PANEL MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} DNSTT (53,5300 UDP)              $dnstt_status"
        echo -e "  ${C_GREEN}2)${C_RESET} DNS2TCP (53,5300 TCP)            $dns2tcp_status"
        echo -e "  ${C_GREEN}3)${C_RESET} V2RAY over DNSTT                 $v2ray_status"
        echo -e "  ${C_GREEN}4)${C_RESET} badvpn (7300 UDP)                $badvpn_status"
        echo -e "  ${C_GREEN}5)${C_RESET} udp-custom                       $udp_status"
        echo -e "  ${C_GREEN}6)${C_RESET} SSL Tunnel (HAProxy)             $haproxy_status"
        echo -e "  ${C_GREEN}7)${C_RESET} VOLTRON Proxy                    $voltronproxy_status"
        echo -e "  ${C_GREEN}8)${C_RESET} Nginx Proxy                      $nginx_status"
        echo -e "  ${C_GREEN}9)${C_RESET} ZiVPN                            $zivpn_status"
        echo -e "  ${C_GREEN}10)${C_RESET} X-UI Panel                      $( [ -f /usr/local/x-ui/bin/x-ui ] && echo -e "${C_GREEN}RUNNING${C_RESET}" )"
        echo -e "  ${C_GREEN}11)${C_RESET} DT Proxy                        $( [ -f /usr/local/bin/main ] && echo -e "${C_GREEN}RUNNING${C_RESET}" )"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select protocol: " choice
        
        case $choice in
            1)
                echo ""
                echo "1) Install DNSTT"
                echo "2) View Details"
                echo "3) Uninstall"
                read -p "Choice: " sub
                case $sub in
                    1) install_dnstt ;;
                    2) show_dnstt_details ;;
                    3) uninstall_dnstt ;;
                esac
                ;;
            2)
                echo ""
                echo "1) Install DNS2TCP"
                echo "2) View Details"
                echo "3) Uninstall"
                read -p "Choice: " sub
                case $sub in
                    1) install_dns2tcp ;;
                    2) show_dns2tcp_details ;;
                    3) uninstall_dns2tcp ;;
                esac
                ;;
            3)
                v2ray_menu
                ;;
            4)
                echo ""
                echo "1) Install badvpn"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_badvpn || uninstall_badvpn
                ;;
            5)
                echo ""
                echo "1) Install udp-custom"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_udp_custom || uninstall_udp_custom
                ;;
            6)
                echo ""
                echo "1) Install SSL Tunnel"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_ssl_tunnel || uninstall_ssl_tunnel
                ;;
            7)
                echo ""
                echo "1) Install VOLTRON Proxy"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_voltron_proxy || uninstall_voltron_proxy
                ;;
            8)
                echo ""
                echo "1) Install Nginx Proxy"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_nginx_proxy || uninstall_nginx_proxy
                ;;
            9)
                echo ""
                echo "1) Install ZiVPN"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_zivpn || uninstall_zivpn
                ;;
            10)
                echo ""
                echo "1) Install X-UI Panel"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_xui_panel || uninstall_xui_panel
                ;;
            11)
                echo ""
                echo "1) Install DT Proxy"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_dt_proxy || uninstall_dt_proxy
                ;;
            0) return ;;
            *) echo -e "${C_RED}Invalid${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== UNINSTALL EVERYTHING ==========
uninstall_everything() {
    clear
    show_banner
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_RED}           💥 UNINSTALL EVERYTHING${C_RESET}"
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    read -p "Type YES to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "${C_GREEN}Cancelled${C_RESET}"
        read -p "Press Enter"
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
    while true; do
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    👤 SSH USER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} Create SSH User"
        echo -e "  ${C_GREEN}2)${C_RESET} Delete SSH User"
        echo -e "  ${C_GREEN}3)${C_RESET} List SSH Users"
        echo -e "  ${C_GREEN}4)${C_RESET} Lock SSH User"
        echo -e "  ${C_GREEN}5)${C_RESET} Unlock SSH User"
        echo -e "  ${C_GREEN}6)${C_RESET} Renew SSH User"
        echo -e "  ${C_GREEN}7)${C_RESET} Cleanup Expired SSH Users"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}8)${C_RESET} Protocols & Panels"
        echo -e "  ${C_GREEN}9)${C_RESET} Set MTU"
        echo -e "  ${C_GREEN}10)${C_RESET} Generate Cloudflare DNS"
        echo -e "  ${C_GREEN}11)${C_RESET} Backup Data"
        echo -e "  ${C_GREEN}12)${C_RESET} Restore Data"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    🔥 DANGER ZONE${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_RED}99)${C_RESET} Uninstall Everything"
        echo -e "  ${C_RED}0)${C_RESET} Exit"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) create_user ;;
            2) delete_user ;;
            3) list_users ;;
            4) lock_user ;;
            5) unlock_user ;;
            6) renew_user ;;
            7) cleanup_expired ;;
            8) protocol_menu ;;
            9) mtu_selection ;;
            10) generate_cloudflare_dns ;;
            11) backup_data ;;
            12) restore_data ;;
            99) uninstall_everything ;;
            0) echo -e "${C_GREEN}👋 Goodbye!${C_RESET}"; exit 0 ;;
            *) echo -e "${C_RED}Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== START ==========
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}❌ This script must be run as root!${C_RESET}"
    exit 1
fi

# Run initial setup
detect_os
detect_package_manager
detect_service_manager
detect_firewall
create_directories
create_traffic_monitor
create_limiter_service
get_ip_info

main_menu
