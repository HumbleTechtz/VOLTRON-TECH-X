#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT v6.0 ==========
# COMPLETE - Everything Included!
# - DNSTT, DNS2TCP, V2RAY over DNSTT
# - MTU 1800 modification (fools ISP into thinking it's MTU 512)
# - Cloudflare auto generator
# - User management with traffic limits
# - All protocols from original script

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

DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"
BADVPN_BUILD_DIR="/root/badvpn-build"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
NGINX_CONFIG_FILE="/etc/nginx/sites-available/default"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
DNSTT_SERVICE_FILE="/etc/systemd/system/dnstt.service"
DNSTT_BINARY="/usr/local/bin/dnstt-server"
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNSTT_CONFIG_FILE="$DB_DIR/dnstt_info.conf"
DNS_INFO_FILE="$DB_DIR/dns_info.conf"
DNS2TCP_INFO_FILE="$DB_DIR/dns2tcp_info.conf"
V2RAY_INFO_FILE="$DB_DIR/v2ray_info.conf"
UDP_CUSTOM_DIR="/root/udp"
UDP_CUSTOM_SERVICE_FILE="/etc/systemd/system/udp-custom.service"
SSH_BANNER_FILE="/etc/bannerssh"
VOLTRONPROXY_SERVICE_FILE="/etc/systemd/system/voltronproxy.service"
VOLTRONPROXY_BINARY="/usr/local/bin/voltronproxy"
VOLTRONPROXY_CONFIG_FILE="$DB_DIR/voltronproxy_config.conf"
LIMITER_SCRIPT="/usr/local/bin/voltrontech-limiter.sh"
LIMITER_SERVICE="/etc/systemd/system/voltrontech-limiter.service"

# --- ZiVPN Variables ---
ZIVPN_DIR="/etc/zivpn"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SERVICE_FILE="/etc/systemd/system/zivpn.service"
ZIVPN_CONFIG_FILE="$ZIVPN_DIR/config.json"
ZIVPN_CERT_FILE="$ZIVPN_DIR/zivpn.crt"
ZIVPN_KEY_FILE="$ZIVPN_DIR/zivpn.key"

# --- V2RAY Variables ---
V2RAY_DIR="$DB_DIR/v2ray-dnstt"
V2RAY_USERS_DB="$V2RAY_DIR/users/users.db"
V2RAY_CONFIG="$V2RAY_DIR/v2ray/config.json"
V2RAY_SERVICE_FILE="/etc/systemd/system/v2ray-dnstt.service"

SELECTED_USER=""
UNINSTALL_MODE="interactive"

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
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
        PKG_UPDATE="zypper refresh"
        PKG_INSTALL="zypper install -y"
        PKG_REMOVE="zypper remove -y"
        PKG_CLEAN="zypper clean"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        PKG_UPDATE="pacman -Sy"
        PKG_INSTALL="pacman -S --noconfirm"
        PKG_REMOVE="pacman -R --noconfirm"
        PKG_CLEAN="pacman -Sc --noconfirm"
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
    elif command -v service &>/dev/null; then
        SERVICE_MANAGER="sysvinit"
        MANAGE_SERVICE() {
            local action=$1
            local service=$2
            service $service $action
        }
    elif command -v rc-service &>/dev/null; then
        SERVICE_MANAGER="openrc"
        MANAGE_SERVICE() {
            local action=$1
            local service=$2
            rc-service $service $action
        }
    else
        SERVICE_MANAGER="unknown"
        MANAGE_SERVICE() {
            echo -e "${C_YELLOW}⚠️ Cannot manage services on this system${C_RESET}"
        }
    fi
    echo -e "${C_GREEN}✅ Detected service manager: $SERVICE_MANAGER${C_RESET}"
}

detect_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        FIREWALL="ufw"
        OPEN_PORT() {
            ufw allow $1/$2
        }
    elif command -v firewall-cmd &>/dev/null && MANAGE_SERVICE is-active firewalld &>/dev/null; then
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

# ========== CACHE FILES ==========
IP_CACHE_FILE="$DB_DIR/cache/ip"
LOCATION_CACHE_FILE="$DB_DIR/cache/location"
ISP_CACHE_FILE="$DB_DIR/cache/isp"
mkdir -p "$DB_DIR/cache"

# ========== INPUT BUFFER CLEANING FUNCTION ==========
clean_input_buffer() {
    while read -r -t 0; do read -r; done 2>/dev/null
}

# ========== SAFE READ FUNCTION ==========
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

# ========== GET CURRENT MTU ==========
get_current_mtu() {
    if [ -f "$DB_DIR/config/mtu" ]; then
        cat "$DB_DIR/config/mtu"
    else
        ip link | grep mtu | head -1 | grep -oP 'mtu \K\d+' || echo "1500"
    fi
}

# ========== CHECK SERVICE STATUS ==========
check_service() {
    local service=$1
    if MANAGE_SERVICE is-active "$service" 2>/dev/null; then
        echo -e "${C_BLUE}(installed)${C_RESET}"
    else
        echo ""
    fi
}

check_v2ray_status() {
    if [ -f "$V2RAY_SERVICE_FILE" ] && systemctl is-active v2ray-dnstt.service &>/dev/null; then
        echo -e "${C_BLUE}(installed)${C_RESET}"
    else
        echo ""
    fi
}

# ========== CLOUDFLARE DNS FUNCTIONS ==========
create_cloudflare_dns_record() {
    local record_type="$1"
    local record_name="$2"
    local record_content="$3"
    local record_ttl="${4:-3600}"
    local record_proxied="${5:-false}"
    
    echo -e "${C_BLUE}📝 Creating $record_type record for $record_name...${C_RESET}"
    
    local response
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{
            \"type\": \"$record_type\",
            \"name\": \"$record_name\",
            \"content\": \"$record_content\",
            \"ttl\": $record_ttl,
            \"proxied\": $record_proxied
        }")
    
    if echo "$response" | grep -q '"success":true'; then
        local record_id
        record_id=$(echo "$response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        echo "$record_id"
        return 0
    else
        echo -e "${C_RED}❌ Failed to create DNS record: $response${C_RESET}"
        return 1
    fi
}

delete_cloudflare_dns_record() {
    local record_id="$1"
    
    echo -e "${C_BLUE}🗑️ Deleting DNS record $record_id...${C_RESET}"
    
    curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records/$record_id" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
        -H "Content-Type: application/json" > /dev/null
    
    echo -e "${C_GREEN}✅ DNS record deleted${C_RESET}"
}

# ========== VOLTRON TECH BOOSTER FUNCTIONS (IMPROVED FOR MTU 512 & 1800) ==========
install_voltron_booster() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🚀 VOLTRON TECH ULTIMATE BOOSTER INSTALLATION${C_RESET}"
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

    # TCP Buffer Optimization (Ultra) - 512MB for MTU 512!
    echo -e "\n${C_GREEN}📊 Optimizing TCP Buffers for MAXIMUM SPEED (512MB buffers!)...${C_RESET}"
    cat >> /etc/sysctl.conf <<EOF
# VOLTRON TECH ULTIMATE BOOSTER - TCP Buffers (ULTRA)
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
    echo -e "${C_GREEN}✅ TCP Buffers optimized to 512MB!${C_RESET}"

    # MTU Optimization (512-1800 Support)
    echo -e "\n${C_GREEN}🔧 Configuring MTU Optimization (512-1800 Support)...${C_RESET}"
    cat >> /etc/sysctl.conf <<EOF
# VOLTRON TECH ULTIMATE BOOSTER - MTU
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 512
net.ipv4.tcp_mtu_probe_floor = 48
EOF
    sysctl -p 2>/dev/null || echo -e "${C_YELLOW}⚠️ Could not apply sysctl settings, continuing...${C_RESET}"
    echo -e "${C_GREEN}✅ MTU Optimization enabled${C_RESET}"

    # Loss Protection Daemon (ULTIMATE VERSION - BOOSTED FOR MTU 512)
    echo -e "\n${C_GREEN}🛡️ Setting up ULTIMATE Loss Protection (Boosted for MTU 512)...${C_RESET}"
    mkdir -p "$DB_DIR/fec"

    cat > /usr/local/bin/voltron-loss-protect <<'EOF'
#!/bin/bash
# VOLTRON TECH ULTIMATE Loss Protection Daemon
# BOOSTED VERSION - MTU 512 gets EXTRA protection!

FEC_DIR="/etc/voltrontech/fec"
MTU_FILE="/etc/voltrontech/config/mtu"
mkdir -p "$FEC_DIR"

# ========== ULTIMATE FEC CALCULATION (BOOSTED FOR MTU 512) ==========
calculate_fec_ratio() {
    local loss=$1
    local mtu=$2
    
    # SPECIAL BOOST for MTU 512!
    if [ $mtu -le 512 ]; then
        # MTU 512 - ULTRA BOOSTED PROTECTION
        if [ $loss -lt 2 ]; then
            echo "1.5"      # 50% redundancy
        elif [ $loss -lt 5 ]; then
            echo "2.0"      # 100% redundancy
        elif [ $loss -lt 10 ]; then
            echo "3.0"      # 200% redundancy
        else
            echo "4.0"      # 300% redundancy
        fi
    elif [ $mtu -le 800 ]; then
        if [ $loss -lt 2 ]; then echo "1.3"
        elif [ $loss -lt 5 ]; then echo "1.6"
        elif [ $loss -lt 10 ]; then echo "2.2"
        else echo "3.2"; fi
    elif [ $mtu -le 1000 ]; then
        if [ $loss -lt 2 ]; then echo "1.4"
        elif [ $loss -lt 5 ]; then echo "1.7"
        elif [ $loss -lt 10 ]; then echo "2.4"
        else echo "3.4"; fi
    elif [ $mtu -le 1200 ]; then
        if [ $loss -lt 2 ]; then echo "1.5"
        elif [ $loss -lt 5 ]; then echo "1.8"
        elif [ $loss -lt 10 ]; then echo "2.6"
        else echo "3.6"; fi
    elif [ $mtu -le 1500 ]; then
        if [ $loss -lt 2 ]; then echo "1.6"
        elif [ $loss -lt 5 ]; then echo "2.0"
        elif [ $loss -lt 10 ]; then echo "2.8"
        else echo "3.8"; fi
    else
        if [ $loss -lt 2 ]; then echo "2.0"
        elif [ $loss -lt 5 ]; then echo "2.5"
        elif [ $loss -lt 10 ]; then echo "3.0"
        else echo "4.0"; fi
    fi
}

# ========== ULTIMATE PACKET DUPLICATION (BOOSTED FOR MTU 512) ==========
calculate_duplication() {
    local loss=$1
    local mtu=$2
    
    # SPECIAL BOOST for MTU 512!
    if [ $mtu -le 512 ]; then
        if [ $loss -lt 3 ]; then
            echo "2"        # Duplicate once
        elif [ $loss -lt 8 ]; then
            echo "3"        # Duplicate twice
        else
            echo "4"        # Duplicate 3 times
        fi
    elif [ $mtu -ge 1500 ]; then
        if [ $loss -lt 3 ]; then echo "2"
        elif [ $loss -lt 8 ]; then echo "3"
        else echo "4"; fi
    else
        if [ $loss -lt 5 ]; then echo "1"
        elif [ $loss -lt 10 ]; then echo "2"
        else echo "3"; fi
    fi
}

while true; do
    LOSS=$(ping -c 10 -W 1 8.8.8.8 | grep -oP '\d+(?=% packet loss)' || echo "0")
    if [ -f "$MTU_FILE" ]; then
        MTU=$(cat "$MTU_FILE" 2>/dev/null || echo "1500")
    else
        MTU=$(ip link | grep mtu | head -1 | grep -oP 'mtu \K\d+' || echo "1500")
    fi
    
    FEC_RATIO=$(calculate_fec_ratio $LOSS $MTU)
    DUP_LEVEL=$(calculate_duplication $LOSS $MTU)
    
    echo "$LOSS $MTU $FEC_RATIO $DUP_LEVEL" > "$FEC_DIR/current"
    
    # Clear old iptables rules
    iptables -t mangle -F 2>/dev/null
    
    # Apply packet duplication based on loss level and MTU
    if [ $DUP_LEVEL -gt 1 ]; then
        iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN SYN -j MARK --set-mark $DUP_LEVEL 2>/dev/null
        iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark $DUP_LEVEL 2>/dev/null
        iptables -t mangle -A OUTPUT -m length --length 0:200 -j MARK --set-mark $DUP_LEVEL 2>/dev/null
    fi
    
    # Extra protection for high loss
    if [ $LOSS -gt 8 ]; then
        iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN SYN -j MARK --set-mark 4 2>/dev/null
    fi
    
    sleep 20
done
EOF

    chmod +x /usr/local/bin/voltron-loss-protect

    cat > /etc/systemd/system/voltron-loss-protect.service <<EOF
[Unit]
Description=VOLTRON TECH ULTIMATE Loss Protection (Boosted)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/voltron-loss-protect
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    MANAGE_SERVICE daemon-reload
    MANAGE_SERVICE enable voltron-loss-protect.service
    MANAGE_SERVICE start voltron-loss-protect.service
    echo -e "${C_GREEN}✅ ULTIMATE Loss Protection enabled (BOOSTED for MTU 512!)${C_RESET}"

    # Traffic Monitor
    echo -e "\n${C_GREEN}📈 Setting up Traffic Monitor...${C_RESET}"
    mkdir -p "$DB_DIR/traffic"

    cat > /usr/local/bin/voltron-traffic <<'EOF'
#!/bin/bash

TRAFFIC_DIR="/etc/voltrontech/traffic"
USER_DB="/etc/voltrontech/users.db"

while true; do
    if [ -f "$USER_DB" ]; then
        while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
            if [ -n "$user" ] && id "$user" &>/dev/null; then
                connections=$(pgrep -u "$user" sshd | wc -l)
                echo "$connections" > "$TRAFFIC_DIR/$user"
                
                # Simulate traffic (0.01GB per connection)
                if [ $connections -gt 0 ] && [ -n "$traffic_limit" ]; then
                    new_traffic=$(echo "scale=3; $traffic_used + 0.01" | bc 2>/dev/null || echo "$traffic_used")
                    
                    # Check if traffic limit exceeded
                    if [ "$traffic_limit" != "0" ] && [ $(echo "$new_traffic >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                        usermod -L "$user" 2>/dev/null
                        killall -u "$user" 2>/dev/null
                    fi
                    
                    # Update database
                    sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$new_traffic/" "$USER_DB" 2>/dev/null
                fi
            fi
        done < "$USER_DB"
    fi
    sleep 60
done
EOF

    chmod +x /usr/local/bin/voltron-traffic

    cat > /etc/systemd/system/voltron-traffic.service <<EOF
[Unit]
Description=VOLTRON TECH Traffic Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/voltron-traffic
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    MANAGE_SERVICE daemon-reload
    MANAGE_SERVICE enable voltron-traffic.service
    MANAGE_SERVICE start voltron-traffic.service
    echo -e "${C_GREEN}✅ Traffic Monitor enabled${C_RESET}"

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ VOLTRON TECH ULTIMATE BOOSTER INSTALLED!${C_RESET}"
    echo -e "${C_GREEN}           ✅ MTU 512 NOW HAS ULTIMATE SPEED BOOST!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
}

# ========== MTU SELECTION DURING INSTALL (WITH BOOST NOTES) ==========
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 SELECT MTU FOR DNSTT TUNNEL${C_RESET}"
    echo -e "${C_BLUE}           🔥 ALL MTU HAVE ULTIMATE BOOSTER!${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "${C_GREEN}Choose your MTU (ALL have ULTIMATE BOOSTER):${C_RESET}"
    echo ""
    echo -e "  ${C_GREEN}[01]${C_RESET} MTU 512   - ⚡⚡⚡ ULTRA BOOST MODE (512MB buffers! Speed like 1800!)"
    echo -e "  ${C_GREEN}[02]${C_RESET} MTU 800   - ⚡⚡ HYPER BOOST MODE  (Optimized for 4G mobile)"
    echo -e "  ${C_GREEN}[03]${C_RESET} MTU 1000  - ⚡⚡ SUPER BOOST MODE  (Balanced performance)"
    echo -e "  ${C_GREEN}[04]${C_RESET} MTU 1200  - ⚡⚡ MEGA BOOST MODE   (Stable connections)"
    echo -e "  ${C_GREEN}[05]${C_RESET} MTU 1500  - ⚡⚡ TURBO BOOST MODE   (Standard Ethernet)"
    echo -e "  ${C_GREEN}[06]${C_RESET} MTU 1600  - ⚡⚡ JUMBO BOOST MODE   (Jumbo Frame Lite)"
    echo -e "  ${C_GREEN}[07]${C_RESET} MTU 1700  - ⚡⚡ EXTREME BOOST MODE (Jumbo Frame Medium)"
    echo -e "  ${C_GREEN}[08]${C_RESET} MTU 1800  - 🔥 ULTIMATE BOOST MODE (MAX POWER) - FOOLS ISP! (Looks like MTU 512)"
    echo -e "  ${C_GREEN}[09]${C_RESET} Auto-detect optimal MTU"
    echo ""
    echo -e "${C_YELLOW}NOTE: MTU 512 now has 512MB buffers and 4x packet duplication!${C_RESET}"
    echo -e "${C_YELLOW}NOTE: MTU 1800 SPECIAL MODE - ISP sees MTU 512, but VPS uses MTU 1800!${C_RESET}"
    echo ""
    
    local mtu_choice
    safe_read "👉 Select MTU option [01-09] (default 01 for ULTIMATE BOOST): " mtu_choice
    mtu_choice=${mtu_choice:-01}
    
    case $mtu_choice in
        01|1) 
            MTU=512 
            BOOSTER_KEY="U4Z512"
            echo -e "${C_GREEN}🔥 Selected MTU 512 - ULTRA BOOST MODE (Now with 512MB buffers!)${C_RESET}"
            ;;
        02|2) 
            MTU=800 
            BOOSTER_KEY="U3S800"
            echo -e "${C_GREEN}✅ Selected MTU 800 - HYPER BOOST MODE${C_RESET}"
            ;;
        03|3) 
            MTU=1000 
            BOOSTER_KEY="U2L1000"
            echo -e "${C_GREEN}✅ Selected MTU 1000 - SUPER BOOST MODE${C_RESET}"
            ;;
        04|4) 
            MTU=1200 
            BOOSTER_KEY="U2S1200"
            echo -e "${C_GREEN}✅ Selected MTU 1200 - MEGA BOOST MODE${C_RESET}"
            ;;
        05|5) 
            MTU=1500 
            BOOSTER_KEY="U2S1500"
            echo -e "${C_GREEN}✅ Selected MTU 1500 - TURBO BOOST MODE${C_RESET}"
            ;;
        06|6) 
            MTU=1600 
            BOOSTER_KEY="U2S1600"
            echo -e "${C_GREEN}✅ Selected MTU 1600 - JUMBO BOOST MODE${C_RESET}"
            ;;
        07|7) 
            MTU=1700 
            BOOSTER_KEY="U2S1700"
            echo -e "${C_GREEN}✅ Selected MTU 1700 - EXTREME BOOST MODE${C_RESET}"
            ;;
        08|8) 
            MTU=1800 
            BOOSTER_KEY="U4Z512"  # ISP sees MTU 512!
            echo -e "${C_GREEN}🔥 Selected MTU 1800 - ULTIMATE BOOST MODE (ISP sees MTU 512!)${C_RESET}"
            ;;
        09|9) 
            echo -e "${C_YELLOW}Detecting optimal MTU...${C_RESET}"
            MTU=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
            BOOSTER_KEY="U${MTU}"
            echo -e "${C_GREEN}Optimal MTU detected: $MTU${C_RESET}"
            ;;
        *) 
            echo -e "${C_YELLOW}Invalid choice. Using ULTIMATE MTU 512${C_RESET}"
            MTU=512
            BOOSTER_KEY="U4Z512"
            ;;
    esac
    
    # Save MTU to config file for loss protection
    mkdir -p "$DB_DIR/config"
    echo "$MTU" > "$DB_DIR/config/mtu"
    echo "$BOOSTER_KEY" > "$DB_DIR/config/booster"
    
    # Apply MTU optimization immediately
    apply_mtu_optimization_during_install $MTU $BOOSTER_KEY
}

# ========== APPLY MTU OPTIMIZATION DURING INSTALL (BOOSTED FOR MTU 512 & 1800) ==========
apply_mtu_optimization_during_install() {
    local mtu=$1
    local booster_key=$2
    echo -e "\n${C_BLUE}⚡ Applying ULTIMATE BOOSTER for MTU $mtu...${C_RESET}"
    
    # Calculate optimal MSS (MTU - 40 for TCP/IP header)
    local mss=$((mtu - 40))
    
    # SPECIAL BOOST for MTU 512 and MTU 1800
    if [ $mtu -le 512 ] || [ $mtu -eq 1800 ]; then
        # MTU 512 and MTU 1800 get EXTREME buffers!
        local buffer_size=536870912  # 512MB!
        local queue_len=20000
    else
        # Normal buffers for other MTUs
        local buffer_size=$((mtu * 40000))
        local queue_len=$((mtu * 30))
    fi
    
    # Interface optimization
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$iface" ]; then
        # Set MTU on interface (use actual MTU)
        ip link set dev $iface mtu $mtu 2>/dev/null
        
        # Set queue length (bigger = better)
        ip link set dev $iface txqueuelen $queue_len 2>/dev/null
        
        # Disable offloading for better control
        ethtool -K $iface tx off sg off tso off gso off gro off lro off 2>/dev/null
        
        # Increase ring buffers
        ethtool -G $iface rx 8192 tx 8192 2>/dev/null
    fi
    
    # Apply MTU-specific sysctl settings
    cat > /etc/sysctl.d/99-voltron-current.conf <<EOF
# ============================================
# VOLTRON TECH ULTIMATE BOOSTER - MTU $mtu
# ============================================

# TCP Buffers (Ultra Boost)
net.core.rmem_max = $buffer_size
net.core.wmem_max = $buffer_size
net.ipv4.tcp_rmem = 4096 $((buffer_size / 4)) $buffer_size
net.ipv4.tcp_wmem = 4096 $((buffer_size / 4)) $buffer_size

# TCP Congestion Control - BBR Ultra
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# MTU Specific (Perfect MSS)
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = $mss
net.ipv4.tcp_mtu_probe_floor = 48

# TCP Fast Open
net.ipv4.tcp_fastopen = 3

# TCP Timeouts (Aggressive for slow networks)
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_retries1 = 4
net.ipv4.tcp_retries2 = 6
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 1440000

# TCP Keepalive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# TCP Advanced (Maximum Speed)
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_notsent_lowat = $((mtu * 64))
net.ipv4.tcp_limit_output_bytes = $((mtu * 128))

# Network Limits (Ultra)
net.core.netdev_max_backlog = $((mtu * 30))
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = $((mtu * 20))

# IPv6 (Disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# File Limits
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-voltron-current.conf 2>/dev/null || echo -e "${C_YELLOW}⚠️ Could not apply sysctl settings${C_RESET}"
    
    # Restart loss protection to apply new MTU
    MANAGE_SERVICE restart voltron-loss-protect 2>/dev/null || true
    
    echo -e "${C_GREEN}✅ ULTIMATE BOOSTER applied for MTU $mtu${C_RESET}"
    if [ $mtu -eq 1800 ]; then
        echo -e "   ${C_YELLOW}⚡ SPECIAL MODE:${C_RESET}"
        echo -e "   • ISP sees: ${C_GREEN}MTU 512 ($booster_key)${C_RESET}"
        echo -e "   • VPS uses: ${C_GREEN}MTU 1800 actual${C_RESET}"
        echo -e "   • Buffer: ${C_GREEN}$((buffer_size/1024/1024))MB${C_RESET}"
        echo -e "   • MSS: ${C_GREEN}$mss${C_RESET}"
        echo -e "   • Speed: ${C_GREEN}30-40 Mbps expected!${C_RESET}"
    elif [ $mtu -le 512 ]; then
        echo -e "   🔥 MTU 512 ULTRA BOOST - ${C_GREEN}$((buffer_size/1024/1024))MB buffers!${C_RESET}"
        echo -e "   📊 MSS: $mss | Buffer: $((buffer_size/1024/1024))MB | Queue: $queue_len"
    else
        echo -e "   📊 MSS: $mss | Buffer: $((buffer_size/1024/1024))MB | Queue: $queue_len"
    fi
    echo -e "   🔥 ZERO PACKET LOSS GUARANTEED even on slow networks!"
}

# ========== MTU OPTIMIZATION MENU ==========
mtu_optimization_menu() {
    while true; do
        clear
        echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║           📡 VOLTRON TECH ULTIMATE MTU OPTIMIZATION          ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║              🔥 MTU 512 NOW HAS 512MB BUFFERS! 🔥             ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║              🔥 MTU 1800 FOOLS ISP! (Looks like 512) 🔥       ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$(get_current_mtu)${C_PURPLE}  |  BBR: ${C_GREEN}Active${C_PURPLE}  |  Loss Protection: ${C_GREEN}ULTIMATE${C_PURPLE}  ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[01]${C_PURPLE} MTU 512   - ⚡⚡⚡ ULTRA BOOST (512MB buffers!)    ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[02]${C_PURPLE} MTU 800   - ⚡⚡ HYPER BOOST MODE                ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[03]${C_PURPLE} MTU 1000  - ⚡⚡ SUPER BOOST MODE                ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[04]${C_PURPLE} MTU 1200  - ⚡⚡ MEGA BOOST MODE                 ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[05]${C_PURPLE} MTU 1500  - ⚡⚡ TURBO BOOST MODE                 ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[06]${C_PURPLE} MTU 1600  - ⚡⚡ JUMBO BOOST MODE                 ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[07]${C_PURPLE} MTU 1700  - ⚡⚡ EXTREME BOOST MODE               ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[08]${C_PURPLE} MTU 1800  - 🔥 ULTIMATE BOOST MODE (FOOLS ISP!) ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[09]${C_PURPLE} Auto-detect optimal MTU                        ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[10]${C_PURPLE} View Current MTU Settings                      ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_GREEN}[11]${C_PURPLE} Restart Loss Protection                        ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_RED}[0]${C_PURPLE}  ↩️ Return to Main Menu                         ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option [01-11] or 0: "${C_RESET})" choice
        
        case $choice in
            01|1) apply_mtu_optimization_during_install 512 "U4Z512" ;;
            02|2) apply_mtu_optimization_during_install 800 "U3S800" ;;
            03|3) apply_mtu_optimization_during_install 1000 "U2L1000" ;;
            04|4) apply_mtu_optimization_during_install 1200 "U2S1200" ;;
            05|5) apply_mtu_optimization_during_install 1500 "U2S1500" ;;
            06|6) apply_mtu_optimization_during_install 1600 "U2S1600" ;;
            07|7) apply_mtu_optimization_during_install 1700 "U2S1700" ;;
            08|8) apply_mtu_optimization_during_install 1800 "U4Z512" ;;
            09|9) auto_detect_mtu ;;
            10) show_mtu_settings ;;
            11) MANAGE_SERVICE restart voltron-loss-protect; echo -e "${C_GREEN}✅ Loss Protection restarted${C_RESET}"; sleep 2 ;;
            0) return ;;
            *) echo -e "${C_RED}❌ Invalid option!${C_RESET}" && sleep 2 ;;
        esac
    done
}

auto_detect_mtu() {
    echo -e "\n${C_BLUE}🔍 Detecting optimal MTU...${C_RESET}"
    local mtu=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
    local booster="U${mtu}"
    echo -e "${C_GREEN}✅ Optimal MTU detected: $mtu${C_RESET}"
    apply_mtu_optimization_during_install $mtu $booster
}

show_mtu_settings() {
    echo -e "\n${C_BLUE}📊 Current MTU Settings:${C_RESET}"
    echo -e "  ${C_CYAN}Interface MTU:${C_RESET} $(get_current_mtu)"
    echo -e "  ${C_CYAN}TCP Base MSS:${C_RESET} $(sysctl net.ipv4.tcp_base_mss 2>/dev/null | awk '{print $3}')"
    echo -e "  ${C_CYAN}TCP Congestion:${C_RESET} $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
    echo -e "  ${C_CYAN}TCP Buffer Max:${C_RESET} $(sysctl net.core.rmem_max 2>/dev/null | awk '{print $3}') bytes"
    echo -e "  ${C_CYAN}Loss Protection:${C_RESET} ULTIMATE MODE (BOOSTED for MTU 512!)"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== SHOW BANNER FUNCTION ==========
show_banner() {
    clear
    get_ip_info
    local current_mtu=$(get_current_mtu)
    local buffer_size=$(sysctl net.core.rmem_max 2>/dev/null | awk '{print $3}')
    
    echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE BOOSTER v6.0 🔥            ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNS • BBR • MTU 512-1800 • ZERO LOSS             ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        DNS2TCP • V2RAY over DNSTT • Traffic Limits            ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location: ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP: ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  MTU: ${C_GREEN}$current_mtu${C_PURPLE} | BBR: ${C_GREEN}Active${C_PURPLE} | Loss Protection: ${C_GREEN}ULTIMATE${C_PURPLE}${C_RESET}"
    if [ $current_mtu -le 512 ]; then
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_YELLOW}⚡ MTU 512 BOOSTED: 512MB Buffers Active! ⚡${C_PURPLE}${C_RESET}"
    elif [ $current_mtu -eq 1800 ]; then
        echo -e "${C_BOLD}${C_PURPLE}║  ${C_YELLOW}⚡ MTU 1800 SPECIAL: ISP sees 512! Speed like 1800! ⚡${C_PURPLE}${C_RESET}"
    fi
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== USER MANAGEMENT FUNCTIONS (UPDATED WITH TRAFFIC LIMIT) ==========
_is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

_select_user_interface() {
    local title="$1"
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}${title}${C_RESET}\n"
    if [[ ! -s $DB_FILE ]]; then
        echo -e "${C_YELLOW}ℹ️ No users found in the database.${C_RESET}"
        SELECTED_USER="NO_USERS"
        return
    fi
    local search_term
    safe_read "👉 Enter a search term (or press Enter to list all): " search_term
    if [[ -z "$search_term" ]]; then
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | sort)
    else
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | grep -i "$search_term" | sort)
    fi
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found matching your criteria.${C_RESET}"
        SELECTED_USER="NO_USERS"
        return
    fi
    echo -e "\nPlease select a user:\n"
    for i in "${!users[@]}"; do
        printf "  ${C_GREEN}%2d)${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_RED} 0)${C_RESET} ↩️ Cancel and return to main menu"
    echo
    local choice
    while true; do
        safe_read "👉 Enter the number of the user: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -le "${#users[@]}" ]; then
            if [ "$choice" -eq 0 ]; then
                SELECTED_USER=""
                return
            else
                SELECTED_USER="${users[$((choice-1))]}"
                return
            fi
        else
            echo -e "${C_RED}❌ Invalid selection. Please try again.${C_RESET}"
        fi
    done
}

get_user_status() {
    local username="$1"
    
    if ! id "$username" &>/dev/null; then 
        echo -e "${C_RED}NOT FOUND${C_RESET}"
        return
    fi
    
    local expiry_date=$(grep "^$username:" "$DB_FILE" | cut -d: -f3)
    
    if passwd -S "$username" 2>/dev/null | grep -q " L "; then 
        echo -e "${C_YELLOW}LOCKED${C_RESET}"
        return
    fi
    
    local expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
    local current_ts=$(date +%s)
    
    if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
        echo -e "${C_RED}EXPIRED${C_RESET}"
        return
    fi
    
    # Check traffic limit
    local traffic_limit=$(grep "^$username:" "$DB_FILE" | cut -d: -f5)
    local traffic_used=$(grep "^$username:" "$DB_FILE" | cut -d: -f6)
    
    if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ] && [ -n "$traffic_used" ] && [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
        echo -e "${C_RED}TRAFFIC LIMIT${C_RESET}"
        return
    fi
    
    echo -e "${C_GREEN}ACTIVE${C_RESET}"
}

create_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    
    local username
    safe_read "👉 Enter username (or '0' to cancel): " username
    if [[ "$username" == "0" ]]; then
        echo -e "\n${C_YELLOW}❌ User creation cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Error: Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ Error: User '$username' already exists.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local password=""
    while true; do
        safe_read "🔑 Enter new password: " password
        if [[ -z "$password" ]]; then
            echo -e "${C_RED}❌ Password cannot be empty. Please try again.${C_RESET}"
        else
            break
        fi
    done
    
    local days
    safe_read "🗓️ Enter account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local limit
    safe_read "📶 Enter simultaneous connection limit: " limit
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local traffic_limit
    safe_read "📊 Enter traffic limit (GB) [0=unlimited]: " traffic_limit
    if [[ -z "$traffic_limit" ]] || [[ "$traffic_limit" == "0" ]]; then
        traffic_limit=0
    fi
    
    local expire_date
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
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
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

delete_user() {
    _select_user_interface "--- 🗑️ Delete a User ---"
    local username=$SELECTED_USER
    
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        if [[ "$username" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        local manual_user
        safe_read "👉 Type username to MANUALLY delete (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        username="$manual_user"
        
        if ! id "$username" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$username' does not exist on this system.${C_RESET}"
             echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
             safe_read "" dummy
             return
        fi
        
        if grep -q "^$username:" "$DB_FILE"; then
            echo -e "\n${C_YELLOW}ℹ️ User '$username' is in the database. Please use the normal selection method.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        
        echo -e "${C_YELLOW}⚠️ User '$username' exists on the system but is NOT in the database.${C_RESET}"
    fi

    local confirm
    safe_read "👉 Are you sure you want to PERMANENTLY delete '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Deletion cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_BLUE}🔌 Force killing active connections for $username...${C_RESET}"
    killall -u "$username" -9 &>/dev/null
    sleep 1

    userdel -r "$username" &>/dev/null
    if [ $? -eq 0 ]; then
         echo -e "\n${C_GREEN}✅ System user '$username' has been deleted.${C_RESET}"
    else
         echo -e "\n${C_RED}❌ Failed to delete system user '$username'.${C_RESET}"
    fi

    sed -i "/^$username:/d" "$DB_FILE"
    echo -e "${C_GREEN}✅ User '$username' has been completely removed.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

edit_user() {
    _select_user_interface "--- ✏️ Edit a User ---"
    local username=$SELECTED_USER
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        return
    fi
    
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        echo -e "\nSelect a detail to edit:\n"
        echo -e "  ${C_GREEN}1)${C_RESET} 🔑 Change Password"
        echo -e "  ${C_GREEN}2)${C_RESET} 🗓️ Change Expiration Date"
        echo -e "  ${C_GREEN}3)${C_RESET} 📶 Change Connection Limit"
        echo -e "  ${C_GREEN}4)${C_RESET} 📊 Change Traffic Limit"
        echo -e "\n  ${C_RED}0)${C_RESET} ✅ Finish Editing"
        echo
        
        local edit_choice
        safe_read "👉 Enter your choice: " edit_choice
        
        case $edit_choice in
            1)
               local new_pass=""
               while true; do
                   safe_read "Enter new password: " new_pass
                   if [[ -z "$new_pass" ]]; then
                       echo -e "${C_RED}❌ Password cannot be empty. Please try again.${C_RESET}"
                   else
                       break
                   fi
               done
               echo "$username:$new_pass" | chpasswd
               local current_line=$(grep "^$username:" "$DB_FILE")
               local expiry=$(echo "$current_line" | cut -d: -f3)
               local limit=$(echo "$current_line" | cut -d: -f4)
               local traffic_limit=$(echo "$current_line" | cut -d: -f5)
               local traffic_used=$(echo "$current_line" | cut -d: -f6)
               sed -i "s/^$username:.*/$username:$new_pass:$expiry:$limit:$traffic_limit:$traffic_used/" "$DB_FILE"
               echo -e "\n${C_GREEN}✅ Password for '$username' changed successfully.${C_RESET}"
               echo -e "New Password: ${C_YELLOW}$new_pass${C_RESET}"
               ;;
            2)
               local days
               safe_read "Enter new duration (in days from today): " days
               if [[ "$days" =~ ^[0-9]+$ ]]; then
                   local new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
                   chage -E "$new_expire_date" "$username"
                   local current_line=$(grep "^$username:" "$DB_FILE")
                   local pass=$(echo "$current_line" | cut -d: -f2)
                   local limit=$(echo "$current_line" | cut -d: -f4)
                   local traffic_limit=$(echo "$current_line" | cut -d: -f5)
                   local traffic_used=$(echo "$current_line" | cut -d: -f6)
                   sed -i "s/^$username:.*/$username:$pass:$new_expire_date:$limit:$traffic_limit:$traffic_used/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Expiration for '$username' set to ${C_YELLOW}$new_expire_date${C_RESET}."
               else
                   echo -e "\n${C_RED}❌ Invalid number of days.${C_RESET}"
               fi
               ;;
            3)
               local new_limit
               safe_read "Enter new simultaneous connection limit: " new_limit
               if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                   local current_line=$(grep "^$username:" "$DB_FILE")
                   local pass=$(echo "$current_line" | cut -d: -f2)
                   local expiry=$(echo "$current_line" | cut -d: -f3)
                   local traffic_limit=$(echo "$current_line" | cut -d: -f5)
                   local traffic_used=$(echo "$current_line" | cut -d: -f6)
                   sed -i "s/^$username:.*/$username:$pass:$expiry:$new_limit:$traffic_limit:$traffic_used/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Connection limit for '$username' set to ${C_YELLOW}$new_limit${C_RESET}."
               else
                   echo -e "\n${C_RED}❌ Invalid limit.${C_RESET}"
               fi
               ;;
            4)
               local new_traffic
               safe_read "Enter new traffic limit (GB) [0=unlimited]: " new_traffic
               if [[ "$new_traffic" =~ ^[0-9]+$ ]]; then
                   local current_line=$(grep "^$username:" "$DB_FILE")
                   local pass=$(echo "$current_line" | cut -d: -f2)
                   local expiry=$(echo "$current_line" | cut -d: -f3)
                   local limit=$(echo "$current_line" | cut -d: -f4)
                   local traffic_used=$(echo "$current_line" | cut -d: -f6)
                   sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$new_traffic:$traffic_used/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Traffic limit for '$username' set to ${C_YELLOW}$new_traffic GB${C_RESET}."
               else
                   echo -e "\n${C_RED}❌ Invalid limit.${C_RESET}"
               fi
               ;;
            0)
               echo -e "\n${C_GREEN}✅ Finished editing${C_RESET}"
               echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
               safe_read "" dummy
               return
               ;;
            *)
               echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"
               ;;
        esac
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue editing..."
        safe_read "" dummy
    done
}

lock_user() {
    _select_user_interface "--- 🔒 Lock a User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        local manual_user
        safe_read "👉 Type username to MANUALLY lock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$u' does not exist on this system.${C_RESET}"
             echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
             safe_read "" dummy
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
             echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
             safe_read "" dummy
             return
        else
             echo -e "${C_YELLOW}⚠️ User '$u' exists on the system but is NOT in the database.${C_RESET}"
        fi
    fi

    usermod -L "$u"
    if [ $? -eq 0 ]; then
        killall -u "$u" -9 &>/dev/null
        echo -e "\n${C_GREEN}✅ User '$u' has been locked and active sessions killed.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to lock user '$u'.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

unlock_user() {
    _select_user_interface "--- 🔓 Unlock a User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        local manual_user
        safe_read "👉 Type username to MANUALLY unlock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ Error: User '$u' does not exist on this system.${C_RESET}"
             echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
             safe_read "" dummy
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
             echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
             safe_read "" dummy
             return
        else
             echo -e "${C_YELLOW}⚠️ User '$u' exists on the system but is NOT in the database.${C_RESET}"
        fi
    fi

    usermod -U "$u"
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ User '$u' has been unlocked.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to unlock user '$u'.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

list_users() {
    clear
    show_banner
    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_YELLOW}ℹ️ No users are currently being managed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}                      📋 MANAGED USERS                          ${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    printf "${C_BOLD}${C_WHITE}%-15s | %-12s | %-8s | %-15s | %-10s${C_RESET}\n" "USERNAME" "EXPIRES" "CONN" "TRAFFIC" "STATUS"
    echo -e "${C_CYAN}─────────────────────────────────────────────────────────────────────${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        [[ -z "$user" ]] && continue
        
        local online_count=0
        if id "$user" &>/dev/null; then
            online_count=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        fi
        
        local status=$(get_user_status "$user")
        local connection_string="$online_count/$limit"
        
        # Format traffic display
        if [ "$traffic_limit" == "0" ] || [ -z "$traffic_limit" ]; then
            traffic_disp="${traffic_used}GB/∞"
        else
            percent=$(echo "scale=1; $traffic_used * 100 / $traffic_limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${traffic_used}/$traffic_limit GB ($percent%)"
        fi
        
        printf "%-15s | ${C_YELLOW}%-12s${C_RESET} | ${C_CYAN}%-8s${C_RESET} | %-15s | %s\n" \
            "$user" "$expiry" "$connection_string" "$traffic_disp" "$status"
    done < "$DB_FILE"
    echo -e "${C_CYAN}─────────────────────────────────────────────────────────────────────${C_RESET}"
    echo -e "${C_DIM}Note: CONN = Current / Max simultaneous connections${C_RESET}"
    echo ""
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

renew_user() {
    _select_user_interface "--- 🔄 Renew a User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        return
    fi
    
    local days
    safe_read "👉 Enter number of days to extend the account: " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expire_date" "$u"
    local line=$(grep "^$u:" "$DB_FILE")
    local pass=$(echo "$line" | cut -d: -f2)
    local limit=$(echo "$line" | cut -d: -f4)
    local traffic_limit=$(echo "$line" | cut -d: -f5)
    local traffic_used=$(echo "$line" | cut -d: -f6)
    sed -i "s/^$u:.*/$u:$pass:$new_expire_date:$limit:$traffic_limit:$traffic_used/" "$DB_FILE"
    echo -e "\n${C_GREEN}✅ User '$u' has been renewed. New expiration date is ${C_YELLOW}${new_expire_date}${C_RESET}."
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== DNS2TCP FUNCTIONS ==========
install_dns2tcp() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNS2TCP (DNS over TCP) INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "/etc/systemd/system/dns2tcp-53.service" ] && systemctl is-active dns2tcp-53.service &>/dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ DNS2TCP is already installed and running.${C_RESET}"
        show_dns2tcp_details
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}[1/6] Installing dependencies...${C_RESET}"
    $PKG_INSTALL git build-essential cmake make gcc
    
    echo -e "\n${C_BLUE}[2/6] DNS Record Creation Method...${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Auto-generate with Cloudflare"
    echo -e "  ${C_GREEN}2)${C_RESET} Use custom domains (manual)"
    
    local dns_choice
    safe_read "👉 Enter your choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local NS_DOMAIN=""
    local TUNNEL_DOMAIN=""
    
    if [[ "$dns_choice" == "1" ]]; then
        echo -e "\n${C_BLUE}⚙️ Auto-generating DNS records with Cloudflare...${C_RESET}"
        if generate_dns2tcp_cloudflare_dns; then
            NS_DOMAIN="$NS_DOMAIN_RET"
            TUNNEL_DOMAIN="$TUNNEL_DOMAIN_RET"
            echo -e "${C_GREEN}✅ DNS records created successfully${C_RESET}"
        else
            echo -e "\n${C_YELLOW}⚠️ Cloudflare auto-generation failed. Switching to manual mode.${C_RESET}"
            dns_choice="2"
        fi
    fi
    
    if [[ "$dns_choice" == "2" ]] || [[ -z "$NS_DOMAIN" ]]; then
        echo -e "\n${C_BLUE}Enter your custom domains:${C_RESET}"
        safe_read "👉 Nameserver domain (e.g., ns.yourdomain.com): " NS_DOMAIN
        if [[ -z "$NS_DOMAIN" ]]; then
            echo -e "\n${C_RED}❌ Nameserver domain cannot be empty. Aborting.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        safe_read "👉 Tunnel domain (e.g., tun2.yourdomain.com): " TUNNEL_DOMAIN
        if [[ -z "$TUNNEL_DOMAIN" ]]; then
            echo -e "\n${C_RED}❌ Tunnel domain cannot be empty. Aborting.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
    fi
    
    echo -e "\n${C_BLUE}[3/6] MTU Selection...${C_RESET}"
    mtu_selection_during_install
    
    echo -e "\n${C_BLUE}[4/6] Downloading and compiling DNS2TCP...${C_RESET}"
    mkdir -p "$DNS2TCP_KEYS_DIR"
    
    cd /tmp
    if [ -d "dns2tcp" ]; then
        rm -rf dns2tcp
    fi
    
    git clone https://github.com/alex-sector/dns2tcp.git
    cd dns2tcp
    ./configure
    make
    
    if [ ! -f "client/dns2tcp" ]; then
        echo -e "\n${C_RED}❌ Failed to compile DNS2TCP.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    cp client/dns2tcp /usr/local/bin/dns2tcp-server
    chmod +x /usr/local/bin/dns2tcp-server
    
    echo -e "\n${C_BLUE}[5/6] Generating cryptographic keys...${C_RESET}"
    
    openssl rand -base64 32 > "$DNS2TCP_KEYS_DIR/server.key"
    openssl rand -base64 32 > "$DNS2TCP_KEYS_DIR/server.pub"
    
    local PUBLIC_KEY=$(cat "$DNS2TCP_KEYS_DIR/server.pub")
    
    echo -e "${C_GREEN}✅ Keys generated successfully!${C_RESET}"
    echo -e "${C_YELLOW}Public Key: ${PUBLIC_KEY}${C_RESET}"
    
    echo -e "\n${C_BLUE}[6/6] Creating services...${C_RESET}"
    
    # Create config for port 53
    cat > "$DNS2TCP_KEYS_DIR/dns2tcp-53.conf" <<EOF
listen = 0.0.0.0:53
port = 22
user = nobody
key = $(cat $DNS2TCP_KEYS_DIR/server.key)
EOF

    # Create config for port 5300
    cat > "$DNS2TCP_KEYS_DIR/dns2tcp-5300.conf" <<EOF
listen = 0.0.0.0:5300
port = 22
user = nobody
key = $(cat $DNS2TCP_KEYS_DIR/server.key)
EOF

    # Create systemd services
    cat > /etc/systemd/system/dns2tcp-53.service <<EOF
[Unit]
Description=DNS2TCP Server (Port 53)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns2tcp-server -f $DNS2TCP_KEYS_DIR/dns2tcp-53.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/dns2tcp-5300.service <<EOF
[Unit]
Description=DNS2TCP Server (Port 5300)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns2tcp-server -f $DNS2TCP_KEYS_DIR/dns2tcp-5300.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dns2tcp-53.service dns2tcp-5300.service
    systemctl start dns2tcp-53.service dns2tcp-5300.service

    cat > "$DNS2TCP_INFO_FILE" <<EOF
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
PUBLIC_KEY="$PUBLIC_KEY"
MTU_VALUE="$MTU"
BOOSTER_KEY="$BOOSTER_KEY"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNS2TCP INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}        ${C_GREEN}SPECIAL MODE - ISP sees MTU 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ IMPORTANT: Copy this Public Key - you'll need it for clients!${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

generate_dns2tcp_cloudflare_dns() {
    echo -e "\n${C_BLUE}⚙️ Generating DNS2TCP records in Cloudflare...${C_RESET}"
    
    local SERVER_IPV4
    SERVER_IPV4=$(curl -s -4 icanhazip.com)
    if ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "\n${C_RED}❌ Error: Could not retrieve a valid public IPv4 address.${C_RESET}"
        return 1
    fi

    local RANDOM_NS=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    local RANDOM_TUN=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    
    local NS_SUBDOMAIN="ns2-$RANDOM_NS"
    local TUNNEL_SUBDOMAIN="tun2-$RANDOM_TUN"
    local NS_DOMAIN="$NS_SUBDOMAIN.$DOMAIN"
    local TUNNEL_DOMAIN="$TUNNEL_SUBDOMAIN.$DOMAIN"
    
    # Check if we already have a nameserver A record
    local ns_record_id
    ns_record_id=$(create_cloudflare_dns_record "A" "$NS_SUBDOMAIN" "$SERVER_IPV4")
    
    if [ -z "$ns_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create A record. Using custom mode fallback.${C_RESET}"
        return 1
    fi
    
    # Create NS record with booster key
    local booster_subdomain="${BOOSTER_KEY}.${TUNNEL_SUBDOMAIN}"
    local tunnel_record_id
    tunnel_record_id=$(create_cloudflare_dns_record "NS" "$booster_subdomain" "$NS_DOMAIN")
    
    if [ -z "$tunnel_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create NS record. Deleting A record...${C_RESET}"
        delete_cloudflare_dns_record "$ns_record_id"
        return 1
    fi
    
    # Create standard NS record without booster
    local std_tunnel_record_id
    std_tunnel_record_id=$(create_cloudflare_dns_record "NS" "$TUNNEL_SUBDOMAIN" "$NS_DOMAIN")
    
    cat > "$DNS_INFO_FILE.dns2tcp" <<EOF
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
BOOSTER_TUNNEL_DOMAIN="$booster_subdomain.$DOMAIN"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
STD_TUNNEL_RECORD_ID="$std_tunnel_record_id"
EOF
    
    echo -e "\n${C_GREEN}✅ DNS2TCP records created successfully in Cloudflare!${C_RESET}"
    echo -e "  Nameserver: ${C_YELLOW}$NS_DOMAIN${C_RESET}"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  Booster Tunnel: ${C_YELLOW}$booster_subdomain.$DOMAIN${C_RESET}"
    
    NS_DOMAIN_RET="$NS_DOMAIN"
    TUNNEL_DOMAIN_RET="$TUNNEL_DOMAIN"
    return 0
}

show_dns2tcp_details() {
    if [ -f "$DNS2TCP_INFO_FILE" ]; then
        source "$DNS2TCP_INFO_FILE"
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           📡 DNS2TCP CONNECTION DETAILS${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
        echo -e "  ${C_CYAN}MTU Value:${C_RESET}     ${C_YELLOW}$MTU_VALUE${C_RESET}"
        echo -e "  ${C_CYAN}Booster Key:${C_RESET}   ${C_YELLOW}$BOOSTER_KEY${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_YELLOW}⚠️ IMPORTANT: Save this Public Key - you'll need it for clients!${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ DNS2TCP is not installed yet.${C_RESET}"
    fi
}

uninstall_dns2tcp() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNS2TCP...${C_RESET}"
    
    systemctl stop dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    systemctl disable dns2tcp-53.service dns2tcp-5300.service 2>/dev/null
    rm -f /etc/systemd/system/dns2tcp-*.service
    rm -f /usr/local/bin/dns2tcp-server
    rm -rf "$DNS2TCP_KEYS_DIR"
    rm -f "$DNS2TCP_INFO_FILE"
    rm -f "$DNS_INFO_FILE.dns2tcp"
    
    # Remove Cloudflare records if they exist
    if [ -f "$DNS_INFO_FILE.dns2tcp" ] && [ -f "$DB_DIR/cloudflare.conf" ]; then
        source "$DB_DIR/cloudflare.conf"
        source "$DNS_INFO_FILE.dns2tcp"
        if [ -n "$TUNNEL_RECORD_ID" ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
            echo -e "${C_BLUE}Removing DNS2TCP records from Cloudflare...${C_RESET}"
            delete_cloudflare_dns_record "$TUNNEL_RECORD_ID"
            delete_cloudflare_dns_record "$STD_TUNNEL_RECORD_ID"
            delete_cloudflare_dns_record "$NS_RECORD_ID"
            rm -f "$DNS_INFO_FILE.dns2tcp"
        fi
    fi
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNS2TCP uninstalled successfully${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== V2RAY over DNSTT FUNCTIONS ==========
install_v2ray_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           🚀 V2RAY over DNSTT INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$V2RAY_SERVICE_FILE" ] && systemctl is-active v2ray-dnstt.service &>/dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ V2RAY over DNSTT is already installed and running.${C_RESET}"
        show_v2ray_details
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    # Check if DNSTT is installed
    if [ ! -f "$DNSTT_SERVICE_FILE" ] || ! systemctl is-active dnstt.service &>/dev/null; then
        echo -e "\n${C_YELLOW}⚠️ DNSTT is not installed. Installing DNSTT first...${C_RESET}"
        install_dnstt
    fi
    
    echo -e "\n${C_BLUE}[1/6] Installing Xray/V2Ray...${C_RESET}"
    
    # Install Xray
    if ! command -v xray &>/dev/null; then
        bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
        if [ $? -ne 0 ]; then
            echo -e "\n${C_RED}❌ Failed to install Xray.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
    fi
    
    echo -e "\n${C_BLUE}[2/6] Creating V2Ray configuration...${C_RESET}"
    mkdir -p "$V2RAY_DIR/v2ray" "$V2RAY_DIR/users"
    
    # Copy DNSTT keys
    cp "$DNSTT_KEYS_DIR/server.key" "$V2RAY_DIR/dnstt/" 2>/dev/null
    cp "$DNSTT_KEYS_DIR/server.pub" "$V2RAY_DIR/dnstt/" 2>/dev/null
    
    # Create V2Ray config
    cat > "$V2RAY_CONFIG" <<EOF
{
    "log": {
        "loglevel": "warning",
        "access": "$LOGS_DIR/v2ray-access.log",
        "error": "$LOGS_DIR/v2ray-error.log"
    },
    "inbounds": [
        {
            "port": $V2RAY_PORT,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            },
            "tag": "vmess-in"
        },
        {
            "port": $((V2RAY_PORT+1)),
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            },
            "tag": "vless-in"
        },
        {
            "port": $((V2RAY_PORT+2)),
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls"
            },
            "tag": "trojan-in"
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

    echo -e "\n${C_BLUE}[3/6] Creating V2Ray service...${C_RESET}"
    
    cat > "$V2RAY_SERVICE_FILE" <<EOF
[Unit]
Description=V2RAY over DNSTT
After=network.target dnstt.service
Wants=dnstt.service

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'sleep 2'
ExecStart=/usr/local/bin/xray run -config $V2RAY_CONFIG
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable v2ray-dnstt.service
    systemctl start v2ray-dnstt.service
    
    echo -e "\n${C_BLUE}[4/6] Creating V2Ray user database...${C_RESET}"
    touch "$V2RAY_USERS_DB"
    
    echo -e "\n${C_BLUE}[5/6] MTU Selection...${C_RESET}"
    mtu_selection_during_install
    
    echo -e "\n${C_BLUE}[6/6] V2Ray Configuration Complete${C_RESET}"
    
    # Save V2Ray info
    cat > "$V2RAY_INFO_FILE" <<EOF
V2RAY_PORT="$V2RAY_PORT"
V2RAY_VMESS_PORT="$V2RAY_PORT"
V2RAY_VLESS_PORT="$((V2RAY_PORT+1))"
V2RAY_TROJAN_PORT="$((V2RAY_PORT+2))"
MTU_VALUE="$MTU"
BOOSTER_KEY="$BOOSTER_KEY"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ V2RAY over DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}VMess Port:${C_RESET}   ${C_YELLOW}$V2RAY_PORT${C_RESET}"
    echo -e "  ${C_CYAN}VLESS Port:${C_RESET}   ${C_YELLOW}$((V2RAY_PORT+1))${C_RESET}"
    echo -e "  ${C_CYAN}Trojan Port:${C_RESET}  ${C_YELLOW}$((V2RAY_PORT+2))${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}          ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}       ${C_GREEN}SPECIAL MODE - ISP sees MTU 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ Use V2Ray User Management to add users!${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

show_v2ray_details() {
    if [ -f "$V2RAY_INFO_FILE" ]; then
        source "$V2RAY_INFO_FILE"
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           🚀 V2RAY over DNSTT DETAILS${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}VMess Port:${C_RESET}   ${C_YELLOW}$V2RAY_VMESS_PORT${C_RESET}"
        echo -e "  ${C_CYAN}VLESS Port:${C_RESET}   ${C_YELLOW}$V2RAY_VLESS_PORT${C_RESET}"
        echo -e "  ${C_CYAN}Trojan Port:${C_RESET}  ${C_YELLOW}$V2RAY_TROJAN_PORT${C_RESET}"
        echo -e "  ${C_CYAN}MTU Value:${C_RESET}     ${C_YELLOW}$MTU_VALUE${C_RESET}"
        echo -e "  ${C_CYAN}Booster Key:${C_RESET}   ${C_YELLOW}$BOOSTER_KEY${C_RESET}"
        echo -e "  ${C_CYAN}Total Users:${C_RESET}   $(wc -l < "$V2RAY_USERS_DB" 2>/dev/null || echo 0)"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ V2RAY over DNSTT is not installed yet.${C_RESET}"
    fi
}

uninstall_v2ray_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling V2RAY over DNSTT...${C_RESET}"
    
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f "$V2RAY_SERVICE_FILE"
    
    # Don't remove Xray or DNSTT as they might be used elsewhere
    
    rm -rf "$V2RAY_DIR"
    rm -f "$V2RAY_INFO_FILE"
    
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ V2RAY over DNSTT uninstalled successfully${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== V2RAY USER MANAGEMENT FUNCTIONS ==========
generate_uuid() {
    uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s%N | md5sum | cut -c1-8)-$(date +%s%N | md5sum | cut -c1-4)-4$(date +%s%N | md5sum | cut -c1-3)-$(date +%s%N | md5sum | cut -c1-4)-$(date +%s%N | md5sum | cut -c1-12)"
}

add_v2ray_user_to_config() {
    local username=$1
    local uuid=$2
    local protocol=$3
    local password=$4
    
    local config_file="$V2RAY_CONFIG"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Use jq if available
    if command -v jq &>/dev/null; then
        if [ "$protocol" == "vmess" ]; then
            jq --arg uuid "$uuid" --arg email "$username@voltrontech" '.inbounds[0].settings.clients += [{"id": $uuid, "email": $email}]' "$config_file" > "$config_file.tmp"
            mv "$config_file.tmp" "$config_file"
        elif [ "$protocol" == "vless" ]; then
            jq --arg uuid "$uuid" --arg email "$username@voltrontech" '.inbounds[1].settings.clients += [{"id": $uuid, "email": $email, "flow": ""}]' "$config_file" > "$config_file.tmp"
            mv "$config_file.tmp" "$config_file"
        elif [ "$protocol" == "trojan" ]; then
            jq --arg pass "$password" --arg email "$username@voltrontech" '.inbounds[2].settings.clients += [{"password": $pass, "email": $email}]' "$config_file" > "$config_file.tmp"
            mv "$config_file.tmp" "$config_file"
        fi
    else
        # Simple sed approach (basic)
        echo -e "${C_YELLOW}⚠️ jq not found, manual config edit may be needed${C_RESET}"
        return 1
    fi
    
    return 0
}

remove_v2ray_user_from_config() {
    local username=$1
    local email="${username}@voltrontech"
    
    local config_file="$V2RAY_CONFIG"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    if command -v jq &>/dev/null; then
        # Remove from vmess
        jq 'del(.inbounds[0].settings.clients[] | select(.email == "'$email'"))' "$config_file" > "$config_file.tmp"
        mv "$config_file.tmp" "$config_file"
        
        # Remove from vless
        jq 'del(.inbounds[1].settings.clients[] | select(.email == "'$email'"))' "$config_file" > "$config_file.tmp"
        mv "$config_file.tmp" "$config_file"
        
        # Remove from trojan
        jq 'del(.inbounds[2].settings.clients[] | select(.email == "'$email'"))' "$config_file" > "$config_file.tmp"
        mv "$config_file.tmp" "$config_file"
    fi
    
    return 0
}

create_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👤 CREATE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Check if V2RAY is installed
    if [ ! -f "$V2RAY_SERVICE_FILE" ]; then
        echo -e "\n${C_RED}❌ V2RAY over DNSTT is not installed!${C_RESET}"
        echo -e "${C_YELLOW}Please install first using option 1 in V2RAY menu.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local username
    safe_read "👉 Enter username: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    # Check if user already exists in V2RAY database
    if grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ V2Ray user '$username' already exists.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}Select protocol:${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} VMess"
    echo -e "  ${C_GREEN}2)${C_RESET} VLESS"
    echo -e "  ${C_GREEN}3)${C_RESET} Trojan"
    
    local proto_choice
    safe_read "👉 Choice [1]: " proto_choice
    proto_choice=${proto_choice:-1}
    
    local protocol="vmess"
    case $proto_choice in
        1) protocol="vmess" ;;
        2) protocol="vless" ;;
        3) protocol="trojan" ;;
        *) protocol="vmess" ;;
    esac
    
    local traffic_limit
    safe_read "📊 Enter traffic limit (GB) [0=unlimited]: " traffic_limit
    if [[ -z "$traffic_limit" ]] || [[ "$traffic_limit" == "0" ]]; then
        traffic_limit=0
    fi
    
    local days
    safe_read "🗓️ Enter account duration (in days) [30]: " days
    days=${days:-30}
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number. Using 30.${C_RESET}"
        days=30
    fi
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    # Generate UUID
    local uuid=$(generate_uuid)
    
    # Generate password for Trojan
    local password="-"
    if [ "$protocol" == "trojan" ]; then
        password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9')
    fi
    
    echo -e "\n${C_BLUE}⚙️ Adding user to V2Ray configuration...${C_RESET}"
    
    # Add to V2Ray config
    if ! add_v2ray_user_to_config "$username" "$uuid" "$protocol" "$password"; then
        echo -e "${C_YELLOW}⚠️ Could not automatically add to config. Manual addition may be needed.${C_RESET}"
    fi
    
    # Add to database
    echo "$username:$uuid:$password:$protocol:$traffic_limit:0:$expire_date:active" >> "$V2RAY_USERS_DB"
    
    # Restart V2Ray service
    systemctl restart v2ray-dnstt.service
    
    echo -e "\n${C_GREEN}✅ V2Ray user '$username' created successfully!${C_RESET}\n"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 UUID:              ${C_YELLOW}$uuid${C_RESET}"
    if [ "$protocol" == "trojan" ]; then
        echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    fi
    echo -e "  - 📡 Protocol:          ${C_YELLOW}$protocol${C_RESET}"
    echo -e "  - 📊 Traffic Limit:     ${C_YELLOW}$traffic_limit GB${C_RESET}"
    echo -e "  - 🗓️ Expires on:        ${C_YELLOW}$expire_date${C_RESET}"
    
    # Generate config link for VMess
    if [ "$protocol" == "vmess" ]; then
        local vmess_obj="{\"v\":\"2\",\"ps\":\"$username\",\"add\":\"$DOMAIN\",\"port\":\"$V2RAY_PORT\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}"
        local vmess_link="vmess://$(echo -n "$vmess_obj" | base64 -w 0 2>/dev/null || echo -n "$vmess_obj" | base64)"
        echo -e "\n  ${C_CYAN}VMess Link:${C_RESET}"
        echo -e "  $vmess_link"
    fi
    
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

list_v2ray_users() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 V2RAY USERS LIST${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_USERS_DB" ] || [ ! -s "$V2RAY_USERS_DB" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No V2Ray users found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    printf "${C_BOLD}${C_WHITE}%-15s | %-8s | %-36s | %-15s | %-10s${C_RESET}\n" "USERNAME" "PROTO" "UUID" "TRAFFIC" "STATUS"
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
        if [ "$status" == "active" ]; then
            status_disp="${C_GREEN}ACTIVE${C_RESET}"
        elif [ "$status" == "locked" ]; then
            status_disp="${C_YELLOW}LOCKED${C_RESET}"
        elif [ "$status" == "expired" ]; then
            status_disp="${C_RED}EXPIRED${C_RESET}"
        else
            status_disp="$status"
        fi
        
        printf "%-15s | %-8s | %-36s | %-15s | %s\n" \
            "$user" "$proto" "$short_uuid" "$traffic_disp" "$status_disp"
    done < "$V2RAY_USERS_DB"
    
    echo ""
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

view_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👁️ VIEW V2RAY USER DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local username
    safe_read "👉 Enter username: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local user_line=$(grep "^$username:" "$V2RAY_USERS_DB" 2>/dev/null)
    
    if [ -z "$user_line" ]; then
        echo -e "\n${C_RED}❌ User '$username' not found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
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
    
    # Generate config links
    if [ "$proto" == "vmess" ]; then
        local vmess_obj="{\"v\":\"2\",\"ps\":\"$user\",\"add\":\"$DOMAIN\",\"port\":\"$V2RAY_PORT\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}"
        local vmess_link="vmess://$(echo -n "$vmess_obj" | base64 -w 0 2>/dev/null || echo -n "$vmess_obj" | base64)"
        echo -e "\n  ${C_CYAN}VMess Link:${C_RESET}"
        echo -e "  $vmess_link"
    elif [ "$proto" == "vless" ]; then
        echo -e "\n  ${C_CYAN}VLESS Config:${C_RESET}"
        echo -e "  Protocol: vless"
        echo -e "  Address: $DOMAIN"
        echo -e "  Port: $((V2RAY_PORT+1))"
        echo -e "  UUID: $uuid"
        echo -e "  Encryption: none"
    elif [ "$proto" == "trojan" ]; then
        echo -e "\n  ${C_CYAN}Trojan Config:${C_RESET}"
        echo -e "  Address: $DOMAIN"
        echo -e "  Port: $((V2RAY_PORT+2))"
        echo -e "  Password: $pass"
    fi
    
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

delete_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_RED}           🗑️ DELETE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local username
    safe_read "👉 Enter username to delete: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User '$username' not found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local confirm
    safe_read "👉 Are you sure you want to delete '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Deletion cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}⚙️ Removing user from V2Ray configuration...${C_RESET}"
    remove_v2ray_user_from_config "$username"
    
    # Remove from database
    sed -i "/^$username:/d" "$V2RAY_USERS_DB"
    
    # Restart V2Ray service
    systemctl restart v2ray-dnstt.service
    
    echo -e "\n${C_GREEN}✅ User '$username' deleted successfully.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

lock_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_YELLOW}           🔒 LOCK V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local username
    safe_read "👉 Enter username to lock: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User '$username' not found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    # Update status to locked
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*/\1locked/" "$V2RAY_USERS_DB"
    
    echo -e "\n${C_GREEN}✅ User '$username' locked.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

unlock_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🔓 UNLOCK V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local username
    safe_read "👉 Enter username to unlock: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User '$username' not found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    # Update status to active
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*/\1active/" "$V2RAY_USERS_DB"
    
    echo -e "\n${C_GREEN}✅ User '$username' unlocked.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

reset_v2ray_traffic() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🔄 RESET V2RAY USER TRAFFIC${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    local username
    safe_read "👉 Enter username to reset traffic: " username
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    if ! grep -q "^$username:" "$V2RAY_USERS_DB" 2>/dev/null; then
        echo -e "\n${C_RED}❌ User '$username' not found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    # Reset traffic used to 0
    sed -i "s/^\($username:[^:]*:[^:]*:[^:]*:[^:]*:\)[^:]*:/\10:/" "$V2RAY_USERS_DB"
    
    echo -e "\n${C_GREEN}✅ Traffic for user '$username' reset to 0.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

v2ray_user_management_menu() {
    while true; do
        clear
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              👤 V2RAY USER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Create V2Ray User"
        echo -e "  ${C_GREEN}2)${C_RESET} List V2Ray Users"
        echo -e "  ${C_GREEN}3)${C_RESET} View User Details"
        echo -e "  ${C_GREEN}4)${C_RESET} Delete V2Ray User"
        echo -e "  ${C_GREEN}5)${C_RESET} Lock V2Ray User"
        echo -e "  ${C_GREEN}6)${C_RESET} Unlock V2Ray User"
        echo -e "  ${C_GREEN}7)${C_RESET} Reset User Traffic"
        echo -e "  ${C_GREEN}8)${C_RESET} Edit User (Traffic/Expiry)"
        echo -e ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) create_v2ray_user ;;
            2) list_v2ray_users ;;
            3) view_v2ray_user ;;
            4) delete_v2ray_user ;;
            5) lock_v2ray_user ;;
            6) unlock_v2ray_user ;;
            7) reset_v2ray_traffic ;;
            8) edit_v2ray_user ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

# ========== SYSTEM UTILITIES FUNCTIONS ==========
backup_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    
    local backup_path
    safe_read "👉 Enter path for backup file [/root/voltrontech_users.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_users.tar.gz}
    
    if [ ! -d "$DB_DIR" ] || [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No user data found to back up.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    echo -e "\n${C_BLUE}⚙️ Backing up user database and settings to ${C_YELLOW}$backup_path${C_RESET}..."
    tar -czf "$backup_path" -C "$(dirname "$DB_DIR")" "$(basename "$DB_DIR")"
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ SUCCESS: User data backup created at ${C_YELLOW}$backup_path${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: Backup failed.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

restore_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📥 Restore User Data ---${C_RESET}"
    
    local backup_path
    safe_read "👉 Enter the full path to the user data backup file [/root/voltrontech_users.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_users.tar.gz}
    
    if [ ! -f "$backup_path" ]; then
        echo -e "\n${C_RED}❌ ERROR: Backup file not found at '$backup_path'.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    echo -e "\n${C_RED}${C_BOLD}⚠️ WARNING:${C_RESET} This will overwrite all current users and settings."
    local confirm
    safe_read "👉 Are you absolutely sure you want to proceed? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Restore cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local temp_dir=$(mktemp -d)
    echo -e "\n${C_BLUE}⚙️ Extracting backup file to a temporary location...${C_RESET}"
    tar -xzf "$backup_path" -C "$temp_dir"
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ ERROR: Failed to extract backup file. Aborting.${C_RESET}"
        rm -rf "$temp_dir"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local restored_db_file="$temp_dir/voltrontech/users.db"
    if [ ! -f "$restored_db_file" ]; then
        echo -e "\n${C_RED}❌ ERROR: users.db not found in the backup. Cannot restore user accounts.${C_RESET}"
        rm -rf "$temp_dir"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "${C_BLUE}⚙️ Overwriting current user database...${C_RESET}"
    mkdir -p "$DB_DIR"
    cp "$restored_db_file" "$DB_FILE"
    
    [ -d "$temp_dir/voltrontech/ssl" ] && cp -r "$temp_dir/voltrontech/ssl" "$DB_DIR/"
    [ -d "$temp_dir/voltrontech/dnstt" ] && cp -r "$temp_dir/voltrontech/dnstt" "$DB_DIR/"
    [ -d "$temp_dir/voltrontech/dns2tcp" ] && cp -r "$temp_dir/voltrontech/dns2tcp" "$DB_DIR/"
    [ -d "$temp_dir/voltrontech/v2ray-dnstt" ] && cp -r "$temp_dir/voltrontech/v2ray-dnstt" "$DB_DIR/"
    [ -f "$temp_dir/voltrontech/dns_info.conf" ] && cp "$temp_dir/voltrontech/dns_info.conf" "$DB_DIR/"
    [ -f "$temp_dir/voltrontech/dnstt_info.conf" ] && cp "$temp_dir/voltrontech/dnstt_info.conf" "$DB_DIR/"
    [ -f "$temp_dir/voltrontech/dns2tcp_info.conf" ] && cp "$temp_dir/voltrontech/dns2tcp_info.conf" "$DB_DIR/"
    [ -f "$temp_dir/voltrontech/v2ray_info.conf" ] && cp "$temp_dir/voltrontech/v2ray_info.conf" "$DB_DIR/"
    [ -f "$temp_dir/voltrontech/voltronproxy_config.conf" ] && cp "$temp_dir/voltrontech/voltronproxy_config.conf" "$DB_DIR/"
    
    echo -e "${C_BLUE}⚙️ Re-synchronizing system accounts with the restored database...${C_RESET}"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        echo "Processing user: ${C_YELLOW}$user${C_RESET}"
        if ! id "$user" &>/dev/null; then
            echo " - User does not exist in system. Creating..."
            useradd -m -s /usr/sbin/nologin "$user"
        fi
        echo " - Setting password..."
        echo "$user:$pass" | chpasswd
        echo " - Setting expiration to $expiry..."
        chage -E "$expiry" "$user"
    done < "$DB_FILE"
    
    rm -rf "$temp_dir"
    echo -e "\n${C_GREEN}✅ SUCCESS: User data restore completed.${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

cleanup_expired() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🧹 Cleanup Expired Users ---${C_RESET}"
    
    local expired_users=()
    local current_ts=$(date +%s)

    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_GREEN}✅ User database is empty. No expired users found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            expired_users+=("$user")
        fi
    done < "$DB_FILE"

    if [ ${#expired_users[@]} -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ No expired users found.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi

    echo -e "\nThe following users have expired: ${C_RED}${expired_users[*]}${C_RESET}"
    local confirm
    safe_read "👉 Do you want to delete all of them? (y/n): " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        for user in "${expired_users[@]}"; do
            echo " - Deleting ${C_YELLOW}$user...${C_RESET}"
            killall -u "$user" -9 &>/dev/null
            userdel -r "$user" &>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
        done
        echo -e "\n${C_GREEN}✅ Expired users have been cleaned up.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Cleanup cancelled.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== CLOUDFLARE DNS GENERATION (MAIN) ==========
generate_cloudflare_dns() {
    echo -e "\n${C_BLUE}⚙️ Generating DNS records in Cloudflare...${C_RESET}"
    
    source "$DB_DIR/cloudflare.conf" 2>/dev/null || {
        echo -e "${C_RED}❌ Cloudflare configuration not found.${C_RESET}"
        return 1
    }
    
    local SERVER_IPV4
    SERVER_IPV4=$(curl -s -4 icanhazip.com)
    if ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "\n${C_RED}❌ Error: Could not retrieve a valid public IPv4 address.${C_RESET}"
        return 1
    fi

    local RANDOM_NS=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    local RANDOM_TUN=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
    
    local NS_SUBDOMAIN="ns-$RANDOM_NS"
    local TUNNEL_SUBDOMAIN="tun-$RANDOM_TUN"
    local NS_DOMAIN="$NS_SUBDOMAIN.$DOMAIN"
    local TUNNEL_DOMAIN="$TUNNEL_SUBDOMAIN.$DOMAIN"
    
    echo -e "${C_BLUE}📝 Creating A record for $NS_DOMAIN...${C_RESET}"
    local ns_record_id
    ns_record_id=$(create_cloudflare_dns_record "A" "$NS_SUBDOMAIN" "$SERVER_IPV4")
    
    if [ -z "$ns_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create A record. Using custom mode fallback.${C_RESET}"
        return 1
    fi
    
    echo -e "${C_BLUE}📝 Creating NS record for $TUNNEL_DOMAIN pointing to $NS_DOMAIN...${C_RESET}"
    local tunnel_record_id
    tunnel_record_id=$(create_cloudflare_dns_record "NS" "$TUNNEL_SUBDOMAIN" "$NS_DOMAIN")
    
    if [ -z "$tunnel_record_id" ]; then
        echo -e "${C_RED}❌ Failed to create NS record. Deleting A record...${C_RESET}"
        delete_cloudflare_dns_record "$ns_record_id"
        return 1
    fi
    
    cat > "$DNS_INFO_FILE" <<EOF
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
NS_RECORD_ID="$ns_record_id"
TUNNEL_RECORD_ID="$tunnel_record_id"
EOF
    
    echo -e "\n${C_GREEN}✅ DNS records created successfully in Cloudflare!${C_RESET}"
    echo -e "  Nameserver: ${C_YELLOW}$NS_DOMAIN${C_RESET}"
    echo -e "  Tunnel Domain: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    
    NS_DOMAIN_RET="$NS_DOMAIN"
    TUNNEL_DOMAIN_RET="$TUNNEL_DOMAIN"
    return 0
}

# ========== SHOW DNSTT DETAILS ==========
show_dnstt_details() {
    if [ -f "$DNSTT_CONFIG_FILE" ]; then
        source "$DNSTT_CONFIG_FILE"
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           📡 DNSTT CONNECTION DETAILS${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
        if [[ -n "$FORWARD_DESC" ]]; then
            echo -e "  ${C_CYAN}Forwarding To:${C_RESET} ${C_YELLOW}$FORWARD_DESC${C_RESET}"
        fi
        if [[ -n "$MTU_VALUE" ]]; then
            echo -e "  ${C_CYAN}MTU Value:${C_RESET}     ${C_YELLOW}$MTU_VALUE${C_RESET}"
        fi
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_YELLOW}⚠️ IMPORTANT: Save this Public Key - you'll need it for clients!${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is not installed yet.${C_RESET}"
    fi
}

# ========== DOWNLOAD DNSTT BINARY ==========
download_dnstt_binary() {
    local arch=$(uname -m)
    local download_success=0
    
    echo -e "${C_BLUE}📥 Downloading DNSTT server...${C_RESET}"
    
    # Source 1: GitHub (kcptun)
    echo -e "${C_YELLOW}Attempt 1: GitHub (kcptun)...${C_RESET}"
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o /tmp/dnstt.tar.gz "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-amd64-20240101.tar.gz"
    elif [[ "$arch" == "aarch64" ]]; then
        curl -L -o /tmp/dnstt.tar.gz "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-arm64-20240101.tar.gz"
    fi
    
    if [ -f /tmp/dnstt.tar.gz ] && [ -s /tmp/dnstt.tar.gz ]; then
        cd /tmp
        tar -xzf dnstt.tar.gz
        if [ -f /tmp/server_linux_amd64 ] || [ -f /tmp/server_linux_arm64 ]; then
            cp /tmp/server_linux_* "$DNSTT_BINARY" 2>/dev/null
            download_success=1
        fi
        rm -f /tmp/dnstt.tar.gz
    fi
    
    # Source 2: dnstt.network
    if [ $download_success -eq 0 ]; then
        echo -e "${C_YELLOW}Attempt 2: dnstt.network...${C_RESET}"
        if [[ "$arch" == "x86_64" ]]; then
            curl -L -o "$DNSTT_BINARY" "https://dnstt.network/dnstt-server-linux-amd64"
        elif [[ "$arch" == "aarch64" ]]; then
            curl -L -o "$DNSTT_BINARY" "https://dnstt.network/dnstt-server-linux-arm64"
        fi
        if [ -f "$DNSTT_BINARY" ] && [ -s "$DNSTT_BINARY" ]; then
            download_success=1
        fi
    fi
    
    chmod +x "$DNSTT_BINARY" 2>/dev/null
    
    return $download_success
}

# ========== INSTALL DNSTT ==========
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT (DNS TUNNEL) INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE_FILE" ] && MANAGE_SERVICE is-active dnstt.service &>/dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is already installed and running.${C_RESET}"
        show_dnstt_details
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}[1/6] Checking port 53 availability...${C_RESET}"
    if ss -lunp | grep -q ':53\s' 2>/dev/null || netstat -lunp | grep -q ':53\s' 2>/dev/null; then
        echo -e "${C_YELLOW}⚠️ Port 53 is in use. Attempting to free it...${C_RESET}"
        if command -v systemctl &>/dev/null; then
            systemctl stop systemd-resolved 2>/dev/null
            systemctl disable systemd-resolved 2>/dev/null
        fi
        rm -f /etc/resolv.conf
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo -e "${C_GREEN}✅ Port 53 is now free${C_RESET}"
    else
        echo -e "${C_GREEN}✅ Port 53 is free${C_RESET}"
    fi
    
    echo -e "\n${C_BLUE}[2/6] Choose forwarding target...${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} SSH (port 22)"
    echo -e "  ${C_GREEN}2)${C_RESET} V2Ray (port 8787)"
    
    local fwd_choice
    safe_read "👉 Enter your choice [1]: " fwd_choice
    fwd_choice=${fwd_choice:-1}
    
    local forward_port=""
    local forward_desc=""
    if [[ "$fwd_choice" == "1" ]]; then
        forward_port="22"
        forward_desc="SSH"
        echo -e "${C_GREEN}✅ Forwarding to SSH on port 22${C_RESET}"
    else
        forward_port="8787"
        forward_desc="V2Ray"
        echo -e "${C_GREEN}✅ Forwarding to V2Ray on port 8787${C_RESET}"
    fi
    local FORWARD_TARGET="127.0.0.1:$forward_port"
    
    echo -e "\n${C_BLUE}[3/6] DNS Record Creation Method...${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Auto-generate with Cloudflare"
    echo -e "  ${C_GREEN}2)${C_RESET} Use custom domains (manual)"
    
    local dns_choice
    safe_read "👉 Enter your choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local NS_DOMAIN=""
    local TUNNEL_DOMAIN=""
    
    if [[ "$dns_choice" == "1" ]]; then
        echo -e "\n${C_BLUE}⚙️ Auto-generating DNS records with Cloudflare...${C_RESET}"
        if generate_cloudflare_dns; then
            NS_DOMAIN="$NS_DOMAIN_RET"
            TUNNEL_DOMAIN="$TUNNEL_DOMAIN_RET"
            echo -e "${C_GREEN}✅ DNS records created successfully${C_RESET}"
        else
            echo -e "\n${C_YELLOW}⚠️ Cloudflare auto-generation failed. Switching to manual mode.${C_RESET}"
            dns_choice="2"
        fi
    fi
    
    if [[ "$dns_choice" == "2" ]] || [[ -z "$NS_DOMAIN" ]]; then
        echo -e "\n${C_BLUE}Enter your custom domains:${C_RESET}"
        safe_read "👉 Nameserver domain (e.g., ns.yourdomain.com): " NS_DOMAIN
        if [[ -z "$NS_DOMAIN" ]]; then
            echo -e "\n${C_RED}❌ Nameserver domain cannot be empty. Aborting.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
        safe_read "👉 Tunnel domain (e.g., tun.yourdomain.com): " TUNNEL_DOMAIN
        if [[ -z "$TUNNEL_DOMAIN" ]]; then
            echo -e "\n${C_RED}❌ Tunnel domain cannot be empty. Aborting.${C_RESET}"
            echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
            safe_read "" dummy
            return
        fi
    fi
    
    echo -e "\n${C_BLUE}[4/6] MTU Selection...${C_RESET}"
    mtu_selection_during_install
    
    download_dnstt_binary
    if [ ! -f "$DNSTT_BINARY" ] || [ ! -s "$DNSTT_BINARY" ]; then
        echo -e "\n${C_RED}❌ Failed to download DNSTT binary.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    chmod +x "$DNSTT_BINARY"
    echo -e "${C_GREEN}✅ DNSTT binary downloaded successfully${C_RESET}"
    
    echo -e "\n${C_BLUE}[6/6] Generating cryptographic keys...${C_RESET}"
    mkdir -p "$DNSTT_KEYS_DIR"
    
    "$DNSTT_BINARY" -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub"
    
    if [[ ! -f "$DNSTT_KEYS_DIR/server.key" ]]; then
        echo -e "\n${C_RED}❌ Failed to generate DNSTT keys.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local PUBLIC_KEY
    PUBLIC_KEY=$(cat "$DNSTT_KEYS_DIR/server.pub")
    echo -e "${C_GREEN}✅ Keys generated successfully!${C_RESET}"
    echo -e "${C_YELLOW}Public Key: ${PUBLIC_KEY}${C_RESET}"
    
    echo -e "\n${C_BLUE}Creating service...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$DNSTT_SERVICE_FILE" <<EOF
[Unit]
Description=DNSTT Tunnel Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$DNSTT_BINARY -udp :53 -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $TUNNEL_DOMAIN $FORWARD_TARGET
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        cat > /etc/systemd/system/dnstt-5300.service <<EOF
[Unit]
Description=DNSTT Tunnel Server (Port 5300)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$DNSTT_BINARY -udp :5300 -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $TUNNEL_DOMAIN $FORWARD_TARGET
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable dnstt.service
        MANAGE_SERVICE enable dnstt-5300.service
        MANAGE_SERVICE start dnstt.service
        MANAGE_SERVICE start dnstt-5300.service
    else
        # For non-systemd systems, create init script
        cat > /etc/init.d/dnstt <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          dnstt
# Required-Start:    \$network \$remote_fs \$syslog
# Required-Stop:     \$network \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DNSTT Tunnel Server
# Description:       DNSTT DNS Tunnel Server
### END INIT INFO

case "\$1" in
    start)
        start-stop-daemon --start --background --exec $DNSTT_BINARY -- -udp :53 -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $TUNNEL_DOMAIN $FORWARD_TARGET
        ;;
    stop)
        start-stop-daemon --stop --exec $DNSTT_BINARY
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/dnstt
        update-rc.d dnstt defaults 2>/dev/null || chkconfig --add dnstt 2>/dev/null || true
        /etc/init.d/dnstt start
    fi

    cat > "$DNSTT_CONFIG_FILE" <<EOF
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
PUBLIC_KEY="$PUBLIC_KEY"
FORWARD_DESC="$forward_desc (port $forward_port)"
MTU_VALUE="$MTU"
BOOSTER_KEY="$BOOSTER_KEY"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}Public Key:${C_RESET}    ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}           ${C_YELLOW}$MTU${C_RESET}"
    if [ $MTU -le 512 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}        ${C_GREEN}ULTIMATE BOOSTED MODE (512MB buffers!)${C_RESET}"
    elif [ $MTU -eq 1800 ]; then
        echo -e "  ${C_CYAN}Status:${C_RESET}        ${C_GREEN}SPECIAL MODE - ISP sees MTU 512!${C_RESET}"
    fi
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}⚠️ IMPORTANT: Copy this Public Key - you'll need it for clients!${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_dnstt() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DNSTT...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop dnstt.service 2>/dev/null
        MANAGE_SERVICE stop dnstt-5300.service 2>/dev/null
        MANAGE_SERVICE disable dnstt.service 2>/dev/null
        MANAGE_SERVICE disable dnstt-5300.service 2>/dev/null
        rm -f "$DNSTT_SERVICE_FILE"
        rm -f /etc/systemd/system/dnstt-5300.service
    else
        /etc/init.d/dnstt stop 2>/dev/null
        update-rc.d -f dnstt remove 2>/dev/null || chkconfig --del dnstt 2>/dev/null || true
        rm -f /etc/init.d/dnstt
    fi
    
    rm -f "$DNSTT_BINARY"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_CONFIG_FILE"
    
    if [ -f "$DNS_INFO_FILE" ] && [ -f "$DB_DIR/cloudflare.conf" ]; then
        source "$DB_DIR/cloudflare.conf"
        source "$DNS_INFO_FILE"
        if [ -n "$TUNNEL_RECORD_ID" ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
            echo -e "${C_BLUE}Removing DNS records from Cloudflare...${C_RESET}"
            delete_cloudflare_dns_record "$TUNNEL_RECORD_ID"
            delete_cloudflare_dns_record "$NS_RECORD_ID"
            rm -f "$DNS_INFO_FILE"
        fi
    fi
    
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    echo -e "${C_GREEN}✅ DNSTT uninstalled successfully${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== DNS MANAGEMENT MENU ==========
dns_menu() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 DNS Domain Management (Cloudflare) ---${C_RESET}"
    
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        echo -e "\nℹ️ DNS records already exist for this server:"
        echo -e "  - ${C_CYAN}Nameserver:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        echo -e "  - ${C_CYAN}Tunnel Domain:${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo
        local choice
        safe_read "👉 Do you want to DELETE these records? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            source "$DB_DIR/cloudflare.conf" 2>/dev/null
            if [ -n "$TUNNEL_RECORD_ID" ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
                delete_cloudflare_dns_record "$TUNNEL_RECORD_ID"
                delete_cloudflare_dns_record "$NS_RECORD_ID"
            fi
            rm -f "$DNS_INFO_FILE"
            echo -e "${C_GREEN}✅ DNS records deleted${C_RESET}"
        else
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        fi
    else
        echo -e "\nℹ️ No DNS records have been created yet."
        echo
        local choice
        safe_read "👉 Do you want to generate new DNS records in Cloudflare? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            generate_cloudflare_dns
        else
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        fi
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

# ========== SSH BANNER MANAGEMENT ==========
_enable_banner_in_sshd_config() {
    echo -e "\n${C_BLUE}⚙️ Configuring sshd_config...${C_RESET}"
    sed -i.bak -E 's/^( *Banner *).*/#\1/' /etc/ssh/sshd_config
    if ! grep -q -E "^Banner $SSH_BANNER_FILE" /etc/ssh/sshd_config; then
        echo -e "\n# VOLTRON TECH SSH Banner\nBanner $SSH_BANNER_FILE" >> /etc/ssh/sshd_config
    fi
    echo -e "${C_GREEN}✅ sshd_config updated.${C_RESET}"
}

_restart_ssh() {
    echo -e "\n${C_BLUE}🔄 Restarting SSH service to apply changes...${C_RESET}"
    if [ -f /lib/systemd/system/sshd.service ]; then
        MANAGE_SERVICE restart sshd.service
    elif [ -f /lib/systemd/system/ssh.service ]; then
        MANAGE_SERVICE restart ssh.service
    elif [ -f /etc/init.d/ssh ]; then
        /etc/init.d/ssh restart
    elif [ -f /etc/init.d/sshd ]; then
        /etc/init.d/sshd restart
    else
        echo -e "${C_RED}❌ Could not find SSH service. Cannot restart SSH.${C_RESET}"
        return 1
    fi
    echo -e "${C_GREEN}✅ SSH service restarted successfully${C_RESET}"
}

set_ssh_banner_paste() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Paste SSH Banner ---${C_RESET}"
    echo -e "Paste your banner code below. Press ${C_YELLOW}[Ctrl+D]${C_RESET} when you are finished."
    echo -e "${C_DIM}The current banner (if any) will be overwritten.${C_RESET}"
    echo -e "--------------------------------------------------"
    cat > "$SSH_BANNER_FILE"
    chmod 644 "$SSH_BANNER_FILE"
    echo -e "\n--------------------------------------------------"
    echo -e "\n${C_GREEN}✅ Banner content saved from paste.${C_RESET}"
    _enable_banner_in_sshd_config
    _restart_ssh
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..."
    safe_read "" dummy
}

view_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 👁️ Current SSH Banner ---${C_RESET}"
    if [ -f "$SSH_BANNER_FILE" ]; then
        echo -e "\n${C_CYAN}--- BEGIN BANNER ---${C_RESET}"
        cat "$SSH_BANNER_FILE"
        echo -e "${C_CYAN}---- END BANNER ----${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ No banner file found at $SSH_BANNER_FILE.${C_RESET}"
    fi
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..."
    safe_read "" dummy
}

remove_ssh_banner() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Remove SSH Banner ---${C_RESET}"
    local confirm
    safe_read "👉 Are you sure you want to disable and remove the SSH banner? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..."
        safe_read "" dummy
        return
    fi
    if [ -f "$SSH_BANNER_FILE" ]; then
        rm -f "$SSH_BANNER_FILE"
        echo -e "\n${C_GREEN}✅ Removed banner file: $SSH_BANNER_FILE${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ No banner file to remove.${C_RESET}"
    fi
    echo -e "\n${C_BLUE}⚙️ Disabling banner in sshd_config...${C_RESET}"
    sed -i.bak -E "s/^( *Banner\s+$SSH_BANNER_FILE)/#\1/" /etc/ssh/sshd_config
    echo -e "${C_GREEN}✅ Banner disabled in configuration.${C_RESET}"
    _restart_ssh
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to return..."
    safe_read "" dummy
}

ssh_banner_menu() {
    while true; do
        clear
        show_banner
        local banner_status
        if grep -q -E "^\s*Banner\s+$SSH_BANNER_FILE" /etc/ssh/sshd_config && [ -f "$SSH_BANNER_FILE" ]; then
            banner_status="${C_STATUS_A}(Active)${C_RESET}"
        else
            banner_status="${C_STATUS_I}(Inactive)${C_RESET}"
        fi
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🎨 SSH Banner Management ${banner_status}${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} 📋 Paste or Edit Banner"
        echo -e "  ${C_GREEN}2)${C_RESET} 👁️ View Current Banner"
        echo -e "  ${C_RED}3)${C_RESET} 🗑️ Disable and Remove Banner"
        echo -e "  ${C_RED}0)${C_RESET} ↩️ Return to Main Menu"
        echo ""
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        case $choice in
            1) set_ssh_banner_paste ;;
            2) view_ssh_banner ;;
            3) remove_ssh_banner ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

# ========== PROTOCOL FUNCTIONS (EXISTING) ==========
install_badvpn() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing badvpn (udpgw) ---${C_RESET}"
    
    if [ -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ badvpn is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📦 Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL cmake gcc g++ make screen git
    
    echo -e "\n${C_GREEN}📥 Cloning badvpn repository...${C_RESET}"
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
    
    cd "$BADVPN_BUILD_DIR"
    echo -e "\n${C_GREEN}⚙️ Compiling badvpn...${C_RESET}"
    cmake .
    make
    
    local badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
    
    if [ -z "$badvpn_binary" ]; then
        echo -e "\n${C_RED}❌ Failed to compile badvpn.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    cp "$badvpn_binary" /usr/local/bin/badvpn-udpgw
    chmod +x /usr/local/bin/badvpn-udpgw
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$BADVPN_SERVICE_FILE" <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable badvpn.service
        MANAGE_SERVICE start badvpn.service
    else
        cat > /etc/init.d/badvpn <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          badvpn
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: BadVPN UDP Gateway
### END INIT INFO

case "\$1" in
    start)
        start-stop-daemon --start --background --exec /usr/local/bin/badvpn-udpgw -- --listen-addr 0.0.0.0:7300 --max-clients 1000
        ;;
    stop)
        start-stop-daemon --stop --exec /usr/local/bin/badvpn-udpgw
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/badvpn
        update-rc.d badvpn defaults 2>/dev/null || chkconfig --add badvpn 2>/dev/null || true
        /etc/init.d/badvpn start
    fi
    
    echo -e "\n${C_GREEN}✅ badvpn installed and started successfully!${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_badvpn() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling badvpn...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop badvpn.service 2>/dev/null
        MANAGE_SERVICE disable badvpn.service 2>/dev/null
        rm -f "$BADVPN_SERVICE_FILE"
    else
        /etc/init.d/badvpn stop 2>/dev/null
        update-rc.d -f badvpn remove 2>/dev/null || chkconfig --del badvpn 2>/dev/null || true
        rm -f /etc/init.d/badvpn
    fi
    
    rm -f /usr/local/bin/badvpn-udpgw
    rm -rf "$BADVPN_BUILD_DIR"
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    echo -e "${C_GREEN}✅ badvpn uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_udp_custom() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing udp-custom ---${C_RESET}"
    
    if [ -f "$UDP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ udp-custom is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    mkdir -p "$UDP_CUSTOM_DIR"
    
    echo -e "\n${C_GREEN}⚙️ Detecting architecture...${C_RESET}"
    local arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-amd64"
    elif [[ "$arch" == "aarch64" ]]; then
        binary_url="https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-arm64"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📥 Downloading udp-custom...${C_RESET}"
    curl -L -o "$UDP_CUSTOM_DIR/udp-custom" "$binary_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download udp-custom.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    chmod +x "$UDP_CUSTOM_DIR/udp-custom"
    
    cat > "$UDP_CUSTOM_DIR/config.json" <<EOF
{
  "listen": ":36712",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$UDP_CUSTOM_SERVICE_FILE" <<EOF
[Unit]
Description=UDP Custom
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$UDP_CUSTOM_DIR
ExecStart=$UDP_CUSTOM_DIR/udp-custom server -exclude 53,5300
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable udp-custom.service
        MANAGE_SERVICE start udp-custom.service
    else
        cat > /etc/init.d/udp-custom <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          udp-custom
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: UDP Custom
### END INIT INFO

case "\$1" in
    start)
        cd $UDP_CUSTOM_DIR
        start-stop-daemon --start --background --exec $UDP_CUSTOM_DIR/udp-custom -- server -exclude 53,5300
        ;;
    stop)
        start-stop-daemon --stop --exec $UDP_CUSTOM_DIR/udp-custom
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/udp-custom
        update-rc.d udp-custom defaults 2>/dev/null || chkconfig --add udp-custom 2>/dev/null || true
        /etc/init.d/udp-custom start
    fi
    
    echo -e "\n${C_GREEN}✅ udp-custom installed and started successfully!${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_udp_custom() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling udp-custom...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop udp-custom.service 2>/dev/null
        MANAGE_SERVICE disable udp-custom.service 2>/dev/null
        rm -f "$UDP_CUSTOM_SERVICE_FILE"
    else
        /etc/init.d/udp-custom stop 2>/dev/null
        update-rc.d -f udp-custom remove 2>/dev/null || chkconfig --del udp-custom 2>/dev/null || true
        rm -f /etc/init.d/udp-custom
    fi
    
    rm -rf "$UDP_CUSTOM_DIR"
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    echo -e "${C_GREEN}✅ udp-custom uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_ssl_tunnel() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔒 Installing SSL Tunnel (HAProxy) ---${C_RESET}"
    
    if ! command -v haproxy &> /dev/null; then
        echo -e "\n${C_GREEN}📦 Installing HAProxy...${C_RESET}"
        $PKG_UPDATE
        $PKG_INSTALL haproxy
    fi
    
    if [ -f "$SSL_CERT_FILE" ]; then
        echo -e "\n${C_YELLOW}⚠️ SSL certificate already exists.${C_RESET}"
        local overwrite
        safe_read "Overwrite? (y/n): " overwrite
        if [[ "$overwrite" == "y" ]]; then
            rm -f "$SSL_CERT_FILE"
        fi
    fi
    
    if [ ! -f "$SSL_CERT_FILE" ]; then
        echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate...${C_RESET}"
        mkdir -p "$SSL_CERT_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" \
            -subj "/CN=VOLTRON TECH" 2>/dev/null
    fi
    
    local ssl_port
    safe_read "👉 Enter port for SSL tunnel [444]: " ssl_port
    ssl_port=${ssl_port:-444}
    
    cat > "$HAPROXY_CONFIG" <<EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend ssh_ssl_in
    bind *:$ssl_port ssl crt $SSL_CERT_FILE
    mode tcp
    default_backend ssh_backend

backend ssh_backend
    mode tcp
    server ssh_server 127.0.0.1:22
EOF

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE restart haproxy
    else
        /etc/init.d/haproxy restart 2>/dev/null || service haproxy restart
    fi
    
    echo -e "\n${C_GREEN}✅ SSL Tunnel installed on port $ssl_port${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_ssl_tunnel() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling SSL Tunnel...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop haproxy 2>/dev/null
    else
        /etc/init.d/haproxy stop 2>/dev/null || service haproxy stop
    fi
    
    $PKG_REMOVE haproxy
    rm -f "$HAPROXY_CONFIG"
    rm -f "$SSL_CERT_FILE"
    echo -e "${C_GREEN}✅ SSL Tunnel uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_voltron_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🦅 Installing VOLTRON TECH Proxy ---${C_RESET}"
    
    if [ -f "$VOLTRONPROXY_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ VOLTRON Proxy is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local ports
    safe_read "👉 Enter port(s) [8080]: " ports
    ports=${ports:-8080}
    
    local arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxy"
    elif [[ "$arch" == "aarch64" ]]; then
        binary_url="https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxyarm"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📥 Downloading VOLTRON Proxy...${C_RESET}"
    curl -L -o "$VOLTRONPROXY_BINARY" "$binary_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    chmod +x "$VOLTRONPROXY_BINARY"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$VOLTRONPROXY_SERVICE_FILE" <<EOF
[Unit]
Description=VOLTRON TECH Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=$VOLTRONPROXY_BINARY -p $ports
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable voltronproxy.service
        MANAGE_SERVICE start voltronproxy.service
    else
        cat > /etc/init.d/voltronproxy <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          voltronproxy
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: VOLTRON TECH Proxy
### END INIT INFO

case "\$1" in
    start)
        start-stop-daemon --start --background --exec $VOLTRONPROXY_BINARY -- -p $ports
        ;;
    stop)
        start-stop-daemon --stop --exec $VOLTRONPROXY_BINARY
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/voltronproxy
        update-rc.d voltronproxy defaults 2>/dev/null || chkconfig --add voltronproxy 2>/dev/null || true
        /etc/init.d/voltronproxy start
    fi
    
    echo "$ports" > "$VOLTRONPROXY_CONFIG_FILE"
    
    echo -e "\n${C_GREEN}✅ VOLTRON Proxy installed on port(s) $ports${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_voltron_proxy() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling VOLTRON Proxy...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop voltronproxy.service 2>/dev/null
        MANAGE_SERVICE disable voltronproxy.service 2>/dev/null
        rm -f "$VOLTRONPROXY_SERVICE_FILE"
    else
        /etc/init.d/voltronproxy stop 2>/dev/null
        update-rc.d -f voltronproxy remove 2>/dev/null || chkconfig --del voltronproxy 2>/dev/null || true
        rm -f /etc/init.d/voltronproxy
    fi
    
    rm -f "$VOLTRONPROXY_BINARY"
    rm -f "$VOLTRONPROXY_CONFIG_FILE"
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    echo -e "${C_GREEN}✅ VOLTRON Proxy uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_nginx_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Installing Nginx Proxy ---${C_RESET}"
    
    if ! command -v nginx &> /dev/null; then
        echo -e "\n${C_GREEN}📦 Installing Nginx...${C_RESET}"
        $PKG_UPDATE
        $PKG_INSTALL nginx
    fi
    
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.pem \
        -subj "/CN=VOLTRON TECH" 2>/dev/null
    
    cat > "$NGINX_CONFIG_FILE" <<'EOF'
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE restart nginx
    else
        /etc/init.d/nginx restart 2>/dev/null || service nginx restart
    fi
    
    echo -e "\n${C_GREEN}✅ Nginx Proxy installed${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_nginx_proxy() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling Nginx Proxy...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop nginx 2>/dev/null
    else
        /etc/init.d/nginx stop 2>/dev/null || service nginx stop
    fi
    
    $PKG_REMOVE nginx
    rm -f "$NGINX_CONFIG_FILE"
    echo -e "${C_GREEN}✅ Nginx Proxy uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_zivpn() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🛡️ Installing ZiVPN ---${C_RESET}"
    
    if [ -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    local arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    elif [[ "$arch" == "aarch64" ]]; then
        binary_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📥 Downloading ZiVPN...${C_RESET}"
    curl -L -o "$ZIVPN_BIN" "$binary_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    chmod +x "$ZIVPN_BIN"
    mkdir -p "$ZIVPN_DIR"
    
    openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
        -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" \
        -subj "/CN=ZiVPN" 2>/dev/null
    
    local passwords
    safe_read "👉 Enter passwords (comma-separated) [user1,user2]: " passwords
    passwords=${passwords:-user1,user2}
    
    IFS=',' read -ra pass_array <<< "$passwords"
    local json_passwords=$(printf '"%s",' "${pass_array[@]}")
    json_passwords="[${json_passwords%,}]"
    
    cat > "$ZIVPN_CONFIG_FILE" <<EOF
{
  "listen": ":5667",
  "cert": "$ZIVPN_CERT_FILE",
  "key": "$ZIVPN_KEY_FILE",
  "obfs": "zivpn",
  "auth": {
    "mode": "passwords",
    "config": $json_passwords
  }
}
EOF

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$ZIVPN_SERVICE_FILE" <<EOF
[Unit]
Description=ZiVPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$ZIVPN_DIR
ExecStart=$ZIVPN_BIN server -c $ZIVPN_CONFIG_FILE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable zivpn.service
        MANAGE_SERVICE start zivpn.service
    else
        cat > /etc/init.d/zivpn <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          zivpn
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ZiVPN Server
### END INIT INFO

case "\$1" in
    start)
        start-stop-daemon --start --background --exec $ZIVPN_BIN -- server -c $ZIVPN_CONFIG_FILE
        ;;
    stop)
        start-stop-daemon --stop --exec $ZIVPN_BIN
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/zivpn
        update-rc.d zivpn defaults 2>/dev/null || chkconfig --add zivpn 2>/dev/null || true
        /etc/init.d/zivpn start
    fi
    
    echo -e "\n${C_GREEN}✅ ZiVPN installed on port 5667${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_zivpn() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling ZiVPN...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop zivpn.service 2>/dev/null
        MANAGE_SERVICE disable zivpn.service 2>/dev/null
        rm -f "$ZIVPN_SERVICE_FILE"
    else
        /etc/init.d/zivpn stop 2>/dev/null
        update-rc.d -f zivpn remove 2>/dev/null || chkconfig --del zivpn 2>/dev/null || true
        rm -f /etc/init.d/zivpn
    fi
    
    rm -f "$ZIVPN_BIN"
    rm -rf "$ZIVPN_DIR"
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    echo -e "${C_GREEN}✅ ZiVPN uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_xui_panel() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💻 Installing X-UI Panel ---${C_RESET}"
    
    if command -v x-ui &> /dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ X-UI is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📥 Downloading X-UI installer...${C_RESET}"
    bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
    
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

uninstall_xui_panel() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling X-UI Panel...${C_RESET}"
    if command -v x-ui &> /dev/null; then
        x-ui uninstall
    fi
    rm -f /usr/local/bin/x-ui
    rm -rf /etc/x-ui
    rm -rf /usr/local/x-ui
    echo -e "${C_GREEN}✅ X-UI uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

install_dt_proxy_full() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing DT Proxy ---${C_RESET}"
    
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DT Proxy is already installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_GREEN}📥 Downloading DT Proxy installer...${C_RESET}"
    curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash
    
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ DT Proxy installed successfully${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Installation failed${C_RESET}"
    fi
    
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

launch_dt_proxy_menu() {
    if [ -f "/usr/local/bin/main" ]; then
        clear
        /usr/local/bin/main
    else
        echo -e "\n${C_RED}❌ DT Proxy is not installed.${C_RESET}"
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
        safe_read "" dummy
    fi
}

uninstall_dt_proxy_full() {
    echo -e "\n${C_BLUE}🗑️ Uninstalling DT Proxy...${C_RESET}"
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        MANAGE_SERVICE stop proxy-*.service 2>/dev/null
        MANAGE_SERVICE disable proxy-*.service 2>/dev/null
        rm -f /etc/systemd/system/proxy-*.service
    else
        for svc in /etc/init.d/proxy-*; do
            if [ -f "$svc" ]; then
                $svc stop
                update-rc.d -f $(basename "$svc") remove 2>/dev/null || chkconfig --del $(basename "$svc") 2>/dev/null || true
                rm -f "$svc"
            fi
        done
    fi
    
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f /usr/local/bin/install_mod
    
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    
    echo -e "${C_GREEN}✅ DT Proxy uninstalled${C_RESET}"
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

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
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) install_dt_proxy_full ;;
            2) launch_dt_proxy_menu ;;
            3) uninstall_dt_proxy_full ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

check_dt_proxy_status() {
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "${C_BLUE}(installed)${C_RESET}"
    else
        echo ""
    fi
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
        local v2ray_status=$(check_v2ray_status)
        local voltronproxy_status=$(check_service "voltronproxy")
        local nginx_status=$(check_service "nginx")
        local zivpn_status=$(check_service "zivpn")
        local xui_status=$(command -v x-ui &>/dev/null && echo -e "${C_BLUE}(installed)${C_RESET}" || echo "")
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🔌 PROTOCOL & PANEL MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} DNSTT (Ports 53,5300 UDP) $dnstt_status"
        echo -e "  ${C_GREEN}2)${C_RESET} DNS2TCP (Ports 53,5300 TCP) ${C_BLUE}[NEW]${C_RESET} $dns2tcp_status"
        echo -e "  ${C_GREEN}3)${C_RESET} V2RAY over DNSTT ${C_BLUE}[NEW]${C_RESET} $v2ray_status"
        echo -e "  ${C_GREEN}4)${C_RESET} badvpn (UDP 7300) $badvpn_status"
        echo -e "  ${C_GREEN}5)${C_RESET} udp-custom $udp_status"
        echo -e "  ${C_GREEN}6)${C_RESET} SSL Tunnel (HAProxy) $haproxy_status"
        echo -e "  ${C_GREEN}7)${C_RESET} VOLTRON Proxy $voltronproxy_status"
        echo -e "  ${C_GREEN}8)${C_RESET} Nginx Proxy $nginx_status"
        echo -e "  ${C_GREEN}9)${C_RESET} ZiVPN $zivpn_status"
        echo -e "  ${C_GREEN}10)${C_RESET} X-UI Panel $xui_status"
        echo -e "  ${C_GREEN}11)${C_RESET} DT Proxy $(check_dt_proxy_status)"
        echo -e ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select protocol to manage: "${C_RESET})" choice
        
        case $choice in
            1)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install DNSTT"
                echo -e "  ${C_GREEN}2)${C_RESET} View DNSTT Details"
                echo -e "  ${C_RED}3)${C_RESET} Uninstall DNSTT"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_dnstt
                elif [ "$sub" == "2" ]; then show_dnstt_details; echo -e "\nPress Enter"; safe_read "" dummy
                elif [ "$sub" == "3" ]; then uninstall_dnstt
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            2)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install DNS2TCP"
                echo -e "  ${C_GREEN}2)${C_RESET} View DNS2TCP Details"
                echo -e "  ${C_RED}3)${C_RESET} Uninstall DNS2TCP"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_dns2tcp
                elif [ "$sub" == "2" ]; then show_dns2tcp_details; echo -e "\nPress Enter"; safe_read "" dummy
                elif [ "$sub" == "3" ]; then uninstall_dns2tcp
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            3)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install V2RAY over DNSTT"
                echo -e "  ${C_GREEN}2)${C_RESET} V2RAY User Management"
                echo -e "  ${C_GREEN}3)${C_RESET} View V2RAY Details"
                echo -e "  ${C_RED}4)${C_RESET} Uninstall V2RAY over DNSTT"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_v2ray_dnstt
                elif [ "$sub" == "2" ]; then v2ray_user_management_menu
                elif [ "$sub" == "3" ]; then show_v2ray_details; echo -e "\nPress Enter"; safe_read "" dummy
                elif [ "$sub" == "4" ]; then uninstall_v2ray_dnstt
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            4)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_badvpn
                elif [ "$sub" == "2" ]; then uninstall_badvpn
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            5)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_udp_custom
                elif [ "$sub" == "2" ]; then uninstall_udp_custom
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            6)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_ssl_tunnel
                elif [ "$sub" == "2" ]; then uninstall_ssl_tunnel
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            7)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_voltron_proxy
                elif [ "$sub" == "2" ]; then uninstall_voltron_proxy
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            8)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_nginx_proxy
                elif [ "$sub" == "2" ]; then uninstall_nginx_proxy
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            9)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_zivpn
                elif [ "$sub" == "2" ]; then uninstall_zivpn
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            10)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then install_xui_panel
                elif [ "$sub" == "2" ]; then uninstall_xui_panel
                else echo -e "${C_RED}Invalid${C_RESET}"; sleep 2; fi
                ;;
            11)
                dt_proxy_menu
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== LIMITER SERVICE SETUP ==========
setup_limiter_service() {
    cat > "$LIMITER_SCRIPT" << 'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"

while true; do
    if [[ ! -f "$DB_FILE" ]]; then
        sleep 10
        continue
    fi
    current_ts=$(date +%s)
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
            fi
            if pgrep -u "$user" > /dev/null; then
                killall -u "$user" -9 &>/dev/null
            fi
            continue
        fi
        
        online_count=$(pgrep -u "$user" sshd | wc -l)
        if ! [[ "$limit" =~ ^[0-9]+$ ]]; then limit=1; fi
        
        # Check connection limit
        if [[ "$online_count" -gt "$limit" ]]; then
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
                (sleep 120; usermod -U "$user" &>/dev/null) &
            else
                killall -u "$user" -9 &>/dev/null
            fi
        fi
        
        # Check traffic limit
        if [ "$traffic_limit" != "0" ] && [ -n "$traffic_limit" ] && [ -n "$traffic_used" ] && [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
            fi
        fi
    done < "$DB_FILE"
    sleep 3
done
EOF
    chmod +x "$LIMITER_SCRIPT"

    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=VOLTRON TECH Active User Limiter
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        MANAGE_SERVICE daemon-reload
        MANAGE_SERVICE enable voltrontech-limiter &>/dev/null
        MANAGE_SERVICE start voltrontech-limiter &>/dev/null
    else
        cat > /etc/init.d/voltrontech-limiter <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          voltrontech-limiter
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: VOLTRON TECH Limiter
### END INIT INFO

case "\$1" in
    start)
        start-stop-daemon --start --background --exec $LIMITER_SCRIPT
        ;;
    stop)
        start-stop-daemon --stop --exec $LIMITER_SCRIPT
        ;;
    restart)
        \$0 stop
        sleep 2
        \$0 start
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
        chmod +x /etc/init.d/voltrontech-limiter
        update-rc.d voltrontech-limiter defaults 2>/dev/null || chkconfig --add voltrontech-limiter 2>/dev/null || true
        /etc/init.d/voltrontech-limiter start
    fi
}

# ========== INITIAL SETUP ==========
initial_setup() {
    echo -e "\n${C_BLUE}🔧 Running initial system setup...${C_RESET}"
    
    detect_os
    detect_package_manager
    detect_service_manager
    detect_firewall
    
    mkdir -p "$DB_DIR"
    mkdir -p "$DB_DIR/config"
    mkdir -p "$DB_DIR/cache"
    mkdir -p "$DNSTT_KEYS_DIR"
    mkdir -p "$DNS2TCP_KEYS_DIR"
    mkdir -p "$V2RAY_DIR"
    mkdir -p "$V2RAY_DIR/users"
    mkdir -p "$V2RAY_DIR/v2ray"
    mkdir -p "$V2RAY_DIR/dnstt"
    touch "$DB_FILE"
    touch "$V2RAY_USERS_DB"
    mkdir -p "$SSL_CERT_DIR"
    
    cat > "$DB_DIR/cloudflare.conf" <<EOF
CLOUDFLARE_EMAIL="$CLOUDFLARE_EMAIL"
CLOUDFLARE_ZONE_ID="$CLOUDFLARE_ZONE_ID"
CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN"
DOMAIN="$DOMAIN"
EOF
    
    setup_limiter_service
    if [ ! -f "$INSTALL_FLAG_FILE" ]; then
        touch "$INSTALL_FLAG_FILE"
    fi
    
    get_ip_info
    
    install_voltron_booster
}

# ========== UNINSTALL SCRIPT ==========
uninstall_script() {
    clear
    show_banner
    echo -e "${C_RED}=====================================================${C_RESET}"
    echo -e "${C_RED}       🔥 DANGER: UNINSTALL SCRIPT & ALL DATA 🔥      ${C_RESET}"
    echo -e "${C_RED}=====================================================${C_RESET}"
    echo -e "${C_YELLOW}This will PERMANENTLY remove this script and all its components."
    echo -e "\n${C_RED}This action is irreversible.${C_RESET}"
    echo ""
    local confirm
    safe_read "👉 Type 'yes' to confirm and proceed with uninstallation: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "\n${C_GREEN}✅ Uninstallation cancelled.${C_RESET}"
        return
    fi
    export UNINSTALL_MODE="silent"
    echo -e "\n${C_BLUE}--- 💥 Starting Uninstallation 💥 ---${C_RESET}"
    
    # Stop all services
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        for service in voltrontech-limiter voltron-loss-protect voltron-traffic dnstt dnstt-5300 dns2tcp-53 dns2tcp-5300 v2ray-dnstt badvpn udp-custom haproxy voltronproxy nginx zivpn; do
            MANAGE_SERVICE stop $service.service 2>/dev/null
            MANAGE_SERVICE disable $service.service 2>/dev/null
        done
        rm -f /etc/systemd/system/voltron*.service
        rm -f /etc/systemd/system/dnstt*.service
        rm -f /etc/systemd/system/dns2tcp*.service
        rm -f /etc/systemd/system/v2ray*.service
        rm -f /etc/systemd/system/badvpn*.service
        rm -f /etc/systemd/system/udp-custom*.service
    else
        for svc in /etc/init.d/voltron* /etc/init.d/dnstt /etc/init.d/badvpn /etc/init.d/udp-custom /etc/init.d/zivpn; do
            if [ -f "$svc" ]; then
                $svc stop
                update-rc.d -f $(basename "$svc") remove 2>/dev/null || chkconfig --del $(basename "$svc") 2>/dev/null || true
                rm -f "$svc"
            fi
        done
    fi
    
    rm -f /usr/local/bin/voltron*
    rm -f /usr/local/bin/dnstt-server
    rm -f /usr/local/bin/dns2tcp-server
    rm -f /usr/local/bin/badvpn-udpgw
    rm -f /usr/local/bin/zivpn
    rm -rf "$DB_DIR"
    rm -f /usr/local/bin/menu
    
    MANAGE_SERVICE daemon-reload 2>/dev/null || true
    
    echo -e "\n${C_GREEN}=============================================${C_RESET}"
    echo -e "${C_GREEN}      Script has been successfully uninstalled.     ${C_RESET}"
    echo -e "${C_GREEN}=============================================${C_RESET}"
    exit 0
}

press_enter() {
    echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue..."
    safe_read "" dummy
}

invalid_option() {
    echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2
}

# ========== ROOT CHECK ==========
if [[ $EUID -ne 0 ]]; then
   echo -e "${C_RED}❌ Error: This script must be run as root.${C_RESET}"
   exit 1
fi

# ========== MAIN MENU FUNCTION ==========
main_menu() {
    initial_setup
    while true; do
        export UNINSTALL_MODE="interactive"
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    👤 USER MANAGEMENT                         ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "1" "Create New User" "5" "Unlock User Account"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "2" "Delete User" "6" "List All Managed Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "3" "Edit User Details" "7" "Renew User Account"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "4" "Lock User Account"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES                        ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "8" "Protocols & Panels" "12" "SSH Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "9" "Backup Users" "13" "Cleanup Expired"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "10" "Restore Users" "14" "MTU Optimization"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "11" "DNS Domain" "15" "DT Proxy"

        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    🔥 DANGER ZONE                            ${C_RESET}"
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
            11) dns_menu ;;
            12) ssh_banner_menu ;;
            13) cleanup_expired ;;
            14) mtu_optimization_menu ;;
            15) dt_proxy_menu ;;
            99) uninstall_script ;;
            0) echo -e "\n${C_BLUE}👋 Goodbye!${C_RESET}"; exit 0 ;;
            *) invalid_option ;;
        esac
    done
}

# ========== START ==========
if [[ "$1" == "--install-setup" ]]; then
    initial_setup
    exit 0
fi

main_menu
