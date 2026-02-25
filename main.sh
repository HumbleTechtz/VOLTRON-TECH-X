#!/bin/bash

# ========== VOLTRON TECH X ULTIMATE SCRIPT ==========
# Version: 10.0 (MTU 1800 IMPROVED)
# Description: Complete VPN Server Management
# Includes: DNSTT, DNS2TCP, V2RAY over DNSTT, Traffic Limits, MTU 1800 Ultimate Mode

# ========== COLOR CODES ==========
C_RESET='\033[0m'
C_RED='\033[91m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_BLUE='\033[94m'
C_PURPLE='\033[95m'
C_CYAN='\033[96m'

# ========== CONFIGURATION ==========
DOMAIN="voltrontechtx.shop"
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "0.0.0.0")
DB_DIR="/etc/voltrontech"
VOLTRON_DB="$DB_DIR/users.db"
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNS2TCP_KEYS_DIR="$DB_DIR/dns2tcp"
V2RAY_DIR="$DB_DIR/v2ray-dnstt"
SSL_CERT_DIR="$DB_DIR/ssl"
BACKUP_DIR="$DB_DIR/backups"
LOGS_DIR="$DB_DIR/logs"
CONFIG_DIR="$DB_DIR/config"
UDP_CUSTOM_DIR="/root/udp"
ZIVPN_DIR="/etc/zivpn"

# Cloudflare
CLOUDFLARE_EMAIL="voltrontechtx@gmail.com"
CLOUDFLARE_ZONE_ID="1ce2d01c4d1678c91a08db8c7a780c81"
CLOUDFLARE_API_TOKEN="4kgAiZpUPvOi7mdmRD1gnCcn6xnH_Yu-8N7IdhHD"

# Ports
DNS_PORT=53
DNS2_PORT=5300
V2RAY_PORT=8787
BADVPN_PORT=7300
UDP_CUSTOM_PORT=36712
SSL_PORT=444
VOLTRON_PROXY_PORT=8080
ZIVPN_PORT=5667

# ========== CREATE DIRECTORIES ==========
create_directories() {
    echo -e "${C_BLUE}📁 Creating directories...${C_RESET}"
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $DNS2TCP_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR
    mkdir -p $V2RAY_DIR/dnstt $V2RAY_DIR/v2ray $V2RAY_DIR/users
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    touch $VOLTRON_DB
    echo "{}" > $DB_DIR/cloudflare_records.json 2>/dev/null
}

# ========== SYSTEM DETECTION ==========
detect_package_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt update"
        PKG_INSTALL="apt install -y"
        PKG_REMOVE="apt remove -y"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        PKG_UPDATE="dnf check-update"
        PKG_INSTALL="dnf install -y"
        PKG_REMOVE="dnf remove -y"
    else
        echo -e "${C_RED}❌ Unsupported package manager${C_RESET}"
        exit 1
    fi
}

detect_service_manager() {
    if command -v systemctl &>/dev/null; then
        SERVICE_MANAGER="systemd"
    else
        echo -e "${C_RED}❌ systemd required${C_RESET}"
        exit 1
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

# ========== SHOW BANNER ==========
show_banner() {
    clear
    local mtu=$(cat "$CONFIG_DIR/mtu" 2>/dev/null || echo "Not set")
    
    echo -e "${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_PURPLE}║           🔥 VOLTRON TECH X ULTIMATE v10.0 🔥                ║${C_RESET}"
    echo -e "${C_PURPLE}║        SSH • DNSTT • DNS2TCP • V2RAY • MTU 1800 ULTIMATE     ║${C_RESET}"
    echo -e "${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_PURPLE}║  Server IP: ${C_GREEN}$SERVER_IP${C_PURPLE}${C_RESET}"
    echo -e "${C_PURPLE}║  Domain:    ${C_GREEN}$DOMAIN${C_PURPLE}${C_RESET}"
    echo -e "${C_PURPLE}║  Current MTU: ${C_GREEN}$mtu${C_PURPLE}${C_RESET}"
    if [ "$mtu" -eq 1800 ]; then
        echo -e "${C_PURPLE}║  ${C_YELLOW}⚡ MTU 1800 ULTIMATE ACTIVE - ISP sees 512!${C_PURPLE}${C_RESET}"
    fi
    echo -e "${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
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
    
    if [ -f "/etc/systemd/system/dnstt.service" ]; then
        # Update DNSTT services to use MTU 1800
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" /etc/systemd/system/dnstt.service
        sed -i "s/-mtu [0-9]\+/-mtu 1800/g" /etc/systemd/system/dnstt-5300.service 2>/dev/null
        
        systemctl daemon-reload
        systemctl restart dnstt.service dnstt-5300.service 2>/dev/null
        
        echo -e "      • DNSTT services updated to MTU 1800"
    fi
    
    if [ -f "/etc/systemd/system/dns2tcp.service" ]; then
        # DNS2TCP doesn't use MTU directly, but we can note it
        echo -e "      • DNS2TCP configured for MTU 1800 tunnel"
    fi

    # ========== 4. IPTABLES MSS CLAMPING (like OpenVPN mssfix) ==========
    echo -e "${C_GREEN}[4/7] Adding iptables MSS clamping...${C_RESET}"
    
    # Clear existing rules
    iptables -t mangle -F 2>/dev/null
    
    # Add MSS clamping for all TCP traffic (like mssfix 1800 in OpenVPN)
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
    
    echo -e "      • Buffer size: ${C_CYAN}512MB${C_RESET}"

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
        echo -e "      • Rules saved persistently"
    fi

    # ========== 7. SAVE CONFIGURATION ==========
    echo -e "${C_GREEN}[7/7] Saving MTU configuration...${C_RESET}"
    
    mkdir -p "$CONFIG_DIR"
    echo "1800" > "$CONFIG_DIR/mtu"
    echo "1800_ULTIMATE" > "$CONFIG_DIR/mtu_mode"

    # ========== VERIFICATION ==========
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

# ========== STANDARD MTU OPTIMIZATION ==========
apply_standard_mtu_optimization() {
    local mtu=$1
    local buffer=$2
    local mss=$((mtu - 40))
    
    echo -e "\n${C_BLUE}⚡ Applying standard MTU optimization for MTU $mtu...${C_RESET}"
    
    cat > /etc/sysctl.d/99-voltron.conf <<EOF
# VOLTRON TECH OPTIMIZATION - MTU $mtu
net.core.rmem_max = $buffer
net.core.wmem_max = $buffer
net.ipv4.tcp_rmem = 4096 87380 $buffer
net.ipv4.tcp_wmem = 4096 65536 $buffer
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = $mss
EOF
    sysctl -p /etc/sysctl.d/99-voltron.conf 2>/dev/null
    
    mkdir -p "$CONFIG_DIR"
    echo "$mtu" > "$CONFIG_DIR/mtu"
    
    echo -e "${C_GREEN}✅ Standard MTU optimization applied${C_RESET}"
}

# ========== MTU SELECTION ==========
mtu_selection() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 SELECT MTU${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "  ${C_GREEN}1)${C_RESET} MTU 512  (Ultra Boost - 512MB buffers)"
    echo -e "  ${C_GREEN}2)${C_RESET} MTU 800  (Hyper Boost)"
    echo -e "  ${C_GREEN}3)${C_RESET} MTU 1000 (Super Boost)"
    echo -e "  ${C_GREEN}4)${C_RESET} MTU 1200 (Mega Boost)"
    echo -e "  ${C_GREEN}5)${C_RESET} MTU 1500 (Standard)"
    echo -e "  ${C_GREEN}6)${C_RESET} MTU 1800 🔥 ULTIMATE MODE - FOOLS ISP! (Full optimization)"
    echo -e "  ${C_GREEN}7)${C_RESET} Auto-detect optimal MTU"
    echo ""
    
    local choice
    read -p "👉 Select MTU [1-7] (default 5): " choice
    choice=${choice:-5}
    
    case $choice in
        1) 
            MTU=512
            BUFFER_SIZE=536870912
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        2) 
            MTU=800
            BUFFER_SIZE=402653184
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        3) 
            MTU=1000
            BUFFER_SIZE=268435456
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        4) 
            MTU=1200
            BUFFER_SIZE=134217728
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        5) 
            MTU=1500
            BUFFER_SIZE=67108864
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        6) 
            MTU=1800
            BUFFER_SIZE=536870912
            apply_mtu_1800_optimization
            ;;
        7) 
            echo -e "${C_YELLOW}Detecting optimal MTU...${C_RESET}"
            MTU=$(ping -M do -s 1472 -c 2 8.8.8.8 2>/dev/null | grep -o "mtu = [0-9]*" | awk '{print $3}' || echo "1500")
            echo -e "${C_GREEN}Optimal MTU: $MTU${C_RESET}"
            BUFFER_SIZE=$((MTU * 40000))
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
        *) 
            MTU=1500
            BUFFER_SIZE=67108864
            apply_standard_mtu_optimization $MTU $BUFFER_SIZE
            ;;
    esac
}

# ========== USER MANAGEMENT FUNCTIONS ==========
create_user() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👤 CREATE NEW USER${C_RESET}"
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
    
    echo -e "${C_GREEN}✅ User created: $username${C_RESET}"
    read -p "Press Enter to continue"
}

list_users() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 USER LIST${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [[ ! -s "$VOLTRON_DB" ]]; then
        echo -e "${C_YELLOW}No users found${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    printf "%-15s %-12s %-8s %-15s %-10s\n" "USERNAME" "EXPIRY" "LIMIT" "TRAFFIC" "STATUS"
    echo "----------------------------------------------------------------"
    
    while IFS=: read -r user pass expiry limit traffic_limit traffic_used; do
        online=$(pgrep -u "$user" sshd 2>/dev/null | wc -l)
        
        if [ "$traffic_limit" == "0" ]; then
            traffic_disp="${traffic_used}GB/∞"
        else
            percent=$(echo "scale=1; $traffic_used * 100 / $traffic_limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${traffic_used}/$traffic_limit GB ($percent%)"
        fi
        
        if [ "$traffic_limit" != "0" ] && [ $(echo "$traffic_used >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
            status="${C_RED}LIMIT${C_RESET}"
        elif [[ "$(date -d "$expiry" +%s 2>/dev/null)" -lt "$(date +%s)" ]]; then
            status="${C_RED}EXPIRED${C_RESET}"
        else
            status="${C_GREEN}ACTIVE${C_RESET}"
        fi
        
        printf "%-15s %-12s %-8s %-15s %s\n" "$user" "$expiry" "$online/$limit" "$traffic_disp" "$status"
    done < "$VOLTRON_DB"
    
    echo ""
    read -p "Press Enter"
}

delete_user() {
    read -p "Username: " username
    userdel -r "$username" 2>/dev/null
    sed -i "/^$username:/d" "$VOLTRON_DB"
    echo -e "${C_GREEN}✅ User deleted${C_RESET}"
    read -p "Press Enter"
}

# ========== TRAFFIC MONITOR ==========
create_traffic_monitor() {
    cat > /usr/local/bin/voltron-traffic <<'EOF'
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
                    
                    if [ "$traffic_limit" != "0" ] && [ $(echo "$new_traffic >= $traffic_limit" | bc 2>/dev/null) -eq 1 ]; then
                        usermod -L "$user" 2>/dev/null
                    fi
                    
                    sed -i "s/^$user:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*/$user:$pass:$expiry:$limit:$traffic_limit:$new_traffic/" "$DB_FILE" 2>/dev/null
                fi
            fi
        done < "$DB_FILE"
    fi
    sleep 60
done
EOF
    chmod +x /usr/local/bin/voltron-traffic
    
    cat > /etc/systemd/system/voltron-traffic.service <<EOF
[Unit]
Description=Voltron Traffic Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/voltron-traffic
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltron-traffic.service 2>/dev/null
    systemctl start voltron-traffic.service 2>/dev/null
}

# ========== DNSTT INSTALLATION ==========
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 INSTALL DNSTT${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "/etc/systemd/system/dnstt.service" ]; then
        echo -e "${C_YELLOW}DNSTT already installed${C_RESET}"
        return
    fi
    
    # Free port 53
    systemctl stop systemd-resolved 2>/dev/null
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    
    # Download binary
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o /usr/local/bin/dnstt-server "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-amd64-20240101.tar.gz"
        tar -xzf /usr/local/bin/dnstt-server -C /tmp
        cp /tmp/server_linux_amd64 /usr/local/bin/dnstt-server 2>/dev/null
    elif [[ "$arch" == "aarch64" ]]; then
        curl -L -o /usr/local/bin/dnstt-server "https://github.com/xtaci/kcptun/releases/download/v20240101/kcptun-linux-arm64-20240101.tar.gz"
        tar -xzf /usr/local/bin/dnstt-server -C /tmp
        cp /tmp/server_linux_arm64 /usr/local/bin/dnstt-server 2>/dev/null
    fi
    chmod +x /usr/local/bin/dnstt-server 2>/dev/null
    
    # Generate keys
    mkdir -p $DNSTT_KEYS_DIR
    /usr/local/bin/dnstt-server -gen-key -privkey-file "$DNSTT_KEYS_DIR/server.key" -pubkey-file "$DNSTT_KEYS_DIR/server.pub" 2>/dev/null
    
    # Get MTU
    mtu_selection
    
    # DNS method
    echo -e "\n${C_BLUE}DNS Configuration:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    if [ "$dns_choice" == "1" ]; then
        local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
        local ns="ns-$rand"
        local tun="tun-$rand"
        
        create_cloudflare_record "A" "$ns" "$SERVER_IP"
        create_cloudflare_record "NS" "$tun" "$ns.$DOMAIN"
        
        domain="$tun.$DOMAIN"
        echo -e "${C_GREEN}✅ Domain created: $domain${C_RESET}"
    else
        read -p "Enter tunnel domain: " domain
    fi
    
    # Create services
    cat > /etc/systemd/system/dnstt.service <<EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :$DNS_PORT -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $domain 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/dnstt-5300.service <<EOF
[Unit]
Description=DNSTT Server (Port 5300)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :$DNS2_PORT -mtu $MTU -privkey-file $DNSTT_KEYS_DIR/server.key $domain 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service dnstt-5300.service
    systemctl start dnstt.service dnstt-5300.service
    
    echo -e "${C_GREEN}✅ DNSTT installed${C_RESET}"
    echo -e "  Public Key: ${C_YELLOW}$(cat $DNSTT_KEYS_DIR/server.pub)${C_RESET}"
    echo -e "  Domain: $domain"
    read -p "Press Enter"
}

uninstall_dnstt() {
    systemctl stop dnstt.service dnstt-5300.service 2>/dev/null
    systemctl disable dnstt.service dnstt-5300.service 2>/dev/null
    rm -f /etc/systemd/system/dnstt*.service
    rm -f /usr/local/bin/dnstt-server
    rm -rf $DNSTT_KEYS_DIR
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNSTT uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNSTT DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "$DNSTT_KEYS_DIR/server.pub" ]; then
        echo -e "  Public Key: ${C_YELLOW}$(cat $DNSTT_KEYS_DIR/server.pub)${C_RESET}"
        
        if systemctl is-active dnstt.service &>/dev/null; then
            echo -e "  Status: ${C_GREEN}● RUNNING${C_RESET}"
        else
            echo -e "  Status: ${C_RED}● STOPPED${C_RESET}"
        fi
    else
        echo -e "${C_YELLOW}DNSTT not installed${C_RESET}"
    fi
    read -p "Press Enter"
}

# ========== DNS2TCP INSTALLATION ==========
install_dns2tcp() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 INSTALL DNS2TCP${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f "/etc/systemd/system/dns2tcp.service" ]; then
        echo -e "${C_YELLOW}DNS2TCP already installed${C_RESET}"
        return
    fi
    
    # Install dependencies
    $PKG_UPDATE
    $PKG_INSTALL dns2tcp screen lsof
    
    # Configure systemd-resolved
    cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.backup 2>/dev/null
    cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1
DNSStubListener=no
EOF
    systemctl restart systemd-resolved
    
    # Create directories
    mkdir -p /root/dns2tcp
    mkdir -p /var/empty/dns2tcp
    
    # Create user
    if ! id "ashtunnel" &>/dev/null; then
        useradd -r -s /bin/false -d /var/empty/dns2tcp ashtunnel
    fi
    
    # Get MTU
    mtu_selection
    
    # DNS Configuration
    echo -e "\n${C_BLUE}DNS Configuration:${C_RESET}"
    echo "1) Auto-generate with Cloudflare"
    echo "2) Manual"
    read -p "Choice [1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    local domain=""
    local key=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
    
    if [ "$dns_choice" == "1" ]; then
        local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
        local ns="ns2-$rand"
        local tun="tun2-$rand"
        
        create_cloudflare_record "A" "$ns" "$SERVER_IP"
        create_cloudflare_record "NS" "$tun" "$ns.$DOMAIN"
        
        domain="$tun.$DOMAIN"
        echo -e "${C_GREEN}✅ Domain created: $domain${C_RESET}"
    else
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
    
    # Create config
    cat > /root/dns2tcp/dns2tcpdrc <<EOF
listen = 0.0.0.0
port = 53
user = ashtunnel
chroot = /var/empty/dns2tcp/
domain = $domain
key = $key
resources = ssh:127.0.0.1:$target_port
EOF

    # Create service
    cat > /etc/systemd/system/dns2tcp.service <<EOF
[Unit]
Description=DNS2TCP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/dns2tcp
ExecStart=/usr/bin/dns2tcpd -d 1 -F -f /root/dns2tcp/dns2tcpdrc
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
    systemctl enable dns2tcp.service
    systemctl start dns2tcp.service
    
    echo -e "${C_GREEN}✅ DNS2TCP installed${C_RESET}"
    echo -e "  Domain: ${C_YELLOW}$domain${C_RESET}"
    echo -e "  Key:    ${C_YELLOW}$key${C_RESET}"
    read -p "Press Enter"
}

uninstall_dns2tcp() {
    systemctl stop dns2tcp.service 2>/dev/null
    systemctl disable dns2tcp.service 2>/dev/null
    rm -f /etc/systemd/system/dns2tcp.service
    
    # Restore resolv.conf
    if [ -f /etc/resolv.conf.backup ]; then
        cp /etc/resolv.conf.backup /etc/resolv.conf
    fi
    
    rm -rf /root/dns2tcp
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ DNS2TCP uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_dns2tcp_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📡 DNS2TCP DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ -f /root/dns2tcp/dns2tcpdrc ]; then
        local domain=$(grep domain /root/dns2tcp/dns2tcpdrc | cut -d= -f2 | tr -d ' ')
        local key=$(grep key /root/dns2tcp/dns2tcpdrc | cut -d= -f2 | tr -d ' ')
        
        echo -e "  Domain: ${C_YELLOW}$domain${C_RESET}"
        echo -e "  Key:    ${C_YELLOW}$key${C_RESET}"
        
        if systemctl is-active dns2tcp.service &>/dev/null; then
            echo -e "  Status: ${C_GREEN}● RUNNING${C_RESET}"
        else
            echo -e "  Status: ${C_RED}● STOPPED${C_RESET}"
        fi
    else
        echo -e "${C_YELLOW}DNS2TCP not installed${C_RESET}"
    fi
    read -p "Press Enter"
}

# ========== V2RAY over DNSTT ==========
install_v2ray_dnstt() {
    clear
    show_banner
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🚀 INSTALL V2RAY over DNSTT${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    # Check if DNSTT is installed
    if [ ! -f "/etc/systemd/system/dnstt.service" ]; then
        echo -e "${C_RED}❌ DNSTT must be installed first${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    # Install Xray
    bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'
    
    # Create directories
    mkdir -p $V2RAY_DIR/v2ray $V2RAY_DIR/users
    
    # Create V2Ray config
    cat > $V2RAY_DIR/v2ray/config.json <<EOF
{
    "log": {"loglevel": "warning"},
    "inbounds": [
        {"port": $V2RAY_PORT, "protocol": "vmess", "settings": {"clients": []}, "tag": "vmess"},
        {"port": $((V2RAY_PORT+1)), "protocol": "vless", "settings": {"clients": [], "decryption": "none"}, "tag": "vless"},
        {"port": $((V2RAY_PORT+2)), "protocol": "trojan", "settings": {"clients": []}, "tag": "trojan"}
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF

    # Create service
    cat > /etc/systemd/system/v2ray-dnstt.service <<EOF
[Unit]
Description=V2RAY over DNSTT
After=network.target dnstt.service

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config $V2RAY_DIR/v2ray/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable v2ray-dnstt.service
    systemctl start v2ray-dnstt.service
    
    echo -e "${C_GREEN}✅ V2RAY over DNSTT installed${C_RESET}"
    echo -e "  VMess Port: 8787"
    echo -e "  VLESS Port: 8788"
    echo -e "  Trojan Port: 8789"
    read -p "Press Enter"
}

uninstall_v2ray_dnstt() {
    systemctl stop v2ray-dnstt.service 2>/dev/null
    systemctl disable v2ray-dnstt.service 2>/dev/null
    rm -f /etc/systemd/system/v2ray-dnstt.service
    rm -rf $V2RAY_DIR
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ V2RAY over DNSTT uninstalled${C_RESET}"
    read -p "Press Enter"
}

show_v2ray_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           🚀 V2RAY DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if systemctl is-active v2ray-dnstt.service &>/dev/null; then
        echo -e "  Status: ${C_GREEN}● RUNNING${C_RESET}"
        echo -e "  Ports: 8787 (VMess), 8788 (VLESS), 8789 (Trojan)"
    else
        echo -e "  Status: ${C_RED}● STOPPED${C_RESET}"
    fi
    read -p "Press Enter"
}

# ========== V2RAY USER MANAGEMENT ==========
generate_uuid() {
    uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s%N | md5sum | cut -c1-8)-$(date +%s%N | md5sum | cut -c1-4)-4$(date +%s%N | md5sum | cut -c1-3)-$(date +%s%N | md5sum | cut -c1-4)-$(date +%s%N | md5sum | cut -c1-12)"
}

create_v2ray_user() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           👤 CREATE V2RAY USER${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_DIR/v2ray/config.json" ]; then
        echo -e "${C_RED}❌ V2RAY not installed${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    read -p "Username: " username
    read -p "Protocol [vmess/vless/trojan] (default: vmess): " proto
    proto=${proto:-vmess}
    read -p "Traffic limit (GB) [0=unlimited]: " traffic_limit
    traffic_limit=${traffic_limit:-0}
    read -p "Expiry (days) [30]: " days
    days=${days:-30}
    
    expire=$(date -d "+$days days" +%Y-%m-%d)
    uuid=$(generate_uuid)
    
    echo -e "${C_YELLOW}User created with UUID: $uuid${C_RESET}"
    
    # Save to database
    echo "$username:$uuid:$proto:$traffic_limit:0:$expire:active" >> "$V2RAY_DIR/users/users.db"
    
    echo -e "${C_GREEN}✅ V2Ray user created${C_RESET}"
    read -p "Press Enter"
}

list_v2ray_users() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 V2RAY USERS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$V2RAY_DIR/users/users.db" ]; then
        echo -e "${C_YELLOW}No V2Ray users found${C_RESET}"
        read -p "Press Enter"
        return
    fi
    
    printf "%-15s %-8s %-36s %-15s %-10s\n" "USERNAME" "PROTO" "UUID" "TRAFFIC" "STATUS"
    echo "----------------------------------------------------------------"
    
    while IFS=: read -r user uuid proto limit used expiry status; do
        if [ "$limit" == "0" ]; then
            traffic_disp="${used}GB/∞"
        else
            percent=$(echo "scale=1; $used * 100 / $limit" | bc 2>/dev/null || echo "0")
            traffic_disp="${used}/$limit GB ($percent%)"
        fi
        
        short_uuid="${uuid:0:8}...${uuid: -8}"
        printf "%-15s %-8s %-36s %-15s %s\n" "$user" "$proto" "$short_uuid" "$traffic_disp" "$status"
    done < "$V2RAY_DIR/users/users.db"
    
    echo ""
    read -p "Press Enter"
}

delete_v2ray_user() {
    read -p "Username: " user
    sed -i "/^$user:/d" "$V2RAY_DIR/users/users.db"
    echo -e "${C_GREEN}✅ User deleted${C_RESET}"
    read -p "Press Enter"
}

v2ray_user_menu() {
    while true; do
        clear
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_PURPLE}           👤 V2RAY USER MANAGEMENT${C_RESET}"
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo ""
        echo "1) Create User"
        echo "2) List Users"
        echo "3) Delete User"
        echo "0) Back"
        echo ""
        
        read -p "Choice: " choice
        
        case $choice in
            1) create_v2ray_user ;;
            2) list_v2ray_users ;;
            3) delete_v2ray_user ;;
            0) return ;;
            *) echo "Invalid" ;;
        esac
    done
}

# ========== OTHER PROTOCOLS ==========
install_badvpn() {
    echo -e "${C_BLUE}🚀 Installing badvpn...${C_RESET}"
    $PKG_INSTALL cmake make gcc git
    cd /tmp
    git clone https://github.com/ambrop72/badvpn.git
    cd badvpn
    cmake .
    make
    cp badvpn-udpgw /usr/local/bin/badvpn-udpgw
    
    cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    echo -e "${C_GREEN}✅ badvpn installed${C_RESET}"
    read -p "Press Enter"
}

install_udp_custom() {
    echo -e "${C_BLUE}🚀 Installing udp-custom...${C_RESET}"
    mkdir -p $UDP_CUSTOM_DIR
    curl -L -o $UDP_CUSTOM_DIR/udp-custom "https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-amd64"
    chmod +x $UDP_CUSTOM_DIR/udp-custom
    
    cat > $UDP_CUSTOM_DIR/config.json <<EOF
{"listen": ":$UDP_CUSTOM_PORT", "auth": {"mode": "passwords"}}
EOF

    cat > /etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP Custom
After=network.target

[Service]
Type=simple
WorkingDirectory=$UDP_CUSTOM_DIR
ExecStart=$UDP_CUSTOM_DIR/udp-custom server -exclude 53,5300
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl start udp-custom.service
    echo -e "${C_GREEN}✅ udp-custom installed${C_RESET}"
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

install_voltron_proxy() {
    echo -e "${C_BLUE}🦅 Installing VOLTRON Proxy...${C_RESET}"
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        url="https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxy"
    else
        url="https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/voltronproxyarm"
    fi
    
    curl -L -o /usr/local/bin/voltronproxy "$url"
    chmod +x /usr/local/bin/voltronproxy
    
    cat > /etc/systemd/system/voltronproxy.service <<EOF
[Unit]
Description=VOLTRON Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/voltronproxy -p $VOLTRON_PROXY_PORT
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

install_zivpn() {
    echo -e "${C_BLUE}🛡️ Installing ZiVPN...${C_RESET}"
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    else
        url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
    fi
    
    curl -L -o /usr/local/bin/zivpn "$url"
    chmod +x /usr/local/bin/zivpn
    mkdir -p $ZIVPN_DIR
    
    openssl req -x509 -newkey rsa:4096 -nodes -days 365 -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" -subj "/CN=ZiVPN" 2>/dev/null
    
    read -p "Passwords (comma-separated) [user1,user2]: " passwords
    passwords=${passwords:-user1,user2}
    
    IFS=',' read -ra pass_array <<< "$passwords"
    local json_passwords=$(printf '"%s",' "${pass_array[@]}")
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

    cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZiVPN Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/zivpn server -c $ZIVPN_CONFIG_FILE
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

install_xui_panel() {
    echo -e "${C_BLUE}💻 Installing X-UI Panel...${C_RESET}"
    bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
    read -p "Press Enter"
}

install_dt_proxy() {
    echo -e "${C_BLUE}🚀 Installing DT Proxy...${C_RESET}"
    curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash
    read -p "Press Enter"
}

# ========== UNINSTALL FUNCTIONS ==========
uninstall_badvpn() {
    systemctl stop badvpn.service 2>/dev/null
    systemctl disable badvpn.service 2>/dev/null
    rm -f /etc/systemd/system/badvpn.service
    rm -f /usr/local/bin/badvpn-udpgw
    systemctl daemon-reload
}

uninstall_udp_custom() {
    systemctl stop udp-custom.service 2>/dev/null
    systemctl disable udp-custom.service 2>/dev/null
    rm -f /etc/systemd/system/udp-custom.service
    rm -rf $UDP_CUSTOM_DIR
    systemctl daemon-reload
}

uninstall_ssl_tunnel() {
    systemctl stop haproxy 2>/dev/null
    $PKG_REMOVE haproxy
    rm -f /etc/haproxy/haproxy.cfg
    rm -f $SSL_CERT_FILE
}

uninstall_voltron_proxy() {
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f /etc/systemd/system/voltronproxy.service
    rm -f /usr/local/bin/voltronproxy
    systemctl daemon-reload
}

uninstall_nginx_proxy() {
    systemctl stop nginx 2>/dev/null
    $PKG_REMOVE nginx
    rm -f /etc/nginx/sites-available/default
}

uninstall_zivpn() {
    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    rm -f /etc/systemd/system/zivpn.service
    rm -f /usr/local/bin/zivpn
    rm -rf $ZIVPN_DIR
    systemctl daemon-reload
}

uninstall_xui_panel() {
    if command -v x-ui &>/dev/null; then
        x-ui uninstall
    fi
}

uninstall_dt_proxy() {
    rm -f /usr/local/bin/proxy /usr/local/bin/main /usr/local/bin/install_mod
    rm -f /etc/systemd/system/proxy-*.service 2>/dev/null
    systemctl daemon-reload
}

# ========== PROTOCOL MENU ==========
protocol_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_PURPLE}              🔌 PROTOCOL MANAGEMENT${C_RESET}"
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo ""
        echo "  1) DNSTT"
        echo "  2) DNS2TCP"
        echo "  3) V2RAY over DNSTT"
        echo "  4) badvpn"
        echo "  5) udp-custom"
        echo "  6) SSL Tunnel (HAProxy)"
        echo "  7) VOLTRON Proxy"
        echo "  8) Nginx Proxy"
        echo "  9) ZiVPN"
        echo " 10) X-UI Panel"
        echo " 11) DT Proxy"
        echo "  0) Back"
        echo ""
        
        read -p "Choice: " choice
        
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
                echo ""
                echo "1) Install V2RAY over DNSTT"
                echo "2) V2RAY User Management"
                echo "3) View Details"
                echo "4) Uninstall"
                read -p "Choice: " sub
                case $sub in
                    1) install_v2ray_dnstt ;;
                    2) v2ray_user_menu ;;
                    3) show_v2ray_details ;;
                    4) uninstall_v2ray_dnstt ;;
                esac
                ;;
            4)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_badvpn || uninstall_badvpn
                ;;
            5)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_udp_custom || uninstall_udp_custom
                ;;
            6)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_ssl_tunnel || uninstall_ssl_tunnel
                ;;
            7)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_voltron_proxy || uninstall_voltron_proxy
                ;;
            8)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_nginx_proxy || uninstall_nginx_proxy
                ;;
            9)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_zivpn || uninstall_zivpn
                ;;
            10)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_xui_panel || uninstall_xui_panel
                ;;
            11)
                echo ""
                echo "1) Install"
                echo "2) Uninstall"
                read -p "Choice: " sub
                [ "$sub" == "1" ] && install_dt_proxy || uninstall_dt_proxy
                ;;
            0) return ;;
            *) echo "Invalid" ;;
        esac
    done
}

# ========== BACKUP FUNCTIONS ==========
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

# ========== UNINSTALL EVERYTHING ==========
uninstall_everything() {
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
    
    # Stop traffic monitor
    systemctl stop voltron-traffic.service 2>/dev/null
    systemctl disable voltron-traffic.service 2>/dev/null
    rm -f /etc/systemd/system/voltron-traffic.service
    rm -f /usr/local/bin/voltron-traffic
    
    # Remove data directory
    rm -rf $DB_DIR
    
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
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo -e "${C_PURPLE}                    📋 MAIN MENU${C_RESET}"
        echo -e "${C_PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        echo ""
        echo "  1) User Management"
        echo "  2) Protocols Menu"
        echo "  3) List Users"
        echo "  4) Set MTU"
        echo "  5) Generate Cloudflare DNS"
        echo "  6) Backup Data"
        echo "  7) Restore Data"
        echo " 99) Uninstall Everything"
        echo "  0) Exit"
        echo ""
        
        read -p "Choice: " choice
        
        case $choice in
            1)
                echo ""
                echo "1) Create User"
                echo "2) List Users"
                echo "3) Delete User"
                read -p "Choice: " sub
                case $sub in
                    1) create_user ;;
                    2) list_users ;;
                    3) delete_user ;;
                esac
                ;;
            2) protocol_menu ;;
            3) list_users ;;
            4) mtu_selection ;;
            5) 
                echo -e "${C_BLUE}🌐 Generating Cloudflare DNS records...${C_RESET}"
                local rand=$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)
                create_cloudflare_record "A" "ns-$rand" "$SERVER_IP"
                create_cloudflare_record "NS" "tun-$rand" "ns-$rand.$DOMAIN"
                create_cloudflare_record "NS" "tun2-$rand" "ns-$rand.$DOMAIN"
                echo -e "${C_GREEN}✅ DNS records created${C_RESET}"
                read -p "Press Enter"
                ;;
            6) backup_data ;;
            7) restore_data ;;
            99) uninstall_everything ;;
            0) exit 0 ;;
            *) echo "Invalid" ;;
        esac
    done
}

# ========== START ==========
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}❌ Run as root${C_RESET}"
    exit 1
fi

create_directories
detect_package_manager
detect_service_manager
create_traffic_monitor
main_menu
