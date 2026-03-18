#!/bin/bash

# ========== VOLTRON TECH MANAGER v10.0 - FIXED ==========
# Description: Complete Server Management Script
# Author: Voltron Tech

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
DNSTT_SERVICE_FILE="/etc/systemd/system/dnstt.service"
DNSTT_BINARY="/usr/local/bin/dnstt-server"
DNSTT_CLIENT="/usr/local/bin/dnstt-client"
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNSTT_CONFIG_FILE="$DB_DIR/dnstt_info.conf"
DNS_INFO_FILE="$DB_DIR/dns_info.conf"
LIMITER_SCRIPT="/usr/local/bin/voltrontech-limiter.sh"
LIMITER_SERVICE="/etc/systemd/system/voltrontech-limiter.service"
BANNER_DIR="/etc/voltrontech/banners"
BANNER_ENABLED="/etc/voltrontech/banners_enabled"
SSHD_VOLTRON_CONFIG="/etc/ssh/sshd_config.d/voltrontech.conf"
LOGS_DIR="$DB_DIR/logs"
CONFIG_DIR="$DB_DIR/config"

mkdir -p $DB_DIR $DNSTT_KEYS_DIR $LOGS_DIR $CONFIG_DIR $BANNER_DIR
touch $DB_FILE
touch $BANNER_ENABLED
chmod 755 $BANNER_DIR

# ========== DESEC.IO CONFIG ==========
DESEC_TOKEN="3WxD4Hkiu5VYBLWVizVhf1rzyKbz"
DESEC_DOMAIN="voltrontechtx.shop"

# ========== COLOR CODES ==========
C_RESET='\033[0m'
C_RED='\033[91m'
C_GREEN='\033[92m'
C_YELLOW='\033[93m'
C_BLUE='\033[94m'
C_PURPLE='\033[95m'
C_CYAN='\033[96m'
C_WHITE='\033[97m'

# ========== SSH BANNER CONFIG (FIXED) ==========
setup_ssh_banner() {
    echo -e "${C_GREEN}[1/4] Setting up SSH banner...${C_RESET}"
    
    # Create SSH config
    cat > "$SSHD_VOLTRON_CONFIG" << 'EOF'
# VoltronTech Dynamic Banners
Match User *
    Banner /etc/voltrontech/banners/%u.txt
EOF

    # Ensure sshd includes config.d
    if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi
    
    # Enable banner
    touch "$BANNER_ENABLED"
    chmod 644 "$BANNER_ENABLED"
    
    # Restart SSH
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    echo -e "${C_GREEN}  ✓ SSH banner configured${C_RESET}"
}

# ========== LIMITER SERVICE (WITH BANNER) ==========
setup_limiter() {
    echo -e "${C_GREEN}[2/4] Setting up limiter service...${C_RESET}"
    
    cat > "$LIMITER_SCRIPT" << 'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
BANNER_DIR="/etc/voltrontech/banners"
BANNER_ENABLED="/etc/voltrontech/banners_enabled"

mkdir -p "$BANNER_DIR"

generate_banner() {
    local user=$1
    local expiry=$2
    local limit=$3
    local current_ts=$4
    local online_count=$5
    
    # Calculate days left
    local days_left="N/A"
    if [[ "$expiry" != "Never" ]]; then
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -gt 0 ]]; then
            local diff_secs=$((expiry_ts - current_ts))
            if [[ $diff_secs -le 0 ]]; then
                days_left="EXPIRED"
            else
                local d_l=$(( diff_secs / 86400 ))
                local h_l=$(( (diff_secs % 86400) / 3600 ))
                days_left="${d_l}d ${h_l}h"
            fi
        fi
    fi
    
    # Create banner file
    cat > "$BANNER_DIR/${user}.txt" << EOB
<font color="white">

===============================

WELCOME TO VOLTRON TECH

===============================

      ✨ ACCOUNT STATUS ✨      

👤 Username   : ${user}
📅 Expiration : ${expiry} (${days_left})
🔌 Sessions   : ${online_count}/${limit}

===============================

</font>
EOB
    
    chmod 644 "$BANNER_DIR/${user}.txt"
}

while true; do
    if [[ -f "$BANNER_ENABLED" ]] && [[ -f "$DB_FILE" ]]; then
        current_ts=$(date +%s)
        while IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status; do
            [[ -z "$user" ]] && continue
            online_count=$(pgrep -c -u "$user" sshd 2>/dev/null)
            generate_banner "$user" "$expiry" "$limit" "$current_ts" "$online_count"
        done < "$DB_FILE"
    fi
    sleep 15
done
EOF

    chmod +x "$LIMITER_SCRIPT"
    
    cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=VoltronTech Banner Limiter
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltrontech-limiter.service
    systemctl restart voltrontech-limiter.service
    
    echo -e "${C_GREEN}  ✓ Limiter service started${C_RESET}"
}

# ========== DNSTT INSTALLATION (FIXED) ==========
install_dnstt() {
    clear
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Check if already installed
    if [ -f "$DNSTT_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}⚠️ DNSTT is already installed${C_RESET}"
        read -p "Reinstall? (y/n): " reinstall
        [[ "$reinstall" != "y" ]] && return
        systemctl stop dnstt.service 2>/dev/null
    fi
    
    echo -e "\n${C_GREEN}[1/9] Installing dependencies...${C_RESET}"
    apt-get update
    apt-get install -y wget curl git build-essential openssl netcat-openbsd jq
    
    echo -e "\n${C_GREEN}[2/9] Installing Go...${C_RESET}"
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    echo -e "\n${C_GREEN}[3/9] Building DNSTT from source...${C_RESET}"
    cd /tmp
    rm -rf dnstt
    git clone https://www.bamsoftware.com/git/dnstt.git
    cd dnstt/dnstt-server
    go build -o "$DNSTT_BINARY"
    cd ../dnstt-client
    go build -o "$DNSTT_CLIENT"
    chmod 755 "$DNSTT_BINARY" "$DNSTT_CLIENT"
    
    echo -e "\n${C_GREEN}[4/9] Configuring firewall...${C_RESET}"
    # Stop systemd-resolved
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    
    # Set DNS
    chattr -i /etc/resolv.conf 2>/dev/null
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null
    
    # Clear iptables
    iptables -F
    iptables -t nat -F
    
    # Allow ports
    iptables -A INPUT -p udp --dport 5300 -j ACCEPT
    iptables -A OUTPUT -p udp --sport 5300 -j ACCEPT
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    echo -e "\n${C_GREEN}[5/9] Generating keys...${C_RESET}"
    cd "$DNSTT_KEYS_DIR"
    "$DNSTT_BINARY" -gen-key -privkey-file server.key -pubkey-file server.pub
    chmod 600 server.key
    chmod 644 server.pub
    PUBLIC_KEY=$(cat server.pub)
    
    echo -e "\n${C_GREEN}[6/9] Choose forwarding destination:${C_RESET}"
    echo "  1) SSH (port 22)"
    echo "  2) V2Ray (port 8787)"
    read -p "👉 Choice [2]: " fwd_choice
    fwd_choice=${fwd_choice:-2}
    
    if [[ "$fwd_choice" == "1" ]]; then
        forward_port="22"
        forward_desc="SSH"
    else
        forward_port="8787"
        forward_desc="V2Ray"
    fi
    
    echo -e "\n${C_GREEN}[7/9] Domain configuration...${C_RESET}"
    echo "  1) Custom domain"
    echo "  2) Auto-generate with Desec.io"
    read -p "👉 Choice [2]: " domain_choice
    domain_choice=${domain_choice:-2}
    
    if [[ "$domain_choice" == "1" ]]; then
        read -p "👉 Enter domain: " DOMAIN
    else
        echo -e "${C_BLUE}Generating domain with Desec.io...${C_RESET}"
        SERVER_IPV4=$(curl -s -4 icanhazip.com)
        RANDOM_SUB="vps-$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
        FULL_DOMAIN="$RANDOM_SUB.$DESEC_DOMAIN"
        
        API_DATA="[{\"subname\":\"$RANDOM_SUB\",\"type\":\"A\",\"ttl\":3600,\"records\":[\"$SERVER_IPV4\"]}]"
        curl -s -X POST "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/" \
            -H "Authorization: Token $DESEC_TOKEN" \
            -H "Content-Type: application/json" \
            --data "$API_DATA" > /dev/null
        
        DOMAIN="$FULL_DOMAIN"
        echo -e "${C_GREEN}  ✓ Domain: $DOMAIN${C_RESET}"
        
        cat > "$DNS_INFO_FILE" << EOF
SUBDOMAIN="$RANDOM_SUB"
FULL_DOMAIN="$FULL_DOMAIN"
SERVER_IPV4="$SERVER_IPV4"
EOF
    fi
    
    echo -e "\n${C_GREEN}[8/9] Creating DNSTT service...${C_RESET}"
    cat > "$DNSTT_SERVICE_FILE" << EOF
[Unit]
Description=DNSTT Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DNSTT_KEYS_DIR
ExecStart=$DNSTT_BINARY -udp :5300 \\
    -privkey-file $DNSTT_KEYS_DIR/server.key \\
    -mtu 512 \\
    $DOMAIN 127.0.0.1:$forward_port
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service
    
    echo -e "\n${C_GREEN}[9/9] Starting DNSTT service...${C_RESET}"
    systemctl start dnstt.service
    sleep 3
    
    # Save info
    cat > "$DNSTT_CONFIG_FILE" << EOF
TUNNEL_DOMAIN="$DOMAIN"
PUBLIC_KEY="$PUBLIC_KEY"
FORWARD_DESC="$forward_desc"
MTU_VALUE="512"
SSH_PORT="$forward_port"
EOF
    
    # Check status
    if systemctl is-active dnstt.service >/dev/null; then
        echo -e "\n${C_GREEN}✅ DNSTT is RUNNING!${C_RESET}"
    else
        echo -e "\n${C_RED}❌ DNSTT is STOPPED${C_RESET}"
        echo -e "\n${C_YELLOW}Checking logs...${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
    fi
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           📋 DNSTT DETAILS${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  Domain:     $DOMAIN"
    echo -e "  Forward:    $forward_desc"
    echo -e "  Public Key: ${PUBLIC_KEY:0:50}..."
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    read -p "Press [Enter] to continue..."
}

# ========== CHECK DNSTT STATUS ==========
check_dnstt() {
    clear
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           🔍 DNSTT STATUS CHECK${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo -e "\n${C_CYAN}[1] Service status:${C_RESET}"
    systemctl status dnstt.service --no-pager
    
    echo -e "\n${C_CYAN}[2] Port 5300:${C_RESET}"
    ss -lunp | grep 5300 || echo "  ❌ Port 5300 not listening"
    
    echo -e "\n${C_CYAN}[3] Firewall:${C_RESET}"
    iptables -L INPUT -n -v | grep 5300 || echo "  ❌ No firewall rule for port 5300"
    
    echo -e "\n${C_CYAN}[4] Last 10 log lines:${C_RESET}"
    journalctl -u dnstt.service -n 10 --no-pager
    
    echo -e "\n${C_YELLOW}Options:${C_RESET}"
    echo "  1) Restart DNSTT"
    echo "  2) Open firewall port"
    echo "  0) Return"
    echo
    read -p "👉 Choice: " ch
    
    case $ch in
        1) systemctl restart dnstt.service; sleep 2; check_dnstt ;;
        2) 
            iptables -I INPUT 1 -p udp --dport 5300 -j ACCEPT
            iptables-save > /etc/iptables/rules.v4
            echo -e "${C_GREEN}✓ Port opened${C_RESET}"
            sleep 2
            check_dnstt
            ;;
        0) return ;;
    esac
}

# ========== CREATE USER ==========
create_user() {
    clear
    read -p "Username: " username
    read -p "Password: " password
    read -p "Days: " days
    read -p "Connection limit: " limit
    
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    useradd -m -s /usr/sbin/nologin "$username"
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:0:0:ACTIVE" >> "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User $username created${C_RESET}"
    read -p "Press [Enter]..."
}

# ========== LIST USERS ==========
list_users() {
    clear
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Users ---${C_RESET}\n"
    
    if [[ ! -s "$DB_FILE" ]]; then
        echo "No users found"
        read -p "Press [Enter]..."
        return
    fi
    
    printf "%-15s | %-12s | %-8s | %-10s\n" "USERNAME" "EXPIRY" "LIMIT" "STATUS"
    echo "----------------------------------------"
    
    while IFS=: read -r user pass expiry limit bw tu status; do
        online=$(pgrep -u "$user" sshd | wc -l)
        printf "%-15s | %-12s | %s/%s | %s\n" "$user" "$expiry" "$online" "$limit" "$status"
    done < "$DB_FILE"
    
    echo ""
    read -p "Press [Enter]..."
}

# ========== DELETE USER ==========
delete_user() {
    read -p "Username: " username
    read -p "Confirm? (y/n): " confirm
    [[ "$confirm" != "y" ]] && return
    
    killall -u "$username" 2>/dev/null
    userdel -r "$username" 2>/dev/null
    sed -i "/^$username:/d" "$DB_FILE"
    rm -f "$BANNER_DIR/${username}.txt"
    
    echo -e "\n${C_GREEN}✅ User deleted${C_RESET}"
    read -p "Press [Enter]..."
}

# ========== MAIN MENU ==========
main_menu() {
    while true; do
        clear
        echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH MANAGER v10.0 🔥                   ║${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""
        echo "  1) Create User"
        echo "  2) List Users"
        echo "  3) Delete User"
        echo "  4) Install DNSTT"
        echo "  5) Check DNSTT Status"
        echo "  6) Test SSH Banner"
        echo "  0) Exit"
        echo ""
        read -p "👉 Choice: " choice
        
        case $choice in
            1) create_user ;;
            2) list_users ;;
            3) delete_user ;;
            4) install_dnstt ;;
            5) check_dnstt ;;
            6) 
                echo -e "\n${C_YELLOW}Testing SSH banner...${C_RESET}"
                echo "Run this command: ssh localhost"
                read -p "Press [Enter]..."
                ;;
            0) exit 0 ;;
            *) echo -e "\n${C_RED}Invalid${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== START ==========
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}❌ Must be root${C_RESET}"
    exit 1
fi

setup_ssh_banner
setup_limiter
main_menu
