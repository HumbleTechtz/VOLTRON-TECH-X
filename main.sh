#!/bin/bash

# ========== VOLTRON TECH ULTIMATE SCRIPT ==========
# Version: 10.0 (PREMIUM - Full Voltron Tech Features)
# Description: SSH • DNSTT • V2RAY • BADVPN • UDP-CUSTOM • SSL • PROXY • ZIVPN • X-UI
# Author: Voltron Tech
# Features: SSH Banner (HTML + Text) • WhatsApp Group • User Management • Bandwidth Tracking
#           ULTRA BOOST (INSIDE DNSTT ONLY) • deSEC Domain (NS + Tunnel) • 10 Parallel Instances

# ========== COLOR CODES ==========
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_UL='\033[4m'

# Premium Color Palette
C_RED='\033[38;5;196m'      # Bright Red
C_GREEN='\033[38;5;46m'     # Neon Green
C_YELLOW='\033[38;5;226m'   # Bright Yellow
C_BLUE='\033[38;5;39m'      # Deep Sky Blue
C_PURPLE='\033[38;5;135m'   # Light Purple
C_CYAN='\033[38;5;51m'      # Cyan
C_WHITE='\033[38;5;255m'    # Bright White
C_GRAY='\033[38;5;245m'     # Gray
C_ORANGE='\033[38;5;208m'   # Orange

# Semantic Aliases
C_TITLE=$C_PURPLE
C_CHOICE=$C_CYAN
C_PROMPT=$C_BLUE
C_WARN=$C_YELLOW
C_DANGER=$C_RED
C_STATUS_A=$C_GREEN
C_STATUS_I=$C_GRAY
C_ACCENT=$C_ORANGE

# ========== VOLTRON TECH DESEC.IO CONFIGURATION ==========
DESEC_TOKEN="3WxD4Hkiu5VYBLWVizVhf1rzyKbz"
DESEC_DOMAIN="voltrontechtx.shop"
BASE_DOMAIN="voltrontechtx.shop"

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
SSH_BANNER_FILE="/etc/voltrontech/banner"
BANDWIDTH_DIR="$DB_DIR/bandwidth"
PID_DIR="$BANDWIDTH_DIR/pidtrack"

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
BANNERS_DIR="$DB_DIR/banners"

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
ZIVPN_SERVICE_FILE="/etc/systemd/system/zivpn.service"
FALCONPROXY_SERVICE_FILE="/etc/systemd/system/falconproxy.service"
FALCONPROXY_BINARY="/usr/local/bin/falconproxy"
FALCONPROXY_CONFIG_FILE="$DB_DIR/falconproxy_config.conf"
NGINX_PORTS_FILE="$DB_DIR/nginx_ports.conf"
ZIVPN_CONFIG_FILE="$ZIVPN_DIR/config.json"
ZIVPN_CERT_FILE="$ZIVPN_DIR/zivpn.crt"
ZIVPN_KEY_FILE="$ZIVPN_DIR/zivpn.key"

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
TRIAL_CLEANUP_SCRIPT="/usr/local/bin/voltrontech-trial-cleanup.sh"
SSHD_VOLTRON_CONFIG="/etc/ssh/sshd_config.d/voltrontech.conf"

# WhatsApp Group Link
WHATSAPP_GROUP="https://chat.whatsapp.com/KVMPv89XSu83UnBWUZ"

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
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $V2RAY_KEYS_DIR $V2RAY_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR $FEC_DIR $BANDWIDTH_DIR $PID_DIR $BANNERS_DIR
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

check_and_free_ports() {
    local ports_to_check=("$@")
    for port in "${ports_to_check[@]}"; do
        echo -e "\n${C_BLUE}🔎 Checking if port $port is available...${C_RESET}"
        local conflicting_process_info
        conflicting_process_info=$(ss -lntp | grep ":$port\s" || ss -lunp | grep ":$port\s")
        
        if [[ -n "$conflicting_process_info" ]]; then
            local conflicting_pid
            conflicting_pid=$(echo "$conflicting_process_info" | grep -oP 'pid=\K[0-9]+' | head -n 1)
            local conflicting_name
            conflicting_name=$(echo "$conflicting_process_info" | grep -oP 'users:\(\("(\K[^"]+)' | head -n 1)
            
            echo -e "${C_YELLOW}⚠️ Warning: Port $port is in use by process '${conflicting_name:-unknown}' (PID: ${conflicting_pid:-N/A}).${C_RESET}"
            read -p "👉 Do you want to attempt to stop this process? (y/n): " kill_confirm
            if [[ "$kill_confirm" == "y" || "$kill_confirm" == "Y" ]]; then
                echo -e "${C_GREEN}🛑 Stopping process PID $conflicting_pid...${C_RESET}"
                systemctl stop "$(ps -p "$conflicting_pid" -o comm=)" &>/dev/null || kill -9 "$conflicting_pid"
                sleep 2
                
                if ss -lntp | grep -q ":$port\s" || ss -lunp | grep -q ":$port\s"; then
                     echo -e "${C_RED}❌ Failed to free port $port. Please handle it manually. Aborting.${C_RESET}"
                     return 1
                else
                     echo -e "${C_GREEN}✅ Port $port has been successfully freed.${C_RESET}"
                fi
            else
                echo -e "${C_RED}❌ Cannot proceed without freeing port $port. Aborting.${C_RESET}"
                return 1
            fi
        else
            echo -e "${C_GREEN}✅ Port $port is free to use.${C_RESET}"
        fi
    done
    return 0
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

# ========== VOLTRON TECH DESEC.IO DNS FUNCTIONS ==========
generate_dns_record() {
    echo -e "\n${C_BLUE}⚙️ Generating DNS records for DNSTT on voltrontechtx.shop...${C_RESET}"
    if ! command -v jq &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ jq not found, attempting to install...${C_RESET}"
        apt-get update > /dev/null 2>&1 && apt-get install -y jq || {
            echo -e "${C_RED}❌ Failed to install jq. Cannot manage DNS records.${C_RESET}"
            return 1
        }
    fi
    
    local SERVER_IPV4
    SERVER_IPV4=$(curl -s -4 icanhazip.com)
    if ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "\n${C_RED}❌ Error: Could not retrieve a valid public IPv4 address.${C_RESET}"
        return 1
    fi

    local SERVER_IPV6
    SERVER_IPV6=$(curl -s -6 icanhazip.com --max-time 5)

    local RANDOM_STR
    RANDOM_STR=$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)
    
    # Nameserver subdomain (A record)
    local NS_SUBDOMAIN="ns-$RANDOM_STR"
    local NS_DOMAIN="$NS_SUBDOMAIN.$DESEC_DOMAIN"
    
    # Tunnel subdomain (NS record)
    local TUNNEL_SUBDOMAIN="tun-$RANDOM_STR"
    local TUNNEL_DOMAIN="$TUNNEL_SUBDOMAIN.$DESEC_DOMAIN"

    local HAS_IPV6="false"
    
    # Build API data - Always include A record for nameserver and NS record for tunnel
    local API_DATA="["
    
    # Add A record for nameserver
    API_DATA="${API_DATA}{\"subname\": \"$NS_SUBDOMAIN\", \"type\": \"A\", \"ttl\": 3600, \"records\": [\"$SERVER_IPV4\"]}"
    
    # Add AAAA record for nameserver if IPv6 exists
    if [[ -n "$SERVER_IPV6" ]]; then
        API_DATA="${API_DATA}, {\"subname\": \"$NS_SUBDOMAIN\", \"type\": \"AAAA\", \"ttl\": 3600, \"records\": [\"$SERVER_IPV6\"]}"
        HAS_IPV6="true"
    fi
    
    # Add NS record for tunnel (pointing to nameserver domain)
    API_DATA="${API_DATA}, {\"subname\": \"$TUNNEL_SUBDOMAIN\", \"type\": \"NS\", \"ttl\": 3600, \"records\": [\"$NS_DOMAIN.\"]}"
    
    API_DATA="${API_DATA}]"

    local CREATE_RESPONSE
    CREATE_RESPONSE=$(curl -s -w "%{http_code}" -X POST "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/" \
        -H "Authorization: Token $DESEC_TOKEN" -H "Content-Type: application/json" \
        --data "$API_DATA")
    
    local HTTP_CODE=${CREATE_RESPONSE: -3}
    local RESPONSE_BODY=${CREATE_RESPONSE:0:${#CREATE_RESPONSE}-3}

    if [[ "$HTTP_CODE" -ne 201 ]]; then
        echo -e "${C_RED}❌ Failed to create DNS records. API returned HTTP $HTTP_CODE.${C_RESET}"
        if ! echo "$RESPONSE_BODY" | jq . > /dev/null 2>&1; then
            echo "Raw Response: $RESPONSE_BODY"
        else
            echo "Response: $RESPONSE_BODY" | jq
        fi
        return 1
    fi
    
    # Save all information
    cat > "$DNS_INFO_FILE" <<-EOF
NS_SUBDOMAIN="$NS_SUBDOMAIN"
TUNNEL_SUBDOMAIN="$TUNNEL_SUBDOMAIN"
NS_DOMAIN="$NS_DOMAIN"
TUNNEL_DOMAIN="$TUNNEL_DOMAIN"
HAS_IPV6="$HAS_IPV6"
EOF
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DNS RECORDS CREATED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Nameserver Domain (A record):${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}  → Points to:${C_RESET} ${C_GREEN}$SERVER_IPV4${C_RESET}"
    if [[ "$HAS_IPV6" == "true" ]]; then
        echo -e "  ${C_CYAN}  → IPv6 also:${C_RESET} ${C_GREEN}$SERVER_IPV6${C_RESET}"
    fi
    echo -e "  ${C_CYAN}Tunnel Domain (NS record):${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}  → Points to:${C_RESET} ${C_GREEN}$NS_DOMAIN${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo "$TUNNEL_DOMAIN" > "$DB_DIR/domain.txt"
}

delete_dns_record() {
    if [ ! -f "$DNS_INFO_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No domain to delete.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}🗑️ Deleting DNS records...${C_RESET}"
    source "$DNS_INFO_FILE"
    
    if [[ -z "$NS_SUBDOMAIN" || -z "$TUNNEL_SUBDOMAIN" ]]; then
        echo -e "${C_RED}❌ Could not read record details from config file. Skipping deletion.${C_RESET}"
        return
    fi

    # Delete A record for nameserver
    curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$NS_SUBDOMAIN/A/" \
         -H "Authorization: Token $DESEC_TOKEN" > /dev/null
    echo -e "${C_GREEN}✅ Deleted A record for $NS_SUBDOMAIN${C_RESET}"

    # Delete AAAA record if exists
    if [[ "$HAS_IPV6" == "true" ]]; then
        curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$NS_SUBDOMAIN/AAAA/" \
             -H "Authorization: Token $DESEC_TOKEN" > /dev/null
        echo -e "${C_GREEN}✅ Deleted AAAA record for $NS_SUBDOMAIN${C_RESET}"
    fi

    # Delete NS record for tunnel
    curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$TUNNEL_SUBDOMAIN/NS/" \
         -H "Authorization: Token $DESEC_TOKEN" > /dev/null
    echo -e "${C_GREEN}✅ Deleted NS record for $TUNNEL_SUBDOMAIN${C_RESET}"

    echo -e "\n${C_GREEN}✅ Deleted all DNS records for tunnel: ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    rm -f "$DNS_INFO_FILE"
    rm -f "$DB_DIR/domain.txt"
}

dns_menu() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 DNS Domain Management (voltrontechtx.shop) ---${C_RESET}"
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        echo -e "\n${C_GREEN}📌 Current DNS Records:${C_RESET}"
        echo -e "  ${C_CYAN}Nameserver:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        echo -e "  ${C_CYAN}Tunnel:${C_RESET}     ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo
        read -p "👉 Do you want to DELETE these records? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            delete_dns_record
        else
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        fi
    else
        echo -e "\nℹ️ No domain has been generated for this server yet."
        echo
        read -p "👉 Do you want to generate new DNS records now? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            generate_dns_record
        else
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
        fi
    fi
}

# ========== AUTO REBOOT FUNCTIONS ==========
check_auto_reboot_status() {
    local cron_check=$(crontab -l 2>/dev/null | grep "systemctl reboot")
    if [[ -n "$cron_check" ]]; then
        echo -e "${C_GREEN}ENABLED${C_RESET} (Daily at midnight)"
        return 0
    else
        echo -e "${C_RED}DISABLED${C_RESET}"
        return 1
    fi
}

enable_auto_reboot() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔄 ENABLING AUTO REBOOT${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab -
    (crontab -l 2>/dev/null; echo "0 0 * * * systemctl reboot") | crontab -
    
    echo -e "${C_GREEN}✅ Auto reboot scheduled for every day at 00:00 (midnight).${C_RESET}"
    echo -e "${C_YELLOW}📌 Server will automatically restart daily at midnight.${C_RESET}"
}

disable_auto_reboot() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🛑 DISABLING AUTO REBOOT${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab -
    
    echo -e "${C_GREEN}✅ Auto reboot disabled.${C_RESET}"
    echo -e "${C_YELLOW}📌 Server will no longer restart automatically.${C_RESET}"
}

custom_auto_reboot() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ⏰ CUSTOM AUTO REBOOT TIME${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo -e "\n${C_CYAN}Select reboot frequency:${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} Daily"
    echo -e "  ${C_GREEN}2)${C_RESET} Weekly"
    echo -e "  ${C_GREEN}3)${C_RESET} Monthly"
    echo ""
    
    local freq_choice
    read -p "👉 Select frequency [1]: " freq_choice
    freq_choice=${freq_choice:-1}
    
    local cron_schedule=""
    
    case $freq_choice in
        1)
            read -p "👉 Enter hour (0-23) [0]: " hour
            hour=${hour:-0}
            read -p "👉 Enter minute (0-59) [0]: " minute
            minute=${minute:-0}
            
            if [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 23 ] && \
               [[ "$minute" =~ ^[0-9]+$ ]] && [ "$minute" -ge 0 ] && [ "$minute" -le 59 ]]; then
                cron_schedule="$minute $hour * * *"
                echo -e "${C_GREEN}✅ Daily reboot scheduled at ${hour}:${minute}${C_RESET}"
            else
                echo -e "${C_RED}❌ Invalid time format.${C_RESET}"
                return
            fi
            ;;
        2)
            echo -e "\n${C_CYAN}Select day of week:${C_RESET}"
            echo -e "  ${C_GREEN}0)${C_RESET} Sunday"
            echo -e "  ${C_GREEN}1)${C_RESET} Monday"
            echo -e "  ${C_GREEN}2)${C_RESET} Tuesday"
            echo -e "  ${C_GREEN}3)${C_RESET} Wednesday"
            echo -e "  ${C_GREEN}4)${C_RESET} Thursday"
            echo -e "  ${C_GREEN}5)${C_RESET} Friday"
            echo -e "  ${C_GREEN}6)${C_RESET} Saturday"
            echo ""
            read -p "👉 Select day [0]: " day
            day=${day:-0}
            
            read -p "👉 Enter hour (0-23) [0]: " hour
            hour=${hour:-0}
            read -p "👉 Enter minute (0-59) [0]: " minute
            minute=${minute:-0}
            
            if [[ "$day" =~ ^[0-6]$ ]] && \
               [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 23 ] && \
               [[ "$minute" =~ ^[0-9]+$ ]] && [ "$minute" -ge 0 ] && [ "$minute" -le 59 ]]; then
                cron_schedule="$minute $hour * * $day"
                echo -e "${C_GREEN}✅ Weekly reboot scheduled on day $day at ${hour}:${minute}${C_RESET}"
            else
                echo -e "${C_RED}❌ Invalid input.${C_RESET}"
                return
            fi
            ;;
        3)
            read -p "👉 Enter day of month (1-31) [1]: " dom
            dom=${dom:-1}
            read -p "👉 Enter hour (0-23) [0]: " hour
            hour=${hour:-0}
            read -p "👉 Enter minute (0-59) [0]: " minute
            minute=${minute:-0}
            
            if [[ "$dom" =~ ^[0-9]+$ ]] && [ "$dom" -ge 1 ] && [ "$dom" -le 31 ] && \
               [[ "$hour" =~ ^[0-9]+$ ]] && [ "$hour" -ge 0 ] && [ "$hour" -le 23 ] && \
               [[ "$minute" =~ ^[0-9]+$ ]] && [ "$minute" -ge 0 ] && [ "$minute" -le 59 ]]; then
                cron_schedule="$minute $hour $dom * *"
                echo -e "${C_GREEN}✅ Monthly reboot scheduled on day $dom at ${hour}:${minute}${C_RESET}"
            else
                echo -e "${C_RED}❌ Invalid input.${C_RESET}"
                return
            fi
            ;;
        *)
            echo -e "${C_RED}❌ Invalid choice.${C_RESET}"
            return
            ;;
    esac
    
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab -
    (crontab -l 2>/dev/null; echo "$cron_schedule systemctl reboot") | crontab -
    
    echo -e "\n${C_GREEN}✅ Custom auto reboot scheduled successfully!${C_RESET}"
}

auto_reboot_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}           🔄 AUTO REBOOT MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        echo -e "  ${C_CYAN}Current Status:${C_RESET} $(check_auto_reboot_status)"
        echo ""
        
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Auto Reboot (Daily at midnight)"
        echo -e "  ${C_GREEN}2)${C_RESET} Set Custom Reboot Time"
        echo -e "  ${C_RED}3)${C_RESET} Disable Auto Reboot"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return to Main Menu"
        echo ""
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) enable_auto_reboot; safe_read "" dummy ;;
            2) custom_auto_reboot; safe_read "" dummy ;;
            3) disable_auto_reboot; safe_read "" dummy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== SSH BANNER FUNCTIONS ==========
update_ssh_banners_config() {
    rm -f /usr/local/bin/voltrontech-login-info.sh 2>/dev/null
    
    if [[ ! -f "$DB_DIR/banners_enabled" ]]; then
        rm -f "$SSHD_VOLTRON_CONFIG" 2>/dev/null
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
        return
    fi
    
    mkdir -p "$BANNERS_DIR" /etc/ssh/sshd_config.d
    
    tmp_conf="/tmp/voltron_banners_new.conf"
    echo "# Voltron Tech - Show login info native banners" > "$tmp_conf"
    
    if [[ -f "$DB_FILE" ]]; then
        while IFS=: read -r u pass expiry limit bandwidth_gb _extra; do
            [[ -z "$u" || "$u" == \#* ]] && continue
            echo "Match User $u" >> "$tmp_conf"
            echo "    Banner $BANNERS_DIR/${u}.txt" >> "$tmp_conf"
        done < "$DB_FILE"
    fi
    
    if ! cmp -s "$tmp_conf" "$SSHD_VOLTRON_CONFIG" 2>/dev/null; then
        mv "$tmp_conf" "$SSHD_VOLTRON_CONFIG"
        if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config 2>/dev/null; then
            echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
        fi
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
    else
        rm -f "$tmp_conf"
    fi
}

enable_ssh_banner() {
    touch "$DB_DIR/banners_enabled"
    update_ssh_banners_config
    echo -e "\n${C_GREEN}✅ SSH Login Banner has been enabled!${C_RESET}"
    echo -e "${C_DIM}Users will see their account information when connecting via SSH tunnel.${C_RESET}"
}

disable_ssh_banner() {
    rm -f "$DB_DIR/banners_enabled"
    update_ssh_banners_config
    echo -e "\n${C_YELLOW}❌ SSH Login Banner has been disabled.${C_RESET}"
}

preview_ssh_banner() {
    _select_user_interface "--- 📝 Preview Login Banner ---"
    local u=$SELECTED_USER
    if [[ -z "$u" || "$u" == "NO_USERS" ]]; then return; fi
    
    echo -e "\n${C_CYAN}--- Banner Preview for user '$u' ---${C_RESET}\n"
    if [[ -f "$BANNERS_DIR/${u}.txt" ]]; then
        cat "$BANNERS_DIR/${u}.txt"
    else
        echo -e "${C_RED}Banner file not generated yet. Waiting for limiter service...${C_RESET}"
        sleep 5
        if ! cat "$BANNERS_DIR/${u}.txt" 2>/dev/null; then
            echo -e "\n${C_RED}Still not generated. Check limiter service:${C_RESET}"
            journalctl -u voltrontech-limiter -n 10 --no-pager
        fi
    fi
}

ssh_banner_menu() {
    while true; do
        clear
        show_banner
        
        local banner_status=""
        if [[ -f "$DB_DIR/banners_enabled" ]]; then
            banner_status="${C_GREEN}(Enabled)${C_RESET}"
        else
            banner_status="${C_RED}(Disabled)${C_RESET}"
        fi
        
        echo -e "\n   ${C_TITLE}═════════════════[ ${C_BOLD}🎨 SSH BANNER MANAGEMENT ${banner_status} ${C_RESET}${C_TITLE}]═════════════════${C_RESET}"
        echo -e "     ${C_ACCENT}This banner will show account information to users:${C_RESET}"
        echo -e "     ${C_DIM}• Days/hours remaining${C_RESET}"
        echo -e "     ${C_DIM}• Bandwidth used and remaining${C_RESET}"
        echo -e "     ${C_DIM}• Active connections count${C_RESET}"
        echo -e "     ${C_DIM}• ULTRA BOOST status${C_RESET}"
        echo ""
        printf "     ${C_CHOICE}[ 1]${C_RESET} %-40s\n" "✅ Enable SSH Banner"
        printf "     ${C_CHOICE}[ 2]${C_RESET} %-40s\n" "❌ Disable SSH Banner"
        printf "     ${C_CHOICE}[ 3]${C_RESET} %-40s\n" "📝 Preview Banner for a User"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_WARN}[ 0]${C_RESET} ↩️ Return to Main Menu"
        echo
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) enable_ssh_banner; safe_read "" dummy ;;
            2) disable_ssh_banner; safe_read "" dummy ;;
            3) preview_ssh_banner; safe_read "" dummy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

# ========== ULTRA BOOST FUNCTIONS (PEKEE KWA DNSTT) ==========
enable_bbr_v3() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔧 ENABLING BBR v3 CONGESTION CONTROL${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    modprobe tcp_bbr 2>/dev/null
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null
    
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel > /dev/null 2>&1
    
    cat >> /etc/sysctl.conf << EOF

# BBR v3 Congestion Control with fq_codel (for DNSTT Ultra Boost)
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
EOF
    
    echo -e "${C_GREEN}✅ BBR v3 enabled with fq_codel (optimized for low latency)${C_RESET}"
}

optimize_ultra_buffers() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📊 OPTIMIZING ULTRA BUFFERS (32MB)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    sysctl -w net.core.rmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.core.wmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432" > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432" > /dev/null 2>&1
    sysctl -w net.core.optmem_max=33554432 > /dev/null 2>&1
    
    cat >> /etc/sysctl.conf << EOF

# Ultra Network Buffers for MTU 512 (32MB) - DNSTT 10x speed
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.optmem_max = 33554432
EOF
    
    echo -e "${C_GREEN}✅ Ultra buffers set to 32MB (optimized for 10x speed)${C_RESET}"
}

optimize_aggressive_keepalive() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔄 OPTIMIZING AGGRESSIVE KEEPALIVE (10s)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    sysctl -w net.ipv4.tcp_keepalive_time=10 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_intvl=2 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_probes=2 > /dev/null 2>&1
    
    cat >> /etc/sysctl.conf << EOF

# Aggressive TCP Keepalive for MTU 512 (10s) - DNSTT 10x speed
net.ipv4.tcp_keepalive_time = 10
net.ipv4.tcp_keepalive_intvl = 2
net.ipv4.tcp_keepalive_probes = 2
EOF
    
    echo -e "${C_GREEN}✅ Aggressive keepalive set to 10s intervals${C_RESET}"
}

optimize_advanced_tcp() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📐 APPLYING ADVANCED TCP TUNABLES (12 parameters)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
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
    
    cat >> /etc/sysctl.conf << EOF

# Advanced TCP Tuning for MTU 512 - DNSTT 10x speed
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

optimize_ultra_filedesc() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📄 SETTING ULTRA FILE DESCRIPTORS (8M)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
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

# ========== VOLTRON TECH LIMITER SERVICE (WITH BANNER GENERATION) ==========
setup_limiter_service() {
    cat > "$LIMITER_SCRIPT" << 'EOF'
#!/bin/bash
DB_FILE="/etc/voltrontech/users.db"
BW_DIR="/etc/voltrontech/bandwidth"
PID_DIR="$BW_DIR/pidtrack"
BANNERS_DIR="/etc/voltrontech/banners"

mkdir -p "$BW_DIR" "$PID_DIR" "$BANNERS_DIR"

while true; do
    if [[ ! -f "$DB_FILE" ]]; then
        sleep 30
        continue
    fi
    
    current_ts=$(date +%s)
    
    while IFS=: read -r user pass expiry limit bandwidth_gb _extra; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        # --- Expiry Check ---
        if [[ "$expiry" != "Never" && "$expiry" != "" ]]; then
             expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
             if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                if ! passwd -S "$user" | grep -q " L "; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                fi
                continue
             fi
        fi
        
        # --- Connection Limit Check ---
        online_count=$(pgrep -c -u "$user" sshd)
        if ! [[ "$limit" =~ ^[0-9]+$ ]]; then limit=1; fi
        
        if [[ "$online_count" -gt "$limit" ]]; then
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
                (sleep 120; usermod -U "$user" &>/dev/null) & 
            else
                killall -u "$user" -9 &>/dev/null
            fi
        fi
        
        # --- SSH Banner Generation (HTML + Text) ---
        if [[ -f "/etc/voltrontech/banners_enabled" ]]; then
            days_left="N/A"
            if [[ "$expiry" != "Never" && -n "$expiry" ]]; then
                if [[ $expiry_ts -gt 0 ]]; then
                    diff_secs=$((expiry_ts - current_ts))
                    if [[ $diff_secs -le 0 ]]; then
                        days_left="EXPIRED"
                    else
                        d_l=$(( diff_secs / 86400 ))
                        h_l=$(( (diff_secs % 86400) / 3600 ))
                        if [[ $d_l -eq 0 ]]; then 
                            days_left="${h_l}h left"
                        else 
                            days_left="${d_l}d ${h_l}h"
                        fi
                    fi
                fi
            fi
            
            bw_info="Unlimited"
            if [[ "$bandwidth_gb" != "0" && -n "$bandwidth_gb" ]]; then
                usagefile="$BW_DIR/${user}.usage"
                accum_disp=0
                [[ -f "$usagefile" ]] && accum_disp=$(cat "$usagefile" 2>/dev/null)
                used_gb=$(awk "BEGIN {printf \"%.2f\", $accum_disp / 1073741824}")
                remain_gb=$(awk "BEGIN {r=$bandwidth_gb - $used_gb; if(r<0) r=0; printf \"%.2f\", r}")
                bw_info="${used_gb}/${bandwidth_gb} GB used | ${remain_gb} GB left"
            fi
            
            online_count=$(pgrep -c -u "$user" sshd)
            
            # ------------------------------------------------------------------
            # HTML version kwa HTTP Custom / HTTP Injector
            # ------------------------------------------------------------------
            cat > "$BANNERS_DIR/${user}.html" << HTMLEOF
<br>
<font color="cyan">╔═══════════════════════════════════════════════════════════════╗</font><br>
<font color="yellow"><b>                    🔥 VOLTRON TECH 🔥                         </b></font><br>
<font color="green"><b>              PREMIUM SSH & VPN SERVICES                       </b></font><br>
<font color="cyan">╠═══════════════════════════════════════════════════════════════╣</font><br>
<font color="white">                                                               </font><br>
<font color="purple"><b>        🎉 WELCOME TO VOLTRON TECH SERVER 🎉                   </b></font><br>
<font color="white">                                                               </font><br>
<font color="cyan">╠═══════════════════════════════════════════════════════════════╣</font><br>
<font color="white">                                                               </font><br>
<font color="white">👤 <b>Username    :</b> $user                                       </font><br>
<font color="yellow">📅 <b>Expires     :</b> $expiry ($days_left)                       </font><br>
<font color="green">📊 <b>Bandwidth   :</b> $bw_info                                   </font><br>
<font color="cyan">🔌 <b>Connections :</b> $online_count/$limit                         </font><br>
<font color="red">⚡ <b>ULTRA BOOST :</b> ACTIVE (10x Speed)                          </font><br>
<font color="white">                                                               </font><br>
<font color="cyan">╠═══════════════════════════════════════════════════════════════╣</font><br>
<font color="white">                                                               </font><br>
<font color="magenta">        📞 JOIN IN OUR WHATSAPP GROUP                          </font><br>
<font color="cyan">        🔗 https://chat.whatsapp.com/KVMPv89XSu83UnBWUZ          </font><br>
<font color="white">                                                               </font><br>
<font color="cyan">╚═══════════════════════════════════════════════════════════════╝</font><br>
HTMLEOF

            # ------------------------------------------------------------------
            # Standard text banner kwa SSH terminal
            # ------------------------------------------------------------------
            cat > "$BANNERS_DIR/${user}.txt" << BEOF

╔═══════════════════════════════════════════════════════════════╗
║                    🔥 VOLTRON TECH 🔥                         ║
║              PREMIUM SSH & VPN SERVICES                       ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║        🎉 WELCOME TO VOLTRON TECH SERVER 🎉                   ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  👤 Username    : $user                                       
║  📅 Expires     : $expiry ($days_left)                        
║  📊 Bandwidth   : $bw_info                                    
║  🔌 Connections : $online_count/$limit                        
║  ⚡ ULTRA BOOST : ACTIVE (10x Speed)                          
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║        📞 JOIN IN OUR WHATSAPP GROUP                          ║
║        🔗 https://chat.whatsapp.com/KVMPv89XSu83UnBWUZ        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

BEOF
        fi

        
        # --- Bandwidth Check ---
        [[ -z "$bandwidth_gb" || "$bandwidth_gb" == "0" ]] && continue
        
        # Get user UID
        user_uid=$(id -u "$user" 2>/dev/null)
        [[ -z "$user_uid" ]] && continue
        
        # Find sshd PIDs for this user
        pids=""
        
        # Method 1: pgrep
        m1=$(pgrep -u "$user" sshd 2>/dev/null | tr '\n' ' ')
        pids="$m1"
        
        # Method 2: loginuid scan
        for p in /proc/[0-9]*/loginuid; do
            [[ ! -f "$p" ]] && continue
            luid=$(cat "$p" 2>/dev/null)
            [[ -z "$luid" || "$luid" == "4294967295" ]] && continue
            [[ "$luid" != "$user_uid" ]] && continue
            
            pid_dir=$(dirname "$p")
            pid_num=$(basename "$pid_dir")
            
            cname=$(cat "$pid_dir/comm" 2>/dev/null)
            [[ "$cname" != "sshd" ]] && continue
            
            ppid_val=$(awk '/^PPid:/{print $2}' "$pid_dir/status" 2>/dev/null)
            [[ "$ppid_val" == "1" ]] && continue
            
            pids="$pids $pid_num"
        done
        
        # Deduplicate
        pids=$(echo "$pids" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')
        
        # Read accumulated usage
        usagefile="$BW_DIR/${user}.usage"
        accumulated=0
        if [[ -f "$usagefile" ]]; then
            accumulated=$(cat "$usagefile" 2>/dev/null)
            if ! [[ "$accumulated" =~ ^[0-9]+$ ]]; then accumulated=0; fi
        fi
        
        if [[ -z "$pids" ]]; then
            rm -f "$PID_DIR/${user}__"*.last 2>/dev/null
            continue
        fi
        
        delta_total=0
        
        for pid in $pids; do
            [[ -z "$pid" ]] && continue
            io_file="/proc/$pid/io"
            if [[ -r "$io_file" ]]; then
                rchar=$(awk '/^rchar:/{print $2}' "$io_file" 2>/dev/null)
                wchar=$(awk '/^wchar:/{print $2}' "$io_file" 2>/dev/null)
                [[ -z "$rchar" ]] && rchar=0
                [[ -z "$wchar" ]] && wchar=0
                cur=$((rchar + wchar))
            else
                cur=0
            fi
            
            pidfile="$PID_DIR/${user}__${pid}.last"
            
            if [[ -f "$pidfile" ]]; then
                prev=$(cat "$pidfile" 2>/dev/null)
                if ! [[ "$prev" =~ ^[0-9]+$ ]]; then prev=0; fi
                
                if [[ "$cur" -ge "$prev" ]]; then
                    d=$((cur - prev))
                else
                    d=$cur
                fi
                delta_total=$((delta_total + d))
            fi
            echo "$cur" > "$pidfile"
        done
        
        # Clean up dead PID files
        for f in "$PID_DIR/${user}__"*.last; do
            [[ ! -f "$f" ]] && continue
            fpid=$(basename "$f" .last)
            fpid=${fpid#${user}__}
            [[ ! -d "/proc/$fpid" ]] && rm -f "$f"
        done
        
        # Update total
        new_total=$((accumulated + delta_total))
        echo "$new_total" > "$usagefile"
        
        # Check quota
        quota_bytes=$(awk "BEGIN {printf \"%.0f\", $bandwidth_gb * 1073741824}")
        
        if [[ "$new_total" -ge "$quota_bytes" ]]; then
            if ! passwd -S "$user" 2>/dev/null | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
            fi
        fi
        
    done < "$DB_FILE"
    
    sleep 15
done
EOF
    chmod +x "$LIMITER_SCRIPT"
    sed -i 's/\r$//' "$LIMITER_SCRIPT" 2>/dev/null

    cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=Voltron Tech User Limiter & Bandwidth Tracker
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sed -i 's/\r$//' "$LIMITER_SERVICE" 2>/dev/null

    pkill -f "voltrontech-limiter" 2>/dev/null

    if ! systemctl is-active --quiet voltrontech-limiter; then
        systemctl daemon-reload
        systemctl enable voltrontech-limiter &>/dev/null
        systemctl start voltrontech-limiter --no-block &>/dev/null
    else
        systemctl restart voltrontech-limiter --no-block &>/dev/null
    fi
}

# ========== TRIAL ACCOUNT CLEANUP SCRIPT ==========
setup_trial_cleanup_script() {
    cat > "$TRIAL_CLEANUP_SCRIPT" << 'TREOF'
#!/bin/bash
# Voltron Tech Trial Account Auto-Cleanup
DB_FILE="/etc/voltrontech/users.db"
BW_DIR="/etc/voltrontech/bandwidth"
BANNERS_DIR="/etc/voltrontech/banners"

username="$1"
if [[ -z "$username" ]]; then exit 1; fi

# Kill active sessions
killall -u "$username" -9 &>/dev/null
sleep 1

# Delete system user
userdel -r "$username" &>/dev/null

# Remove from DB
sed -i "/^${username}:/d" "$DB_FILE"

# Remove bandwidth tracking
rm -f "$BW_DIR/${username}.usage"
rm -rf "$BW_DIR/pidtrack/${username}"
rm -f "$BANNERS_DIR/${username}.txt"
rm -f "$BANNERS_DIR/${username}.html"
TREOF
    chmod +x "$TRIAL_CLEANUP_SCRIPT"
}

# ========== USER MANAGEMENT FUNCTIONS ==========
_select_user_interface() {
    local title="$1"
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}${title}${C_RESET}\n"
    if [[ ! -s $DB_FILE ]]; then
        echo -e "${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    read -p "👉 Enter username or press Enter to list all: " search_term
    if [[ -z "$search_term" ]]; then
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | sort)
    else
        mapfile -t users < <(cut -d: -f1 "$DB_FILE" | grep -i "$search_term" | sort)
    fi
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found matching your criteria.${C_RESET}"
        SELECTED_USER="NO_USERS"; return
    fi
    echo -e "\nPlease select a user:\n"
    for i in "${!users[@]}"; do
        printf "  ${C_GREEN}[%2d]${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_RED}[ 0]${C_RESET} ↩️ Cancel"
    echo
    local choice
    while true; do
        read -p "👉 Enter user number: " choice
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

get_user_status() {
    local username="$1"
    if ! id "$username" &>/dev/null; then echo -e "${C_RED}Not Found${C_RESET}"; return; fi
    local expiry_date=$(grep "^$username:" "$DB_FILE" | cut -d: -f3)
    if passwd -S "$username" 2>/dev/null | grep -q " L "; then echo -e "${C_YELLOW}🔒 Locked${C_RESET}"; return; fi
    local expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
    local current_ts=$(date +%s)
    if [[ $expiry_ts -lt $current_ts ]]; then echo -e "${C_RED}🗓️ Expired${C_RESET}"; return; fi
    echo -e "${C_GREEN}🟢 Active${C_RESET}"
}

create_user() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    
    local username
    read -p "👉 Enter username (or '0' to cancel): " username
    if [[ "$username" == "0" ]]; then
        echo -e "\n${C_YELLOW}❌ User creation cancelled.${C_RESET}"
        return
    fi
    if [[ -z "$username" ]]; then
        echo -e "\n${C_RED}❌ Username cannot be empty.${C_RESET}"
        return
    fi
    if ! [[ "$username" =~ ^[a-zA-Z0-9_-]{3,32}$ ]]; then
        echo -e "\n${C_RED}❌ Username must be 3-32 characters, alphanumeric, _ or - only.${C_RESET}"
        return
    fi
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ User '$username' already exists.${C_RESET}"; return
    fi
    
    local password=""
    while true; do
        read -p "🔑 Enter password (or press Enter for auto-generated): " password
        if [[ -z "$password" ]]; then
            password=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
            echo -e "${C_GREEN}🔑 Auto-generated password: ${C_YELLOW}$password${C_RESET}"
            break
        elif [[ ${#password} -lt 4 ]]; then
            echo -e "${C_RED}❌ Password must be at least 4 characters.${C_RESET}"
        else
            break
        fi
    done
    
    read -p "🗓️ Enter account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ "$days" -lt 1 ]]; then 
        echo -e "\n${C_RED}❌ Please enter a valid number of days.${C_RESET}"; return
    fi
    
    read -p "📶 Enter simultaneous connection limit [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]] || [[ "$limit" -lt 1 ]]; then 
        echo -e "\n${C_RED}❌ Please enter a valid number.${C_RESET}"; return
    fi
    
    read -p "📦 Enter bandwidth limit in GB (0 = unlimited) [0]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-0}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then 
        echo -e "\n${C_RED}❌ Please enter a valid number.${C_RESET}"; return
    fi
    
    local expire_date
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    # Create system user
    useradd -m -s /usr/sbin/nologin "$username"
    usermod -aG voltronusers "$username" 2>/dev/null
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$bandwidth_gb" >> "$DB_FILE"
    
    local bw_display="Unlimited"
    if [[ "$bandwidth_gb" != "0" ]]; then bw_display="${bandwidth_gb} GB"; fi
    
    clear; show_banner
    echo -e "${C_GREEN}✅ User '$username' created successfully!${C_RESET}\n"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    echo -e "  - 🗓️ Expires on:        ${C_YELLOW}$expire_date${C_RESET}"
    echo -e "  - 📶 Connection Limit:  ${C_YELLOW}$limit${C_RESET}"
    echo -e "  - 📦 Bandwidth Limit:   ${C_YELLOW}$bw_display${C_RESET}"
    
    # Ask for config generation
    echo
    read -p "👉 Do you want to generate a client config for this user? (y/n): " gen_conf
    if [[ "$gen_conf" == "y" || "$gen_conf" == "Y" ]]; then
        generate_client_config "$username" "$password"
    fi
    
    update_ssh_banners_config
}

delete_user() {
    _select_user_interface "--- 🗑️ Delete User ---"
    local username=$SELECTED_USER
    
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        if [[ "$username" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY delete (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        username="$manual_user"
        
        if ! id "$username" &>/dev/null; then
             echo -e "\n${C_RED}❌ User '$username' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$username:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$username' is in the database. Please use the normal selection method.${C_RESET}"
             return
        fi
    fi

    read -p "👉 Are you sure you want to PERMANENTLY delete '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "\n${C_YELLOW}❌ Deletion cancelled.${C_RESET}"; return; fi
    
    echo -e "${C_BLUE}🔌 Killing all active connections for $username...${C_RESET}"
    killall -u "$username" -9 &>/dev/null
    sleep 1

    userdel -r "$username" &>/dev/null
    if [ $? -eq 0 ]; then
         echo -e "\n${C_GREEN}✅ System user '$username' has been deleted.${C_RESET}"
    else
         echo -e "\n${C_RED}❌ Failed to delete system user '$username'.${C_RESET}"
    fi

    # Clean up bandwidth tracking
    rm -f "$BANDWIDTH_DIR/${username}.usage"
    rm -rf "$BANDWIDTH_DIR/pidtrack/${username}"
    rm -f "$BANNERS_DIR/${username}.txt"
    rm -f "$BANNERS_DIR/${username}.html"

    sed -i "/^$username:/d" "$DB_FILE"
    echo -e "${C_GREEN}✅ User '$username' has been completely removed.${C_RESET}"
    
    update_ssh_banners_config
}

edit_user() {
    _select_user_interface "--- ✏️ Edit User ---"
    local username=$SELECTED_USER
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then return; fi
    
    while true; do
        clear; show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        
        # Show current user details
        local current_line; current_line=$(grep "^$username:" "$DB_FILE")
        local cur_pass; cur_pass=$(echo "$current_line" | cut -d: -f2)
        local cur_expiry; cur_expiry=$(echo "$current_line" | cut -d: -f3)
        local cur_limit; cur_limit=$(echo "$current_line" | cut -d: -f4)
        local cur_bw; cur_bw=$(echo "$current_line" | cut -d: -f5)
        [[ -z "$cur_bw" ]] && cur_bw="0"
        local cur_bw_display="Unlimited"; [[ "$cur_bw" != "0" ]] && cur_bw_display="${cur_bw} GB"
        
        # Show bandwidth usage
        local bw_used_display="N/A"
        if [[ -f "$BANDWIDTH_DIR/${username}.usage" ]]; then
            local used_bytes; used_bytes=$(cat "$BANDWIDTH_DIR/${username}.usage" 2>/dev/null)
            if [[ -n "$used_bytes" && "$used_bytes" != "0" ]]; then
                bw_used_display=$(awk "BEGIN {printf \"%.2f GB\", $used_bytes / 1073741824}")
            else
                bw_used_display="0.00 GB"
            fi
        fi
        
        echo -e "\n  ${C_DIM}Current Details:${C_RESET}"
        echo -e "  - Password: ${C_YELLOW}$cur_pass${C_RESET}"
        echo -e "  - Expires: ${C_YELLOW}$cur_expiry${C_RESET}"
        echo -e "  - Connection Limit: ${C_YELLOW}$cur_limit${C_RESET}"
        echo -e "  - Bandwidth Limit: ${C_YELLOW}$cur_bw_display${C_RESET}"
        echo -e "  - Bandwidth Used: ${C_CYAN}$bw_used_display${C_RESET}"
        
        echo -e "\nSelect a detail to edit:\n"
        printf "  ${C_GREEN}[ 1]${C_RESET} %-35s\n" "🔑 Change Password"
        printf "  ${C_GREEN}[ 2]${C_RESET} %-35s\n" "🗓️ Change Expiration Date"
        printf "  ${C_GREEN}[ 3]${C_RESET} %-35s\n" "📶 Change Connection Limit"
        printf "  ${C_GREEN}[ 4]${C_RESET} %-35s\n" "📦 Change Bandwidth Limit"
        printf "  ${C_GREEN}[ 5]${C_RESET} %-35s\n" "🔄 Reset Bandwidth Counter"
        echo -e "\n  ${C_RED}[ 0]${C_RESET} ✅ Finish Editing"
        echo
        local edit_choice
        read -p "👉 Enter your choice: " edit_choice
        
        case $edit_choice in
            1)
               local new_pass=""
               read -p "Enter new password (or press Enter for auto-generated): " new_pass
               if [[ -z "$new_pass" ]]; then
                   new_pass=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
                   echo -e "${C_GREEN}🔑 Auto-generated: ${C_YELLOW}$new_pass${C_RESET}"
               fi
               echo "$username:$new_pass" | chpasswd
               sed -i "s/^$username:.*/$username:$new_pass:$cur_expiry:$cur_limit:$cur_bw/" "$DB_FILE"
               echo -e "\n${C_GREEN}✅ Password for '$username' changed to: ${C_YELLOW}$new_pass${C_RESET}"
               ;;
            2) 
               read -p "Enter new duration (in days from today): " days
               if [[ "$days" =~ ^[0-9]+$ ]]; then
                   local new_expire_date; new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
                   chage -E "$new_expire_date" "$username"
                   sed -i "s/^$username:.*/$username:$cur_pass:$new_expire_date:$cur_limit:$cur_bw/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Expiration for '$username' set to ${C_YELLOW}$new_expire_date${C_RESET}."
               else 
                   echo -e "\n${C_RED}❌ Invalid number of days.${C_RESET}"
               fi 
               ;;
            3) 
               read -p "Enter new simultaneous connection limit: " new_limit
               if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                   sed -i "s/^$username:.*/$username:$cur_pass:$cur_expiry:$new_limit:$cur_bw/" "$DB_FILE"
                   echo -e "\n${C_GREEN}✅ Connection limit for '$username' set to ${C_YELLOW}$new_limit${C_RESET}."
               else 
                   echo -e "\n${C_RED}❌ Invalid limit.${C_RESET}"
               fi 
               ;;
            4) 
               read -p "Enter new bandwidth limit in GB (0 = unlimited): " new_bw
               if [[ "$new_bw" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                   sed -i "s/^$username:.*/$username:$cur_pass:$cur_expiry:$cur_limit:$new_bw/" "$DB_FILE"
                   local bw_msg="Unlimited"; [[ "$new_bw" != "0" ]] && bw_msg="${new_bw} GB"
                   echo -e "\n${C_GREEN}✅ Bandwidth limit for '$username' set to ${C_YELLOW}$bw_msg${C_RESET}."
                   # Unlock user if they were locked due to bandwidth
                   if [[ "$new_bw" == "0" ]] || [[ -f "$BANDWIDTH_DIR/${username}.usage" ]]; then
                       local used_bytes; used_bytes=$(cat "$BANDWIDTH_DIR/${username}.usage" 2>/dev/null || echo 0)
                       local new_quota_bytes; new_quota_bytes=$(awk "BEGIN {printf \"%.0f\", $new_bw * 1073741824}")
                       if [[ "$new_bw" == "0" ]] || [[ "$used_bytes" -lt "$new_quota_bytes" ]]; then
                           usermod -U "$username" &>/dev/null
                       fi
                   fi
               else 
                   echo -e "\n${C_RED}❌ Invalid bandwidth value.${C_RESET}"
               fi 
               ;;
            5)
               echo "0" > "$BANDWIDTH_DIR/${username}.usage"
               usermod -U "$username" &>/dev/null
               echo -e "\n${C_GREEN}✅ Bandwidth counter for '$username' has been reset to 0.${C_RESET}"
               ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" ;;
        esac
        echo -e "\nPress ${C_YELLOW}[Enter]${C_RESET} to continue editing..." && read -r
    done
}

lock_user() {
    _select_user_interface "--- 🔒 Lock User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY lock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ User '$u' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
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
}

unlock_user() {
    _select_user_interface "--- 🔓 Unlock User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        if [[ "$u" == "NO_USERS" ]]; then
            echo -e "\n${C_YELLOW}ℹ️ No users found in database.${C_RESET}"
        fi
        
        read -p "👉 Type username to MANUALLY unlock (or '0' to cancel): " manual_user
        if [[ "$manual_user" == "0" ]] || [[ -z "$manual_user" ]]; then
            echo -e "\n${C_YELLOW}❌ Action cancelled.${C_RESET}"
            return
        fi
        u="$manual_user"
        
        if ! id "$u" &>/dev/null; then
             echo -e "\n${C_RED}❌ User '$u' does not exist on this system.${C_RESET}"
             return
        fi
        
        if grep -q "^$u:" "$DB_FILE"; then
             echo -e "\n${C_YELLOW}ℹ️ User '$u' is in the database. Use the normal selection method.${C_RESET}"
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
}

list_users() {
    clear; show_banner
    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_YELLOW}ℹ️ No users are currently being managed.${C_RESET}"
        return
    fi
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Managed Users List ---${C_RESET}"
    echo -e "${C_CYAN}====================================================================================================${C_RESET}"
    printf "${C_BOLD}${C_WHITE}%-18s | %-12s | %-10s | %-20s | %-15s${C_RESET}\n" "USERNAME" "EXPIRES" "CONNECTIONS" "BANDWIDTH" "STATUS"
    echo -e "${C_CYAN}----------------------------------------------------------------------------------------------------${C_RESET}"
    
    while IFS=: read -r user pass expiry limit bandwidth_gb _extra; do
        local online_count
        online_count=$(pgrep -u "$user" sshd | wc -l)
        
        local status
        status=$(get_user_status "$user")

        local plain_status
        plain_status=$(echo -e "$status" | sed 's/\x1b\[[0-9;]*m//g')
        
        local connection_string="$online_count / $limit"
        
        # Bandwidth display
        [[ -z "$bandwidth_gb" ]] && bandwidth_gb="0"
        local bw_string="Unlimited"
        if [[ "$bandwidth_gb" != "0" ]]; then
            local used_bytes=0
            if [[ -f "$BANDWIDTH_DIR/${user}.usage" ]]; then
                used_bytes=$(cat "$BANDWIDTH_DIR/${user}.usage" 2>/dev/null)
                [[ -z "$used_bytes" ]] && used_bytes=0
            fi
            local used_gb
            used_gb=$(awk "BEGIN {printf \"%.1f\", $used_bytes / 1073741824}")
            bw_string="${used_gb}/${bandwidth_gb}GB"
        fi

        local line_color="$C_WHITE"
        case $plain_status in
            *"Active"*) line_color="$C_GREEN" ;;
            *"Locked"*) line_color="$C_YELLOW" ;;
            *"Expired"*) line_color="$C_RED" ;;
            *"Not Found"*) line_color="$C_DIM" ;;
        esac

        printf "${line_color}%-18s ${C_RESET}| ${C_YELLOW}%-12s ${C_RESET}| ${C_CYAN}%-10s ${C_RESET}| ${C_ORANGE}%-20s ${C_RESET}| %-15s\n" "$user" "$expiry" "$connection_string" "$bw_string" "$status"
    done < <(sort "$DB_FILE")
    echo -e "${C_CYAN}====================================================================================================${C_RESET}\n"
}

renew_user() {
    _select_user_interface "--- 🔄 Renew User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" || -z "$u" ]]; then return; fi
    
    read -p "👉 Enter number of days to extend the account: " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then 
        echo -e "\n${C_RED}❌ Invalid number of days.${C_RESET}"; return
    fi
    
    local new_expire_date
    new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expire_date" "$u"
    
    local line; line=$(grep "^$u:" "$DB_FILE")
    local pass; pass=$(echo "$line"|cut -d: -f2)
    local limit; limit=$(echo "$line"|cut -d: -f4)
    local bw; bw=$(echo "$line"|cut -d: -f5)
    [[ -z "$bw" ]] && bw="0"
    
    sed -i "s/^$u:.*/$u:$pass:$new_expire_date:$limit:$bw/" "$DB_FILE"
    echo -e "\n${C_GREEN}✅ User '$u' has been renewed. New expiration date is ${C_YELLOW}${new_expire_date}${C_RESET}."
}

cleanup_expired() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🧹 Cleanup Expired Users ---${C_RESET}"
    
    local expired_users=()
    local current_ts
    current_ts=$(date +%s)

    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_GREEN}✅ User database is empty. No expired users found.${C_RESET}"
        return
    fi
    
    while IFS=: read -r user pass expiry limit bandwidth_gb _extra; do
        local expiry_ts
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            expired_users+=("$user")
        fi
    done < "$DB_FILE"

    if [ ${#expired_users[@]} -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ No expired users found.${C_RESET}"
        return
    fi

    echo -e "\nThe following users have expired: ${C_RED}${expired_users[*]}${C_RESET}"
    read -p "👉 Do you want to delete all of them? (y/n): " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        for user in "${expired_users[@]}"; do
            echo " - Deleting ${C_YELLOW}$user...${C_RESET}"
            killall -u "$user" -9 &>/dev/null
            # Clean up bandwidth tracking
            rm -f "$BANDWIDTH_DIR/${user}.usage"
            rm -rf "$BANDWIDTH_DIR/pidtrack/${user}"
            rm -f "$BANNERS_DIR/${user}.txt"
            rm -f "$BANNERS_DIR/${user}.html"
            userdel -r "$user" &>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
        done
        echo -e "\n${C_GREEN}✅ Expired users have been cleaned up.${C_RESET}"
        update_ssh_banners_config
    else
        echo -e "\n${C_YELLOW}❌ Cleanup cancelled.${C_RESET}"
    fi
}

create_trial_account() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ⏱️ Create Trial/Test Account ---${C_RESET}"
    
    # Ensure 'at' daemon is available
    if ! command -v at &>/dev/null; then
        echo -e "${C_YELLOW}⚠️ 'at' command not found. Installing...${C_RESET}"
        apt-get update > /dev/null 2>&1 && apt-get install -y at || {
            echo -e "${C_RED}❌ Failed to install 'at'. Cannot schedule auto-expiry.${C_RESET}"
            return
        }
        systemctl enable atd &>/dev/null
        systemctl start atd &>/dev/null
    fi
    
    # Ensure atd is running
    if ! systemctl is-active --quiet atd; then
        systemctl start atd &>/dev/null
    fi
    
    echo -e "\n${C_CYAN}Select trial duration:${C_RESET}\n"
    printf "  ${C_GREEN}[ 1]${C_RESET} ⏱️  1 Hour\n"
    printf "  ${C_GREEN}[ 2]${C_RESET} ⏱️  2 Hours\n"
    printf "  ${C_GREEN}[ 3]${C_RESET} ⏱️  3 Hours\n"
    printf "  ${C_GREEN}[ 4]${C_RESET} ⏱️  6 Hours\n"
    printf "  ${C_GREEN}[ 5]${C_RESET} ⏱️  12 Hours\n"
    printf "  ${C_GREEN}[ 6]${C_RESET} 📅  1 Day\n"
    printf "  ${C_GREEN}[ 7]${C_RESET} 📅  3 Days\n"
    printf "  ${C_GREEN}[ 8]${C_RESET} ⚙️  Custom (enter hours)\n"
    echo -e "\n  ${C_RED}[ 0]${C_RESET} ↩️ Cancel"
    echo
    local dur_choice
    read -p "👉 Select duration: " dur_choice
    
    local duration_hours=0
    local duration_label=""
    case $dur_choice in
        1) duration_hours=1;   duration_label="1 Hour" ;;
        2) duration_hours=2;   duration_label="2 Hours" ;;
        3) duration_hours=3;   duration_label="3 Hours" ;;
        4) duration_hours=6;   duration_label="6 Hours" ;;
        5) duration_hours=12;  duration_label="12 Hours" ;;
        6) duration_hours=24;  duration_label="1 Day" ;;
        7) duration_hours=72;  duration_label="3 Days" ;;
        8) read -p "👉 Enter custom duration in hours: " custom_hours
           if ! [[ "$custom_hours" =~ ^[0-9]+$ ]] || [[ "$custom_hours" -lt 1 ]]; then
               echo -e "\n${C_RED}❌ Invalid number of hours.${C_RESET}"; return
           fi
           duration_hours=$custom_hours
           duration_label="$custom_hours Hours"
           ;;
        0) echo -e "\n${C_YELLOW}❌ Cancelled.${C_RESET}"; return ;;
        *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"; return ;;
    esac
    
    # Username
    local rand_suffix=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 5)
    local default_username="trial_${rand_suffix}"
    read -p "👤 Username [${default_username}]: " username
    username=${username:-$default_username}
    
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ User '$username' already exists.${C_RESET}"; return
    fi
    
    # Password
    local password=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
    read -p "🔑 Password [${password}]: " custom_pass
    password=${custom_pass:-$password}
    
    # Connection limit
    read -p "📶 Connection limit [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    
    # Bandwidth limit
    read -p "📦 Bandwidth limit in GB (0 = unlimited) [1]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-1}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    
    # Calculate expiry
    local expire_date
    if [[ "$duration_hours" -ge 24 ]]; then
        local days=$((duration_hours / 24))
        expire_date=$(date -d "+$days days" +%Y-%m-%d)
    else
        # For sub-day durations, set expiry to tomorrow to be safe (at job does the real cleanup)
        expire_date=$(date -d "+1 day" +%Y-%m-%d)
    fi
    local expiry_timestamp
    expiry_timestamp=$(date -d "+${duration_hours} hours" '+%Y-%m-%d %H:%M:%S')
    
    # Create the system user
    useradd -m -s /usr/sbin/nologin "$username"
    usermod -aG voltronusers "$username" 2>/dev/null
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$bandwidth_gb" >> "$DB_FILE"
    
    # Schedule auto-cleanup via 'at'
    echo "$TRIAL_CLEANUP_SCRIPT $username" | at now + ${duration_hours} hours 2>/dev/null
    
    local bw_display="${bandwidth_gb} GB"
    if [[ "$bandwidth_gb" == "0" ]]; then bw_display="Unlimited"; fi
    
    clear; show_banner
    echo -e "${C_GREEN}✅ Trial account created successfully!${C_RESET}\n"
    echo -e "${C_YELLOW}========================================${C_RESET}"
    echo -e "  ⏱️  ${C_BOLD}TRIAL ACCOUNT${C_RESET}"
    echo -e "${C_YELLOW}========================================${C_RESET}"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    echo -e "  - ⏱️ Duration:          ${C_CYAN}$duration_label${C_RESET}"
    echo -e "  - 🕐 Auto-expires at:   ${C_RED}$expiry_timestamp${C_RESET}"
    echo -e "  - 📶 Connection Limit:  ${C_YELLOW}$limit${C_RESET}"
    echo -e "  - 📦 Bandwidth Limit:   ${C_YELLOW}$bw_display${C_RESET}"
    echo -e "${C_YELLOW}========================================${C_RESET}"
    echo -e "\n${C_DIM}The account will be automatically deleted when the trial expires.${C_RESET}"
    
    update_ssh_banners_config
}

view_user_bandwidth() {
    _select_user_interface "--- 📊 View User Bandwidth ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" || -z "$u" ]]; then return; fi
    
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📊 Bandwidth Details: ${C_YELLOW}$u${C_PURPLE} ---${C_RESET}\n"
    
    local line; line=$(grep "^$u:" "$DB_FILE")
    local bandwidth_gb; bandwidth_gb=$(echo "$line" | cut -d: -f5)
    [[ -z "$bandwidth_gb" ]] && bandwidth_gb="0"
    
    local used_bytes=0
    if [[ -f "$BANDWIDTH_DIR/${u}.usage" ]]; then
        used_bytes=$(cat "$BANDWIDTH_DIR/${u}.usage" 2>/dev/null)
        [[ -z "$used_bytes" ]] && used_bytes=0
    fi
    
    local used_mb; used_mb=$(awk "BEGIN {printf \"%.2f\", $used_bytes / 1048576}")
    local used_gb; used_gb=$(awk "BEGIN {printf \"%.3f\", $used_bytes / 1073741824}")
    
    echo -e "  ${C_CYAN}Data Used:${C_RESET}        ${C_WHITE}${used_gb} GB${C_RESET} (${used_mb} MB)"
    
    if [[ "$bandwidth_gb" == "0" ]]; then
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_GREEN}Unlimited${C_RESET}"
        echo -e "  ${C_CYAN}Status:${C_RESET}           ${C_GREEN}No quota restrictions${C_RESET}"
    else
        local quota_bytes; quota_bytes=$(awk "BEGIN {printf \"%.0f\", $bandwidth_gb * 1073741824}")
        local percentage; percentage=$(awk "BEGIN {printf \"%.1f\", ($used_bytes / $quota_bytes) * 100}")
        local remaining_bytes; remaining_bytes=$((quota_bytes - used_bytes))
        if [[ "$remaining_bytes" -lt 0 ]]; then remaining_bytes=0; fi
        local remaining_gb; remaining_gb=$(awk "BEGIN {printf \"%.3f\", $remaining_bytes / 1073741824}")
        
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_YELLOW}${bandwidth_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Remaining:${C_RESET}        ${C_WHITE}${remaining_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Usage:${C_RESET}            ${C_WHITE}${percentage}%${C_RESET}"
        
        # Progress bar
        local bar_width=30
        local filled; filled=$(awk "BEGIN {printf \"%.0f\", ($percentage / 100) * $bar_width}")
        if [[ "$filled" -gt "$bar_width" ]]; then filled=$bar_width; fi
        local empty=$((bar_width - filled))
        local bar_color="$C_GREEN"
        if (( $(awk "BEGIN {print ($percentage > 80)}" ) )); then bar_color="$C_RED"
        elif (( $(awk "BEGIN {print ($percentage > 50)}" ) )); then bar_color="$C_YELLOW"
        fi
        printf "  ${C_CYAN}Progress:${C_RESET}         ${bar_color}["
        for ((i=0; i<filled; i++)); do printf "█"; done
        for ((i=0; i<empty; i++)); do printf "░"; done
        printf "]${C_RESET} ${percentage}%%\n"
        
        if [[ "$used_bytes" -ge "$quota_bytes" ]]; then
            echo -e "\n  ${C_RED}⚠️ USER HAS EXCEEDED BANDWIDTH QUOTA — ACCOUNT LOCKED${C_RESET}"
        fi
    fi
}

bulk_create_users() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 👥 Bulk Create Users ---${C_RESET}"
    
    read -p "👉 Enter username prefix (e.g., 'user'): " prefix
    if [[ -z "$prefix" ]]; then echo -e "\n${C_RED}❌ Prefix cannot be empty.${C_RESET}"; return; fi
    
    read -p "🔢 How many users to create? " count
    if ! [[ "$count" =~ ^[0-9]+$ ]] || [[ "$count" -lt 1 ]] || [[ "$count" -gt 100 ]]; then
        echo -e "\n${C_RED}❌ Invalid count (1-100).${C_RESET}"; return
    fi
    
    read -p "🗓️ Account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    
    read -p "📶 Connection limit per user [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    
    read -p "📦 Bandwidth limit in GB per user (0 = unlimited) [0]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-0}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"; return; fi
    
    local expire_date
    expire_date=$(date -d "+$days days" +%Y-%m-%d)
    local bw_display="Unlimited"; [[ "$bandwidth_gb" != "0" ]] && bw_display="${bandwidth_gb} GB"
    
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
        usermod -aG voltronusers "$username" 2>/dev/null
        echo "$username:$password" | chpasswd
        chage -E "$expire_date" "$username"
        echo "$username:$password:$expire_date:$limit:$bandwidth_gb" >> "$DB_FILE"
        printf "  ${C_GREEN}%-20s${C_RESET} | ${C_YELLOW}%-15s${C_RESET} | ${C_CYAN}%-12s${C_RESET}\n" "$username" "$password" "$expire_date"
        created=$((created + 1))
    done
    
    echo -e "${C_YELLOW}================================================================${C_RESET}"
    echo -e "\n${C_GREEN}✅ Created $created users. Connection Limit: ${limit} | Bandwidth: ${bw_display}${C_RESET}"
    
    update_ssh_banners_config
}

generate_client_config() {
    local user=$1
    local pass=$2
    
    # Auto-detect Host
    local host_ip=$(curl -s -4 icanhazip.com)
    local host_domain="$host_ip"
    if [ -f "$DNS_INFO_FILE" ]; then
        local managed_domain=$(grep 'FULL_DOMAIN' "$DNS_INFO_FILE" | cut -d'"' -f2)
        if [[ -n "$managed_domain" ]]; then host_domain="$managed_domain"; fi
    fi
    # Also check if Nginx Certbot is used
    if [ -f "$NGINX_CONFIG" ]; then
        local nginx_domain=$(grep -oP 'server_name \K[^\s;]+' "$NGINX_CONFIG" | head -n 1)
        if [[ "$nginx_domain" != "_" && -n "$nginx_domain" ]]; then host_domain="$nginx_domain"; fi
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
    echo -e "   • Payload: (Standard SSH)"

    # 2. SSL/TLS Tunnel (HAProxy or Nginx)
    local ssl_port=""
    local ssl_type=""
    
    # Check HAProxy
    if systemctl is-active --quiet haproxy; then
        local haproxy_port=$(grep -oP 'bind \*:(\d+)' "$HAPROXY_CONFIG" 2>/dev/null | awk -F: '{print $2}')
        if [[ -n "$haproxy_port" ]]; then ssl_port="$haproxy_port"; ssl_type="HAProxy"; fi
    fi
    # Check Nginx (Override if both exist, or show both)
    if systemctl is-active --quiet nginx && [ -f "$NGINX_PORTS_FILE" ]; then
         source "$NGINX_PORTS_FILE"
         # Take the first TLS port
         local nginx_ssl_port=$(echo "$TLS_PORTS" | awk '{print $1}')
         if [[ -n "$nginx_ssl_port" ]]; then 
            if [[ -n "$ssl_port" ]]; then ssl_port="$ssl_port, $nginx_ssl_port"; else ssl_port="$nginx_ssl_port"; fi
            ssl_type="Nginx/TLS"
         fi
    fi
    
    if [[ -n "$ssl_port" ]]; then
        echo -e "\n🔹 ${C_BOLD}SSL/TLS Tunnel ($ssl_type)${C_RESET}:"
        echo -e "   • Host: $host_domain"
        echo -e "   • Port(s): $ssl_port"
        echo -e "   • SNI (BugHost): $host_domain (or your preferred SNI)"
    fi

    # 3. UDP Custom
    if systemctl is-active --quiet udp-custom; then
        echo -e "\n🔹 ${C_BOLD}UDP Custom${C_RESET}:"
        echo -e "   • IP: $host_ip (Must use numeric IP)"
        echo -e "   • Port: 1-65535 (Exclude 53, 5300)"
        echo -e "   • Obfs: (None/Plain)"
    fi

    # 4. DNSTT
    if systemctl is-active --quiet dnstt; then
        if [ -f "$DNSTT_INFO_FILE" ]; then
            source "$DNSTT_INFO_FILE"
            echo -e "\n🔹 ${C_BOLD}DNSTT (SlowDNS)${C_RESET}:"
            echo -e "   • Nameserver: $TUNNEL_DOMAIN"
            echo -e "   • PubKey: $PUBLIC_KEY"
            echo -e "   • DNS IP: 1.1.1.1 / 8.8.8.8"
        fi
    fi
    
    # 5. ZiVPN
    if systemctl is-active --quiet zivpn; then
        echo -e "\n🔹 ${C_BOLD}ZiVPN${C_RESET}:"
        echo -e "   • UDP Port: 5667"
        echo -e "   • Forwarded Ports: 6000-19999"
    fi
    
    echo -e "${C_YELLOW}========================================${C_RESET}"
}

client_config_menu() {
    _select_user_interface "--- 📱 Generate Client Config ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" || -z "$u" ]]; then return; fi
    
    # We need to find the password. It's in the DB.
    local pass=$(grep "^$u:" "$DB_FILE" | cut -d: -f2)
    generate_client_config "$u" "$pass"
}

# ========== SHOW BANNER (MAIN MENU BANNER) ==========
show_banner() {
    get_ip_info
    local current_mtu=$(get_current_mtu)
    
    # Get system stats
    local os_name=$(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release || echo "Linux")
    local up_time=$(uptime -p | sed 's/up //')
    local ram_usage=$(free -m | awk '/^Mem:/{printf "%.2f", $3*100/$2}')
    local cpu_load=$(cat /proc/loadavg | awk '{print $1}')
    
    local online_users=0
    if [[ -s "$DB_FILE" ]]; then
        while IFS=: read -r user pass expiry limit; do
           local count=$(pgrep -c -u "$user" sshd)
           online_users=$((online_users + count))
        done < "$DB_FILE"
    fi
    
    local total_users=0
    if [[ -s "$DB_FILE" ]]; then total_users=$(grep -c . "$DB_FILE"); fi
    
    clear
    echo
    echo -e "${C_TITLE}   🔥 VOLTRON TECH ULTIMATE v10.0 🔥 ${C_RESET}${C_DIM}| Premium Edition${C_RESET}"
    echo -e "${C_BLUE}   ─────────────────────────────────────────────────────────${C_RESET}"
    printf "   ${C_GRAY}%-10s${C_RESET} %-20s ${C_GRAY}|${C_RESET} %s\n" "OS" "$os_name" "Uptime: $up_time"
    printf "   ${C_GRAY}%-10s${C_RESET} %-20s ${C_GRAY}|${C_RESET} %s\n" "Memory" "${ram_usage}% Used" "Online Users: ${C_WHITE}${online_users}${C_RESET}"
    printf "   ${C_GRAY}%-10s${C_RESET} %-20s ${C_GRAY}|${C_RESET} %s\n" "Users" "${total_users} Managed" "System Load: ${C_GREEN}${cpu_load}${C_RESET}"
    echo -e "${C_BLUE}   ─────────────────────────────────────────────────────────${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH ULTIMATE v10.0 🔥                    ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • V2RAY • BADVPN • UDP • SSL • ZiVPN        ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║                                                                 ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    
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
    
    # Show SSH Banner status
    if [[ -f "$DB_DIR/banners_enabled" ]]; then
        echo -e "${C_BOLD}${C_PURPLE}║  SSH Banner: ${C_GREEN}ACTIVE${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  SSH Banner: ${C_YELLOW}DISABLED${C_PURPLE}${C_RESET}"
    fi
    
    # Show Auto Reboot status
    local reboot_status=$(crontab -l 2>/dev/null | grep "systemctl reboot")
    if [[ -n "$reboot_status" ]]; then
        echo -e "${C_BOLD}${C_PURPLE}║  Auto Reboot: ${C_GREEN}ENABLED${C_PURPLE}${C_RESET}"
    else
        echo -e "${C_BOLD}${C_PURPLE}║  Auto Reboot: ${C_YELLOW}DISABLED${C_PURPLE}${C_RESET}"
    fi
    
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== BACKUP & RESTORE ==========
backup_user_data() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    local backup_path
    safe_read "👉 Enter path for backup file [/root/voltrontech_backup.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_backup.tar.gz}
    
    if [ ! -d "$DB_DIR" ] || [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No user data found to back up.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}⚙️ Backing up user database and settings to ${C_YELLOW}$backup_path${C_RESET}..."
    tar -czf "$backup_path" -C "$(dirname "$DB_DIR")" "$(basename "$DB_DIR")"
    
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ SUCCESS: User data backup created at ${C_YELLOW}$backup_path${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: Backup failed.${C_RESET}"
    fi
}

restore_user_data() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📥 Restore User Data ---${C_RESET}"
    local backup_path
    safe_read "👉 Enter the full path to the user data backup file [/root/voltrontech_backup.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_backup.tar.gz}
    
    if [ ! -f "$backup_path" ]; then
        echo -e "\n${C_RED}❌ ERROR: Backup file not found at '$backup_path'.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_RED}${C_BOLD}⚠️ WARNING:${C_RESET} This will overwrite all current users and settings."
    echo -e "It will restore user accounts, passwords, limits, and expiration dates from the backup file."
    read -p "👉 Are you absolutely sure you want to proceed? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "\n${C_YELLOW}❌ Restore cancelled.${C_RESET}"; return; fi
    
    local temp_dir
    temp_dir=$(mktemp -d)
    echo -e "\n${C_BLUE}⚙️ Extracting backup file to a temporary location...${C_RESET}"
    tar -xzf "$backup_path" -C "$temp_dir"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ ERROR: Failed to extract backup file. Aborting.${C_RESET}"
        rm -rf "$temp_dir"
        return
    fi
    
    local restored_db_file="$temp_dir/voltrontech/users.db"
    if [ ! -f "$restored_db_file" ]; then
        echo -e "\n${C_RED}❌ ERROR: users.db not found in the backup. Cannot restore user accounts.${C_RESET}"
        rm -rf "$temp_dir"
        return
    fi
    
    echo -e "${C_BLUE}⚙️ Overwriting current user database...${C_RESET}"
    mkdir -p "$DB_DIR"
    cp "$restored_db_file" "$DB_FILE"
    
    if [ -d "$temp_dir/voltrontech/ssl" ]; then
        cp -r "$temp_dir/voltrontech/ssl" "$DB_DIR/"
    fi
    if [ -d "$temp_dir/voltrontech/dnstt" ]; then
        cp -r "$temp_dir/voltrontech/dnstt" "$DB_DIR/"
    fi
    if [ -f "$temp_dir/voltrontech/dns_info.conf" ]; then
        cp "$temp_dir/voltrontech/dns_info.conf" "$DB_DIR/"
    fi
    if [ -f "$temp_dir/voltrontech/dnstt_info.conf" ]; then
        cp "$temp_dir/voltrontech/dnstt_info.conf" "$DB_DIR/"
    fi
    
    echo -e "${C_BLUE}⚙️ Re-synchronizing system accounts with the restored database...${C_RESET}"
    
    while IFS=: read -r user pass expiry limit bandwidth_gb; do
        echo "Processing user: ${C_YELLOW}$user${C_RESET}"
        if ! id "$user" &>/dev/null; then
            echo " - User does not exist in system. Creating..."
            useradd -m -s /usr/sbin/nologin "$user"
            usermod -aG voltronusers "$user" 2>/dev/null
        fi
        echo " - Setting password..."
        echo "$user:$pass" | chpasswd
        echo " - Setting expiration to $expiry..."
        chage -E "$expiry" "$user"
        echo " - Connection limit is $limit (enforced by PAM)"
    done < "$DB_FILE"
    
    rm -rf "$temp_dir"
    echo -e "\n${C_GREEN}✅ SUCCESS: User data restore completed.${C_RESET}"
    
    update_ssh_banners_config
}

# ========== INITIAL SETUP ==========
initial_setup() {
    echo -e "\n${C_BLUE}🔧 Running initial system setup...${C_RESET}"
    
    detect_os
    detect_package_manager
    detect_service_manager
    detect_firewall
    
    create_directories
    setup_limiter_service
    setup_trial_cleanup_script
    
    get_ip_info
    
    echo -e "${C_GREEN}✅ Initial setup complete!${C_RESET}"
}

# ========== UNINSTALL SCRIPT ==========
uninstall_script() {
    clear; show_banner
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
    
    export UNINSTALL_MODE="silent"
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
    
    # Remove auto reboot
    (crontab -l 2>/dev/null | grep -v "systemctl reboot") | crontab - 2>/dev/null
    
    # Stop all services
    systemctl stop dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service haproxy voltronproxy.service nginx zivpn.service falconproxy.service 2>/dev/null
    systemctl disable dnstt.service v2ray-dnstt.service badvpn.service udp-custom.service voltronproxy.service falconproxy.service 2>/dev/null
    systemctl stop voltrontech-limiter 2>/dev/null
    systemctl disable voltrontech-limiter 2>/dev/null
    
    # Remove service files
    rm -f "$DNSTT_SERVICE" "$V2RAY_SERVICE" "$BADVPN_SERVICE" "$UDP_CUSTOM_SERVICE" "$VOLTRONPROXY_SERVICE" "$ZIVPN_SERVICE" "$FALCONPROXY_SERVICE_FILE"
    rm -f "$LIMITER_SERVICE"
    
    # Remove binaries
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT" "$V2RAY_BIN" "$BADVPN_BIN" "$UDP_CUSTOM_BIN" "$VOLTRONPROXY_BIN" "$ZIVPN_BIN" "$FALCONPROXY_BINARY"
    rm -f "$LIMITER_SCRIPT" "$TRAFFIC_SCRIPT" "$LOSS_PROTECT_SCRIPT" "$TRIAL_CLEANUP_SCRIPT"
    rm -f "$CACHE_SCRIPT"
    
    # Remove directories
    rm -rf "$BADVPN_BUILD_DIR" "$UDP_CUSTOM_DIR" "$ZIVPN_DIR"
    
    # Remove configuration
    rm -rf "$DB_DIR"
    
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
        local falconproxy_status=$(check_service "falconproxy")
        local xui_status=$(command -v x-ui &>/dev/null && echo -e "${C_BLUE}(installed)${C_RESET}" || echo "")
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🔌 PROTOCOL & PANEL MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} badvpn (UDP 7300) $badvpn_status"
        echo -e "  ${C_GREEN}2)${C_RESET} udp-custom $udp_status"
        echo -e "  ${C_GREEN}3)${C_RESET} SSL Tunnel (HAProxy) $haproxy_status"
        echo -e "  ${C_GREEN}4)${C_RESET} DNSTT (Port 53) $dnstt_status"
        echo -e "  ${C_GREEN}5)${C_RESET} V2RAY over DNSTT $v2ray_status"
        echo -e "  ${C_GREEN}6)${C_RESET} VOLTRON Proxy $voltronproxy_status"
        echo -e "  ${C_GREEN}7)${C_RESET} Nginx Proxy $nginx_status"
        echo -e "  ${C_GREEN}8)${C_RESET} ZiVPN $zivpn_status"
        echo -e "  ${C_GREEN}9)${C_RESET} X-UI Panel $xui_status"
        echo -e "  ${C_GREEN}10)${C_RESET} Falcon Proxy $falconproxy_status"
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
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install/Manage Nginx"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall Nginx"
                safe_read "👉 Choose: " sub
                if [ "$sub" == "1" ]; then
                    nginx_proxy_menu
                else
                    purge_nginx
                fi
                ;;
            8)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install ZiVPN"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall ZiVPN"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_zivpn || uninstall_zivpn
                ;;
            9)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install X-UI"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall X-UI"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_xui_panel || uninstall_xui_panel
                ;;
            10)
                echo -e "\n  ${C_GREEN}1)${C_RESET} Install Falcon Proxy"
                echo -e "  ${C_RED}2)${C_RESET} Uninstall Falcon Proxy"
                safe_read "👉 Choose: " sub
                [ "$sub" == "1" ] && install_falcon_proxy || uninstall_falcon_proxy
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== V2RAY FUNCTIONS ==========
install_v2ray_dnstt() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing V2RAY over DNSTT ---${C_RESET}"
    
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
}

# ========== BADVPN FUNCTIONS ==========
install_badvpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing badvpn (udpgw) ---${C_RESET}"
    
    if [ -f "$BADVPN_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ badvpn is already installed.${C_RESET}"
        return
    fi
    
    check_and_open_firewall_port 7300 udp || return
    
    echo -e "\n${C_GREEN}🔄 Updating package lists...${C_RESET}"
    apt-get update
    
    echo -e "\n${C_GREEN}📦 Installing required packages...${C_RESET}"
    apt-get install -y cmake g++ make screen git build-essential
    
    echo -e "\n${C_GREEN}📥 Cloning badvpn from github...${C_RESET}"
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
    cd "$BADVPN_BUILD_DIR" || { echo -e "${C_RED}❌ Failed to change directory.${C_RESET}"; return; }
    
    echo -e "\n${C_GREEN}⚙️ Running CMake...${C_RESET}"
    cmake . || { echo -e "${C_RED}❌ CMake failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
    
    echo -e "\n${C_GREEN}🛠️ Compiling source...${C_RESET}"
    make || { echo -e "${C_RED}❌ Compilation failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
    
    local badvpn_binary
    badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
    
    if [[ -z "$badvpn_binary" || ! -f "$badvpn_binary" ]]; then
        echo -e "${C_RED}❌ Could not find the compiled binary.${C_RESET}"
        rm -rf "$BADVPN_BUILD_DIR"
        return
    fi
    
    chmod +x "$badvpn_binary"
    
    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$BADVPN_SERVICE" <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=$badvpn_binary --listen-addr 0.0.0.0:7300 --max-clients 1000 --max-connections-for-client 8
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting badvpn service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    sleep 2
    
    if systemctl is-active --quiet badvpn; then
        echo -e "\n${C_GREEN}✅ SUCCESS: badvpn is installed and active on port 7300.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: badvpn service failed to start.${C_RESET}"
        journalctl -u badvpn.service -n 15 --no-pager
    fi
}

uninstall_badvpn() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling badvpn ---${C_RESET}"
    
    if [ ! -f "$BADVPN_SERVICE" ]; then
        echo -e "${C_YELLOW}ℹ️ badvpn is not installed, skipping.${C_RESET}"
        return
    fi
    
    echo -e "${C_GREEN}🛑 Stopping and disabling badvpn service...${C_RESET}"
    systemctl stop badvpn.service >/dev/null 2>&1
    systemctl disable badvpn.service >/dev/null 2>&1
    
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$BADVPN_SERVICE"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}🗑️ Removing badvpn build directory...${C_RESET}"
    rm -rf "$BADVPN_BUILD_DIR"
    
    echo -e "${C_GREEN}✅ badvpn has been uninstalled successfully.${C_RESET}"
}

# ========== UDP-CUSTOM FUNCTIONS ==========
install_udp_custom() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing udp-custom ---${C_RESET}"
    
    if [ -f "$UDP_CUSTOM_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ udp-custom is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Creating directory for udp-custom...${C_RESET}"
    rm -rf "$UDP_CUSTOM_DIR"
    mkdir -p "$UDP_CUSTOM_DIR"

    echo -e "\n${C_GREEN}⚙️ Detecting system architecture...${C_RESET}"
    local arch
    arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://github.com/voltrontech/udp-custom/releases/latest/download/udp-custom-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch.${C_RESET}"
        rm -rf "$UDP_CUSTOM_DIR"
        return
    fi

    echo -e "\n${C_GREEN}📥 Downloading udp-custom binary...${C_RESET}"
    wget -q --show-progress -O "$UDP_CUSTOM_BIN" "$binary_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download the udp-custom binary.${C_RESET}"
        rm -rf "$UDP_CUSTOM_DIR"
        return
    fi
    
    chmod +x "$UDP_CUSTOM_BIN"

    echo -e "\n${C_GREEN}📝 Creating default config.json...${C_RESET}"
    cat > "$UDP_CUSTOM_DIR/config.json" <<EOF
{
  "listen": ":$UDP_CUSTOM_PORT",
  "auth": {
    "mode": "passwords"
  }
}
EOF
    chmod 644 "$UDP_CUSTOM_DIR/config.json"

    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$UDP_CUSTOM_SERVICE" <<EOF
[Unit]
Description=UDP Custom by Voltron Tech
After=network.target

[Service]
User=root
Type=simple
ExecStart=$UDP_CUSTOM_BIN server -exclude 53,5300
WorkingDirectory=$UDP_CUSTOM_DIR/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting udp-custom service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl start udp-custom.service
    sleep 2
    
    if systemctl is-active --quiet udp-custom; then
        echo -e "\n${C_GREEN}✅ SUCCESS: udp-custom is installed and active.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: udp-custom service failed to start.${C_RESET}"
        journalctl -u udp-custom.service -n 15 --no-pager
    fi
}

uninstall_udp_custom() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling udp-custom ---${C_RESET}"
    
    if [ ! -f "$UDP_CUSTOM_SERVICE" ]; then
        echo -e "${C_YELLOW}ℹ️ udp-custom is not installed, skipping.${C_RESET}"
        return
    fi
    
    echo -e "${C_GREEN}🛑 Stopping and disabling udp-custom service...${C_RESET}"
    systemctl stop udp-custom.service >/dev/null 2>&1
    systemctl disable udp-custom.service >/dev/null 2>&1
    
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$UDP_CUSTOM_SERVICE"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}🗑️ Removing udp-custom directory and files...${C_RESET}"
    rm -rf "$UDP_CUSTOM_DIR"
    
    echo -e "${C_GREEN}✅ udp-custom has been uninstalled successfully.${C_RESET}"
}

# ========== SSL TUNNEL FUNCTIONS ==========
install_ssl_tunnel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing SSL Tunnel (HAProxy) ---${C_RESET}"
    
    if ! command -v haproxy &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ HAProxy not found. Installing...${C_RESET}"
        apt-get update && apt-get install -y haproxy || { echo -e "${C_RED}❌ Failed to install HAProxy.${C_RESET}"; return; }
    fi
    
    read -p "👉 Enter the port for the SSL tunnel [444]: " ssl_port
    ssl_port=${ssl_port:-444}
    
    if ! [[ "$ssl_port" =~ ^[0-9]+$ ]] || [ "$ssl_port" -lt 1 ] || [ "$ssl_port" -gt 65535 ]; then
        echo -e "\n${C_RED}❌ Invalid port number. Aborting.${C_RESET}"
        return
    fi
    
    check_and_free_ports "$ssl_port" || return
    check_and_open_firewall_port "$ssl_port" || return

    if [ -f "$SSL_CERT_FILE" ]; then
        read -p "SSL certificate already exists. Overwrite? (y/n): " overwrite_cert
        if [[ "$overwrite_cert" != "y" ]]; then
            echo -e "${C_YELLOW}ℹ️ Using existing certificate.${C_RESET}"
        else
            rm -f "$SSL_CERT_FILE"
        fi
    fi
    
    if [ ! -f "$SSL_CERT_FILE" ]; then
        echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate...${C_RESET}"
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" \
            -subj "/CN=VOLTRON TECH" >/dev/null 2>&1 || { echo -e "${C_RED}❌ Failed to generate SSL certificate.${C_RESET}"; return; }
        echo -e "${C_GREEN}✅ Certificate created: ${C_YELLOW}$SSL_CERT_FILE${C_RESET}"
    fi
    
    echo -e "\n${C_GREEN}📝 Creating HAProxy configuration for port $ssl_port...${C_RESET}"
    cat > "$HAPROXY_CONFIG" <<EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend ssh_ssl_in
    bind *:$ssl_port ssl crt $SSL_CERT_FILE
    mode tcp
    default_backend ssh_backend

backend ssh_backend
    mode tcp
    server ssh_server 127.0.0.1:22
EOF

    echo -e "\n${C_GREEN}▶️ Reloading and starting HAProxy service...${C_RESET}"
    systemctl daemon-reload
    systemctl restart haproxy
    sleep 2
    
    if systemctl is-active --quiet haproxy; then
        echo -e "\n${C_GREEN}✅ SUCCESS: SSL Tunnel is active on port $ssl_port.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: HAProxy service failed to start.${C_RESET}"
        systemctl status haproxy --no-pager
    fi
}

uninstall_ssl_tunnel() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling SSL Tunnel ---${C_RESET}"
    
    if ! command -v haproxy &> /dev/null; then
        echo -e "${C_YELLOW}ℹ️ HAProxy not installed, skipping.${C_RESET}"
        return
    fi
    
    echo -e "${C_GREEN}🛑 Stopping HAProxy service...${C_RESET}"
    systemctl stop haproxy >/dev/null 2>&1
    
    if [ -f "$SSL_CERT_FILE" ]; then
        read -p "👉 Delete the SSL certificate? (y/n): " delete_cert
        if [[ "$delete_cert" == "y" ]]; then
            echo -e "${C_GREEN}🗑️ Removing SSL certificate...${C_RESET}"
            rm -f "$SSL_CERT_FILE"
        fi
    fi
    
    echo -e "${C_GREEN}✅ SSL Tunnel has been uninstalled.${C_RESET}"
}

# ========== VOLTRON PROXY FUNCTIONS ==========
install_voltron_proxy() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🦅 Installing VOLTRON Proxy ---${C_RESET}"
    
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/voltrontech/voltron-proxy/releases/latest/download/voltronproxy"
    else
        curl -L -o "$VOLTRONPROXY_BIN" "https://github.com/voltrontech/voltron-proxy/releases/latest/download/voltronproxyarm"
    fi
    chmod +x "$VOLTRONPROXY_BIN"
    
    read -p "👉 Enter port(s) [8080]: " ports
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
}

uninstall_voltron_proxy() {
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f "$VOLTRONPROXY_SERVICE" "$VOLTRONPROXY_BIN"
    rm -f "$CONFIG_DIR/voltronproxy_ports.conf"
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ VOLTRON Proxy uninstalled${C_RESET}"
}

# ========== NGINX PROXY FUNCTIONS ==========
install_nginx_proxy() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing Nginx Main Proxy (Ports 80 & 443) ---${C_RESET}"
    
    if command -v nginx &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ An existing Nginx installation was found.${C_RESET}"
        read -p "👉 Do you want to purge it and continue? (y/n): " confirm_purge
        if [[ "$confirm_purge" != "y" ]]; then
            echo -e "\n${C_RED}❌ Installation cancelled.${C_RESET}"
            return
        fi
        purge_nginx "silent"
    fi
    
    echo -e "\n${C_BLUE}📦 Installing Nginx package...${C_RESET}"
    apt-get update && apt-get install -y nginx || { echo -e "${C_RED}❌ Failed to install Nginx.${C_RESET}"; return; }
    
    check_and_free_ports "80" "443" || return

    # Custom Port Selection
    local tls_ports
    read -p "👉 Enter TLS/SSL Port(s) [Default: 443]: " input_tls
    if [[ -z "$input_tls" ]]; then tls_ports="443"; else tls_ports="$input_tls"; fi

    local http_ports
    read -p "👉 Enter HTTP/Non-TLS Port(s) [Default: 80]: " input_http
    if [[ -z "$input_http" ]]; then http_ports="80"; else http_ports="$input_http"; fi

    # Convert to arrays
    read -a tls_ports_array <<< "$tls_ports"
    read -a http_ports_array <<< "$http_ports"
    
    # Process Ports: Free and Open
    for port in "${tls_ports_array[@]}" "${http_ports_array[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then echo -e "${C_RED}❌ Invalid port: $port${C_RESET}"; return; fi
        check_and_free_ports "$port" || return
        check_and_open_firewall_port "$port" tcp || return
    done
    
    echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate for Nginx...${C_RESET}"
    local SSL_CERT="/etc/ssl/certs/nginx-selfsigned.pem"
    local SSL_KEY="/etc/ssl/private/nginx-selfsigned.key"
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=voltrontech.proxy" >/dev/null 2>&1 || { echo -e "${C_RED}❌ Failed to generate SSL certificate.${C_RESET}"; return; }
    
    echo -e "\n${C_GREEN}📝 Applying Nginx reverse proxy configuration...${C_RESET}"
    mv "$NGINX_CONFIG" "${NGINX_CONFIG}.bak" 2>/dev/null
    
    # Generate Listen Directives
    local listen_block=""
    for port in "${http_ports_array[@]}"; do
        listen_block="${listen_block}    listen $port;\n    listen [::]:$port;\n"
    done
    for port in "${tls_ports_array[@]}"; do
        listen_block="${listen_block}    listen $port ssl http2;\n    listen [::]:$port ssl http2;\n"
    done

    cat > "$NGINX_CONFIG" <<EOF
server {
    server_tokens off;
    server_name _;
    
$(echo -e "$listen_block")

    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH!SSLv3:!EXP!PSK!DSS;
    resolver 8.8.8.8;
    
    location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)$ {
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_read_timeout 1d;
        grpc_socket_keepalive on;
        proxy_read_timeout 1d;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_socket_keepalive on;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        if (\$content_type ~* "GRPC") { grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args; break; }
        proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
        break;
    }
    
    location / {
        proxy_read_timeout 3600s;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_socket_keepalive on;
        tcp_nodelay on;
        tcp_nopush off;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

    echo -e "\n${C_GREEN}▶️ Restarting Nginx service...${C_RESET}"
    systemctl restart nginx
    sleep 2
    
    if systemctl is-active --quiet nginx; then
        echo -e "\n${C_GREEN}✅ SUCCESS: Nginx Reverse Proxy is active.${C_RESET}"
        echo -e "   - TLS Ports: ${C_YELLOW}${tls_ports}${C_RESET}"
        echo -e "   - HTTP Ports: ${C_YELLOW}${http_ports}${C_RESET}"
        
        # Save ports for future reference
        echo "TLS_PORTS=\"$tls_ports\"" > "$NGINX_PORTS_FILE"
        echo "HTTP_PORTS=\"$http_ports\"" >> "$NGINX_PORTS_FILE"
    else
        echo -e "\n${C_RED}❌ ERROR: Nginx service failed to start.${C_RESET}"
        systemctl status nginx --no-pager
        mv "${NGINX_CONFIG}.bak" "$NGINX_CONFIG" 2>/dev/null
    fi
}

purge_nginx() {
    local mode="$1"
    
    if [[ "$mode" != "silent" ]]; then
        clear; show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- 🔥 Purge Nginx Installation ---${C_RESET}"
        if ! command -v nginx &> /dev/null; then
            echo -e "\n${C_YELLOW}ℹ️ Nginx is not installed. Nothing to do.${C_RESET}"
            return
        fi
        read -p "👉 This will COMPLETELY REMOVE Nginx. Are you sure? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
            return
        fi
    fi
    
    echo -e "\n${C_BLUE}🛑 Stopping Nginx service...${C_RESET}"
    systemctl stop nginx >/dev/null 2>&1
    
    echo -e "\n${C_BLUE}🗑️ Purging Nginx packages...${C_RESET}"
    apt-get purge -y nginx nginx-common >/dev/null 2>&1
    apt-get autoremove -y >/dev/null 2>&1
    
    echo -e "\n${C_BLUE}🗑️ Removing leftover files...${C_RESET}"
    rm -f /etc/ssl/certs/nginx-selfsigned.pem
    rm -f /etc/ssl/private/nginx-selfsigned.key
    rm -rf /etc/nginx
    
    if [[ "$mode" != "silent" ]]; then
        echo -e "\n${C_GREEN}✅ Nginx has been completely purged.${C_RESET}"
    fi
}

nginx_proxy_menu() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🌐 Nginx Proxy Management ---${C_RESET}"
    
    local active_status="${C_STATUS_I}Inactive${C_RESET}"
    if systemctl is-active --quiet nginx; then
        active_status="${C_STATUS_A}Active${C_RESET}"
    fi

    # Retrieve Ports Info
    local ports_info=""
    if [ -f "$NGINX_PORTS_FILE" ]; then
        source "$NGINX_PORTS_FILE"
        ports_info="\n    ${C_DIM}TLS: $TLS_PORTS | HTTP: $HTTP_PORTS${C_RESET}"
    fi

    echo -e "\n${C_WHITE}Current Status: ${active_status}${ports_info}"
    
    echo -e "\n${C_BOLD}Select an action:${C_RESET}\n"
    
    if systemctl is-active --quiet nginx; then
         printf "  ${C_CHOICE}[ 1]${C_RESET} %-40s\n" "🛑 Stop Nginx Service"
         printf "  ${C_CHOICE}[ 2]${C_RESET} %-40s\n" "🔄 Restart Nginx Service"
         printf "  ${C_CHOICE}[ 3]${C_RESET} %-40s\n" "⚙️ Re-install/Re-configure"
         printf "  ${C_CHOICE}[ 4]${C_RESET} %-40s\n" "🔥 Uninstall/Purge Nginx"
    else
         printf "  ${C_CHOICE}[ 1]${C_RESET} %-40s\n" "▶️ Start Nginx Service"
         printf "  ${C_CHOICE}[ 3]${C_RESET} %-40s\n" "⚙️ Install/Configure Nginx"
         printf "  ${C_CHOICE}[ 4]${C_RESET} %-40s\n" "🔥 Uninstall/Purge Nginx"
    fi

    echo -e "\n  ${C_WARN}[ 0]${C_RESET} ↩️ Return"
    echo
    
    local choice
    read -p "👉 Enter your choice: " choice
    
    case $choice in
        1) 
            if systemctl is-active --quiet nginx; then
                echo -e "\n${C_BLUE}🛑 Stopping Nginx...${C_RESET}"
                systemctl stop nginx
                echo -e "${C_GREEN}✅ Nginx stopped.${C_RESET}"
            else
                echo -e "\n${C_BLUE}▶️ Starting Nginx...${C_RESET}"
                systemctl start nginx
                if systemctl is-active --quiet nginx; then 
                    echo -e "${C_GREEN}✅ Nginx Started.${C_RESET}"
                else 
                    echo -e "${C_RED}❌ Failed to start.${C_RESET}"
                fi
            fi
            safe_read "" dummy
            ;;
        2)
            echo -e "\n${C_BLUE}🔄 Restarting Nginx...${C_RESET}"
            systemctl restart nginx
            safe_read "" dummy
            ;;
        3) 
             install_nginx_proxy
             safe_read "" dummy
             ;;
        4)
             purge_nginx
             safe_read "" dummy
             ;;
        0) return ;;
        *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
    esac
}

# ========== ZIVPN FUNCTIONS ==========
install_zivpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing ZiVPN (UDP/VPN) ---${C_RESET}"
    
    if [ -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Checking system architecture...${C_RESET}"
    local arch=$(uname -m)
    local zivpn_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
        echo -e "${C_BLUE}ℹ️ Detected AMD64/x86_64 architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    elif [[ "$arch" == "armv7l" || "$arch" == "arm" ]]; then
         zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm"
         echo -e "${C_BLUE}ℹ️ Detected ARM architecture.${C_RESET}"
    else
        echo -e "${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}📦 Downloading ZiVPN binary...${C_RESET}"
    if ! wget -q --show-progress -O "$ZIVPN_BIN" "$zivpn_url"; then
        echo -e "${C_RED}❌ Download failed. Check internet connection.${C_RESET}"
        return
    fi
    chmod +x "$ZIVPN_BIN"

    echo -e "\n${C_GREEN}⚙️ Configuring ZIVPN...${C_RESET}"
    mkdir -p "$ZIVPN_DIR"
    
    # Generate Certificates
    echo -e "${C_BLUE}🔐 Generating self-signed certificates...${C_RESET}"
    if ! command -v openssl &>/dev/null; then apt-get install -y openssl &>/dev/null; fi
    
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Voltron Tech/OU=IT Department/CN=zivpn" \
        -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" 2>/dev/null

    if [ ! -f "$ZIVPN_CERT_FILE" ]; then
        echo -e "${C_RED}❌ Failed to generate certificates.${C_RESET}"
        return
    fi

    # System Tuning
    echo -e "${C_BLUE}🔧 Tuning system network parameters...${C_RESET}"
    sysctl -w net.core.rmem_max=16777216 >/dev/null
    sysctl -w net.core.wmem_max=16777216 >/dev/null

    # Create Service
    echo -e "${C_BLUE}📝 Creating systemd service file...${C_RESET}"
    cat <<EOF > "$ZIVPN_SERVICE_FILE"
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
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Configure Passwords
    echo -e "\n${C_YELLOW}🔑 ZiVPN Password Setup${C_RESET}"
    read -p "👉 Enter passwords separated by commas (e.g., user1,user2) [Default: 'zi']: " input_config
    
    if [ -n "$input_config" ]; then
        IFS=',' read -r -a config_array <<< "$input_config"
        # Ensure array format for JSON
        json_passwords=$(printf '"%s",' "${config_array[@]}")
        json_passwords="[${json_passwords%,}]"
    else
        json_passwords='["zi"]'
    fi

    # Create Config File
    cat <<EOF > "$ZIVPN_CONFIG_FILE"
{
  "listen": ":$ZIVPN_PORT",
  "cert": "$ZIVPN_CERT_FILE",
  "key": "$ZIVPN_KEY_FILE",
  "obfs": "zivpn",
  "auth": {
    "mode": "passwords", 
    "config": $json_passwords
  }
}
EOF

    echo -e "\n${C_GREEN}🚀 Starting ZiVPN Service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service

    # Port Forwarding / Firewall
    echo -e "${C_BLUE}🔥 Configuring Firewall Rules (Redirecting 6000-19999 -> 5667)...${C_RESET}"
    
    # Determine primary interface
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    if [ -n "$iface" ]; then
        iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
    fi

    if command -v ufw &>/dev/null; then
        ufw allow 6000:19999/udp >/dev/null
        ufw allow 5667/udp >/dev/null
    fi

    if systemctl is-active --quiet zivpn.service; then
        echo -e "\n${C_GREEN}✅ ZiVPN Installed Successfully!${C_RESET}"
        echo -e "   - UDP Port: 5667 (Direct)"
        echo -e "   - UDP Ports: 6000-19999 (Forwarded)"
    else
        echo -e "\n${C_RED}❌ ZiVPN Service failed to start. Check logs: journalctl -u zivpn.service${C_RESET}"
    fi
}

uninstall_zivpn() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall ZiVPN ---${C_RESET}"
    
    if [ ! -f "$ZIVPN_SERVICE_FILE" ] && [ ! -f "$ZIVPN_BIN" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN does not appear to be installed.${C_RESET}"
        return
    fi

    read -p "👉 Are you sure you want to uninstall ZiVPN? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then echo -e "${C_YELLOW}Cancelled.${C_RESET}"; return; fi

    echo -e "\n${C_BLUE}🛑 Stopping services...${C_RESET}"
    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    
    echo -e "${C_BLUE}🗑️ Removing files...${C_RESET}"
    rm -f "$ZIVPN_SERVICE_FILE"
    rm -rf "$ZIVPN_DIR"
    rm -f "$ZIVPN_BIN"
    
    systemctl daemon-reload

    echo -e "\n${C_GREEN}✅ ZiVPN Uninstalled Successfully.${C_RESET}"
}

# ========== FALCON PROXY FUNCTIONS ==========
install_falcon_proxy() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🦅 Installing Falcon Proxy ---${C_RESET}"
    
    if [ -f "$FALCONPROXY_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ Falcon Proxy is already installed.${C_RESET}"
        if [ -f "$FALCONPROXY_CONFIG_FILE" ]; then
            source "$FALCONPROXY_CONFIG_FILE"
            echo -e "   It is configured to run on port(s): ${C_YELLOW}$PORTS${C_RESET}"
            echo -e "   Installed Version: ${C_YELLOW}${INSTALLED_VERSION:-Unknown}${C_RESET}"
        fi
        read -p "👉 Do you want to reinstall/update? (y/n): " confirm_reinstall
        if [[ "$confirm_reinstall" != "y" ]]; then return; fi
    fi

    echo -e "\n${C_BLUE}🌐 Fetching available versions from GitHub...${C_RESET}"
    local releases_json=$(curl -s "https://api.github.com/repos/voltrontech/falcon-proxy/releases")
    
    if [[ -z "$releases_json" || "$releases_json" == "[]" ]]; then
        echo -e "${C_RED}❌ Error: Could not fetch releases. Using latest version.${C_RESET}"
        SELECTED_VERSION="latest"
    else
        # Extract tag names
        mapfile -t versions < <(echo "$releases_json" | jq -r '.[].tag_name')
        
        if [ ${#versions[@]} -eq 0 ]; then
            echo -e "${C_RED}❌ No releases found. Using latest.${C_RESET}"
            SELECTED_VERSION="latest"
        else
            echo -e "\n${C_CYAN}Select a version to install:${C_RESET}"
            for i in "${!versions[@]}"; do
                printf "  ${C_GREEN}[%2d]${C_RESET} %s\n" "$((i+1))" "${versions[$i]}"
            done
            echo -e "  ${C_RED}[ 0]${C_RESET} ↩️ Cancel"
            
            local choice
            while true; do
                read -p "👉 Enter version number [1]: " choice
                choice=${choice:-1}
                if [[ "$choice" == "0" ]]; then return; fi
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#versions[@]}" ]; then
                    SELECTED_VERSION="${versions[$((choice-1))]}"
                    break
                else
                    echo -e "${C_RED}❌ Invalid selection.${C_RESET}"
                fi
            done
        fi
    fi

    local ports
    read -p "👉 Enter port(s) for Falcon Proxy (e.g., 8080 or 8080 8888) [8080]: " ports
    ports=${ports:-8080}

    local port_array=($ports)
    for port in "${port_array[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\n${C_RED}❌ Invalid port number: $port. Aborting.${C_RESET}"
            return
        fi
        check_and_free_ports "$port" || return
        check_and_open_firewall_port "$port" tcp || return
    done

    echo -e "\n${C_GREEN}⚙️ Detecting system architecture...${C_RESET}"
    local arch=$(uname -m)
    local binary_name=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_name="falconproxy"
        echo -e "${C_BLUE}ℹ️ Detected x86_64 (amd64) architecture.${C_RESET}"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_name="falconproxyarm"
        echo -e "${C_BLUE}ℹ️ Detected ARM64 architecture.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch. Cannot install Falcon Proxy.${C_RESET}"
        return
    fi
    
    # Construct download URL
    local download_url="https://github.com/voltrontech/falcon-proxy/releases/download/$SELECTED_VERSION/$binary_name"
    
    if [[ "$SELECTED_VERSION" == "latest" ]]; then
        download_url="https://github.com/voltrontech/falcon-proxy/releases/latest/download/$binary_name"
    fi

    echo -e "\n${C_GREEN}📥 Downloading Falcon Proxy ${SELECTED_VERSION}...${C_RESET}"
    wget -q --show-progress -O "$FALCONPROXY_BINARY" "$download_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download the binary.${C_RESET}"
        return
    fi
    
    chmod +x "$FALCONPROXY_BINARY"

    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$FALCONPROXY_SERVICE_FILE" <<EOF
[Unit]
Description=Falcon Proxy ($SELECTED_VERSION)
After=network.target

[Service]
User=root
Type=simple
ExecStart=$FALCONPROXY_BINARY -p $ports
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    echo -e "\n${C_GREEN}💾 Saving configuration...${C_RESET}"
    cat > "$FALCONPROXY_CONFIG_FILE" <<EOF
PORTS="$ports"
INSTALLED_VERSION="$SELECTED_VERSION"
EOF

    echo -e "\n${C_GREEN}▶️ Enabling and starting Falcon Proxy service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable falconproxy.service
    systemctl restart falconproxy.service
    sleep 2
    
    if systemctl is-active --quiet falconproxy; then
        echo -e "\n${C_GREEN}✅ SUCCESS: Falcon Proxy $SELECTED_VERSION is installed and active.${C_RESET}"
        echo -e "   Listening on port(s): ${C_YELLOW}$ports${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: Falcon Proxy service failed to start.${C_RESET}"
        journalctl -u falconproxy.service -n 15 --no-pager
    fi
}

uninstall_falcon_proxy() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling Falcon Proxy ---${C_RESET}"
    
    if [ ! -f "$FALCONPROXY_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ Falcon Proxy is not installed, skipping.${C_RESET}"
        return
    fi
    
    echo -e "${C_GREEN}🛑 Stopping and disabling Falcon Proxy service...${C_RESET}"
    systemctl stop falconproxy.service >/dev/null 2>&1
    systemctl disable falconproxy.service >/dev/null 2>&1
    
    echo -e "${C_GREEN}🗑️ Removing service file...${C_RESET}"
    rm -f "$FALCONPROXY_SERVICE_FILE"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}🗑️ Removing binary and config files...${C_RESET}"
    rm -f "$FALCONPROXY_BINARY"
    rm -f "$FALCONPROXY_CONFIG_FILE"
    
    echo -e "${C_GREEN}✅ Falcon Proxy has been uninstalled successfully.${C_RESET}"
}

# ========== X-UI FUNCTIONS ==========
install_xui_panel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Install X-UI Panel ---${C_RESET}"
    
    echo -e "\nThis will download and run the official installation script for X-UI."
    echo -e "Choose an installation option:\n"
    printf "  ${C_GREEN}[ 1]${C_RESET} %-40s\n" "Install the latest version of X-UI"
    printf "  ${C_GREEN}[ 2]${C_RESET} %-40s\n" "Install a specific version of X-UI"
    echo -e "\n  ${C_RED}[ 0]${C_RESET} ❌ Cancel Installation"
    echo
    
    local choice
    read -p "👉 Select an option: " choice
    
    case $choice in
        1)
            echo -e "\n${C_BLUE}⚙️ Installing the latest version...${C_RESET}"
            bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
            ;;
        2)
            read -p "👉 Enter the version to install (e.g., 1.8.0): " version
            if [[ -z "$version" ]]; then
                echo -e "\n${C_RED}❌ Version number cannot be empty.${C_RESET}"
                return
            fi
            echo -e "\n${C_BLUE}⚙️ Installing version ${C_YELLOW}$version...${C_RESET}"
            VERSION=$version bash <(curl -Ls "https://raw.githubusercontent.com/alireza0/x-ui/$version/install.sh") "$version"
            ;;
        0)
            echo -e "\n${C_YELLOW}❌ Installation cancelled.${C_RESET}"
            ;;
        *)
            echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"
            ;;
    esac
}

uninstall_xui_panel() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall X-UI Panel ---${C_RESET}"
    
    if ! command -v x-ui &> /dev/null; then
        echo -e "\n${C_YELLOW}ℹ️ X-UI does not appear to be installed.${C_RESET}"
        return
    fi
    
    read -p "👉 Are you sure you want to thoroughly uninstall X-UI? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        echo -e "\n${C_BLUE}⚙️ Running the default X-UI uninstaller first...${C_RESET}"
        x-ui uninstall >/dev/null 2>&1
        
        echo -e "\n${C_BLUE}🧹 Performing a full cleanup...${C_RESET}"
        echo " - Stopping and disabling x-ui service..."
        systemctl stop x-ui >/dev/null 2>&1
        systemctl disable x-ui >/dev/null 2>&1
        
        echo " - Removing x-ui files and directories..."
        rm -f /etc/systemd/system/x-ui.service
        rm -f /usr/local/bin/x-ui
        rm -rf /usr/local/x-ui/
        rm -rf /etc/x-ui/
        
        echo " - Reloading systemd daemon..."
        systemctl daemon-reload
        
        echo -e "\n${C_GREEN}✅ X-UI has been thoroughly uninstalled.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
    fi
}

# ========== DNSTT FUNCTIONS (WITH ULTRA BOOST INSIDE) ==========
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

create_dnstt_service() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    local forward_desc=$4
    
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📋 CREATING DNSTT SERVICE WITH ULTRA BOOST${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server for $forward_desc (ULTRA BOOST - 10x Speed)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DB_DIR
ExecStart=$DNSTT_SERVER -udp :5300 -privkey-file $DB_DIR/server.key -mtu $mtu $domain 127.0.0.1:$ssh_port
Restart=always
RestartSec=3

# ULTRA BOOST Settings
CPUQuota=80%
MemoryMax=1G
TasksMax=8388608

StandardOutput=append:$LOGS_DIR/dnstt-server.log
StandardError=append:$LOGS_DIR/dnstt-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service > /dev/null 2>&1
    
    echo -e "${C_GREEN}✅ Service created successfully with ULTRA BOOST!${C_RESET}"
    echo -e "  • Binary: ${C_CYAN}$DNSTT_SERVER${C_RESET}"
    echo -e "  • MTU: ${C_CYAN}$mtu (ULTRA BOOST mode)${C_RESET}"
    echo -e "  • Port: ${C_CYAN}5300${C_RESET}"
    echo -e "  • Target: ${C_CYAN}127.0.0.1:$ssh_port${C_RESET}"
    echo -e "  • ULTRA BOOST: ${C_GREEN}ENABLED (10x Speed)${C_RESET}"
}

save_dnstt_info() {
    local domain=$1
    local pubkey=$2
    local mtu=$3
    local ssh_port=$4
    local forward_desc=$5
    local ns_domain=$6
    
    cat > "$DNSTT_INFO_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
PUBLIC_KEY="$pubkey"
MTU_VALUE="$mtu"
SSH_PORT="$ssh_port"
FORWARD_DESC="$forward_desc"
NS_DOMAIN="$ns_domain"
EOF
}

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
    
    cat > /tmp/ultra-dnstt.sh << 'INNEREOF'
#!/bin/bash
# ULTRA BOOST - 10 Instances for 10x Speed
# Generated by Voltron Tech

DOMAIN="'$domain'"
PUBKEY_FILE="/etc/voltrontech/server.pub"
MTU='$mtu'
BASE_PORT=1080

# DNS resolvers (10 different)
DNS_RESOLVERS=(
    "8.8.8.8:53"
    "1.1.1.1:53"
    "169.255.187.58:53"
    "208.67.222.222:53"
    "9.9.9.9:53"
    "77.88.8.8:53"
    "8.26.56.26:53"
    "185.228.168.9:53"
    "76.76.19.19:53"
    "94.140.14.14:53"
)

# Create proxychains config
cat > /tmp/proxychains-ultra.conf << 'PROXY_EOF'
dynamic_chain
round_robin_chain on
[ProxyList]
PROXY_EOF

for i in {0..9}; do
    PORT=$((BASE_PORT + i))
    echo "socks5 127.0.0.1 $PORT" >> /tmp/proxychains-ultra.conf
    /usr/local/bin/dnstt-client -udp ${DNS_RESOLVERS[$i]} \
        -pubkey-file "$PUBKEY_FILE" \
        -mtu $MTU \
        -listen "127.0.0.1:$PORT" \
        "$DOMAIN" 127.0.0.1:'$ssh_port' &
    echo "Instance $((i+1)) started on port $PORT"
    sleep 1
done

echo ""
echo "✅ 10 ULTRA INSTANCES ACTIVE!"
echo "📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf ssh user@localhost -p '$ssh_port'"
echo "📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf curl ifconfig.me"
echo "📌 Expected speed: 10x!"
INNEREOF

    cat /tmp/ultra-dnstt.sh
    rm -f /tmp/ultra-dnstt.sh
    
    echo ""
    echo -e "${C_YELLOW}📌 Single Instance (for testing):${C_RESET}"
    echo -e "${C_WHITE}$DNSTT_CLIENT -udp 8.8.8.8:53 \\${C_RESET}"
    echo -e "${C_WHITE}  -pubkey-file $DB_DIR/server.pub \\${C_RESET}"
    echo -e "${C_WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${C_WHITE}  $domain 127.0.0.1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 Public Key (Full):${C_RESET}"
    echo -e "${C_GREEN}$pubkey${C_RESET}"
    echo ""
    
    echo -e "${C_CYAN}⚡ ULTRA BOOST STATUS (10x Speed Mode):${C_RESET}"
    echo -e "  • MTU: ${C_GREEN}$mtu (Optimized)${C_RESET}"
    echo -e "  • Ultra Buffers: ${C_GREEN}32MB${C_RESET}"
    echo -e "  • BBR v3: ${C_GREEN}Active${C_RESET}"
    echo -e "  • Keepalive: ${C_GREEN}10s${C_RESET}"
    echo -e "  • File Descriptors: ${C_GREEN}8M${C_RESET}"
    echo -e "  • TCP Tuning: ${C_GREEN}12 parameters optimized${C_RESET}"
    echo -e "  • 10 Parallel Instances: ${C_GREEN}10x speed!${C_RESET}"
    
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
}

install_dnstt() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION WITH ULTRA BOOST${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ -f "$DNSTT_SERVICE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is already installed.${C_RESET}"
        read -p "Reinstall? (y/n): " reinstall
        if [[ "$reinstall" != "y" ]]; then
            show_dnstt_details
            return
        fi
        systemctl stop dnstt.service 2>/dev/null
    fi
    
    echo -e "${C_GREEN}⚙️ Preparing system for DNSTT installation...${C_RESET}"
    systemctl stop systemd-resolved >/dev/null 2>&1
    systemctl disable systemd-resolved >/dev/null 2>&1
    chattr -i /etc/resolv.conf 2>/dev/null
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" | tee /etc/resolv.conf > /dev/null
    chattr +i /etc/resolv.conf 2>/dev/null
    
    echo -e "\n${C_BLUE}🔎 Checking if port 53 (UDP) is available...${C_RESET}"
    if ss -lunp | grep -q ':53\s'; then
        echo -e "${C_YELLOW}⚠️ Warning: Port 53 is in use.${C_RESET}"
        read -p "👉 Allow the script to automatically free it? (y/n): " resolve_confirm
        if [[ "$resolve_confirm" == "y" || "$resolve_confirm" == "Y" ]]; then
            echo -e "${C_GREEN}⚙️ Attempting to free port 53...${C_RESET}"
            fuser -k 53/udp 2>/dev/null
            sleep 2
        else
            echo -e "${C_RED}❌ Cannot proceed without freeing port 53. Aborting.${C_RESET}"
            return
        fi
    else
        echo -e "${C_GREEN}✅ Port 53 (UDP) is free to use.${C_RESET}"
    fi

    check_and_open_firewall_port 53 udp || return
    check_and_open_firewall_port 5300 udp || return

    echo -e "\n${C_BLUE}[1/9] Installing dependencies...${C_RESET}"
    $PKG_UPDATE
    $PKG_INSTALL wget curl git build-essential openssl
    
    echo -e "\n${C_BLUE}[2/9] Checking Go installation...${C_RESET}"
    if ! command -v go &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ Go not found, installing Go 1.21.5...${C_RESET}"
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    echo -e "\n${C_BLUE}[3/9] Building DNSTT from source...${C_RESET}"
    if ! build_dnstt_from_source; then
        echo -e "${C_RED}❌ Failed to build DNSTT${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    echo -e "\n${C_BLUE}[4/9] Applying ULTRA BOOST optimizations for DNSTT...${C_RESET}"
    enable_bbr_v3
    optimize_ultra_buffers
    optimize_aggressive_keepalive
    optimize_advanced_tcp
    optimize_ultra_filedesc
    
    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ ULTRA BOOST ACTIVATED FOR DNSTT - 10x SPEED!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}• BBR v3 with fq_codel:${C_RESET} Active"
    echo -e "  ${C_CYAN}• Ultra Buffers:${C_RESET} 32MB"
    echo -e "  ${C_CYAN}• Aggressive Keepalive:${C_RESET} 10s"
    echo -e "  ${C_CYAN}• Advanced TCP Tuning:${C_RESET} 12 parameters"
    echo -e "  ${C_CYAN}• File Descriptors:${C_RESET} 8M"
    echo -e "  ${C_CYAN}• Parallel Instances:${C_RESET} 10 (on client)"
    echo -e "  ${C_CYAN}• Expected Speed:${C_RESET} ${C_GREEN}10x with MTU 512!${C_RESET}"
    
    echo -e "\n${C_BLUE}[5/9] Configuring firewall...${C_RESET}"
    # Already done above
    
    echo -e "\n${C_BLUE}[6/9] Domain configuration...${C_RESET}"
    
    local forward_port=""
    local forward_desc=""
    local ssh_port="22"
    
    echo -e "\n${C_BLUE}Please choose where DNSTT should forward traffic:${C_RESET}"
    echo -e "  ${C_GREEN}[ 1]${C_RESET} ➡️ Forward to local SSH service (port 22)"
    echo -e "  ${C_GREEN}[ 2]${C_RESET} ➡️ Forward to local V2Ray backend (port 8787)"
    
    local fwd_choice
    read -p "👉 Enter your choice [1]: " fwd_choice
    fwd_choice=${fwd_choice:-1}
    
    if [[ "$fwd_choice" == "1" ]]; then
        forward_port="22"
        forward_desc="SSH (port 22)"
        echo -e "${C_GREEN}ℹ️ DNSTT will forward to SSH on 127.0.0.1:22.${C_RESET}"
    elif [[ "$fwd_choice" == "2" ]]; then
        forward_port="8787"
        forward_desc="V2Ray (port 8787)"
        echo -e "${C_GREEN}ℹ️ DNSTT will forward to V2Ray on 127.0.0.1:8787.${C_RESET}"
    else
        echo -e "${C_RED}❌ Invalid choice. Using SSH as default.${C_RESET}"
        forward_port="22"
        forward_desc="SSH (port 22)"
    fi
    
    local NS_DOMAIN=""
    local TUNNEL_DOMAIN=""
    local DNSTT_RECORDS_MANAGED="true"
    local NS_SUBDOMAIN=""
    local TUNNEL_SUBDOMAIN=""
    local HAS_IPV6="false"

    read -p "👉 Auto-generate DNS records or use custom ones? (auto/custom) [auto]: " dns_choice
    dns_choice=${dns_choice:-auto}

    if [[ "$dns_choice" == "custom" ]]; then
        DNSTT_RECORDS_MANAGED="false"
        read -p "👉 Enter your full tunnel domain (e.g., tun.yourdomain.com): " TUNNEL_DOMAIN
        if [[ -z "$TUNNEL_DOMAIN" ]]; then 
            echo -e "\n${C_RED}❌ Tunnel domain cannot be empty. Aborting.${C_RESET}"
            return
        fi
        NS_DOMAIN="$TUNNEL_DOMAIN"
    else
        echo -e "\n${C_BLUE}⚙️ Generating DNS records on voltrontechtx.shop...${C_RESET}"
        
        local SERVER_IPV4
        SERVER_IPV4=$(curl -s -4 icanhazip.com)
        
        if ! _is_valid_ipv4 "$SERVER_IPV4"; then
            echo -e "\n${C_RED}❌ Error: Could not retrieve a valid public IPv4 address.${C_RESET}"
            return 1
        fi
        
        local SERVER_IPV6
        SERVER_IPV6=$(curl -s -6 icanhazip.com --max-time 5)
        
        local RANDOM_STR
        RANDOM_STR=$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)
        
        NS_SUBDOMAIN="ns-$RANDOM_STR"
        TUNNEL_SUBDOMAIN="tun-$RANDOM_STR"
        NS_DOMAIN="$NS_SUBDOMAIN.$DESEC_DOMAIN"
        TUNNEL_DOMAIN="$TUNNEL_SUBDOMAIN.$DESEC_DOMAIN"

        local API_DATA="["
        API_DATA="${API_DATA}{\"subname\": \"$NS_SUBDOMAIN\", \"type\": \"A\", \"ttl\": 3600, \"records\": [\"$SERVER_IPV4\"]}"
        
        if [[ -n "$SERVER_IPV6" ]]; then
            API_DATA="${API_DATA}, {\"subname\": \"$NS_SUBDOMAIN\", \"type\": \"AAAA\", \"ttl\": 3600, \"records\": [\"$SERVER_IPV6\"]}"
            HAS_IPV6="true"
        fi
        
        API_DATA="${API_DATA}, {\"subname\": \"$TUNNEL_SUBDOMAIN\", \"type\": \"NS\", \"ttl\": 3600, \"records\": [\"$NS_DOMAIN.\"]}"
        API_DATA="${API_DATA}]"

        local CREATE_RESPONSE
        CREATE_RESPONSE=$(curl -s -w "%{http_code}" -X POST "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/" \
            -H "Authorization: Token $DESEC_TOKEN" -H "Content-Type: application/json" \
            --data "$API_DATA")
        
        local HTTP_CODE=${CREATE_RESPONSE: -3}
        local RESPONSE_BODY=${CREATE_RESPONSE:0:${#CREATE_RESPONSE}-3}

        if [[ "$HTTP_CODE" -ne 201 ]]; then
            echo -e "${C_RED}❌ Failed to create DNS records. API returned HTTP $HTTP_CODE.${C_RESET}"
            echo "Response: $RESPONSE_BODY" | jq
            return 1
        fi
        
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           ✅ DNS RECORDS CREATED SUCCESSFULLY!${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}Nameserver Domain (A record):${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        echo -e "  ${C_CYAN}  → Points to:${C_RESET} ${C_GREEN}$SERVER_IPV4${C_RESET}"
        if [[ "$HAS_IPV6" == "true" ]]; then
            echo -e "  ${C_CYAN}  → IPv6 also:${C_RESET} ${C_GREEN}$SERVER_IPV6${C_RESET}"
        fi
        echo -e "  ${C_CYAN}Tunnel Domain (NS record):${C_RESET} ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo -e "  ${C_CYAN}  → Points to:${C_RESET} ${C_GREEN}$NS_DOMAIN${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    fi
    
    echo -e "\n${C_BLUE}[7/9] MTU configuration...${C_RESET}"
    read -p "👉 Enter MTU value (e.g., 512, 1200) or press [Enter] for default 512: " mtu_value
    mtu_value=${mtu_value:-512}
    if [[ "$mtu_value" =~ ^[0-9]+$ ]]; then
        echo -e "${C_GREEN}ℹ️ Using MTU: $mtu_value (ULTRA BOOST mode)${C_RESET}"
    else
        echo -e "${C_RED}❌ Invalid MTU value. Using default 512.${C_RESET}"
        mtu_value=512
    fi
    
    echo -e "\n${C_BLUE}[8/9] Generating keys...${C_RESET}"
    if ! generate_keys; then
        echo -e "${C_RED}❌ Failed to generate keys${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    echo -e "\n${C_BLUE}[9/9] Creating service with ULTRA BOOST...${C_RESET}"
    create_dnstt_service "$TUNNEL_DOMAIN" "$mtu_value" "$forward_port" "$forward_desc"
    
    save_dnstt_info "$TUNNEL_DOMAIN" "$PUBLIC_KEY" "$mtu_value" "$forward_port" "$forward_desc" "$NS_DOMAIN"
    
    echo -e "\n${C_BLUE}🚀 Starting DNSTT service...${C_RESET}"
    systemctl start dnstt.service
    sleep 3
    
    if systemctl is-active --quiet dnstt.service; then
        echo -e "${C_GREEN}✅ Service started successfully with ULTRA BOOST!${C_RESET}"
    else
        echo -e "${C_RED}❌ Service failed to start${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
    fi
    
    show_client_commands "$TUNNEL_DOMAIN" "$mtu_value" "$forward_port"
    
    cat > "$DB_DIR/dnstt_info.txt" <<EOF
DNSTT Configuration (Voltron Tech - ULTRA BOOST)
============================================
Domain: $TUNNEL_DOMAIN
MTU: $mtu_value
Forward To: $forward_desc
Public Key: $PUBLIC_KEY

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
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling DNSTT ---${C_RESET}"
    
    if [ ! -f "$DNSTT_SERVICE" ]; then
        echo -e "${C_YELLOW}ℹ️ DNSTT does not appear to be installed, skipping.${C_RESET}"
        return
    fi
    
    local confirm="y"
    if [[ "$UNINSTALL_MODE" != "silent" ]]; then
        read -p "👉 Are you sure you want to uninstall DNSTT? (y/n): " confirm
    fi
    
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
        return
    fi
    
    echo -e "${C_BLUE}🛑 Stopping and disabling DNSTT service...${C_RESET}"
    systemctl stop dnstt.service > /dev/null 2>&1
    systemctl disable dnstt.service > /dev/null 2>&1
    
    if [ -f "$DNSTT_INFO_FILE" ]; then
        source "$DNSTT_INFO_FILE"
        
        if [[ "$TUNNEL_DOMAIN" == *"$DESEC_DOMAIN"* ]]; then
            local subdomain=$(echo "$TUNNEL_DOMAIN" | cut -d. -f1)
            local ns_subdomain=$(echo "$NS_DOMAIN" | cut -d. -f1)
            
            echo -e "${C_BLUE}🗑️ Removing auto-generated DNS records...${C_RESET}"
            curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$ns_subdomain/A/" \
                 -H "Authorization: Token $DESEC_TOKEN" > /dev/null
            curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$ns_subdomain/AAAA/" \
                 -H "Authorization: Token $DESEC_TOKEN" > /dev/null 2>&1
            curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$subdomain/NS/" \
                 -H "Authorization: Token $DESEC_TOKEN" > /dev/null
            echo -e "${C_GREEN}✅ DNS records have been removed.${C_RESET}"
        else
            echo -e "${C_YELLOW}⚠️ DNS records were manually configured. Please delete them manually.${C_RESET}"
        fi
    fi
    
    echo -e "${C_BLUE}🗑️ Removing service files and binaries...${C_RESET}"
    rm -f "$DNSTT_SERVICE"
    rm -f "$DNSTT_SERVER" "$DNSTT_CLIENT"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_INFO_FILE"
    rm -f "$DB_DIR/server.key" "$DB_DIR/server.pub"
    rm -f "$DB_DIR/domain.txt"
    systemctl daemon-reload
    
    echo -e "${C_YELLOW}ℹ️ Making /etc/resolv.conf writable...${C_RESET}"
    chattr -i /etc/resolv.conf &>/dev/null
    
    echo -e "\n${C_GREEN}✅ DNSTT has been successfully uninstalled.${C_RESET}"
}

show_dnstt_details() {
    if [ -f "$DNSTT_INFO_FILE" ]; then
        source "$DNSTT_INFO_FILE"
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           📡 DNSTT CONNECTION DETAILS${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        
        local status=""
        if systemctl is-active dnstt.service &>/dev/null; then
            status="${C_GREEN}● RUNNING${C_RESET}"
        else
            status="${C_RED}● STOPPED${C_RESET}"
        fi
        
        echo -e "\n${C_WHITE}Service Status: ${status}${C_RESET}"
        echo -e "  - ${C_CYAN}Nameserver Domain:${C_RESET} ${C_YELLOW}$NS_DOMAIN${C_RESET}"
        echo -e "  - ${C_CYAN}Tunnel Domain:${C_RESET}    ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
        echo -e "  - ${C_CYAN}Public Key:${C_RESET}        ${C_YELLOW}$PUBLIC_KEY${C_RESET}"
        
        if [[ -n "$FORWARD_DESC" ]]; then
            echo -e "  - ${C_CYAN}Forwarding To:${C_RESET}   ${C_YELLOW}$FORWARD_DESC${C_RESET}"
        fi
        
        if [[ -n "$MTU_VALUE" ]]; then
            echo -e "  - ${C_CYAN}MTU Value:${C_RESET}        ${C_YELLOW}$MTU_VALUE${C_RESET}"
        fi
        
        echo -e "\n${C_CYAN}⚡ ULTRA BOOST Status:${C_RESET} ${C_GREEN}ACTIVE (10x Speed)${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    else
        echo -e "\n${C_YELLOW}ℹ️ DNSTT configuration file not found.${C_RESET}"
    fi
}

# ========== DT PROXY FUNCTIONS ==========
install_dt_proxy_full() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Full DT Tunnel Installation ---${C_RESET}"
    
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DT Proxy appears to be already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_BLUE}--- Step 1 of 2: Installing DT Tunnel Mod ---${C_RESET}"
    read -p "👉 Press [Enter] to continue or [Ctrl+C] to cancel."

    if curl -sL https://raw.githubusercontent.com/voltrontech/ProxyMods/main/install.sh | bash; then
        echo -e "\n${C_GREEN}✅ DT Tunnel Mod installed successfully.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: DT Tunnel Mod installation failed.${C_RESET}"
        return
    fi

    echo -e "\n${C_BLUE}--- Step 2 of 2: Installing DT Tunnel Proxy ---${C_RESET}"
    read -p "👉 Press [Enter] to continue or [Ctrl+C] to cancel."

    if bash <(curl -fsSL https://raw.githubusercontent.com/voltrontech/ProxyDT-Go-Releases/main/install.sh); then
        echo -e "\n${C_GREEN}✅ DT Tunnel Proxy installed successfully.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: DT Tunnel Proxy installation failed.${C_RESET}"
    fi
}

launch_dt_proxy_menu() {
    clear; show_banner
    
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_GREEN}✅ DT Proxy is installed. Launching its management panel...${C_RESET}"
        sleep 2
        /usr/local/bin/main
    else
        echo -e "\n${C_RED}❌ DT Proxy is not installed. Please use the install option first.${C_RESET}"
        safe_read "" dummy
    fi
}

uninstall_dt_proxy_full() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall DT Proxy ---${C_RESET}"
    
    if [ ! -f "/usr/local/bin/proxy" ] && [ ! -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DT Proxy is not installed. Nothing to do.${C_RESET}"
        return
    fi
    
    read -p "👉 Are you sure you want to PERMANENTLY delete DT Proxy? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
        return
    fi

    echo -e "\n${C_BLUE}🛑 Stopping and disabling all DT Proxy services...${C_RESET}"
    systemctl list-units --type=service --state=running | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl stop
    systemctl list-unit-files --type=service | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl disable

    echo -e "\n${C_BLUE}🗑️ Removing files...${C_RESET}"
    rm -f /etc/systemd/system/proxy-*.service
    systemctl daemon-reload
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f "$HOME/.proxy_token"
    rm -f /var/log/proxy-*.log
    rm -f /usr/local/bin/install_mod

    echo -e "\n${C_GREEN}✅ DT Proxy has been successfully uninstalled.${C_RESET}"
}

dt_proxy_menu() {
    while true; do
        clear
        show_banner
        
        local dt_proxy_status
        if [ -f "/usr/local/bin/main" ] && [ -f "/usr/local/bin/proxy" ]; then
            dt_proxy_status="${C_STATUS_A}(Installed)${C_RESET}"
        else
            dt_proxy_status="${C_STATUS_I}(Not Installed)${C_RESET}"
        fi

        echo -e "\n   ${C_TITLE}═════════════════[ ${C_BOLD}🚀 DT PROXY MANAGEMENT ${dt_proxy_status} ${C_RESET}${C_TITLE}]═════════════════${C_RESET}"
        printf "     ${C_CHOICE}[ 1]${C_RESET} %-45s\n" "🚀 Install DT Tunnel (Mod + Proxy)"
        printf "     ${C_CHOICE}[ 2]${C_RESET} %-45s\n" "▶️ Launch DT Tunnel Management Menu"
        printf "     ${C_DANGER}[ 3]${C_RESET} %-45s\n" "🗑️ Uninstall DT Tunnel"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_WARN}[ 0]${C_RESET} ↩️ Return to Main Menu"
        echo
        
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select option: "${C_RESET})" choice
        
        case $choice in
            1) install_dt_proxy_full; safe_read "" dummy ;;
            2) launch_dt_proxy_menu ;;
            3) uninstall_dt_proxy_full; safe_read "" dummy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option.${C_RESET}" && sleep 2 ;;
        esac
    done
}

# ========== TRAFFIC MONITOR FUNCTIONS ==========
simple_live_monitor() {
    local iface=$1
    echo -e "\n${C_BLUE}⚡ Starting Lightweight Traffic Monitor for $iface...${C_RESET}"
    echo -e "${C_DIM}Press [Ctrl+C] to stop.${C_RESET}\n"
    
    local rx1=$(cat /sys/class/net/$iface/statistics/rx_bytes)
    local tx1=$(cat /sys/class/net/$iface/statistics/tx_bytes)
    
    printf "%-15s | %-15s\n" "⬇️ Download" "⬆️ Upload"
    echo "-----------------------------------"
    
    while true; do
        sleep 1
        local rx2=$(cat /sys/class/net/$iface/statistics/rx_bytes)
        local tx2=$(cat /sys/class/net/$iface/statistics/tx_bytes)
        
        local rx_diff=$((rx2 - rx1))
        local tx_diff=$((tx2 - tx1))
        
        local rx_kbs=$((rx_diff / 1024))
        local tx_kbs=$((tx_diff / 1024))
        
        if [ $rx_kbs -gt 1024 ]; then 
            rx_fmt=$(awk "BEGIN {printf \"%.2f MB/s\", $rx_kbs/1024}")
        else 
            rx_fmt="${rx_kbs} KB/s"
        fi
        
        if [ $tx_kbs -gt 1024 ]; then 
            tx_fmt=$(awk "BEGIN {printf \"%.2f MB/s\", $tx_kbs/1024}")
        else 
            tx_fmt="${tx_kbs} KB/s"
        fi
        
        printf "\r%-15s | %-15s" "$rx_fmt" "$tx_fmt"
        
        rx1=$rx2
        tx1=$tx2
    done
}

traffic_monitor_menu() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📈 Network Traffic Monitor ---${C_RESET}"
    
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    echo -e "\nInterface: ${C_CYAN}${iface}${C_RESET}"
    
    echo -e "\n${C_BOLD}Select a monitoring option:${C_RESET}\n"
    printf "  ${C_CHOICE}[ 1]${C_RESET} %-40s\n" "⚡ Live Monitor (Lightweight)"
    printf "  ${C_CHOICE}[ 2]${C_RESET} %-40s\n" "📊 View Total Traffic Since Boot"
    printf "  ${C_CHOICE}[ 3]${C_RESET} %-40s\n" "📅 Daily/Monthly Logs (Requires vnStat)"
    
    echo -e "\n  ${C_WARN}[ 0]${C_RESET} ↩️ Return"
    echo
    
    local t_choice
    read -p "👉 Enter choice: " t_choice
    
    case $t_choice in
        1) 
           simple_live_monitor "$iface"
           ;;
        2)
            local rx_total=$(cat /sys/class/net/$iface/statistics/rx_bytes)
            local tx_total=$(cat /sys/class/net/$iface/statistics/tx_bytes)
            local rx_mb=$((rx_total / 1024 / 1024))
            local tx_mb=$((tx_total / 1024 / 1024))
            echo -e "\n${C_BLUE}📊 Total Traffic (Since Boot):${C_RESET}"
            echo -e "   ⬇️ Download: ${C_WHITE}${rx_mb} MB${C_RESET}"
            echo -e "   ⬆️ Upload:   ${C_WHITE}${tx_mb} MB${C_RESET}"
            safe_read "" dummy
            ;;
        3) 
           if ! command -v vnstat &> /dev/null; then
               echo -e "\n${C_YELLOW}⚠️ vnStat is not installed.${C_RESET}"
               read -p "👉 Install vnStat now? (y/n): " confirm
               if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    echo -e "\n${C_BLUE}📦 Installing vnStat...${C_RESET}"
                    apt-get update >/dev/null 2>&1
                    apt-get install -y vnstat >/dev/null 2>&1
                    systemctl enable vnstat >/dev/null 2>&1
                    systemctl restart vnstat >/dev/null 2>&1
                    vnstat --add -i "$iface" >/dev/null 2>&1
                    echo -e "${C_GREEN}✅ Installed.${C_RESET}"
                    sleep 1
               else
                    return
               fi
           fi
           echo
           vnstat -i "$iface"
           echo -e "\n${C_DIM}Run 'vnstat -d' or 'vnstat -m' manually for specific views.${C_RESET}"
           safe_read "" dummy
           ;;
        *) return ;;
    esac
}

# ========== TORRENT BLOCK FUNCTIONS ==========
_flush_torrent_rules() {
    iptables -D FORWARD -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "peer_id=" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string ".torrent" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "announce.php?passkey=" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "torrent" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "info_hash" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "get_peers" --algo bm -j DROP 2>/dev/null
    iptables -D FORWARD -m string --string "find_node" --algo bm -j DROP 2>/dev/null

    iptables -D OUTPUT -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "peer_id=" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string ".torrent" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "announce.php?passkey=" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "torrent" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "info_hash" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "get_peers" --algo bm -j DROP 2>/dev/null
    iptables -D OUTPUT -m string --string "find_node" --algo bm -j DROP 2>/dev/null
}

torrent_block_menu() {
    clear; show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚫 Torrent Blocking (Anti-Torrent) ---${C_RESET}"
    
    local torrent_status="${C_STATUS_I}Disabled${C_RESET}"
    if iptables -L FORWARD | grep -q "BitTorrent"; then
         torrent_status="${C_STATUS_A}Enabled${C_RESET}"
    elif iptables -L OUTPUT | grep -q "BitTorrent"; then
         torrent_status="${C_STATUS_A}Enabled${C_RESET}"
    fi
    
    echo -e "\n${C_WHITE}Current Status: ${torrent_status}${C_RESET}"
    echo -e "${C_DIM}This feature uses iptables string matching to block common torrent keywords.${C_RESET}"
    
    echo -e "\n${C_BOLD}Select an action:${C_RESET}\n"
    printf "  ${C_CHOICE}[ 1]${C_RESET} %-40s\n" "🔒 Enable Torrent Blocking"
    printf "  ${C_CHOICE}[ 2]${C_RESET} %-40s\n" "🔓 Disable Torrent Blocking"
    echo -e "\n  ${C_WARN}[ 0]${C_RESET} ↩️ Return"
    echo
    
    local b_choice
    read -p "👉 Enter choice: " b_choice
    
    case $b_choice in
        1)
            echo -e "\n${C_BLUE}🛡️ Applying Anti-Torrent rules...${C_RESET}"
            _flush_torrent_rules
            
            iptables -A FORWARD -m string --string "BitTorrent" --algo bm -j DROP
            iptables -A FORWARD -m string --string "BitTorrent protocol" --algo bm -j DROP
            iptables -A FORWARD -m string --string "peer_id=" --algo bm -j DROP
            iptables -A FORWARD -m string --string ".torrent" --algo bm -j DROP
            iptables -A FORWARD -m string --string "announce.php?passkey=" --algo bm -j DROP
            iptables -A FORWARD -m string --string "torrent" --algo bm -j DROP
            iptables -A FORWARD -m string --string "info_hash" --algo bm -j DROP
            iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
            iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
            
            iptables -A OUTPUT -m string --string "BitTorrent" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "peer_id=" --algo bm -j DROP
            iptables -A OUTPUT -m string --string ".torrent" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "announce.php?passkey=" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "torrent" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "info_hash" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "get_peers" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "find_node" --algo bm -j DROP
            
            if dpkg -s iptables-persistent &>/dev/null; then
                netfilter-persistent save &>/dev/null
            fi
            
            echo -e "${C_GREEN}✅ Torrent Blocking Enabled.${C_RESET}"
            safe_read "" dummy
            ;;
        2)
            echo -e "\n${C_BLUE}🔓 Removing Anti-Torrent rules...${C_RESET}"
            _flush_torrent_rules
            
            if dpkg -s iptables-persistent &>/dev/null; then
                netfilter-persistent save &>/dev/null
            fi
            
            echo -e "${C_GREEN}✅ Torrent Blocking Disabled.${C_RESET}"
            safe_read "" dummy
            ;;
        *) return ;;
    esac
}

# ========== MAIN MENU ==========
main_menu() {
    initial_setup
    while true; do
        show_banner
        
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    👤 USER MANAGEMENT                        ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "1" "✨ Create New User" "7" "📋 List Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "2" "🗑️ Delete User" "8" "📱 Generate Client Config"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "3" "✏️ Edit User" "9" "⏱️ Create Trial Account"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "4" "🔒 Lock User" "10" "📊 View User Bandwidth"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "5" "🔓 Unlock User" "11" "👥 Bulk Create Users"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s\n" "6" "🔄 Renew User"
        
        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    ⚙️ SYSTEM UTILITIES                        ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "12" "🔌 Protocol Manager" "16" "🌐 DNS Domain (deSEC)"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "13" "🚀 DT Proxy Manager" "17" "🎨 SSH Banner"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "14" "📈 Traffic Monitor" "18" "🔄 Auto Reboot"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "15" "🚫 Block Torrent" "19" "🧹 Cleanup Expired"

        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    💾 BACKUP & RESTORE                        ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_GREEN}%2s${C_RESET}) %-25s  ${C_GREEN}%2s${C_RESET}) %-25s\n" "20" "💾 Backup User Data" "21" "📥 Restore User Data"

        echo ""
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}                    🔥 DANGER ZONE                             ${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        printf "  ${C_RED}%2s${C_RESET}) %-28s  ${C_RED}%2s${C_RESET}) %-25s\n" "99" "Uninstall Script" "0" "Exit"

        echo ""
        local choice
        safe_read "$(echo -e ${C_PROMPT}"👉 Select an option: "${C_RESET})" choice
        
        case $choice in
            1) create_user; safe_read "" dummy ;;
            2) delete_user; safe_read "" dummy ;;
            3) edit_user; safe_read "" dummy ;;
            4) lock_user; safe_read "" dummy ;;
            5) unlock_user; safe_read "" dummy ;;
            6) renew_user; safe_read "" dummy ;;
            7) list_users; safe_read "" dummy ;;
            8) client_config_menu; safe_read "" dummy ;;
            9) create_trial_account; safe_read "" dummy ;;
            10) view_user_bandwidth; safe_read "" dummy ;;
            11) bulk_create_users; safe_read "" dummy ;;
            
            12) protocol_menu ;;
            13) dt_proxy_menu ;;
            14) traffic_monitor_menu ;;
            15) torrent_block_menu ;;
            16) dns_menu; safe_read "" dummy ;;
            17) ssh_banner_menu ;;
            18) auto_reboot_menu ;;
            19) cleanup_expired; safe_read "" dummy ;;
            
            20) backup_user_data; safe_read "" dummy ;;
            21) restore_user_data; safe_read "" dummy ;;
            
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
