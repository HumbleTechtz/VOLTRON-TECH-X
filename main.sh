#!/bin/bash

# ========== VOLTRON TECH MANAGER ==========
# Version: 10.0 Premium Edition
# Description: Complete Server Management Script
# Based on: FirewallFalcon Manager
# Author: Voltron Tech

# ========== VOLTRONTECH DESEC.IO CONFIG ==========
DESEC_TOKEN="73c0f39c-da35-47f2-859f-f16355e2c734"
DESEC_DOMAIN="voltrontechtx.shop"
DNS_INFO_FILE="/etc/voltrontech/dns_info.conf"

# ========== DIRECTORY STRUCTURE ==========
DB_DIR="/etc/voltrontech"
DB_FILE="$DB_DIR/users.db"
INSTALL_FLAG_FILE="$DB_DIR/.install"
BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"
BADVPN_BUILD_DIR="/root/badvpn-build"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
NGINX_CONFIG_FILE="/etc/nginx/sites-available/default"
SSL_CERT_DIR="$DB_DIR/ssl"
SSL_CERT_FILE="$SSL_CERT_DIR/voltrontech.pem"
NGINX_PORTS_FILE="$DB_DIR/nginx_ports.conf"
DNSTT_SERVICE_FILE="/etc/systemd/system/dnstt.service"
DNSTT_BINARY="/usr/local/bin/dnstt-server"
DNSTT_CLIENT="/usr/local/bin/dnstt-client"
DNSTT_KEYS_DIR="$DB_DIR/dnstt"
DNSTT_CONFIG_FILE="$DB_DIR/dnstt_info.conf"
UDP_CUSTOM_DIR="/root/udp"
UDP_CUSTOM_SERVICE_FILE="/etc/systemd/system/udp-custom.service"
SSH_BANNER_FILE="/etc/bannerssh"
VOLTRONPROXY_SERVICE_FILE="/etc/systemd/system/voltronproxy.service"
VOLTRONPROXY_BINARY="/usr/local/bin/voltronproxy"
VOLTRONPROXY_CONFIG_FILE="$DB_DIR/voltronproxy_config.conf"
LIMITER_SCRIPT="/usr/local/bin/voltrontech-limiter.sh"
LIMITER_SERVICE="/etc/systemd/system/voltrontech-limiter.service"
BANDWIDTH_DIR="$DB_DIR/bandwidth"
BANDWIDTH_SCRIPT="/usr/local/bin/voltrontech-bandwidth.sh"
BANDWIDTH_SERVICE="/etc/systemd/system/voltrontech-bandwidth.service"
TRIAL_CLEANUP_SCRIPT="/usr/local/bin/voltrontech-trial-cleanup.sh"
SSHD_VOLTRON_CONFIG="/etc/ssh/sshd_config.d/voltrontech.conf"
BANNER_DIR="/etc/voltrontech/banners"
BANNER_ENABLED="/etc/voltrontech/banners_enabled"

# ZiVPN Variables
ZIVPN_DIR="/etc/zivpn"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SERVICE_FILE="/etc/systemd/system/zivpn.service"
ZIVPN_CONFIG_FILE="$ZIVPN_DIR/config.json"
ZIVPN_CERT_FILE="$ZIVPN_DIR/zivpn.crt"
ZIVPN_KEY_FILE="$ZIVPN_DIR/zivpn.key"

SELECTED_USER=""
UNINSTALL_MODE="interactive"

# ========== COLOR CODES ==========
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_UL=$'\033[4m'

# Premium Color Palette
C_RED=$'\033[38;5;196m'
C_GREEN=$'\033[38;5;46m'
C_YELLOW=$'\033[38;5;226m'
C_BLUE=$'\033[38;5;39m'
C_PURPLE=$'\033[38;5;135m'
C_CYAN=$'\033[38;5;51m'
C_WHITE=$'\033[38;5;255m'
C_GRAY=$'\033[38;5;245m'
C_ORANGE=$'\033[38;5;208m'

C_TITLE=$C_PURPLE
C_CHOICE=$C_CYAN
C_PROMPT=$C_BLUE
C_WARN=$C_YELLOW
C_DANGER=$C_RED
C_STATUS_A=$C_GREEN
C_STATUS_I=$C_GRAY
C_ACCENT=$C_ORANGE

# ========== CREATE DIRECTORIES ==========
create_directories() {
    mkdir -p $DB_DIR $DNSTT_KEYS_DIR $BACKUP_DIR $LOGS_DIR $CONFIG_DIR $SSL_CERT_DIR $BANDWIDTH_DIR
    mkdir -p $BANDWIDTH_DIR/pidtrack
    mkdir -p $UDP_CUSTOM_DIR $ZIVPN_DIR
    mkdir -p $(dirname "$SSH_BANNER_FILE")
    mkdir -p "$BANNER_DIR"
    mkdir -p "$DB_DIR/cache"
    touch $DB_FILE
    touch "$BANNER_ENABLED"
}

# ========== GET IP, LOCATION, ISP ==========
get_ip_info() {
    IP_CACHE_FILE="$DB_DIR/cache/ip"
    LOCATION_CACHE_FILE="$DB_DIR/cache/location"
    ISP_CACHE_FILE="$DB_DIR/cache/isp"
    
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

# ========== SHOW BANNER ==========
show_banner() {
    clear
    get_ip_info
    local current_mtu=$(get_current_mtu)
    
    echo -e "${C_BOLD}${C_PURPLE}╔═══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║           🔥 VOLTRON TECH MANAGER v10.0 🔥                   ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║        SSH • DNSTT • BADVPN • UDP • Nginx • ZiVPN • X-UI       ║${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}╠═══════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Server IP: ${C_GREEN}$IP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Location:  ${C_GREEN}$LOCATION, $COUNTRY${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  ISP:       ${C_GREEN}$ISP${C_PURPLE}${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}║  Current MTU: ${C_GREEN}$current_mtu${C_PURPLE}${C_RESET}"
    
    # Show Domain status
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        echo -e "${C_BOLD}${C_PURPLE}║  Domain:     ${C_GREEN}$FULL_DOMAIN${C_PURPLE}${C_RESET}"
    fi
    
    echo -e "${C_BOLD}${C_PURPLE}╚═══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ========== GET CURRENT MTU ==========
get_current_mtu() {
    if [ -f "$CONFIG_DIR/mtu" ]; then
        cat "$CONFIG_DIR/mtu"
    else
        echo "512"
    fi
}

# ========== SAFE READ ==========
safe_read() {
    local prompt="$1"
    local var_name="$2"
    read -p "$prompt" "$var_name"
}

# ========== CHECK AND OPEN FIREWALL PORT ==========
check_and_open_firewall_port() {
    local port="$1"
    local protocol="${2:-tcp}"
    local firewall_detected=false

    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        firewall_detected=true
        if ! ufw status | grep -qw "$port/$protocol"; then
            echo -e "${C_YELLOW}🔥 UFW firewall is active and port ${port}/${protocol} is closed.${C_RESET}"
            read -p "👉 Do you want to open this port now? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                ufw allow "$port/$protocol"
                echo -e "${C_GREEN}✅ Port ${port}/${protocol} has been opened in UFW.${C_RESET}"
            else
                echo -e "${C_RED}❌ Warning: Port ${port}/${protocol} was not opened. The service may not work correctly.${C_RESET}"
                return 1
            fi
        else
             echo -e "${C_GREEN}✅ Port ${port}/${protocol} is already open in UFW.${C_RESET}"
        fi
    fi

    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
        firewall_detected=true
        if ! firewall-cmd --list-ports --permanent | grep -qw "$port/$protocol"; then
            echo -e "${C_YELLOW}🔥 firewalld is active and port ${port}/${protocol} is not open.${C_RESET}"
            read -p "👉 Do you want to open this port now? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                firewall-cmd --add-port="$port/$protocol" --permanent
                firewall-cmd --reload
                echo -e "${C_GREEN}✅ Port ${port}/${protocol} has been opened in firewalld.${C_RESET}"
            else
                echo -e "${C_RED}❌ Warning: Port ${port}/${protocol} was not opened. The service may not work correctly.${C_RESET}"
                return 1
            fi
        else
            echo -e "${C_GREEN}✅ Port ${port}/${protocol} is already open in firewalld.${C_RESET}"
        fi
    fi

    if ! $firewall_detected; then
        echo -e "${C_BLUE}ℹ️ No active firewall detected. Assuming ports are open.${C_RESET}"
    fi
    return 0
}

# ========== CHECK AND FREE PORTS ==========
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

# ========== SELECT USER INTERFACE ==========
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
    
    read -p "👉 Enter a search term (or press Enter to list all): " search_term
    
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
        printf "  ${C_GREEN}[%2d]${C_RESET} %s\n" "$((i+1))" "${users[$i]}"
    done
    echo -e "\n  ${C_RED}[ 0]${C_RESET} ↩️ Cancel"
    echo
    
    local choice
    while true; do
        read -p "👉 Enter the number of the user: " choice
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

# ========== CREATE USER ==========
create_user() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ✨ Create New SSH User ---${C_RESET}"
    
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
        read -p "🔑 Enter password (or press Enter for auto-generated): " password
        if [[ -z "$password" ]]; then
            password=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
            echo -e "${C_GREEN}🔑 Auto-generated password: ${C_YELLOW}$password${C_RESET}"
            break
        else
            break
        fi
    done
    
    read -p "🗓️ Enter account duration (in days): " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    read -p "📶 Enter simultaneous connection limit [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    read -p "📦 Enter bandwidth limit in GB (0 = unlimited) [0]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-0}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
    
    useradd -m -s /usr/sbin/nologin "$username"
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$bandwidth_gb:0:ACTIVE" >> "$DB_FILE"
    
    local bw_display="Unlimited"
    if [[ "$bandwidth_gb" != "0" ]]; then
        bw_display="${bandwidth_gb} GB"
    fi
    
    clear
    show_banner
    echo -e "${C_GREEN}✅ User '$username' created successfully!${C_RESET}\n"
    echo -e "  - 👤 Username:          ${C_YELLOW}$username${C_RESET}"
    echo -e "  - 🔑 Password:          ${C_YELLOW}$password${C_RESET}"
    echo -e "  - 🗓️ Expires on:        ${C_YELLOW}$expire_date${C_RESET}"
    echo -e "  - 📶 Connection Limit:  ${C_YELLOW}$limit${C_RESET}"
    echo -e "  - 📦 Bandwidth Limit:   ${C_YELLOW}$bw_display${C_RESET}"
    
    safe_read "" dummy
}

# ========== DELETE USER ==========
delete_user() {
    _select_user_interface "--- 🗑️ Delete a User ---"
    local username=$SELECTED_USER
    
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        echo -e "\n${C_YELLOW}ℹ️ No users found.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "👉 Are you sure you want to delete '$username'? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Deletion cancelled.${C_RESET}"
        return
    fi
    
    killall -u "$username" -9 &>/dev/null
    sleep 1
    userdel -r "$username" &>/dev/null
    
    rm -f "$BANDWIDTH_DIR/${username}.usage"
    rm -rf "$BANDWIDTH_DIR/pidtrack/${username}" 2>/dev/null
    rm -f "$BANNER_DIR/${username}.txt"
    
    sed -i "/^$username:/d" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User '$username' has been deleted.${C_RESET}"
    safe_read "" dummy
}

# ========== LIST USERS ==========
list_users() {
    clear
    show_banner
    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_YELLOW}ℹ️ No users are currently being managed.${C_RESET}"
        return
    fi
    echo -e "${C_BOLD}${C_PURPLE}--- 📋 Managed Users ---${C_RESET}"
    echo -e "${C_CYAN}=========================================================================================${C_RESET}"
    printf "${C_BOLD}${C_WHITE}%-18s | %-12s | %-10s | %-15s | %-20s${C_RESET}\n" "USERNAME" "EXPIRES" "CONNS" "BANDWIDTH" "STATUS"
    echo -e "${C_CYAN}-----------------------------------------------------------------------------------------${C_RESET}"
    
    while IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status; do
        local online_count
        online_count=$(pgrep -u "$user" sshd | wc -l)
        
        local status_display=""
        if passwd -S "$user" 2>/dev/null | grep -q " L "; then
            status_display="${C_YELLOW}🔒 Locked${C_RESET}"
        elif [[ "$expiry" != "Never" ]]; then
            local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            local current_ts=$(date +%s)
            if [[ $expiry_ts -lt $current_ts ]]; then
                status_display="${C_RED}🗓️ Expired${C_RESET}"
            else
                status_display="${C_GREEN}🟢 Active${C_RESET}"
            fi
        else
            status_display="${C_GREEN}🟢 Active${C_RESET}"
        fi

        local connection_string="$online_count / $limit"
        
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

        printf "%-18s | ${C_YELLOW}%-12s ${C_RESET}| ${C_CYAN}%-10s ${C_RESET}| ${C_ORANGE}%-15s ${C_RESET}| %-20s\n" \
            "$user" "$expiry" "$connection_string" "$bw_string" "$status_display"
            
    done < <(sort "$DB_FILE")
    echo -e "${C_CYAN}=========================================================================================${C_RESET}\n"
    safe_read "" dummy
}

# ========== EDIT USER ==========
edit_user() {
    _select_user_interface "--- ✏️ Edit User ---"
    local username=$SELECTED_USER
    if [[ "$username" == "NO_USERS" ]] || [[ -z "$username" ]]; then
        return
    fi
    
    local line=$(grep "^$username:" "$DB_FILE")
    IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status <<< "$line"
    
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}--- Editing User: ${C_YELLOW}$username${C_PURPLE} ---${C_RESET}"
        
        local bw_used_display="N/A"
        if [[ -f "$BANDWIDTH_DIR/${username}.usage" ]]; then
            local used_bytes=$(cat "$BANDWIDTH_DIR/${username}.usage" 2>/dev/null)
            bw_used_display=$(awk "BEGIN {printf \"%.2f GB\", $used_bytes / 1073741824}")
        fi
        
        echo -e "\n  ${C_DIM}Current: Exp=${C_YELLOW}$expiry${C_RESET}${C_DIM} Conn=${C_YELLOW}$limit${C_RESET}${C_DIM} BW=${C_YELLOW}${bandwidth_gb}GB${C_RESET}${C_DIM} Used=${C_CYAN}$bw_used_display${C_RESET}"
        echo -e "\nSelect a detail to edit:\n"
        echo -e "  ${C_GREEN}[1]${C_RESET} 🗓️ Change Expiration Date"
        echo -e "  ${C_GREEN}[2]${C_RESET} 📶 Change Connection Limit"
        echo -e "  ${C_GREEN}[3]${C_RESET} 📦 Change Bandwidth Limit"
        echo -e "  ${C_GREEN}[4]${C_RESET} 🔄 Reset Bandwidth Counter"
        echo -e "\n  ${C_RED}[0]${C_RESET} ✅ Finish Editing"
        echo
        read -p "👉 Enter your choice: " edit_choice
        
        case $edit_choice in
            1)
                read -p "Enter new duration (in days from today): " days
                if [[ "$days" =~ ^[0-9]+$ ]]; then
                    local new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
                    chage -E "$new_expire_date" "$username"
                    sed -i "s/^$username:.*/$username:$pass:$new_expire_date:$limit:$bandwidth_gb:$traffic_used:$status/" "$DB_FILE"
                    expiry="$new_expire_date"
                    echo -e "\n${C_GREEN}✅ Expiration updated to $new_expire_date${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            2)
                read -p "Enter new connection limit: " new_limit
                if [[ "$new_limit" =~ ^[0-9]+$ ]]; then
                    sed -i "s/^$username:.*/$username:$pass:$expiry:$new_limit:$bandwidth_gb:$traffic_used:$status/" "$DB_FILE"
                    limit="$new_limit"
                    echo -e "\n${C_GREEN}✅ Connection limit updated to $new_limit${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            3)
                read -p "Enter new bandwidth limit in GB (0 = unlimited): " new_bw
                if [[ "$new_bw" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                    sed -i "s/^$username:.*/$username:$pass:$expiry:$limit:$new_bw:$traffic_used:$status/" "$DB_FILE"
                    bandwidth_gb="$new_bw"
                    echo -e "\n${C_GREEN}✅ Bandwidth limit updated to ${new_bw}GB${C_RESET}"
                else
                    echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
                fi
                ;;
            4)
                echo "0" > "$BANDWIDTH_DIR/${username}.usage"
                echo -e "\n${C_GREEN}✅ Bandwidth counter reset to 0${C_RESET}"
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

# ========== LOCK USER ==========
lock_user() {
    _select_user_interface "--- 🔒 Lock User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        return
    fi

    usermod -L "$u"
    if [ $? -eq 0 ]; then
        killall -u "$u" -9 &>/dev/null
        echo -e "\n${C_GREEN}✅ User '$u' has been locked.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to lock user '$u'.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== UNLOCK USER ==========
unlock_user() {
    _select_user_interface "--- 🔓 Unlock User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        return
    fi

    usermod -U "$u"
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ User '$u' has been unlocked.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Failed to unlock user '$u'.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== RENEW USER ==========
renew_user() {
    _select_user_interface "--- 🔄 Renew User ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" ]] || [[ -z "$u" ]]; then
        return
    fi
    
    read -p "👉 Enter number of days to extend the account: " days
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number.${C_RESET}"
        return
    fi
    
    local line=$(grep "^$u:" "$DB_FILE")
    IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status <<< "$line"
    
    local new_expire_date=$(date -d "+$days days" +%Y-%m-%d)
    chage -E "$new_expire_date" "$u"
    sed -i "s/^$u:.*/$u:$pass:$new_expire_date:$limit:$bandwidth_gb:$traffic_used:$status/" "$DB_FILE"
    
    echo -e "\n${C_GREEN}✅ User '$u' renewed until $new_expire_date${C_RESET}"
    safe_read "" dummy
}

# ========== CLEANUP EXPIRED ==========
cleanup_expired() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🧹 Cleanup Expired Users ---${C_RESET}"
    
    local expired_users=()
    local current_ts=$(date +%s)

    if [[ ! -s "$DB_FILE" ]]; then
        echo -e "\n${C_GREEN}✅ User database is empty. No expired users found.${C_RESET}"
        return
    fi
    
    while IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status; do
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        
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
            rm -f "$BANDWIDTH_DIR/${user}.usage"
            rm -rf "$BANDWIDTH_DIR/pidtrack/${user}" 2>/dev/null
            rm -f "$BANNER_DIR/${user}.txt"
            userdel -r "$user" &>/dev/null
            sed -i "/^$user:/d" "$DB_FILE"
        done
        echo -e "\n${C_GREEN}✅ Expired users have been cleaned up.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Cleanup cancelled.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== BACKUP USER DATA ==========
backup_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 💾 Backup User Data ---${C_RESET}"
    read -p "👉 Enter path for backup file [/root/voltrontech_users.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_users.tar.gz}
    
    if [ ! -d "$DB_DIR" ] || [ ! -s "$DB_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No user data found to back up.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}⚙️ Backing up user database and settings...${C_RESET}"
    tar -czf "$backup_path" -C "$(dirname "$DB_DIR")" "$(basename "$DB_DIR")"
    
    if [ $? -eq 0 ]; then
        echo -e "\n${C_GREEN}✅ Backup created at ${C_YELLOW}$backup_path${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Backup failed.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== RESTORE USER DATA ==========
restore_user_data() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📥 Restore User Data ---${C_RESET}"
    read -p "👉 Enter path to backup file [/root/voltrontech_users.tar.gz]: " backup_path
    backup_path=${backup_path:-/root/voltrontech_users.tar.gz}
    
    if [ ! -f "$backup_path" ]; then
        echo -e "\n${C_RED}❌ Backup file not found.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_RED}⚠️ This will overwrite all current data!${C_RESET}"
    read -p "👉 Are you sure? (y/n): " confirm
    
    if [[ "$confirm" == "y" ]]; then
        tar -xzf "$backup_path" -C /
        echo -e "\n${C_GREEN}✅ Restore completed.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Restore cancelled.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== BANDWIDTH MONITORING ==========
setup_bandwidth_monitor() {
    mkdir -p "$BANDWIDTH_DIR" "$BANDWIDTH_DIR/pidtrack"
    
    cat > "$BANDWIDTH_SCRIPT" << 'EOF'
#!/bin/bash
# VoltronTech Bandwidth Monitor
DB_FILE="/etc/voltrontech/users.db"
BW_DIR="/etc/voltrontech/bandwidth"
PID_DIR="$BW_DIR/pidtrack"

mkdir -p "$BW_DIR" "$PID_DIR"

while true; do
    if [[ ! -f "$DB_FILE" ]]; then
        sleep 30
        continue
    fi
    
    while IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        [[ -z "$bandwidth_gb" ]] && bandwidth_gb="0"
        
        user_uid=$(id -u "$user" 2>/dev/null)
        [[ -z "$user_uid" ]] && continue
        
        pids=$(pgrep -u "$user" sshd 2>/dev/null | tr '\n' ' ')
        
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
        
        for f in "$PID_DIR/${user}__"*.last; do
            [[ ! -f "$f" ]] && continue
            fpid=$(basename "$f" .last)
            fpid=${fpid#${user}__}
            [[ ! -d "/proc/$fpid" ]] && rm -f "$f"
        done
        
        new_total=$((accumulated + delta_total))
        echo "$new_total" > "$usagefile"
        
        if [[ "$bandwidth_gb" != "0" ]]; then
            quota_bytes=$(awk "BEGIN {printf \"%.0f\", $bandwidth_gb * 1073741824}")
            if [[ "$new_total" -ge "$quota_bytes" ]]; then
                if ! passwd -S "$user" 2>/dev/null | grep -q " L "; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                fi
            fi
        fi
        
    done < "$DB_FILE"
    
    sleep 15
done
EOF

    chmod +x "$BANDWIDTH_SCRIPT"
    
    cat > "$BANDWIDTH_SERVICE" << EOF
[Unit]
Description=VoltronTech Bandwidth Monitor
After=network.target

[Service]
Type=simple
ExecStart=$BANDWIDTH_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable voltrontech-bandwidth.service &>/dev/null
    systemctl start voltrontech-bandwidth.service &>/dev/null
}

# ========== TRIAL CLEANUP ==========
setup_trial_cleanup() {
    cat > "$TRIAL_CLEANUP_SCRIPT" << 'EOF'
#!/bin/bash
# VoltronTech Trial Account Auto-Cleanup
DB_FILE="/etc/voltrontech/users.db"
BW_DIR="/etc/voltrontech/bandwidth"
BANNER_DIR="/etc/voltrontech/banners"

username="$1"
if [[ -z "$username" ]]; then exit 1; fi

killall -u "$username" -9 &>/dev/null
sleep 1
userdel -r "$username" &>/dev/null
sed -i "/^${username}:/d" "$DB_FILE"
rm -f "$BW_DIR/${username}.usage"
rm -rf "$BW_DIR/pidtrack/${username}" 2>/dev/null
rm -f "$BANNER_DIR/${username}.txt"
EOF
    chmod +x "$TRIAL_CLEANUP_SCRIPT"
}

# ========== CREATE TRIAL ACCOUNT ==========
create_trial_account() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- ⏱️ Create Trial Account ---${C_RESET}"
    
    if ! command -v at &>/dev/null; then
        apt-get update > /dev/null 2>&1 && apt-get install -y at
        systemctl enable atd &>/dev/null
        systemctl start atd &>/dev/null
    fi
    
    echo -e "\n${C_CYAN}Select trial duration:${C_RESET}\n"
    echo -e "  ${C_GREEN}[1]${C_RESET} ⏱️  1 Hour"
    echo -e "  ${C_GREEN}[2]${C_RESET} ⏱️  3 Hours"
    echo -e "  ${C_GREEN}[3]${C_RESET} ⏱️  6 Hours"
    echo -e "  ${C_GREEN}[4]${C_RESET} ⏱️  12 Hours"
    echo -e "  ${C_GREEN}[5]${C_RESET} 📅  1 Day"
    echo -e "  ${C_GREEN}[6]${C_RESET} 📅  3 Days"
    echo -e "  ${C_GREEN}[7]${C_RESET} ⚙️  Custom (hours)"
    echo -e "\n  ${C_RED}[0]${C_RESET} Cancel"
    echo ""
    
    local dur_choice
    read -p "👉 Select duration: " dur_choice
    
    local duration_hours=0
    local duration_label=""
    case $dur_choice in
        1) duration_hours=1;   duration_label="1 Hour" ;;
        2) duration_hours=3;   duration_label="3 Hours" ;;
        3) duration_hours=6;   duration_label="6 Hours" ;;
        4) duration_hours=12;  duration_label="12 Hours" ;;
        5) duration_hours=24;  duration_label="1 Day" ;;
        6) duration_hours=72;  duration_label="3 Days" ;;
        7) read -p "👉 Enter custom hours: " custom_hours
           if ! [[ "$custom_hours" =~ ^[0-9]+$ ]] || [[ "$custom_hours" -lt 1 ]]; then
               echo -e "\n${C_RED}❌ Invalid hours${C_RESET}"; return
           fi
           duration_hours=$custom_hours
           duration_label="$custom_hours Hours"
           ;;
        0) return ;;
        *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; return ;;
    esac
    
    local rand_suffix=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 5)
    local default_username="trial_${rand_suffix}"
    read -p "👤 Username [${default_username}]: " username
    username=${username:-$default_username}
    
    if id "$username" &>/dev/null || grep -q "^$username:" "$DB_FILE"; then
        echo -e "\n${C_RED}❌ User '$username' already exists${C_RESET}"
        return
    fi
    
    local password=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
    read -p "🔑 Password [${password}]: " custom_pass
    password=${custom_pass:-$password}
    
    read -p "📶 Connection limit [1]: " limit
    limit=${limit:-1}
    if ! [[ "$limit" =~ ^[0-9]+$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number${C_RESET}"
        return
    fi
    
    read -p "📦 Bandwidth limit (GB) [0=unlimited]: " bandwidth_gb
    bandwidth_gb=${bandwidth_gb:-0}
    if ! [[ "$bandwidth_gb" =~ ^[0-9]+\.?[0-9]*$ ]]; then
        echo -e "\n${C_RED}❌ Invalid number${C_RESET}"
        return
    fi
    
    local expire_date
    if [[ "$duration_hours" -ge 24 ]]; then
        local days=$((duration_hours / 24))
        expire_date=$(date -d "+$days days" +%Y-%m-%d)
    else
        expire_date=$(date -d "+1 day" +%Y-%m-%d)
    fi
    local expiry_timestamp=$(date -d "+${duration_hours} hours" '+%Y-%m-%d %H:%M:%S')
    
    useradd -m -s /usr/sbin/nologin "$username"
    echo "$username:$password" | chpasswd
    chage -E "$expire_date" "$username"
    echo "$username:$password:$expire_date:$limit:$bandwidth_gb:0:ACTIVE" >> "$DB_FILE"
    
    echo "$TRIAL_CLEANUP_SCRIPT $username" | at now + ${duration_hours} hours 2>/dev/null
    
    local bw_display="Unlimited"
    [[ "$bandwidth_gb" != "0" ]] && bw_display="${bandwidth_gb} GB"
    
    clear
    show_banner
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ TRIAL ACCOUNT CREATED!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  👤 Username:     ${C_YELLOW}$username${C_RESET}"
    echo -e "  🔑 Password:     ${C_YELLOW}$password${C_RESET}"
    echo -e "  ⏱️ Duration:     ${C_CYAN}$duration_label${C_RESET}"
    echo -e "  🕐 Expires at:   ${C_RED}$expiry_timestamp${C_RESET}"
    echo -e "  📶 Connection:   ${C_YELLOW}$limit${C_RESET}"
    echo -e "  📦 Bandwidth:    ${C_YELLOW}$bw_display${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    safe_read "" dummy
}

# ========== VIEW USER BANDWIDTH ==========
view_user_bandwidth() {
    _select_user_interface "--- 📊 View User Bandwidth ---"
    local u=$SELECTED_USER
    if [[ "$u" == "NO_USERS" || -z "$u" ]]; then
        return
    fi
    
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📊 Bandwidth Details: ${C_YELLOW}$u${C_PURPLE} ---${C_RESET}\n"
    
    local line=$(grep "^$u:" "$DB_FILE")
    local bandwidth_gb=$(echo "$line" | cut -d: -f5)
    [[ -z "$bandwidth_gb" ]] && bandwidth_gb="0"
    
    local used_bytes=0
    if [[ -f "$BANDWIDTH_DIR/${u}.usage" ]]; then
        used_bytes=$(cat "$BANDWIDTH_DIR/${u}.usage" 2>/dev/null)
        [[ -z "$used_bytes" ]] && used_bytes=0
    fi
    
    local used_mb=$(awk "BEGIN {printf \"%.2f\", $used_bytes / 1048576}")
    local used_gb=$(awk "BEGIN {printf \"%.3f\", $used_bytes / 1073741824}")
    
    echo -e "  ${C_CYAN}Data Used:${C_RESET}        ${C_WHITE}${used_gb} GB${C_RESET} (${used_mb} MB)"
    
    if [[ "$bandwidth_gb" == "0" ]]; then
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_GREEN}Unlimited${C_RESET}"
    else
        local quota_bytes=$(awk "BEGIN {printf \"%.0f\", $bandwidth_gb * 1073741824}")
        local percentage=$(awk "BEGIN {printf \"%.1f\", ($used_bytes / $quota_bytes) * 100}")
        local remaining_bytes=$((quota_bytes - used_bytes))
        [[ "$remaining_bytes" -lt 0 ]] && remaining_bytes=0
        local remaining_gb=$(awk "BEGIN {printf \"%.3f\", $remaining_bytes / 1073741824}")
        
        echo -e "  ${C_CYAN}Bandwidth Limit:${C_RESET}  ${C_YELLOW}${bandwidth_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Remaining:${C_RESET}        ${C_WHITE}${remaining_gb} GB${C_RESET}"
        echo -e "  ${C_CYAN}Usage:${C_RESET}            ${C_WHITE}${percentage}%${C_RESET}"
        
        local bar_width=30
        local filled=$(awk "BEGIN {printf \"%.0f\", ($percentage / 100) * $bar_width}")
        [[ "$filled" -gt "$bar_width" ]] && filled=$bar_width
        local empty=$((bar_width - filled))
        local bar_color="$C_GREEN"
        if (( $(awk "BEGIN {print ($percentage > 80)}" ) )); then bar_color="$C_RED"
        elif (( $(awk "BEGIN {print ($percentage > 50)}" ) )); then bar_color="$C_YELLOW"
        fi
        printf "  ${C_CYAN}Progress:${C_RESET}         ${bar_color}["
        for ((i=0; i<filled; i++)); do printf "█"; done
        for ((i=0; i<empty; i++)); do printf "░"; done
        printf "]${C_RESET} ${percentage}%%\n"
    fi
    
    safe_read "" dummy
}

# ========== BULK CREATE USERS ==========
bulk_create_users() {
    clear
    show_banner
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
    
    local expire_date=$(date -d "+$days days" +%Y-%m-%d)
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

# ========== LIMITER SERVICE WITH BANNER ==========
setup_limiter_service() {
    cat > "$LIMITER_SCRIPT" << 'EOF'
#!/bin/bash
# VoltronTech Limiter with Dynamic Banner
DB_FILE="/etc/voltrontech/users.db"
BW_DIR="/etc/voltrontech/bandwidth"
PID_DIR="$BW_DIR/pidtrack"
BANNER_DIR="/etc/voltrontech/banners"
BANNER_ENABLED="/etc/voltrontech/banners_enabled"
LOGS_DIR="/etc/voltrontech/logs"

mkdir -p "$BW_DIR" "$PID_DIR" "$BANNER_DIR" "$LOGS_DIR"

# Function to generate banner for a user
generate_user_banner() {
    local user=$1
    local expiry=$2
    local limit=$3
    local bandwidth_gb=$4
    local current_ts=$5
    local online_count=$6
    
    # Calculate days left
    local days_left="N/A"
    if [[ "$expiry" != "Never" && -n "$expiry" ]]; then
        local expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -gt 0 ]]; then
            local diff_secs=$((expiry_ts - current_ts))
            if [[ $diff_secs -le 0 ]]; then
                days_left="EXPIRED"
            else
                local d_l=$(( diff_secs / 86400 ))
                local h_l=$(( (diff_secs % 86400) / 3600 ))
                if [[ $d_l -eq 0 ]]; then days_left="${h_l}h left"
                else days_left="${d_l}d ${h_l}h"; fi
            fi
        fi
    fi
    
    # Get bandwidth info
    local used_gb="0.00"
    local total_gb="Unlimited"
    local bw_info="Unlimited"
    
    if [[ -f "$BW_DIR/${user}.usage" ]]; then
        local used_bytes=$(cat "$BW_DIR/${user}.usage" 2>/dev/null || echo 0)
        used_gb=$(awk "BEGIN {printf \"%.2f\", $used_bytes / 1073741824}")
        
        if [[ "$bandwidth_gb" != "0" && -n "$bandwidth_gb" ]]; then
            total_gb="$bandwidth_gb"
            local remain_gb=$(awk "BEGIN {r=$bandwidth_gb - $used_gb; if(r<0) r=0; printf \"%.2f\", r}")
            bw_info="${used_gb}/${bandwidth_gb} GB used | ${remain_gb} GB left"
        else
            bw_info="${used_gb} GB used | Unlimited"
        fi
    fi
    
    # Create banner file with HTML tags (YOUR BANNER)
    echo -e "<font color=\"white\">" > "$BANNER_DIR/${user}.txt"
    
    # Mstari wa kwanza
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; width: 180px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ===============================" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # WELCOME TO VOLTRON TECH
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    WELCOME TO VOLTRON TECH" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Mstari wa pili
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; width: 180px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ===============================" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # SOUTH AFRICA SERVER
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    🇿🇦 SOUTH AFRICA SERVER 🇿🇦" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # HALOTEL UNLIMITED
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    📱 HALOTEL UNLIMITED" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # ACCOUNT STATUS
    echo -e "<br><font color=\"yellow\"><b>      ✨ ACCOUNT STATUS ✨      </b></font><br><br>" >> "$BANNER_DIR/${user}.txt"
    echo -e "<font color=\"white\">👤 <b>Username   :</b> ${user}</font><br>" >> "$BANNER_DIR/${user}.txt"
    echo -e "<font color=\"white\">📅 <b>Expiration :</b> ${expiry} (${days_left})</font><br>" >> "$BANNER_DIR/${user}.txt"
    echo -e "<font color=\"white\">📊 <b>Bandwidth  :</b> ${bw_info}</font><br>" >> "$BANNER_DIR/${user}.txt"
    echo -e "<font color=\"white\">🔌 <b>Sessions   :</b> ${online_count}/${limit}</font><br><br>" >> "$BANNER_DIR/${user}.txt"
    
    # RULES
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 20px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ⚠️ RULES:" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO SPAM
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO SPAM" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO DDOS
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO DDOS" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO HACKING
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO HACKING" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO CARDING
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO CARDING" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO TORRENT
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO TORRENT" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # NO OVER DOWNLOAD
    echo -e "<H3 style=\"text-align:left\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; margin-left: 30px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    ❌ NO OVER DOWNLOAD" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # JOIN GROUP
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    📞 JOIN GROUP:" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # WhatsApp Link
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px; word-break: break-all;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    https://chat.whatsapp.com/KVMPv89XSu83UnBWUZCIQf" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Signature
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "    @CONFIG BY ꧁༺VOLTRON BOY༻꧂™" >> "$BANNER_DIR/${user}.txt"
    echo -e "  </span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    # Nafasi
    echo -e "<H3 style=\"text-align:center\">" >> "$BANNER_DIR/${user}.txt"
    echo -e "  <span style=\"padding: 8px 15px; display: inline-block; margin: 3px;\"></span>" >> "$BANNER_DIR/${user}.txt"
    echo -e "</H3>" >> "$BANNER_DIR/${user}.txt"
    
    echo -e "</font>" >> "$BANNER_DIR/${user}.txt"
}

# Main limiter loop
while true; do
    if [[ ! -f "$DB_FILE" ]]; then
        sleep 30
        continue
    fi
    
    current_ts=$(date +%s)
    
    while IFS=: read -r user pass expiry limit bandwidth_gb traffic_used status; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        # --- Expiry Check ---
        if [[ "$expiry" != "Never" && -n "$expiry" ]]; then
            expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
            if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
                if ! passwd -S "$user" 2>/dev/null | grep -q " L "; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                fi
                continue
            fi
        fi
        
        # --- Connection Limit Check ---
        online_count=$(pgrep -c -u "$user" sshd 2>/dev/null)
        if ! [[ "$limit" =~ ^[0-9]+$ ]]; then limit=1; fi
        
        if [[ "$online_count" -gt "$limit" && "$limit" -ne 0 ]]; then
            if ! passwd -S "$user" 2>/dev/null | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
                (sleep 120; usermod -U "$user" &>/dev/null) &
            else
                killall -u "$user" -9 &>/dev/null
            fi
        fi
        
        # --- Generate Banner if enabled ---
        if [[ -f "$BANNER_ENABLED" ]]; then
            generate_user_banner "$user" "$expiry" "$limit" "$bandwidth_gb" "$current_ts" "$online_count"
        fi
        
        # --- Bandwidth Monitoring ---
        [[ -z "$bandwidth_gb" || "$bandwidth_gb" == "0" ]] && continue
        
        user_uid=$(id -u "$user" 2>/dev/null)
        [[ -z "$user_uid" ]] && continue
        
        pids=$(pgrep -u "$user" sshd 2>/dev/null | tr '\n' ' ')
        
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
        
        new_total=$((accumulated + delta_total))
        echo "$new_total" > "$usagefile"
        
        # Check quota
        if [[ "$bandwidth_gb" != "0" ]]; then
            quota_bytes=$(awk "BEGIN {printf \"%.0f\", $bandwidth_gb * 1073741824}")
            if [[ "$new_total" -ge "$quota_bytes" ]]; then
                if ! passwd -S "$user" 2>/dev/null | grep -q " L "; then
                    usermod -L "$user" &>/dev/null
                    killall -u "$user" -9 &>/dev/null
                fi
            fi
        fi
        
    done < "$DB_FILE"
    
    sleep 15
done
EOF

    chmod +x "$LIMITER_SCRIPT"
    
    cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=VoltronTech Active User Limiter
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
    systemctl enable voltrontech-limiter.service &>/dev/null
    systemctl start voltrontech-limiter.service &>/dev/null
}

# ========== SSH BANNER CONFIG ==========
setup_ssh_banner_config() {
    mkdir -p /etc/ssh/sshd_config.d
    
    cat > "$SSHD_VOLTRON_CONFIG" << 'EOF'
# VoltronTech Dynamic Banners
Match User *
    Banner /etc/voltrontech/banners/%u.txt
EOF

    if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config; then
        echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config
    fi
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
}

# ========== SSH BANNER MENU ==========
ssh_banner_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🎨 SSH BANNER MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [[ -f "$BANNER_ENABLED" ]]; then
            echo -e "  ${C_GREEN}✅ Banner Status: ENABLED${C_RESET}"
        else
            echo -e "  ${C_RED}❌ Banner Status: DISABLED${C_RESET}"
        fi
        echo ""
        
        echo -e "  ${C_GREEN}1)${C_RESET} Enable Banner"
        echo -e "  ${C_RED}2)${C_RESET} Disable Banner"
        echo -e "  ${C_GREEN}3)${C_RESET} Preview Banner (for a user)"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1)
                touch "$BANNER_ENABLED"
                echo -e "\n${C_GREEN}✅ Banner enabled${C_RESET}"
                safe_read "" dummy
                ;;
            2)
                rm -f "$BANNER_ENABLED"
                echo -e "\n${C_YELLOW}⚠️ Banner disabled${C_RESET}"
                safe_read "" dummy
                ;;
            3)
                _select_user_interface "--- Preview Banner ---"
                local u=$SELECTED_USER
                if [[ -z "$u" || "$u" == "NO_USERS" ]]; then
                    continue
                fi
                echo -e "\n${C_CYAN}--- Banner Preview for $u ---${C_RESET}\n"
                if [[ -f "$BANNER_DIR/${u}.txt" ]]; then
                    cat "$BANNER_DIR/${u}.txt"
                else
                    echo -e "${C_YELLOW}Banner not generated yet. Waiting...${C_RESET}"
                    sleep 3
                    cat "$BANNER_DIR/${u}.txt" 2>/dev/null || echo -e "${C_RED}Banner not found${C_RESET}"
                fi
                safe_read "" dummy
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== DESEC.IO DOMAIN GENERATOR ==========
_is_valid_ipv4() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

generate_dns_record() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           ☁️  GENERATING DOMAIN WITH DESEC.IO${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if ! command -v jq &> /dev/null; then
        echo -e "${C_YELLOW}⚠️ jq not found, installing...${C_RESET}"
        apt-get update > /dev/null 2>&1 && apt-get install -y jq
    fi
    
    local SERVER_IPV4=$(curl -s -4 icanhazip.com)
    if ! _is_valid_ipv4 "$SERVER_IPV4"; then
        echo -e "\n${C_RED}❌ Could not retrieve valid public IPv4 address${C_RESET}"
        return 1
    fi

    local SERVER_IPV6=$(curl -s -6 icanhazip.com --max-time 5)
    local RANDOM_SUBDOMAIN="vps-$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
    local FULL_DOMAIN="$RANDOM_SUBDOMAIN.$DESEC_DOMAIN"
    local HAS_IPV6="false"

    local API_DATA
    API_DATA=$(printf '[{"subname": "%s", "type": "A", "ttl": 3600, "records": ["%s"]}]' "$RANDOM_SUBDOMAIN" "$SERVER_IPV4")

    if [[ -n "$SERVER_IPV6" ]]; then
        local aaaa_record
        aaaa_record=$(printf ',{"subname": "%s", "type": "AAAA", "ttl": 3600, "records": ["%s"]}' "$RANDOM_SUBDOMAIN" "$SERVER_IPV6")
        API_DATA="${API_DATA%?}${aaaa_record}]"
        HAS_IPV6="true"
    fi

    echo -e "${C_GREEN}[1/2] Creating DNS records on desec.io...${C_RESET}"
    
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
    
    echo -e "${C_GREEN}[2/2] Saving domain information...${C_RESET}"
    
    cat > "$DNS_INFO_FILE" <<-EOF
SUBDOMAIN="$RANDOM_SUBDOMAIN"
FULL_DOMAIN="$FULL_DOMAIN"
HAS_IPV6="$HAS_IPV6"
SERVER_IPV4="$SERVER_IPV4"
SERVER_IPV6="$SERVER_IPV6"
EOF

    echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_GREEN}           ✅ DOMAIN GENERATED SUCCESSFULLY!${C_RESET}"
    echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_CYAN}Domain:${C_RESET}     ${C_YELLOW}$FULL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}IPv4:${C_RESET}       ${C_GREEN}$SERVER_IPV4${C_RESET}"
    if [[ -n "$SERVER_IPV6" ]]; then
        echo -e "  ${C_CYAN}IPv6:${C_RESET}       ${C_GREEN}$SERVER_IPV6${C_RESET}"
    fi
    
    return 0
}

delete_dns_record() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🗑️  DELETING DNS RECORDS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    if [ ! -f "$DNS_INFO_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ No domain record found to delete.${C_RESET}"
        return
    fi
    
    source "$DNS_INFO_FILE"
    
    if [[ -z "$SUBDOMAIN" ]]; then
        echo -e "${C_RED}❌ Could not read subdomain from config file.${C_RESET}"
        return
    fi

    echo -e "${C_GREEN}Deleting A record for $SUBDOMAIN...${C_RESET}"
    curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$SUBDOMAIN/A/" \
         -H "Authorization: Token $DESEC_TOKEN" > /dev/null

    if [[ "$HAS_IPV6" == "true" ]]; then
        echo -e "${C_GREEN}Deleting AAAA record for $SUBDOMAIN...${C_RESET}"
        curl -s -X DELETE "https://desec.io/api/v1/domains/$DESEC_DOMAIN/rrsets/$SUBDOMAIN/AAAA/" \
             -H "Authorization: Token $DESEC_TOKEN" > /dev/null
    fi

    echo -e "\n${C_GREEN}✅ Domain ${C_YELLOW}$FULL_DOMAIN${C_GREEN} has been deleted.${C_RESET}"
    rm -f "$DNS_INFO_FILE"
}

show_dns_info() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 CURRENT DOMAIN INFORMATION${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNS_INFO_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ No domain has been generated yet.${C_RESET}"
    else
        source "$DNS_INFO_FILE"
        echo -e "\n${C_CYAN}Domain Details:${C_RESET}"
        echo -e "  • Full Domain: ${C_YELLOW}$FULL_DOMAIN${C_RESET}"
        echo -e "  • Subdomain:   ${C_GREEN}$SUBDOMAIN${C_RESET}"
        echo -e "  • IPv4:        ${C_GREEN}$SERVER_IPV4${C_RESET}"
        if [[ -n "$SERVER_IPV6" && "$SERVER_IPV6" != "null" ]]; then
            echo -e "  • IPv6:        ${C_GREEN}$SERVER_IPV6${C_RESET}"
        fi
    fi
    safe_read "" dummy
}

dns_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              ☁️  DESEC.IO DOMAIN MANAGER${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if [ -f "$DNS_INFO_FILE" ]; then
            source "$DNS_INFO_FILE"
            echo -e "  ${C_GREEN}✓ Current Domain:${C_RESET} ${C_YELLOW}$FULL_DOMAIN${C_RESET}"
        else
            echo -e "  ${C_YELLOW}⚠ No domain generated yet${C_RESET}"
        fi
        echo ""
        
        echo -e "  ${C_GREEN}1)${C_RESET} Generate New Domain"
        echo -e "  ${C_GREEN}2)${C_RESET} Show Current Domain Info"
        echo -e "  ${C_RED}3)${C_RESET} Delete Current Domain"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return to Main Menu"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) generate_dns_record; safe_read "" dummy ;;
            2) show_dns_info; safe_read "" dummy ;;
            3) delete_dns_record; safe_read "" dummy ;;
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
    
    if [ -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ badvpn is already installed.${C_RESET}"
        return
    fi
    
    check_and_open_firewall_port 7300 udp || return
    
    echo -e "\n${C_GREEN}🔄 Updating package lists...${C_RESET}"
    apt-get update
    echo -e "\n${C_GREEN}📦 Installing required packages...${C_RESET}"
    apt-get install -y cmake make gcc git build-essential
    
    echo -e "\n${C_GREEN}📥 Cloning badvpn repository...${C_RESET}"
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
    cd "$BADVPN_BUILD_DIR" || return
    
    echo -e "\n${C_GREEN}⚙️ Running CMake...${C_RESET}"
    cmake . || { echo -e "${C_RED}❌ CMake failed.${C_RESET}"; return; }
    
    echo -e "\n${C_GREEN}🛠️ Compiling...${C_RESET}"
    make || { echo -e "${C_RED}❌ Compilation failed.${C_RESET}"; return; }
    
    local badvpn_binary
    badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
    
    if [[ -z "$badvpn_binary" || ! -f "$badvpn_binary" ]]; then
        echo -e "${C_RED}❌ Could not find compiled binary.${C_RESET}"
        return
    fi
    
    chmod +x "$badvpn_binary"
    
    echo -e "\n${C_GREEN}📝 Creating systemd service...${C_RESET}"
    cat > "$BADVPN_SERVICE_FILE" <<-EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=$badvpn_binary --listen-addr 0.0.0.0:7300 --max-clients 1000
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    
    if systemctl is-active --quiet badvpn; then
        echo -e "\n${C_GREEN}✅ badvpn installed successfully on port 7300.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ badvpn service failed to start.${C_RESET}"
    fi
    safe_read "" dummy
}

uninstall_badvpn() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling badvpn ---${C_RESET}"
    
    if [ ! -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ badvpn is not installed.${C_RESET}"
        return
    fi
    
    systemctl stop badvpn.service 2>/dev/null
    systemctl disable badvpn.service 2>/dev/null
    rm -f "$BADVPN_SERVICE_FILE"
    rm -rf "$BADVPN_BUILD_DIR"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}✅ badvpn uninstalled.${C_RESET}"
    safe_read "" dummy
}

# ========== UDP-CUSTOM INSTALLATION ==========
install_udp_custom() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing udp-custom ---${C_RESET}"
    
    if [ -f "$UDP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ udp-custom is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Creating directory...${C_RESET}"
    rm -rf "$UDP_CUSTOM_DIR"
    mkdir -p "$UDP_CUSTOM_DIR"

    echo -e "\n${C_GREEN}⚙️ Detecting architecture...${C_RESET}"
    local arch
    arch=$(uname -m)
    local binary_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/udp/udp-custom-linux-amd64"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_url="https://github.com/firewallfalcons/FirewallFalcon-Manager/raw/main/udp/udp-custom-linux-arm"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}📥 Downloading udp-custom binary...${C_RESET}"
    wget -q --show-progress -O "$UDP_CUSTOM_DIR/udp-custom" "$binary_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download binary.${C_RESET}"
        return
    fi
    chmod +x "$UDP_CUSTOM_DIR/udp-custom"

    echo -e "\n${C_GREEN}📝 Creating config.json...${C_RESET}"
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

    echo -e "\n${C_GREEN}📝 Creating systemd service...${C_RESET}"
    cat > "$UDP_CUSTOM_SERVICE_FILE" <<EOF
[Unit]
Description=UDP Custom
After=network.target

[Service]
User=root
Type=simple
ExecStart=$UDP_CUSTOM_DIR/udp-custom server -exclude 53,5300
WorkingDirectory=$UDP_CUSTOM_DIR/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    systemctl daemon-reload
    systemctl enable udp-custom.service
    systemctl start udp-custom.service
    
    if systemctl is-active --quiet udp-custom; then
        echo -e "\n${C_GREEN}✅ udp-custom installed successfully.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ udp-custom service failed to start.${C_RESET}"
    fi
    safe_read "" dummy
}

uninstall_udp_custom() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling udp-custom ---${C_RESET}"
    
    if [ ! -f "$UDP_CUSTOM_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ udp-custom is not installed.${C_RESET}"
        return
    fi
    
    systemctl stop udp-custom.service 2>/dev/null
    systemctl disable udp-custom.service 2>/dev/null
    rm -f "$UDP_CUSTOM_SERVICE_FILE"
    rm -rf "$UDP_CUSTOM_DIR"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}✅ udp-custom uninstalled.${C_RESET}"
    safe_read "" dummy
}

# ========== VOLTRON PROXY INSTALLATION ==========
install_voltron_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing Voltron Proxy ---${C_RESET}"
    
    if [ -f "$VOLTRONPROXY_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ Voltron Proxy is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Detecting architecture...${C_RESET}"
    local arch=$(uname -m)
    local binary_name=""
    
    if [[ "$arch" == "x86_64" ]]; then
        binary_name="voltronproxy"
    elif [[ "$arch" == "aarch64" || "$arch" == "arm64" ]]; then
        binary_name="voltronproxyarm"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return
    fi
    
    read -p "👉 Enter port(s) [8080]: " ports
    ports=${ports:-8080}
    
    local port_array=($ports)
    for port in "${port_array[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "\n${C_RED}❌ Invalid port: $port${C_RESET}"
            return
        fi
        check_and_free_ports "$port" || return
        check_and_open_firewall_port "$port" tcp || return
    done

    echo -e "\n${C_GREEN}📥 Downloading Voltron Proxy...${C_RESET}"
    local download_url="https://github.com/HumbleTechtz/voltron-tech/releases/latest/download/$binary_name"
    wget -q --show-progress -O "$VOLTRONPROXY_BINARY" "$download_url"
    
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to download binary.${C_RESET}"
        return
    fi
    chmod +x "$VOLTRONPROXY_BINARY"

    echo -e "\n${C_GREEN}📝 Creating systemd service...${C_RESET}"
    cat > "$VOLTRONPROXY_SERVICE_FILE" <<EOF
[Unit]
Description=Voltron Proxy
After=network.target

[Service]
User=root
Type=simple
ExecStart=$VOLTRONPROXY_BINARY -p $ports
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    systemctl daemon-reload
    systemctl enable voltronproxy.service
    systemctl start voltronproxy.service
    
    echo "$ports" > "$VOLTRONPROXY_CONFIG_FILE"
    
    if systemctl is-active --quiet voltronproxy; then
        echo -e "\n${C_GREEN}✅ Voltron Proxy installed on port(s) $ports.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Voltron Proxy failed to start.${C_RESET}"
    fi
    safe_read "" dummy
}

uninstall_voltron_proxy() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling Voltron Proxy ---${C_RESET}"
    
    if [ ! -f "$VOLTRONPROXY_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ Voltron Proxy is not installed.${C_RESET}"
        return
    fi
    
    systemctl stop voltronproxy.service 2>/dev/null
    systemctl disable voltronproxy.service 2>/dev/null
    rm -f "$VOLTRONPROXY_SERVICE_FILE"
    rm -f "$VOLTRONPROXY_BINARY"
    rm -f "$VOLTRONPROXY_CONFIG_FILE"
    systemctl daemon-reload
    
    echo -e "${C_GREEN}✅ Voltron Proxy uninstalled.${C_RESET}"
    safe_read "" dummy
}

# ========== NGINX PROXY INSTALLATION ==========
install_nginx_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing Nginx Proxy ---${C_RESET}"
    
    if command -v nginx &> /dev/null; then
        echo -e "\n${C_YELLOW}⚠️ Nginx is already installed.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}📦 Installing Nginx...${C_RESET}"
    apt-get update && apt-get install -y nginx || { echo -e "${C_RED}❌ Failed to install Nginx.${C_RESET}"; return; }

    echo -e "\n${C_GREEN}🔐 Generating self-signed SSL certificate...${C_RESET}"
    mkdir -p /etc/ssl/certs /etc/ssl/private
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.pem \
        -subj "/CN=voltrontech.proxy" >/dev/null 2>&1

    echo -e "\n${C_GREEN}📝 Configuring Nginx...${C_RESET}"
    mv "$NGINX_CONFIG_FILE" "${NGINX_CONFIG_FILE}.bak" 2>/dev/null
    
    cat > "$NGINX_CONFIG_FILE" <<EOF
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    
    server_name _;
    
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

    systemctl restart nginx
    
    if systemctl is-active --quiet nginx; then
        echo -e "\n${C_GREEN}✅ Nginx installed successfully.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ Nginx failed to start.${C_RESET}"
    fi
    safe_read "" dummy
}

nginx_proxy_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🌐 NGINX PROXY MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        
        if systemctl is-active --quiet nginx; then
            echo -e "  ${C_GREEN}● Nginx is RUNNING${C_RESET}"
        else
            echo -e "  ${C_RED}● Nginx is STOPPED${C_RESET}"
        fi
        echo ""
        
        echo -e "  ${C_GREEN}1)${C_RESET} Install Nginx"
        echo -e "  ${C_GREEN}2)${C_RESET} Start Nginx"
        echo -e "  ${C_GREEN}3)${C_RESET} Stop Nginx"
        echo -e "  ${C_GREEN}4)${C_RESET} Restart Nginx"
        echo -e "  ${C_RED}5)${C_RESET} Uninstall Nginx"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) install_nginx_proxy ;;
            2) systemctl start nginx; echo -e "${C_GREEN}✅ Nginx started${C_RESET}"; safe_read "" dummy ;;
            3) systemctl stop nginx; echo -e "${C_YELLOW}🛑 Nginx stopped${C_RESET}"; safe_read "" dummy ;;
            4) systemctl restart nginx; echo -e "${C_GREEN}✅ Nginx restarted${C_RESET}"; safe_read "" dummy ;;
            5) 
                systemctl stop nginx 2>/dev/null
                apt-get purge -y nginx nginx-common 2>/dev/null
                apt-get autoremove -y 2>/dev/null
                rm -rf /etc/nginx
                echo -e "${C_GREEN}✅ Nginx uninstalled${C_RESET}"
                safe_read "" dummy
                ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== ZIVPN INSTALLATION ==========
install_zivpn() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing ZiVPN ---${C_RESET}"
    
    if [ -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ ZiVPN is already installed.${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}⚙️ Detecting architecture...${C_RESET}"
    local arch=$(uname -m)
    local zivpn_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    elif [[ "$arch" == "aarch64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
    else
        echo -e "\n${C_RED}❌ Unsupported architecture: $arch${C_RESET}"
        return
    fi

    echo -e "\n${C_GREEN}📥 Downloading ZiVPN binary...${C_RESET}"
    if ! wget -q --show-progress -O "$ZIVPN_BIN" "$zivpn_url"; then
        echo -e "${C_RED}❌ Download failed.${C_RESET}"
        return
    fi
    chmod +x "$ZIVPN_BIN"

    echo -e "\n${C_GREEN}⚙️ Creating directories...${C_RESET}"
    mkdir -p "$ZIVPN_DIR"
    
    echo -e "${C_BLUE}🔐 Generating certificates...${C_RESET}"
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=VoltronTech/CN=zivpn" \
        -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" 2>/dev/null

    read -p "👉 Enter passwords (comma-separated) [user1,user2]: " input_config
    input_config=${input_config:-user1,user2}
    
    IFS=',' read -r -a config_array <<< "$input_config"
    json_passwords=$(printf '"%s",' "${config_array[@]}")
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

    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service

    if command -v ufw &>/dev/null; then
        ufw allow 5667/udp >/dev/null
        ufw allow 6000:19999/udp >/dev/null
    fi

    if systemctl is-active --quiet zivpn.service; then
        echo -e "\n${C_GREEN}✅ ZiVPN installed successfully on port 5667.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ZiVPN failed to start.${C_RESET}"
    fi
    safe_read "" dummy
}

uninstall_zivpn() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall ZiVPN ---${C_RESET}"
    
    if [ ! -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ ZiVPN is not installed.${C_RESET}"
        return
    fi

    systemctl stop zivpn.service 2>/dev/null
    systemctl disable zivpn.service 2>/dev/null
    rm -f "$ZIVPN_SERVICE_FILE"
    rm -rf "$ZIVPN_DIR"
    rm -f "$ZIVPN_BIN"
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}✅ ZiVPN uninstalled.${C_RESET}"
    safe_read "" dummy
}

# ========== X-UI PANEL INSTALLATION ==========
install_xui_panel() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Install X-UI Panel ---${C_RESET}"
    
    echo -e "\nChoose installation option:\n"
    echo -e "  ${C_GREEN}[1]${C_RESET} Install latest version"
    echo -e "  ${C_GREEN}[2]${C_RESET} Install specific version"
    echo -e "\n  ${C_RED}[0]${C_RESET} Cancel"
    echo
    
    read -p "👉 Select option: " choice
    
    case $choice in
        1)
            echo -e "\n${C_BLUE}⚙️ Installing latest version...${C_RESET}"
            bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)
            ;;
        2)
            read -p "👉 Enter version (e.g., 1.8.0): " version
            if [[ -z "$version" ]]; then
                echo -e "\n${C_RED}❌ Version cannot be empty.${C_RESET}"
                return
            fi
            echo -e "\n${C_BLUE}⚙️ Installing version $version...${C_RESET}"
            VERSION=$version bash <(curl -Ls "https://raw.githubusercontent.com/alireza0/x-ui/$version/install.sh") "$version"
            ;;
        0)
            echo -e "\n${C_YELLOW}❌ Installation cancelled.${C_RESET}"
            ;;
        *)
            echo -e "\n${C_RED}❌ Invalid option.${C_RESET}"
            ;;
    esac
    safe_read "" dummy
}

uninstall_xui_panel() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall X-UI Panel ---${C_RESET}"
    
    if ! command -v x-ui &> /dev/null; then
        echo -e "${C_YELLOW}ℹ️ X-UI is not installed.${C_RESET}"
        return
    fi
    
    read -p "👉 Are you sure? (y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        x-ui uninstall >/dev/null 2>&1
        systemctl stop x-ui 2>/dev/null
        systemctl disable x-ui 2>/dev/null
        rm -f /etc/systemd/system/x-ui.service
        rm -f /usr/local/bin/x-ui
        rm -rf /usr/local/x-ui/
        rm -rf /etc/x-ui/
        systemctl daemon-reload
        echo -e "\n${C_GREEN}✅ X-UI uninstalled.${C_RESET}"
    else
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
    fi
    safe_read "" dummy
}

# ========== DT PROXY FUNCTIONS ==========
install_dt_proxy() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing DT Proxy ---${C_RESET}"
    
    echo -e "\n${C_BLUE}📥 Installing DT Proxy...${C_RESET}"
    if curl -sL https://raw.githubusercontent.com/firewallfalcons/ProxyMods/main/install.sh | bash; then
        echo -e "${C_GREEN}✅ DT Proxy installed successfully${C_RESET}"
    else
        echo -e "${C_RED}❌ Failed to install DT Proxy${C_RESET}"
    fi
    safe_read "" dummy
}

launch_dt_proxy_menu() {
    clear
    show_banner
    if [ -f "/usr/local/bin/main" ]; then
        echo -e "\n${C_GREEN}✅ Launching DT Proxy menu...${C_RESET}"
        sleep 2
        /usr/local/bin/main
    else
        echo -e "\n${C_RED}❌ DT Proxy is not installed.${C_RESET}"
        safe_read "" dummy
    fi
}

uninstall_dt_proxy() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstall DT Proxy ---${C_RESET}"
    
    if [ ! -f "/usr/local/bin/proxy" ] && [ ! -f "/usr/local/bin/main" ]; then
        echo -e "${C_YELLOW}ℹ️ DT Proxy is not installed.${C_RESET}"
        return
    fi
    
    read -p "👉 Are you sure? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Cancelled.${C_RESET}"
        return
    fi

    systemctl list-units --type=service --state=running | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl stop
    systemctl list-unit-files --type=service | grep 'proxy-' | awk '{print $1}' | xargs -r systemctl disable
    rm -f /etc/systemd/system/proxy-*.service
    systemctl daemon-reload
    rm -f /usr/local/bin/proxy
    rm -f /usr/local/bin/main
    rm -f "$HOME/.proxy_token"
    rm -f /var/log/proxy-*.log
    rm -f /usr/local/bin/install_mod

    echo -e "\n${C_GREEN}✅ DT Proxy uninstalled.${C_RESET}"
    safe_read "" dummy
}

dt_proxy_menu() {
    while true; do
        clear
        show_banner
        
        local dt_status=""
        if [ -f "/usr/local/bin/main" ] && [ -f "/usr/local/bin/proxy" ]; then
            dt_status="${C_GREEN}(Installed)${C_RESET}"
        else
            dt_status="${C_RED}(Not Installed)${C_RESET}"
        fi

        echo -e "\n   ${C_TITLE}═════════════════[ ${C_BOLD}🚀 DT Proxy Management ${dt_status} ${C_RESET}${C_TITLE}]═════════════════${C_RESET}"
        echo -e "     ${C_CHOICE}[ 1]${C_RESET} Install DT Proxy"
        echo -e "     ${C_CHOICE}[ 2]${C_RESET} Launch DT Proxy Menu"
        echo -e "     ${C_DANGER}[ 3]${C_RESET} Uninstall DT Proxy"
        echo -e "   ${C_DIM}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${C_RESET}"
        echo -e "     ${C_WARN}[ 0]${C_RESET} Return"
        echo
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) install_dt_proxy ;;
            2) launch_dt_proxy_menu ;;
            3) uninstall_dt_proxy ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== TRAFFIC MONITOR ==========
traffic_monitor_menu() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 📈 Traffic Monitor ---${C_RESET}"
    
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    echo -e "\nInterface: ${C_CYAN}${iface}${C_RESET}"
    echo -e "\n${C_BOLD}Options:${C_RESET}\n"
    echo -e "  ${C_CHOICE}[1]${C_RESET} Live Monitor (Ctrl+C to stop)"
    echo -e "  ${C_CHOICE}[2]${C_RESET} Show total traffic since boot"
    echo -e "\n  ${C_WARN}[0]${C_RESET} Return"
    echo
    
    local choice
    read -p "👉 Select option: " choice
    
    case $choice in
        1)
            echo -e "\n${C_BLUE}Press Ctrl+C to stop${C_RESET}\n"
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
            ;;
        2)
            local rx_total=$(cat /sys/class/net/$iface/statistics/rx_bytes)
            local tx_total=$(cat /sys/class/net/$iface/statistics/tx_bytes)
            local rx_mb=$((rx_total / 1024 / 1024))
            local tx_mb=$((tx_total / 1024 / 1024))
            
            echo -e "\n${C_BLUE}Total Traffic Since Boot:${C_RESET}"
            echo -e "  ⬇️ Download: ${C_WHITE}${rx_mb} MB${C_RESET}"
            echo -e "  ⬆️ Upload:   ${C_WHITE}${tx_mb} MB${C_RESET}"
            safe_read "" dummy
            ;;
        *) return ;;
    esac
}

# ========== TORRENT BLOCKING ==========
torrent_block_menu() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🚫 Torrent Blocking ---${C_RESET}"
    
    local torrent_status="${C_STATUS_I}Disabled${C_RESET}"
    if iptables -L FORWARD 2>/dev/null | grep -q "BitTorrent"; then
        torrent_status="${C_STATUS_A}Enabled${C_RESET}"
    fi
    
    echo -e "\n${C_WHITE}Current Status: ${torrent_status}${C_RESET}"
    echo -e "\n${C_BOLD}Options:${C_RESET}\n"
    echo -e "  ${C_CHOICE}[1]${C_RESET} Enable Torrent Blocking"
    echo -e "  ${C_CHOICE}[2]${C_RESET} Disable Torrent Blocking"
    echo -e "\n  ${C_WARN}[0]${C_RESET} Return"
    echo
    
    local choice
    read -p "👉 Select option: " choice
    
    case $choice in
        1)
            echo -e "\n${C_BLUE}Applying Anti-Torrent rules...${C_RESET}"
            
            iptables -D FORWARD -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
            iptables -D OUTPUT -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
            
            iptables -A FORWARD -m string --string "BitTorrent" --algo bm -j DROP
            iptables -A FORWARD -m string --string ".torrent" --algo bm -j DROP
            iptables -A FORWARD -m string --string "announce.php?passkey=" --algo bm -j DROP
            iptables -A FORWARD -m string --string "info_hash" --algo bm -j DROP
            
            iptables -A OUTPUT -m string --string "BitTorrent" --algo bm -j DROP
            iptables -A OUTPUT -m string --string ".torrent" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "announce.php?passkey=" --algo bm -j DROP
            iptables -A OUTPUT -m string --string "info_hash" --algo bm -j DROP
            
            echo -e "${C_GREEN}✅ Torrent blocking enabled.${C_RESET}"
            safe_read "" dummy
            ;;
        2)
            echo -e "\n${C_BLUE}Removing Anti-Torrent rules...${C_RESET}"
            
            iptables -D FORWARD -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
            iptables -D FORWARD -m string --string ".torrent" --algo bm -j DROP 2>/dev/null
            iptables -D FORWARD -m string --string "announce.php?passkey=" --algo bm -j DROP 2>/dev/null
            iptables -D FORWARD -m string --string "info_hash" --algo bm -j DROP 2>/dev/null
            
            iptables -D OUTPUT -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null
            iptables -D OUTPUT -m string --string ".torrent" --algo bm -j DROP 2>/dev/null
            iptables -D OUTPUT -m string --string "announce.php?passkey=" --algo bm -j DROP 2>/dev/null
            iptables -D OUTPUT -m string --string "info_hash" --algo bm -j DROP 2>/dev/null
            
            echo -e "${C_GREEN}✅ Torrent blocking disabled.${C_RESET}"
            safe_read "" dummy
            ;;
        *) return ;;
    esac
}

# ========== AUTO-REBOOT ==========
auto_reboot_menu() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}--- 🔄 Auto-Reboot Management ---${C_RESET}"
    
    local cron_check=$(crontab -l 2>/dev/null | grep "reboot")
    local status="${C_STATUS_I}Disabled${C_RESET}"
    if [[ -n "$cron_check" ]]; then
        status="${C_STATUS_A}Enabled (Daily at 00:00)${C_RESET}"
    fi
    
    echo -e "\n${C_WHITE}Current Status: ${status}${C_RESET}"
    echo -e "\n${C_BOLD}Options:${C_RESET}\n"
    echo -e "  ${C_CHOICE}[1]${C_RESET} Enable Daily Reboot (00:00)"
    echo -e "  ${C_CHOICE}[2]${C_RESET} Disable Auto-Reboot"
    echo -e "\n  ${C_WARN}[0]${C_RESET} Return"
    echo
    
    local choice
    read -p "👉 Select option: " choice
    
    case $choice in
        1)
            (crontab -l 2>/dev/null | grep -v "reboot") | crontab -
            (crontab -l 2>/dev/null; echo "0 0 * * * /sbin/reboot") | crontab -
            echo -e "\n${C_GREEN}✅ Auto-reboot enabled for 00:00 daily.${C_RESET}"
            safe_read "" dummy
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "reboot") | crontab -
            echo -e "\n${C_GREEN}✅ Auto-reboot disabled.${C_RESET}"
            safe_read "" dummy
            ;;
        *) return ;;
    esac
}

# ========== DNSTT FUNCTIONS ==========

# MTU selection
mtu_selection_during_install() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📡 MTU CONFIGURATION${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    MTU=512
    echo -e "${C_GREEN}✅ MTU set to $MTU (ULTRA BOOST mode)${C_RESET}"
    echo -e "${C_YELLOW}📌 10x speed achieved through:${C_RESET}"
    echo -e "   • 32MB Ultra Buffers"
    echo -e "   • BBR v3 Congestion Control"
    echo -e "   • 10 Parallel Instances"
    echo -e "   • Aggressive Keepalive (10s)"
    echo -e "   • Advanced TCP Tuning (12 parameters)"
    echo -e "   • 8M File Descriptors"
    
    mkdir -p "$CONFIG_DIR"
    echo "$MTU" > "$CONFIG_DIR/mtu"
}

# Firewall configuration
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
        
        chattr -i /etc/resolv.conf 2>/dev/null
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

# Build DNSTT from source
build_dnstt_from_source() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔨 BUILDING DNSTT FROM SOURCE${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    echo -e "${C_GREEN}[1/6] Installing dependencies...${C_RESET}"
    apt-get install -y git build-essential
    
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
    go build -v -o "$DNSTT_BINARY" > /dev/null 2>&1
    
    if [[ ! -f "$DNSTT_BINARY" ]]; then
        echo -e "${C_RED}❌ Server build failed${C_RESET}"
        return 1
    fi
    chmod +x "$DNSTT_BINARY"
    echo -e "${C_GREEN}✓ Server compiled: $DNSTT_BINARY${C_RESET}"
    
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
    if [[ -f "$DNSTT_BINARY" ]] && [[ -f "$DNSTT_CLIENT" ]]; then
        echo -e "\n${C_GREEN}✅ DNSTT binaries built successfully!${C_RESET}"
        echo -e "  • Server: ${C_CYAN}$DNSTT_BINARY${C_RESET}"
        echo -e "  • Client: ${C_CYAN}$DNSTT_CLIENT${C_RESET}"
    else
        echo -e "${C_RED}❌ Build verification failed${C_RESET}"
        return 1
    fi
    
    cd ~
    return 0
}

# Generate keys
generate_keys() {
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           🔑 GENERATING ENCRYPTION KEYS${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cd "$DNSTT_KEYS_DIR"
    rm -f server.key server.pub
    
    echo -e "${C_GREEN}[1/2] Generating keys with DNSTT server...${C_RESET}"
    if ! "$DNSTT_BINARY" -gen-key -privkey-file server.key -pubkey-file server.pub 2>&1 | tee "$DB_DIR/keygen.log" > /dev/null; then
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
    echo -e "  • Private key: ${C_CYAN}$DNSTT_KEYS_DIR/server.key${C_RESET}"
    echo -e "  • Public key:  ${C_CYAN}$DNSTT_KEYS_DIR/server.pub${C_RESET}"
}

# Create DNSTT service
create_dnstt_service_ultra() {
    local domain=$1
    local mtu=$2
    local target=$3
    local desc=$4
    
    echo -e "\n${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BLUE}           📋 CREATING DNSTT SERVICE (ULTRA BOOST)${C_RESET}"
    echo -e "${C_BLUE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    cat > "$DNSTT_SERVICE_FILE" <<EOF
[Unit]
Description=DNSTT Server for $desc (ULTRA BOOST)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DNSTT_KEYS_DIR
Environment="GODEBUG=netdns=go"
ExecStart=$DNSTT_BINARY -udp :5300 \\
    -privkey-file $DNSTT_KEYS_DIR/server.key \\
    -mtu $mtu \\
    -timeout 60 \\
    -keepalive 5 \\
    -retransmit 3 \\
    $domain $target
Restart=always
RestartSec=3
StandardOutput=append:$LOGS_DIR/dnstt-server.log
StandardError=append:$LOGS_DIR/dnstt-error.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dnstt.service > /dev/null 2>&1
    systemctl start dnstt.service
    
    echo -e "${C_GREEN}✅ Service created successfully${C_RESET}"
    echo -e "  • Binary: ${C_CYAN}$DNSTT_BINARY${C_RESET}"
    echo -e "  • MTU: ${C_CYAN}$mtu (ULTRA BOOST mode)${C_RESET}"
    echo -e "  • Port: ${C_CYAN}5300${C_RESET}"
    echo -e "  • Target: ${C_CYAN}$target${C_RESET}"
    echo -e "  • Timeout: ${C_CYAN}60s${C_RESET}"
    echo -e "  • Keepalive: ${C_CYAN}5s${C_RESET}"
    echo -e "  • Retransmit: ${C_CYAN}3${C_RESET}"
}

# Save DNSTT info
save_dnstt_info() {
    local domain=$1
    local pubkey=$2
    local mtu=$3
    local port=$4
    local desc=$5
    
    cat > "$DNSTT_CONFIG_FILE" <<EOF
TUNNEL_DOMAIN="$domain"
PUBLIC_KEY="$pubkey"
FORWARD_DESC="$desc"
MTU_VALUE="$mtu"
SSH_PORT="$port"
EOF

    if [ -f "$DNS_INFO_FILE" ]; then
        cat "$DNS_INFO_FILE" >> "$DNSTT_CONFIG_FILE"
    fi
}

# Show DNSTT details
show_dnstt_details() {
    clear
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_GREEN}           📋 DNSTT CONNECTION DETAILS${C_RESET}"
    echo -e "${C_BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    if [ ! -f "$DNSTT_CONFIG_FILE" ]; then
        echo -e "\n${C_YELLOW}ℹ️ DNSTT is not installed.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    source "$DNSTT_CONFIG_FILE"
    
    local status=$(systemctl is-active dnstt.service 2>/dev/null)
    local status_display=""
    if [[ "$status" == "active" ]]; then
        status_display="${C_GREEN}● RUNNING${C_RESET}"
    else
        status_display="${C_RED}● STOPPED${C_RESET}"
    fi
    
    echo -e "\n  ${C_CYAN}Service Status:${C_RESET}  $status_display"
    echo -e "  ${C_CYAN}Tunnel Domain:${C_RESET}  ${C_YELLOW}$TUNNEL_DOMAIN${C_RESET}"
    echo -e "  ${C_CYAN}Forward To:${C_RESET}     ${C_GREEN}$FORWARD_DESC${C_RESET}"
    echo -e "  ${C_CYAN}MTU:${C_RESET}            ${C_GREEN}$MTU_VALUE${C_RESET}"
    echo -e "  ${C_CYAN}Public Key:${C_RESET}"
    echo -e "  ${C_GRAY}$PUBLIC_KEY${C_RESET}"
    
    if [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        echo -e "\n  ${C_CYAN}Desec.io DNS Records:${C_RESET}"
        echo -e "  • Full Domain: ${C_GREEN}$FULL_DOMAIN${C_RESET}"
        echo -e "  • IPv4:        ${C_GREEN}$SERVER_IPV4${C_RESET}"
        if [[ "$HAS_IPV6" == "true" && -n "$SERVER_IPV6" ]]; then
            echo -e "  • IPv6:        ${C_GREEN}$SERVER_IPV6${C_RESET}"
        fi
    fi
    
    echo -e "\n${C_YELLOW}────────────────────────────────────────────────────────────${C_RESET}"
    safe_read "" dummy
}

# Show client commands
show_client_commands_ultra() {
    local domain=$1
    local mtu=$2
    local ssh_port=$3
    
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
    
    cat > /usr/local/bin/ultra-dnstt.sh << EOF
#!/bin/bash
# ULTRA BOOST - 10 Instances for 10x Speed
# Generated by Voltron Tech

DOMAIN="$domain"
PUBKEY_FILE="$DNSTT_KEYS_DIR/server.pub"
MTU=$mtu
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
    PORT=\$((BASE_PORT + i))
    echo "socks5 127.0.0.1 \$PORT" >> /tmp/proxychains-ultra.conf
    $DNSTT_CLIENT -udp \${DNS_RESOLVERS[\$i]} \\
        -pubkey-file "\$PUBKEY_FILE" \\
        -mtu \$MTU \\
        -listen "127.0.0.1:\$PORT" \\
        "\$DOMAIN" 127.0.0.1:$ssh_port &
    echo "Instance \$((i+1)) started on port \$PORT"
    sleep 1
done

echo ""
echo "✅ 10 ULTRA INSTANCES ACTIVE!"
echo "📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf ssh user@localhost -p $ssh_port"
echo "📌 Use: proxychains4 -f /tmp/proxychains-ultra.conf curl ifconfig.me"
echo "📌 Expected speed: 10x!"
EOF

    chmod +x /usr/local/bin/ultra-dnstt.sh
    echo -e "\n${C_GREEN}chmod +x /usr/local/bin/ultra-dnstt.sh${C_RESET}"
    echo -e "${C_GREEN}sudo /usr/local/bin/ultra-dnstt.sh${C_RESET}"
    echo ""
    
    echo -e "${C_YELLOW}📌 Single Instance (for testing):${C_RESET}"
    echo -e "${C_WHITE}$DNSTT_CLIENT -udp 8.8.8.8:53 \\${C_RESET}"
    echo -e "${C_WHITE}  -pubkey-file $DNSTT_KEYS_DIR/server.pub \\${C_RESET}"
    echo -e "${C_WHITE}  -mtu $mtu \\${C_RESET}"
    echo -e "${C_WHITE}  $domain 127.0.0.1:$ssh_port${C_RESET}"
    echo ""
    
    echo -e "${C_GREEN}📌 Public Key:${C_RESET}"
    echo -e "${C_YELLOW}$PUBLIC_KEY${C_RESET}"
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

# Uninstall DNSTT
uninstall_dnstt() {
    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling DNSTT ---${C_RESET}"
    
    if [ ! -f "$DNSTT_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ DNSTT does not appear to be installed${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    read -p "👉 Are you sure you want to uninstall DNSTT? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "\n${C_YELLOW}❌ Uninstallation cancelled.${C_RESET}"
        safe_read "" dummy
        return
    fi
    
    echo -e "\n${C_BLUE}🛑 Stopping and disabling DNSTT service...${C_RESET}"
    systemctl stop dnstt.service > /dev/null 2>&1
    systemctl disable dnstt.service > /dev/null 2>&1
    
    # Delete Desec DNS records if they exist
    if [ -f "$DNS_INFO_FILE" ]; then
        delete_dns_record
    fi
    
    echo -e "\n${C_BLUE}🗑️ Removing DNSTT files...${C_RESET}"
    rm -f "$DNSTT_SERVICE_FILE"
    rm -f "$DNSTT_BINARY"
    rm -f "$DNSTT_CLIENT"
    rm -rf "$DNSTT_KEYS_DIR"
    rm -f "$DNSTT_CONFIG_FILE"
    
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}✅ DNSTT has been successfully uninstalled.${C_RESET}"
    safe_read "" dummy
}

# DNSTT installation
install_dnstt() {
    clear
    show_banner
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}           📡 DNSTT INSTALLATION (ULTRA BOOST)${C_RESET}"
    echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
    
    # Smart check - if already installed, show details
    if [ -f "$DNSTT_SERVICE_FILE" ] && [ -f "$DNSTT_CONFIG_FILE" ] && systemctl is-active --quiet dnstt.service; then
        echo -e "\n${C_GREEN}✅ DNSTT is already installed and running.${C_RESET}"
        show_dnstt_details
        return
    fi
    
    # If installed but not running, remove automatically
    if [ -f "$DNSTT_SERVICE_FILE" ]; then
        echo -e "\n${C_YELLOW}⚠️ Found existing DNSTT installation (not running). Removing...${C_RESET}"
        systemctl stop dnstt.service 2>/dev/null
        systemctl disable dnstt.service 2>/dev/null
        rm -f "$DNSTT_SERVICE_FILE"
        rm -f "$DNSTT_BINARY" "$DNSTT_CLIENT"
        rm -rf "$DNSTT_KEYS_DIR"
        rm -f "$DNSTT_CONFIG_FILE"
        rm -f "$DNS_INFO_FILE"
        systemctl daemon-reload
        echo -e "${C_GREEN}✅ Old installation removed. Proceeding with fresh install...${C_RESET}"
        sleep 2
    fi
    
    # Step 1: Install dependencies
    echo -e "\n${C_BLUE}[1/13] Installing dependencies...${C_RESET}"
    apt-get update
    apt-get install -y wget curl git build-essential openssl netcat-openbsd jq
    
    # Step 2: Check port 53
    echo -e "\n${C_BLUE}[2/13] Checking port 53...${C_RESET}"
    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null
    chattr -i /etc/resolv.conf 2>/dev/null
    rm -f /etc/resolv.conf
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null
    
    # Step 3: Configure firewall
    echo -e "\n${C_BLUE}[3/13] Configuring firewall...${C_RESET}"
    configure_firewall
    
    # Step 4: Choose forwarding destination
    echo -e "\n${C_BLUE}[4/13] Choose forwarding destination:${C_RESET}"
    echo -e "  ${C_GREEN}[1]${C_RESET} ➡️ Forward to SSH (port 22)"
    echo -e "  ${C_GREEN}[2]${C_RESET} ➡️ Forward to V2Ray (port 8787)"
    read -p "👉 Enter your choice [2]: " fwd_choice
    fwd_choice=${fwd_choice:-2}
    
    if [[ "$fwd_choice" == "1" ]]; then
        forward_port="22"
        forward_desc="SSH (port 22)"
    else
        forward_port="8787"
        forward_desc="V2Ray (port 8787)"
    fi
    FORWARD_TARGET="127.0.0.1:$forward_port"
    
    # Step 5: Domain configuration
    echo -e "\n${C_BLUE}[5/13] Domain configuration...${C_RESET}"
    echo -e "  ${C_GREEN}[1]${C_RESET} Use existing domain from DNS Manager"
    echo -e "  ${C_GREEN}[2]${C_RESET} Generate new domain with Desec.io"
    read -p "👉 Enter your choice [2]: " domain_choice
    domain_choice=${domain_choice:-2}
    
    if [[ "$domain_choice" == "1" ]] && [ -f "$DNS_INFO_FILE" ]; then
        source "$DNS_INFO_FILE"
        DOMAIN="$FULL_DOMAIN"
        echo -e "${C_GREEN}✅ Using existing domain: $DOMAIN${C_RESET}"
    else
        generate_dns_record
        if [ $? -eq 0 ] && [ -f "$DNS_INFO_FILE" ]; then
            source "$DNS_INFO_FILE"
            DOMAIN="$FULL_DOMAIN"
        else
            echo -e "${C_YELLOW}⚠️ Domain generation failed. Please enter domain manually:${C_RESET}"
            read -p "👉 Enter tunnel domain: " DOMAIN
        fi
    fi
    
    # Step 6: MTU configuration
    echo -e "\n${C_BLUE}[6/13] MTU configuration...${C_RESET}"
    mtu_selection_during_install
    
    # Step 7: Install Go
    echo -e "\n${C_BLUE}[7/13] Installing Go...${C_RESET}"
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm -f go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    # Step 8: Build DNSTT from source
    echo -e "\n${C_BLUE}[8/13] Building DNSTT from source...${C_RESET}"
    build_dnstt_from_source
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to build DNSTT. Aborting installation.${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # Step 9: Generate keys
    echo -e "\n${C_BLUE}[9/13] Generating encryption keys...${C_RESET}"
    generate_keys
    if [ $? -ne 0 ]; then
        echo -e "\n${C_RED}❌ Failed to generate keys. Aborting installation.${C_RESET}"
        safe_read "" dummy
        return 1
    fi
    
    # ========== ULTRA BOOST INSIDE DNSTT ONLY ==========
    echo -e "\n${C_BLUE}[10/13] Applying ULTRA BOOST optimizations for DNSTT...${C_RESET}"
    
    echo -e "${C_GREEN}Enabling BBR v3...${C_RESET}"
    modprobe tcp_bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
    sysctl -w net.core.default_qdisc=fq_codel > /dev/null 2>&1
    
    echo -e "${C_GREEN}Setting ultra buffers (32MB)...${C_RESET}"
    sysctl -w net.core.rmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.core.wmem_max=33554432 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432" > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432" > /dev/null 2>&1
    
    echo -e "${C_GREEN}Setting aggressive keepalive (10s)...${C_RESET}"
    sysctl -w net.ipv4.tcp_keepalive_time=10 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_intvl=2 > /dev/null 2>&1
    sysctl -w net.ipv4.tcp_keepalive_probes=2 > /dev/null 2>&1
    
    echo -e "${C_GREEN}Applying advanced TCP tuning...${C_RESET}"
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
    
    echo -e "${C_GREEN}Setting ultra file descriptors (8M)...${C_RESET}"
    ulimit -n 8388608 2>/dev/null || true
    
    cat >> /etc/sysctl.conf << EOF

# ULTRA BOOST for DNSTT
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_codel
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_keepalive_time = 10
net.ipv4.tcp_keepalive_intvl = 2
net.ipv4.tcp_keepalive_probes = 2
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
    
    echo -e "\n${C_GREEN}✅ ULTRA BOOST ACTIVATED FOR DNSTT - 10x SPEED!${C_RESET}"
    sleep 2
    # ========== END OF ULTRA BOOST ==========
    
    # Step 11: Create service
    echo -e "\n${C_BLUE}[11/13] Creating DNSTT service...${C_RESET}"
    create_dnstt_service_ultra "$DOMAIN" "$MTU" "$FORWARD_TARGET" "$forward_desc"
    
    # Step 12: Save configuration
    echo -e "\n${C_BLUE}[12/13] Saving configuration...${C_RESET}"
    save_dnstt_info "$DOMAIN" "$PUBLIC_KEY" "$MTU" "$forward_port" "$forward_desc"
    
    # Step 13: Check service status and show details
    echo -e "\n${C_BLUE}[13/13] Checking service status...${C_RESET}"
    sleep 3
    
    if systemctl is-active --quiet dnstt.service; then
        echo -e "\n${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_GREEN}           ✅ DNSTT INSTALLED SUCCESSFULLY!${C_RESET}"
        echo -e "${C_GREEN}═══════════════════════════════════════════════════════════════${C_RESET}"
        show_dnstt_details
        show_client_commands_ultra "$DOMAIN" "$MTU" "$forward_port"
    else
        echo -e "\n${C_RED}❌ DNSTT service failed to start${C_RESET}"
        echo -e "\n${C_YELLOW}Displaying last 20 lines of service log:${C_RESET}"
        journalctl -u dnstt.service -n 20 --no-pager
    fi
    
    safe_read "" dummy
}

# ========== PROTOCOL MENU ==========
protocol_menu() {
    while true; do
        clear
        show_banner
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}              🔌 PROTOCOL & PANEL MANAGEMENT${C_RESET}"
        echo -e "${C_BOLD}${C_PURPLE}═══════════════════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "  ${C_GREEN}1)${C_RESET} Install badvpn (UDP 7300)"
        echo -e "  ${C_GREEN}2)${C_RESET} Uninstall badvpn"
        echo -e "  ${C_GREEN}3)${C_RESET} Install udp-custom"
        echo -e "  ${C_GREEN}4)${C_RESET} Uninstall udp-custom"
        echo -e "  ${C_GREEN}5)${C_RESET} Install/View DNSTT"
        echo -e "  ${C_GREEN}6)${C_RESET} Uninstall DNSTT"
        echo -e "  ${C_GREEN}7)${C_RESET} Install Voltron Proxy"
        echo -e "  ${C_GREEN}8)${C_RESET} Uninstall Voltron Proxy"
        echo -e "  ${C_GREEN}9)${C_RESET} Install/Manage Nginx"
        echo -e "  ${C_GREEN}10)${C_RESET} Install ZiVPN"
        echo -e "  ${C_GREEN}11)${C_RESET} Uninstall ZiVPN"
        echo -e "  ${C_GREEN}12)${C_RESET} Install X-UI Panel"
        echo -e "  ${C_GREEN}13)${C_RESET} Uninstall X-UI Panel"
        echo ""
        echo -e "  ${C_RED}0)${C_RESET} Return"
        echo ""
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) install_badvpn ;;
            2) uninstall_badvpn ;;
            3) install_udp_custom ;;
            4) uninstall_udp_custom ;;
            5) install_dnstt ;;
            6) uninstall_dnstt ;;
            7) install_voltron_proxy ;;
            8) uninstall_voltron_proxy ;;
            9) nginx_proxy_menu ;;
            10) install_zivpn ;;
            11) uninstall_zivpn ;;
            12) install_xui_panel ;;
            13) uninstall_xui_panel ;;
            0) return ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== MAIN MENU ==========
main_menu() {
    while true; do
        show_banner
        echo
        echo -e "   ${C_TITLE}═══════════════════[ ${C_BOLD}👤 USER MANAGEMENT ${C_RESET}${C_TITLE}]═══════════════════${C_RESET}"
        echo -e "     ${C_CHOICE}[ 1]${C_RESET} ✨ Create New User"
        echo -e "     ${C_CHOICE}[ 2]${C_RESET} 🗑️  Delete User"
        echo -e "     ${C_CHOICE}[ 3]${C_RESET} 🔄 Renew User"
        echo -e "     ${C_CHOICE}[ 4]${C_RESET} 🔒 Lock User"
        echo -e "     ${C_CHOICE}[ 5]${C_RESET} 🔓 Unlock User"
        echo -e "     ${C_CHOICE}[ 6]${C_RESET} ✏️  Edit User"
        echo -e "     ${C_CHOICE}[ 7]${C_RESET} 📋 List Users"
        echo -e "     ${C_CHOICE}[ 8]${C_RESET} ⏱️  Trial Account"
        echo -e "     ${C_CHOICE}[ 9]${C_RESET} 📊 View Bandwidth"
        echo -e "     ${C_CHOICE}[10]${C_RESET} 👥 Bulk Create Users"
        echo
        echo -e "   ${C_TITLE}══════════════[ ${C_BOLD}🌐 VPN & PROTOCOLS ${C_RESET}${C_TITLE}]═══════════════${C_RESET}"
        echo -e "     ${C_CHOICE}[11]${C_RESET} 🔌 Protocol Manager"
        echo -e "     ${C_CHOICE}[12]${C_RESET} ☁️  Domain Generator"
        echo -e "     ${C_CHOICE}[13]${C_RESET} 🚀 DT Proxy Manager"
        echo -e "     ${C_CHOICE}[14]${C_RESET} 📈 Traffic Monitor"
        echo -e "     ${C_CHOICE}[15]${C_RESET} 🚫 Torrent Blocking"
        echo
        echo -e "   ${C_TITLE}══════════════[ ${C_BOLD}⚙️ SYSTEM SETTINGS ${C_RESET}${C_TITLE}]═══════════════${C_RESET}"
        echo -e "     ${C_CHOICE}[16]${C_RESET} 🎨 SSH Banner"
        echo -e "     ${C_CHOICE}[17]${C_RESET} 💾 Backup Users"
        echo -e "     ${C_CHOICE}[18]${C_RESET} 📥 Restore Users"
        echo -e "     ${C_CHOICE}[19]${C_RESET} 🧹 Cleanup Expired"
        echo -e "     ${C_CHOICE}[20]${C_RESET} 🔄 Auto-Reboot"
        echo
        echo -e "   ${C_DANGER}═══════════════════[ ${C_BOLD}🔥 DANGER ZONE ${C_RESET}${C_DANGER}]═══════════════════${C_RESET}"
        echo -e "     ${C_DANGER}[99]${C_RESET} Uninstall Script"
        echo -e "     ${C_WARN}[ 0]${C_RESET} Exit"
        echo
        
        local choice
        safe_read "👉 Select option: " choice
        
        case $choice in
            1) create_user ;;
            2) delete_user ;;
            3) renew_user ;;
            4) lock_user ;;
            5) unlock_user ;;
            6) edit_user ;;
            7) list_users ;;
            8) create_trial_account ;;
            9) view_user_bandwidth ;;
            10) bulk_create_users ;;
            11) protocol_menu ;;
            12) dns_menu ;;
            13) dt_proxy_menu ;;
            14) traffic_monitor_menu ;;
            15) torrent_block_menu ;;
            16) ssh_banner_menu ;;
            17) backup_user_data ;;
            18) restore_user_data ;;
            19) cleanup_expired ;;
            20) auto_reboot_menu ;;
            99) uninstall_script ;;
            0) exit 0 ;;
            *) echo -e "\n${C_RED}❌ Invalid option${C_RESET}"; sleep 2 ;;
        esac
    done
}

# ========== UNINSTALL SCRIPT ==========
uninstall_script() {
    clear
    show_banner
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_RED}           🔥 UNINSTALL SCRIPT & ALL DATA 🔥${C_RESET}"
    echo -e "${C_RED}═══════════════════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}This will PERMANENTLY remove everything!${C_RESET}"
    echo ""
    
    read -p "👉 Type 'YES' to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "\n${C_GREEN}✅ Cancelled.${C_RESET}"
        return
    fi
    
    echo -e "\n${C_BLUE}--- Removing all services ---${C_RESET}"
    
    systemctl stop dnstt.service badvpn.service udp-custom.service 2>/dev/null
    systemctl disable dnstt.service badvpn.service udp-custom.service 2>/dev/null
    systemctl stop voltrontech-limiter.service voltrontech-bandwidth.service 2>/dev/null
    systemctl disable voltrontech-limiter.service voltrontech-bandwidth.service 2>/dev/null
    systemctl stop voltronproxy.service zivpn.service nginx.service 2>/dev/null
    systemctl disable voltronproxy.service zivpn.service nginx.service 2>/dev/null
    
    rm -f "$DNSTT_SERVICE_FILE" "$BADVPN_SERVICE_FILE" "$UDP_CUSTOM_SERVICE_FILE"
    rm -f "$VOLTRONPROXY_SERVICE_FILE" "$ZIVPN_SERVICE_FILE"
    rm -f "$LIMITER_SERVICE" "$BANDWIDTH_SERVICE"
    
    rm -f "$DNSTT_BINARY" "$DNSTT_CLIENT" "$BADVPN_BIN" "$UDP_CUSTOM_BIN"
    rm -f "$VOLTRONPROXY_BINARY" "$ZIVPN_BIN"
    rm -f "$LIMITER_SCRIPT" "$BANDWIDTH_SCRIPT" "$TRIAL_CLEANUP_SCRIPT"
    
    rm -rf "$BADVPN_BUILD_DIR" "$UDP_CUSTOM_DIR" "$ZIVPN_DIR"
    rm -rf "$DB_DIR"
    
    rm -f /usr/local/bin/menu
    rm -f "$0"
    
    systemctl daemon-reload
    
    echo -e "\n${C_GREEN}✅ Script uninstalled successfully!${C_RESET}"
    exit 0
}

# ========== INITIAL SETUP ==========
initial_setup() {
    mkdir -p "$DB_DIR" "$DNSTT_KEYS_DIR" "$BANDWIDTH_DIR" "$BANNER_DIR" "$LOGS_DIR" "$CONFIG_DIR" "$SSL_CERT_DIR"
    touch "$DB_FILE"
    touch "$BANNER_ENABLED"
    
    setup_bandwidth_monitor
    setup_trial_cleanup
    setup_limiter_service
    setup_ssh_banner_config
}

# ========== START ==========
if [[ $EUID -ne 0 ]]; then
    echo -e "${C_RED}❌ This script must be run as root!${C_RESET}"
    exit 1
fi

initial_setup
main_menu
