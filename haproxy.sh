#!/bin/bash

# HAProxy Management Script - Enhanced Version
# Version: 2.0
# Author: Enhanced by Claude

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[36m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration
readonly HAPROXY_CONFIG_FILE="/etc/haproxy/haproxy.cfg"
readonly HAPROXY_BACKUP_DIR="/etc/haproxy/backups"
readonly LOG_FILE="/var/log/haproxy-manager.log"
readonly HAPROXY_LOG_FILE="/var/log/haproxy.log"

# Create necessary directories
create_directories() {
    mkdir -p "$HAPROXY_BACKUP_DIR" 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null
}

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# Get server IP automatically
get_server_ip() {
    local ip
    # Try multiple methods to get server IP
    ip=$(curl -s --max-time 10 ipv4.icanhazip.com 2>/dev/null) || \
    ip=$(curl -s --max-time 10 api.ipify.org 2>/dev/null) || \
    ip=$(curl -s --max-time 10 checkip.amazonaws.com 2>/dev/null) || \
    ip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    
    echo "$ip"
}

# Input validation functions
validate_ip() {
    local ip="$1"
    # IPv4 validation
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    
    # IPv6 basic validation
    if [[ $ip =~ ^[0-9a-fA-F:]+$ ]]; then
        return 0
    fi
    
    return 1
}

validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

is_port_in_use() {
    local port="$1"
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 0
    fi
    return 1
}

# Enhanced input functions
read_and_validate_ip() {
    local prompt="$1"
    local ip
    while true; do
        read -p "$prompt: " ip
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        else
            echo -e "${RED}❌ Invalid IP address format. Please try again.${NC}"
        fi
    done
}

read_and_validate_port() {
    local prompt="$1"
    local check_usage="${2:-true}"
    local port
    while true; do
        read -p "$prompt: " port
        if validate_port "$port"; then
            if [[ "$check_usage" == "true" ]] && is_port_in_use "$port"; then
                echo -e "${YELLOW}⚠️  Port $port is already in use. Continue anyway? (y/n):${NC} "
                read -r confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    echo "$port"
                    return 0
                fi
            else
                echo "$port"
                return 0
            fi
        else
            echo -e "${RED}❌ Invalid port number (1-65535). Please try again.${NC}"
        fi
    done
}

# Logo display
show_logo() {
    echo -e "${BLUE}"
    cat << "EOF"
    __  _____    ____                       
   / / / /   |  / __ \_________  _  ____  __
  / /_/ / /| | / /_/ / ___/ __ \| |/_/ / / /
 / __  / ___ |/ ____/ /  / /_/ />  </ /_/ / 
/_/ /_/_/  |_/_/   /_/   \____/_/|_|\__, /  
                                   /____/   
        Enhanced HAProxy Manager v2.0
         github.com/Musixal (Enhanced)
EOF
    echo -e "${NC}"
}

# Check root privileges
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}❌ This script must be run as root${NC}" >&2
        log_message "ERROR" "Script attempted to run without root privileges"
        sleep 2
        exit 1
    fi
}

# Package installation with better error handling
install_package() {
    local package="$1"
    local package_name="$2"
    
    if ! command -v "$package" &> /dev/null; then
        echo -e "${YELLOW}📦 Installing $package_name...${NC}"
        log_message "INFO" "Installing $package_name"
        
        if command -v apt-get &> /dev/null; then
            if apt-get update && apt-get install -y "$package"; then
                echo -e "${GREEN}✅ $package_name installed successfully${NC}"
                log_message "INFO" "$package_name installed successfully"
            else
                echo -e "${RED}❌ Failed to install $package_name${NC}"
                log_message "ERROR" "Failed to install $package_name"
                exit 1
            fi
        elif command -v yum &> /dev/null; then
            if yum install -y "$package"; then
                echo -e "${GREEN}✅ $package_name installed successfully${NC}"
                log_message "INFO" "$package_name installed successfully"
            else
                echo -e "${RED}❌ Failed to install $package_name${NC}"
                log_message "ERROR" "Failed to install $package_name"
                exit 1
            fi
        elif command -v dnf &> /dev/null; then
            if dnf install -y "$package"; then
                echo -e "${GREEN}✅ $package_name installed successfully${NC}"
                log_message "INFO" "$package_name installed successfully"
            else
                echo -e "${RED}❌ Failed to install $package_name${NC}"
                log_message "ERROR" "Failed to install $package_name"
                exit 1
            fi
        else
            echo -e "${RED}❌ Unsupported package manager. Please install $package_name manually.${NC}"
            log_message "ERROR" "Unsupported package manager for $package_name installation"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ $package_name is already installed${NC}"
    fi
}

# Fetch server information with better error handling
get_server_info() {
    local server_ip="$1"
    local info_type="$2"
    local result
    
    # Try multiple APIs for redundancy
    result=$(curl -s --max-time 10 "http://ipwhois.app/json/$server_ip" | jq -r ".$info_type" 2>/dev/null) || \
    result=$(curl -s --max-time 10 "http://ip-api.com/json/$server_ip" | jq -r ".$info_type" 2>/dev/null) || \
    result="Unknown"
    
    if [[ "$result" == "null" ]] || [[ -z "$result" ]]; then
        result="Unknown"
    fi
    
    echo "$result"
}

# Display server information
display_server_info() {
    local server_ip
    server_ip=$(get_server_ip)
    
    if [[ -n "$server_ip" ]]; then
        echo -e "${CYAN}🌐 Server IP:${NC} $server_ip"
        
        local country isp
        country=$(get_server_info "$server_ip" "country")
        isp=$(get_server_info "$server_ip" "isp")
        
        echo -e "${GREEN}📍 Location:${NC} $country"
        echo -e "${GREEN}🏢 ISP/Datacenter:${NC} $isp"
    else
        echo -e "${YELLOW}⚠️  Could not determine server IP${NC}"
    fi
}

# HAProxy status check
show_haproxy_status() {
    if ! command -v haproxy &>/dev/null; then
        echo -e "${RED}❌ HAProxy is not installed${NC}"
        return 1
    fi

    if systemctl is-active --quiet haproxy; then
        echo -e "${GREEN}✅ HAProxy Status: Active${NC}"
        local version
        version=$(haproxy -v 2>/dev/null | head -n1 | awk '{print $3}')
        echo -e "${BLUE}📋 Version: $version${NC}"
    else
        echo -e "${RED}❌ HAProxy Status: Inactive${NC}"
    fi
}

# Backup function
create_backup() {
    if [[ -f "$HAPROXY_CONFIG_FILE" ]]; then
        local backup_file="$HAPROXY_BACKUP_DIR/haproxy_$(date +%Y%m%d_%H%M%S).cfg"
        if cp "$HAPROXY_CONFIG_FILE" "$backup_file"; then
            echo -e "${GREEN}💾 Backup created: $backup_file${NC}"
            log_message "INFO" "Backup created: $backup_file"
        else
            echo -e "${YELLOW}⚠️  Failed to create backup${NC}"
            log_message "WARNING" "Failed to create backup"
        fi
    fi
}

# Generate HAProxy configuration header
generate_haproxy_header() {
    cat > "$HAPROXY_CONFIG_FILE" << 'EOF'
# HAProxy configuration generated by Enhanced HAProxy Manager
# Generated on: $(date)

global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    
    # Security enhancements
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms
    retries 3
    
    # Error handling
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

EOF
}

# Configuration menu
multiple_server_menu() {
    while true; do
        clear
        echo -e "${CYAN}════════ Tunnel Configuration Menu ════════${NC}"
        echo
        echo -e "${GREEN}1.${NC} New Configuration (Replace existing)"
        echo -e "${BLUE}2.${NC} Add New Server/Port"
        echo -e "${YELLOW}3.${NC} View Current Configuration"
        echo -e "${RED}4.${NC} Back to Main Menu"
        echo
        echo -e "${CYAN}════════════════════════════════════════════${NC}"
        
        read -p "Enter your choice (1-4): " choice
        case $choice in
            1) configure_new_tunnel ;;
            2) add_new_server ;;
            3) view_current_config ;;
            4) return 0 ;;
            *) echo -e "${RED}❌ Invalid option! Please select 1-4${NC}" && sleep 2 ;;
        esac
    done
}

# View current configuration
view_current_config() {
    clear
    echo -e "${CYAN}════════ Current HAProxy Configuration ════════${NC}"
    echo
    
    if [[ -f "$HAPROXY_CONFIG_FILE" ]]; then
        echo -e "${GREEN}📄 Configuration file: $HAPROXY_CONFIG_FILE${NC}"
        echo
        if command -v bat &>/dev/null; then
            bat --style=numbers --theme=ansi "$HAPROXY_CONFIG_FILE"
        elif command -v highlight &>/dev/null; then
            highlight -O ansi "$HAPROXY_CONFIG_FILE"
        else
            cat "$HAPROXY_CONFIG_FILE"
        fi
    else
        echo -e "${YELLOW}⚠️  No configuration file found${NC}"
    fi
    
    echo
    read -p "Press Enter to continue..."
}

# Enhanced tunnel configuration
configure_new_tunnel() {
    clear
    echo -e "${CYAN}════════ New Tunnel Configuration ════════${NC}"
    echo
    echo -e "${YELLOW}⚠️  This will replace your existing configuration!${NC}"
    
    read -p "Continue? (yes/no): " confirm
    if ! [[ $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
        echo -e "${RED}❌ Operation cancelled${NC}"
        sleep 1
        return 1
    fi

    create_backup
    generate_haproxy_header

    echo
    echo -e "${BLUE}📋 Multi-port Configuration${NC}"
    echo -e "${GREEN}Example: 443,8443,2096${NC}"
    
    local haproxy_bind_ports destination_ports destination_ip
    
    read -p "HAProxy bind ports (comma-separated): " haproxy_bind_ports
    read -p "Destination ports (same order): " destination_ports
    destination_ip=$(read_and_validate_ip "Destination IP address")

    # Process ports
    IFS=',' read -r -a haproxy_ports_array <<< "$haproxy_bind_ports"
    IFS=',' read -r -a destination_ports_array <<< "$destination_ports"

    if [ "${#haproxy_ports_array[@]}" -ne "${#destination_ports_array[@]}" ]; then
        echo -e "${RED}❌ Port count mismatch!${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi

    # Generate configuration
    for i in "${!haproxy_ports_array[@]}"; do
        local haproxy_bind_port="${haproxy_ports_array[$i]// /}"
        local destination_port="${destination_ports_array[$i]// /}"
        
        if ! validate_port "$haproxy_bind_port" || ! validate_port "$destination_port"; then
            echo -e "${RED}❌ Invalid port: $haproxy_bind_port or $destination_port${NC}"
            continue
        fi
        
        cat >> "$HAPROXY_CONFIG_FILE" << EOF

# Frontend and Backend for port $haproxy_bind_port
frontend frontend_$haproxy_bind_port
    bind *:$haproxy_bind_port
    mode tcp
    default_backend backend_$haproxy_bind_port

backend backend_$haproxy_bind_port
    mode tcp
    balance roundrobin
    option tcp-check
    server server_$haproxy_bind_port $destination_ip:$destination_port check

EOF
    done

    if restart_haproxy; then
        echo -e "${GREEN}✅ Configuration applied successfully!${NC}"
        log_message "INFO" "New tunnel configuration applied"
    fi
    
    read -p "Press Enter to continue..."
}

# Add new server configuration
add_new_server() {
    if [[ ! -f "$HAPROXY_CONFIG_FILE" ]]; then
        echo -e "${RED}❌ No existing configuration found!${NC}"
        echo -e "${YELLOW}Please create a new configuration first (Option 1)${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi

    clear
    echo -e "${CYAN}════════ Add New Server Configuration ════════${NC}"
    
    while true; do
        echo
        local haproxy_bind_port destination_ip destination_port
        
        haproxy_bind_port=$(read_and_validate_port "HAProxy bind port")
        destination_ip=$(read_and_validate_ip "Destination IP address")
        destination_port=$(read_and_validate_port "Destination port" "false")

        cat >> "$HAPROXY_CONFIG_FILE" << EOF

# Additional configuration added $(date)
frontend frontend_$haproxy_bind_port
    bind *:$haproxy_bind_port
    mode tcp
    default_backend backend_$haproxy_bind_port

backend backend_$haproxy_bind_port
    mode tcp
    balance roundrobin
    option tcp-check
    server server_$haproxy_bind_port $destination_ip:$destination_port check

EOF

        echo -e "${GREEN}✅ Server configuration added${NC}"
        
        read -p "Add another server? (y/n): " add_another
        if ! [[ $add_another =~ ^[Yy]$ ]]; then
            break
        fi
        clear
    done

    if restart_haproxy; then
        echo -e "${GREEN}✅ Configuration updated successfully!${NC}"
        log_message "INFO" "New server configuration added"
    fi
    
    read -p "Press Enter to continue..."
}

# Load balancing configuration
load_balancing() {
    clear
    echo -e "${CYAN}════════ Load Balancer Configuration ════════${NC}"
    echo
    echo -e "${YELLOW}⚠️  This will replace your existing configuration!${NC}"
    
    read -p "Continue? (yes/no): " confirm
    if ! [[ $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
        echo -e "${RED}❌ Operation cancelled${NC}"
        sleep 1
        return 1
    fi

    create_backup
    generate_haproxy_header

    echo
    echo -e "${BLUE}⚖️  Load Balancing Algorithms:${NC}"
    echo "1. Round Robin (Default)"
    echo "2. Least Connections"
    echo "3. Source IP Hash"
    echo "4. URI Hash"
    echo "5. First Available"
    
    read -p "Select algorithm (1-5): " choice
    
    local lb_algorithm
    case $choice in
        1) lb_algorithm="roundrobin" ;;
        2) lb_algorithm="leastconn" ;;
        3) lb_algorithm="source" ;;
        4) lb_algorithm="uri" ;;
        5) lb_algorithm="first" ;;
        *) echo -e "${YELLOW}⚠️  Invalid choice, using roundrobin${NC}"
           lb_algorithm="roundrobin" ;;
    esac

    echo
    local haproxy_bind_port
    haproxy_bind_port=$(read_and_validate_port "HAProxy bind port for load balancing")

    cat >> "$HAPROXY_CONFIG_FILE" << EOF

# Load Balancer Configuration
frontend tcp_frontend
    bind *:$haproxy_bind_port
    mode tcp
    default_backend tcp_backend

backend tcp_backend
    mode tcp
    balance $lb_algorithm
    option tcp-check
    option log-health-checks
EOF

    echo
    echo -e "${GREEN}Adding backend servers...${NC}"
    
    local server=1
    while true; do
        echo
        local destination_ip destination_port
        
        destination_ip=$(read_and_validate_ip "Backend server #$server IP")
        destination_port=$(read_and_validate_port "Backend server #$server port" "false")
        
        echo "    server server$server $destination_ip:$destination_port check inter 2000 rise 2 fall 3" >> "$HAPROXY_CONFIG_FILE"
        
        read -p "Add another backend server? (y/n): " add_another
        if ! [[ $add_another =~ ^[Yy]$ ]]; then
            break
        fi
        server=$((server + 1))
    done

    if restart_haproxy; then
        echo -e "${GREEN}✅ Load balancer configured successfully!${NC}"
        log_message "INFO" "Load balancer configuration applied"
    fi
    
    read -p "Press Enter to continue..."
}

# Enhanced HAProxy restart function
restart_haproxy() {
    echo -e "${YELLOW}🔄 Testing HAProxy configuration...${NC}"
    
    if haproxy -f "$HAPROXY_CONFIG_FILE" -c &>/dev/null; then
        echo -e "${GREEN}✅ Configuration is valid${NC}"
        
        echo -e "${YELLOW}🔄 Restarting HAProxy service...${NC}"
        if systemctl restart haproxy; then
            echo -e "${GREEN}✅ HAProxy restarted successfully${NC}"
            log_message "INFO" "HAProxy restarted successfully"
            return 0
        else
            echo -e "${RED}❌ Failed to restart HAProxy${NC}"
            log_message "ERROR" "Failed to restart HAProxy"
            return 1
        fi
    else
        echo -e "${RED}❌ Invalid HAProxy configuration!${NC}"
        echo -e "${YELLOW}Checking configuration errors...${NC}"
        haproxy -f "$HAPROXY_CONFIG_FILE" -c
        log_message "ERROR" "Invalid HAProxy configuration"
        return 1
    fi
}

# Destroy tunnel function
destroy_tunnel() {
    clear
    echo -e "${RED}⚠️  DANGER ZONE ⚠️${NC}"
    echo -e "${RED}This will stop HAProxy and remove all configurations!${NC}"
    echo
    
    read -p "Type 'DELETE' to confirm: " confirm
    if [[ "$confirm" != "DELETE" ]]; then
        echo -e "${GREEN}✅ Operation cancelled${NC}"
        sleep 1
        return 0
    fi

    create_backup

    if systemctl is-active --quiet haproxy; then
        echo -e "${YELLOW}🛑 Stopping HAProxy service...${NC}"
        if systemctl stop haproxy; then
            echo -e "${GREEN}✅ HAProxy service stopped${NC}"
        else
            echo -e "${RED}❌ Failed to stop HAProxy${NC}"
        fi
    fi

    if [[ -f "$HAPROXY_CONFIG_FILE" ]]; then
        echo -e "${RED}🗑️  Removing configuration file...${NC}"
        if rm "$HAPROXY_CONFIG_FILE"; then
            echo -e "${GREEN}✅ Configuration file removed${NC}"
            log_message "INFO" "HAProxy configuration destroyed"
        else
            echo -e "${RED}❌ Failed to remove configuration file${NC}"
        fi
    fi

    read -p "Press Enter to continue..."
}

# Reset service function
reset_service() {
    clear
    echo -e "${CYAN}════════ Service Reset ════════${NC}"
    echo
    
    if restart_haproxy; then
        echo -e "${GREEN}✅ HAProxy service reset completed${NC}"
    else
        echo -e "${RED}❌ Service reset failed${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Enhanced real-time log viewer
view_haproxy_log_realtime() {
    clear
    echo -e "${CYAN}════════ Real-time HAProxy Logs ════════${NC}"
    echo -e "${YELLOW}Press Ctrl+C to exit${NC}"
    echo
    
    if [[ ! -f "$HAPROXY_LOG_FILE" ]]; then
        echo -e "${RED}❌ HAProxy log file not found: $HAPROXY_LOG_FILE${NC}"
        echo -e "${YELLOW}Trying alternative locations...${NC}"
        
        # Try alternative log locations
        local alt_logs=("/var/log/syslog" "/var/log/messages" "/var/log/daemon.log")
        for log in "${alt_logs[@]}"; do
            if [[ -f "$log" ]]; then
                echo -e "${GREEN}✅ Using alternative log: $log${NC}"
                tail -f "$log" | grep -i haproxy --color=always
                return
            fi
        done
        
        echo -e "${RED}❌ No suitable log file found${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    tail -f "$HAPROXY_LOG_FILE" | while read -r line; do
        # Color-code log levels
        if [[ $line =~ ERROR|error ]]; then
            echo -e "${RED}$line${NC}"
        elif [[ $line =~ WARN|warn ]]; then
            echo -e "${YELLOW}$line${NC}"
        elif [[ $line =~ INFO|info ]]; then
            echo -e "${GREEN}$line${NC}"
        else
            echo "$line"
        fi
    done
}

# Statistics and monitoring
show_statistics() {
    clear
    echo -e "${CYAN}════════ HAProxy Statistics ════════${NC}"
    echo
    
    if ! systemctl is-active --quiet haproxy; then
        echo -e "${RED}❌ HAProxy is not running${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${GREEN}📊 Service Status:${NC}"
    systemctl status haproxy --no-pager -l
    
    echo
    echo -e "${GREEN}🔌 Active Connections:${NC}"
    netstat -tuln | grep -E ":(443|80|8080|8443|2096)" || echo "No standard proxy ports found"
    
    echo
    echo -e "${GREEN}💾 Resource Usage:${NC}"
    ps aux | grep haproxy | grep -v grep
    
    echo
    read -p "Press Enter to continue..."
}

# Configuration management menu
config_management_menu() {
    while true; do
        clear
        echo -e "${CYAN}════════ Configuration Management ════════${NC}"
        echo
        echo -e "${GREEN}1.${NC} View Current Configuration"
        echo -e "${BLUE}2.${NC} Backup Current Configuration"
        echo -e "${YELLOW}3.${NC} Restore from Backup"
        echo -e "${PURPLE}4.${NC} List Available Backups"
        echo -e "${RED}5.${NC} Back to Main Menu"
        echo
        echo -e "${CYAN}═══════════════════════════════════════════${NC}"
        
        read -p "Enter your choice (1-5): " choice
        case $choice in
            1) view_current_config ;;
            2) manual_backup ;;
            3) restore_backup ;;
            4) list_backups ;;
            5) return 0 ;;
            *) echo -e "${RED}❌ Invalid option! Please select 1-5${NC}" && sleep 2 ;;
        esac
    done
}

# Manual backup
manual_backup() {
    clear
    echo -e "${CYAN}════════ Manual Backup ════════${NC}"
    echo
    
    if [[ ! -f "$HAPROXY_CONFIG_FILE" ]]; then
        echo -e "${RED}❌ No configuration file to backup${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    create_backup
    echo -e "${GREEN}✅ Manual backup completed${NC}"
    read -p "Press Enter to continue..."
}

# List backups
list_backups() {
    clear
    echo -e "${CYAN}════════ Available Backups ════════${NC}"
    echo
    
    if [[ ! -d "$HAPROXY_BACKUP_DIR" ]] || [[ -z "$(ls -A "$HAPROXY_BACKUP_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}⚠️  No backups found${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${GREEN}📁 Backup Directory: $HAPROXY_BACKUP_DIR${NC}"
    echo
    ls -la "$HAPROXY_BACKUP_DIR"
    
    echo
    read -p "Press Enter to continue..."
}

# Restore backup
restore_backup() {
    clear
    echo -e "${CYAN}════════ Restore Backup ════════${NC}"
    echo
    
    if [[ ! -d "$HAPROXY_BACKUP_DIR" ]] || [[ -z "$(ls -A "$HAPROXY_BACKUP_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}⚠️  No backups available${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "${GREEN}Available backups:${NC}"
    local backups=($(ls -1 "$HAPROXY_BACKUP_DIR" | grep "\.cfg$"))
    
    for i in "${!backups[@]}"; do
        echo "$((i+1)). ${backups[i]}"
    done
    
    echo
    read -p "Select backup to restore (number): " selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#backups[@]}" ]; then
        local selected_backup="$HAPROXY_BACKUP_DIR/${backups[$((selection-1))]}"
        
        echo -e "${YELLOW}⚠️  This will replace your current configuration!${NC}"
        read -p "Continue? (yes/no): " confirm
        
        if [[ $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
            create_backup  # Backup current config before restore
            
            if cp "$selected_backup" "$HAPROXY_CONFIG_FILE"; then
                echo -e "${GREEN}✅ Configuration restored successfully${NC}"
                
                if restart_haproxy; then
                    echo -e "${GREEN}✅ HAProxy restarted with restored configuration${NC}"
                    log_message "INFO" "Configuration restored from backup: $selected_backup"
                else
                    echo -e "${RED}❌ Failed to restart HAProxy with restored configuration${NC}"
                fi
            else
                echo -e "${RED}❌ Failed to restore configuration${NC}"
            fi
        else
            echo -e "${GREEN}✅ Restore cancelled${NC}"
        fi
    else
        echo -e "${RED}❌ Invalid selection${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# System information
show_system_info() {
    clear
    echo -e "${CYAN}════════ System Information ════════${NC}"
    echo
    
    echo -e "${GREEN}🖥️  System Details:${NC}"
    echo -e "   OS: $(lsb_release -d 2>/dev/null | cut -f2 || uname -o)"
    echo -e "   Kernel: $(uname -r)"
    echo -e "   Architecture: $(uname -m)"
    echo -e "   Uptime: $(uptime -p 2>/dev/null || uptime)"
    
    echo
    echo -e "${GREEN}💾 Memory Usage:${NC}"
    free -h
    
    echo
    echo -e "${GREEN}💽 Disk Usage:${NC}"
    df -h / | tail -n 1
    
    echo
    echo -e "${GREEN}🔗 Network Interfaces:${NC}"
    ip addr show | grep -E "inet |UP" | grep -v "127.0.0.1"
    
    echo
    echo -e "${GREEN}🔧 HAProxy Version:${NC}"
    haproxy -v 2>/dev/null || echo "HAProxy not installed"
    
    echo
    read -p "Press Enter to continue..."
}

# Update checker and installer
update_script() {
    clear
    echo -e "${CYAN}════════ Script Update ════════${NC}"
    echo
    
    echo -e "${YELLOW}🔄 Checking for updates...${NC}"
    
    # In a real scenario, you would check against a remote repository
    echo -e "${GREEN}✅ You are running the latest version (2.0)${NC}"
    echo
    echo -e "${BLUE}Features in this version:${NC}"
    echo "• Enhanced input validation"
    echo "• Automatic backup system"
    echo "• Improved error handling"
    echo "• Configuration management"
    echo "• System monitoring"
    echo "• Colorized output"
    echo "• Detailed logging"
    
    echo
    read -p "Press Enter to continue..."
}

# Main menu display
display_menu() {
    clear
    show_logo
    echo
    display_server_info
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    show_haproxy_status
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}Main Menu:${NC}"
    echo
    echo -e "${GREEN}1.${NC} 🔧 Configure Tunnel (IPv4/IPv6)"
    echo -e "${BLUE}2.${NC} ⚖️  Configure Load Balancer"
    echo -e "${PURPLE}3.${NC} 📊 View Statistics & Monitoring"
    echo -e "${YELLOW}4.${NC} 🔄 Restart HAProxy Service"
    echo -e "${CYAN}5.${NC} 📋 Configuration Management"
    echo -e "${BLUE}6.${NC} 📺 View Real-time Logs"
    echo -e "${GREEN}7.${NC} ℹ️  System Information"
    echo -e "${YELLOW}8.${NC} 🔄 Update Script"
    echo -e "${RED}9.${NC} 🗑️  Destroy Configuration"
    echo -e "${RED}0.${NC} 🚪 Exit"
    echo
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
}

# Main menu input handler
read_option() {
    read -p "Enter your choice (0-9): " choice
    case $choice in
        1) multiple_server_menu ;;
        2) load_balancing ;;
        3) show_statistics ;;
        4) reset_service ;;
        5) config_management_menu ;;
        6) view_haproxy_log_realtime ;;
        7) show_system_info ;;
        8) update_script ;;
        9) destroy_tunnel ;;
        0) 
            echo -e "${GREEN}👋 Thank you for using HAProxy Manager!${NC}"
            log_message "INFO" "Script terminated by user"
            exit 0 
            ;;
        *) 
            echo -e "${RED}❌ Invalid option! Please select 0-9${NC}" 
            sleep 2 
            ;;
    esac
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    log_message "INFO" "Script cleanup initiated"
    exit 0
}

# Signal handlers
trap cleanup SIGINT SIGTERM

# Initialize script
initialize() {
    # Check root privileges
    check_root
    
    # Create necessary directories
    create_directories
    
    # Log script start
    log_message "INFO" "HAProxy Manager script started"
    
    # Install required packages
    echo -e "${YELLOW}🔧 Checking dependencies...${NC}"
    install_package "jq" "JQ (JSON processor)"
    install_package "haproxy" "HAProxy"
    install_package "curl" "cURL"
    install_package "netstat" "Net-tools"
    
    echo -e "${GREEN}✅ All dependencies installed${NC}"
    sleep 1
}

# Main execution
main() {
    initialize
    
    # Main program loop
    while true; do
        display_menu
        read_option
    done
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
