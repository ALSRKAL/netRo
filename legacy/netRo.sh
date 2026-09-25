#!/bin/bash

# Exit on error, undefined variables, and pipe failures
set -euo pipefail
IFS=$'\n\t'

# Script Configuration
readonly VERSION="4.2"
readonly SCRIPT_NAME=$(basename "$0")
readonly LOG_FILE="/tmp/system_info.log"
readonly CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/system_dashboard"
readonly CONFIG_FILE="$CONFIG_DIR/config"
readonly CACHE_DIR="/tmp/system_dashboard_cache"
readonly UPDATE_INTERVAL=5  # Seconds

# Ensure directories exist
mkdir -p "$CONFIG_DIR" "$CACHE_DIR"

# Theme Configuration with fallback to basic colors if terminal doesn't support RGB
if [[ "$(tput colors 2>/dev/null)" -ge 256 ]]; then
    declare -A THEME=(
        [bg_primary]="\e[48;2;17;21;24m"
        [bg_secondary]="\e[48;2;30;34;37m"
        [fg_primary]="\e[38;2;235;235;235m"
        [fg_secondary]="\e[38;2;190;190;190m"
        [accent1]="\e[38;2;86;182;194m"
        [accent2]="\e[38;2;240;113;120m"
        [accent3]="\e[38;2;158;206;106m"
        [accent4]="\e[38;2;224;175;104m"
        [flag_red]="\e[48;2;206;17;38m"      # Red background
        [flag_white]="\e[48;2;255;255;255m"  # White background
        [flag_black]="\e[48;2;0;0;0m"        # Black background
        [reset]="\e[0m"
    )
else
    declare -A THEME=(
        [bg_primary]="\e[40m"
        [bg_secondary]="\e[100m"
        [fg_primary]="\e[97m"
        [fg_secondary]="\e[37m"
        [accent1]="\e[36m"
        [accent2]="\e[31m"
        [accent3]="\e[32m"
        [accent4]="\e[33m"
        [flag_red]="\e[41m"      # Red background
        [flag_white]="\e[47m"    # White background
        [flag_black]="\e[40m"    # Black background
        [reset]="\e[0m"
    )
fi

# Unicode Symbols with ASCII fallbacks
if [[ "$(locale charmap 2>/dev/null)" == "UTF-8" ]]; then
    declare -A SYMBOLS=(
        [arrow]="→"
        [bullet]="•"
        [check]="✓"
        [cross]="✗"
        [warning]="⚠"
        [info]="ℹ"
        [right_triangle]="▶"
        [vertical_bar]="│"
        [horizontal_bar]="─"
        [top_left]="╭"
        [top_right]="╮"
        [bottom_left]="╰"
        [bottom_right]="╯"
        [block]="█"
        [spinner]="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    )
else
    declare -A SYMBOLS=(
        [arrow]="->"
        [bullet]="*"
        [check]="+"
        [cross]="x"
        [warning]="!"
        [info]="i"
        [right_triangle]=">"
        [vertical_bar]="|"
        [horizontal_bar]="-"
        [top_left]="+"
        [top_right]="+"
        [bottom_left]="+"
        [bottom_right]="+"
        [block]="#"
        [spinner]="-\|/"
    )
fi

# Error Handling
trap cleanup EXIT
trap 'echo -e "${THEME[accent2]}${SYMBOLS[warning]} Interrupted${THEME[reset]}" >&2; exit 1' INT TERM

cleanup() {
    rm -rf "$CACHE_DIR" 2>/dev/null || true
    jobs -p | xargs kill 2>/dev/null || true
    tput cnorm # Show cursor
}

log() {
    local level="$1"
    shift
    local log_message="[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*"
    
    # Ensure the log file exists and is writable
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE" && chmod 644 "$LOG_FILE"
    fi
    
    echo "$log_message" >> "$LOG_FILE"
}

error() {
    log "ERROR" "$*"
    echo -e "${THEME[accent2]}${SYMBOLS[cross]} Error: $*${THEME[reset]}" >&2
}

# Print styled text
print_styled() {
    local style="$1"
    local text="$2"
    echo -e "${THEME[$style]}$text${THEME[reset]}"
}

# Loading Animation
show_spinner() {
    local pid=$1
    local message=$2
    local i=0
    local spin_chars=${SYMBOLS[spinner]}
    
    tput civis # Hide cursor
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i + 1) % ${#spin_chars} ))
        printf "\r${THEME[accent1]}${spin_chars:$i:1}${THEME[reset]} %s" "$message"
        sleep 0.1
    done
    tput cnorm # Show cursor
    echo
}

# Cache Management
get_cached_value() {
    local key=$1
    local ttl=$2
    local cache_file="$CACHE_DIR/$key"
    
    if [[ -f "$cache_file" ]] && [[ $(($(date +%s) - $(stat -c %Y "$cache_file"))) -lt $ttl ]]; then
        cat "$cache_file"
        return 0
    fi
    return 1
}

set_cached_value() {
    local key=$1
    local value=$2
    echo "$value" > "$CACHE_DIR/$key"
}

# Enhanced Flag Drawing with Solid Colors
draw_flag() {
    local width=50
    local height=3
    local term_width=$(tput cols)
    local padding=$(( (term_width - width) / 2 ))
    local padding_str=$(printf "%${padding}s" "")

    # Center the flag in the terminal
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Yemeni tool ${SYMBOLS[info]}${THEME[reset]}"
    echo -e "${THEME[fg_secondary]}create by ${THEME[fg_primary]}ALSRKAL ${THEME[reset]}"
    echo

    # Draw the red stripe
    for ((i=0; i<height; i++)); do
        echo -ne "${padding_str}${THEME[flag_red]}"
        for ((j=0; j<width; j++)); do
            echo -ne " "
        done
        echo -e "${THEME[reset]}"
    done

    # Draw the white stripe
    for ((i=0; i<height; i++)); do
        echo -ne "${padding_str}${THEME[flag_white]}"
        for ((j=0; j<width; j++)); do
            echo -ne " "
        done
        echo -e "${THEME[reset]}"
    done

    # Draw the black stripe
    for ((i=0; i<height; i++)); do
        echo -ne "${padding_str}${THEME[flag_black]}"
        for ((j=0; j<width; j++)); do
            echo -ne " "
        done
        echo -e "${THEME[reset]}"
    done

    echo
}

# Draw Header
draw_header() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} System Dashboard ${SYMBOLS[info]}${THEME[reset]}"
    echo -e "${THEME[fg_secondary]}Version: $VERSION${THEME[reset]}"
    echo
}

# System Health Checks
check_cpu_usage() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    echo -e "${THEME[accent1]}${SYMBOLS[info]} CPU Usage: ${cpu_usage}%${THEME[reset]}"
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        error "High CPU usage detected!"
    fi
}

check_memory_usage() {
    local memory_usage=$(free -m | awk '/Mem:/ {printf "%.2f", $3/$2 * 100}')
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Memory Usage: ${memory_usage}%${THEME[reset]}"
    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        error "High memory usage detected!"
    fi
}

check_disk_usage() {
    local disk_usage=$(df -h / | awk '/\// {print $5}' | tr -d '%')
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Disk Usage: ${disk_usage}%${THEME[reset]}"
    if (( disk_usage > 80 )); then
        error "High disk usage detected!"
    fi
}

# Security Checks
check_suspicious_processes() {
    local suspicious_processes=$(ps aux | grep -Ei "(cryptominer|malware|backdoor|ransomware|nmap|metasploit|hydra|john|sqlmap|wireshark|ettercap|aircrack|nikto|netcat|nc|tcpdump)" | grep -v grep)
    if [[ -n "$suspicious_processes" ]]; then
        error "Suspicious processes detected:"
        echo "$suspicious_processes"
    else
        echo -e "${THEME[accent3]}${SYMBOLS[check]} No suspicious processes detected${THEME[reset]}"
    fi
}

check_open_ports() {
    local open_ports=$(ss -tuln | grep LISTEN)
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Open Ports:${THEME[reset]}"
    echo "$open_ports"
}

check_unauthorized_users() {
    local unauthorized_users=$(awk -F: '($3 < 1000) {print $1}' /etc/passwd)
    if [[ -n "$unauthorized_users" ]]; then
        error "Unauthorized users detected:"
        echo "$unauthorized_users"
    else
        echo -e "${THEME[accent3]}${SYMBOLS[check]} No unauthorized users detected${THEME[reset]}"
    fi
}

check_rootkits() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Rootkit check skipped (rkhunter not installed).${THEME[reset]}"
}

check_file_integrity() {
    local critical_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers")
    for file in "${critical_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            error "Critical file missing: $file"
        elif [[ "$(stat -c %a "$file")" != "644" ]]; then
            error "Incorrect permissions for $file"
        fi
    done
}

# Placeholder Functions
update_system_info() {
    sleep 2 # Simulate a background task
}

show_system_info() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} System Information ${SYMBOLS[info]}${THEME[reset]}"
    echo -e "Hostname: $(hostname)"
    echo -e "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    echo -e "Kernel: $(uname -r)"
    echo
}

show_network_info() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Network Information ${SYMBOLS[info]}${THEME[reset]}"
    ip addr show | grep "inet " | awk '{print $2}'
    echo
}

show_storage_info() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Storage Information ${SYMBOLS[info]}${THEME[reset]}"
    df -h | grep -v "tmpfs"
    echo
}

show_security_info() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Security Information ${SYMBOLS[info]}${THEME[reset]}"
    check_suspicious_processes
    check_open_ports
    check_unauthorized_users
    check_rootkits
    check_file_integrity
    echo
}

show_all_info() {
    show_system_info
    show_network_info
    show_storage_info
    show_security_info
}

exit_script() {
    echo -e "${THEME[accent3]}${SYMBOLS[check]} Exiting...${THEME[reset]}"
    exit 0
}

# Enhanced Menu System with Background Updates
show_menu() {
    local last_update=0
    local update_needed=true
    
    while true; do
        # Check if update is needed
        if [[ $update_needed == true ]] || [[ $(($(date +%s) - last_update)) -gt $UPDATE_INTERVAL ]]; then
            clear
            draw_flag  # Redraw the flag at the top
            draw_header
            update_system_info &
            show_spinner $! "Updating system information..."
            last_update=$(date +%s)
            update_needed=false
        fi
        
        echo -e "${THEME[accent1]}${SYMBOLS[right_triangle]} Menu Options:${THEME[reset]}"
        echo -e "1. Show System Information (Hostname, OS, Kernel)"
        echo -e "2. Show Network Information (IP Addresses)"
        echo -e "3. Show Storage Information (Disk Usage)"
        echo -e "4. Show Security Information (Processes, Ports, Users)"
        echo -e "5. Show All Information"
        echo -e "6. Launch Advanced Network Tool"
        echo -e "7. Exit"
        echo
        
        read -p "$(print_styled 'accent3' 'Enter your choice (1-7): ')" choice
        
        case $choice in
            1) show_system_info; update_needed=true ;;
            2) show_network_info; update_needed=true ;;
            3) show_storage_info; update_needed=true ;;
            4) show_security_info; update_needed=true ;;
            5) show_all_info; update_needed=true ;;
            6) launch_network_tool ;;
            7) exit_script ;;
            *) print_styled "accent2" "${SYMBOLS[cross]} Invalid option" ;;
        esac
        
        if [[ $choice != 7 ]]; then
            read -p "$(print_styled 'accent3' 'Press Enter to continue...')"
        fi
    done
}

# Function to launch the Advanced Network Tool
launch_network_tool() {
    echo -e "${THEME[accent1]}${SYMBOLS[info]} Launching Advanced Network Tool...${THEME[reset]}"
    bash -c "$(cat << 'EOF'
#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="network_tool.log"

# Function to log actions
log_action() {
    local message=$1
    echo -e "${BLUE}[LOG] $message${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Function to display the menu
show_menu() {
    clear
    echo -e "${GREEN}====================================${NC}"
    echo -e "${GREEN}          Advanced Network Tool     ${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo -e "${YELLOW}[1] Ping a host${NC}"
    echo -e "${YELLOW}[2] Scan ports with Nmap${NC}"
    echo -e "${YELLOW}[3] Check network connections${NC}"
    echo -e "${YELLOW}[4] Trace route to a host${NC}"
    echo -e "${YELLOW}[5] DNS lookup${NC}"
    echo -e "${YELLOW}[6] Check open ports on a host${NC}"
    echo -e "${YELLOW}[7] Advanced Nmap scan${NC}"
    echo -e "${YELLOW}[8] Check network interfaces${NC}"
    echo -e "${YELLOW}[9] Check public IP address${NC}"
    echo -e "${YELLOW}[10] Get IP address${NC}"
    echo -e "${YELLOW}[11] List all devices on the network${NC}"
    echo -e "${YELLOW}[12] Block/Unblock a device${NC}"
    echo -e "${YELLOW}[13] Save scan results to file${NC}"
    echo -e "${YELLOW}[14] Show device details${NC}"  # New option
    echo -e "${RED}[15] Exit${NC}"  # Updated exit option number
    echo -e "${GREEN}====================================${NC}"
}

# Function to validate IP or hostname
validate_input() {
    local input=$1
    if [[ -z "$input" ]]; then
        echo -e "${RED}Error: No input provided.${NC}"
        return 1
    fi
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    elif [[ "$input" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        echo -e "${RED}Error: Invalid IP or hostname.${NC}"
        return 1
    fi
}

# Function to ping a host
ping_host() {
    read -p "Enter the host to ping (e.g., google.com): " host
    if validate_input "$host"; then
        echo -e "${YELLOW}Pinging $host...${NC}"
        ping -c 4 "$host" && log_action "Pinged $host successfully." || echo -e "${RED}Failed to ping $host.${NC}"
    fi
}

# Function to scan ports with Nmap
scan_ports() {
    read -p "Enter the target IP or hostname (e.g., 192.168.1.1): " target
    if validate_input "$target"; then
        echo -e "${YELLOW}Scanning $target...${NC}"
        nmap "$target" && log_action "Scanned $target successfully." || echo -e "${RED}Failed to scan $target.${NC}"
    fi
}

# Function to check network connections
check_connections() {
    echo -e "${YELLOW}Active network connections:${NC}"
    netstat -tuln && log_action "Checked network connections." || echo -e "${RED}Failed to check network connections.${NC}"
}

# Function to trace route to a host
trace_route() {
    read -p "Enter the host to trace (e.g., google.com): " host
    if validate_input "$host"; then
        echo -e "${YELLOW}Tracing route to $host...${NC}"
        traceroute "$host" && log_action "Traced route to $host successfully." || echo -e "${RED}Failed to trace route to $host.${NC}"
    fi
}

# Function to perform DNS lookup
dns_lookup() {
    read -p "Enter the domain name (e.g., google.com): " domain
    if validate_input "$domain"; then
        echo -e "${YELLOW}Performing DNS lookup for $domain...${NC}"
        nslookup "$domain" && log_action "Performed DNS lookup for $domain successfully." || echo -e "${RED}Failed to perform DNS lookup for $domain.${NC}"
    fi
}

# Function to check open ports on a host
check_open_ports() {
    read -p "Enter the target IP or hostname (e.g., 192.168.1.1): " target
    if validate_input "$target"; then
        echo -e "${YELLOW}Checking open ports on $target...${NC}"
        nmap -p- "$target" && log_action "Checked open ports on $target successfully." || echo -e "${RED}Failed to check open ports on $target.${NC}"
    fi
}

# Function for advanced Nmap scan
advanced_nmap_scan() {
    read -p "Enter the target IP or hostname (e.g., 192.168.1.1): " target
    if validate_input "$target"; then
        echo -e "${YELLOW}Select an advanced Nmap scan option:${NC}"
        echo -e "${YELLOW}[1] Intense scan${NC}"
        echo -e "${YELLOW}[2] OS detection${NC}"
        echo -e "${YELLOW}[3] Version detection${NC}"
        echo -e "${YELLOW}[4] Aggressive scan${NC}"
        echo -e "${YELLOW}[5] Custom scan${NC}"
        read -p "Choose an option (1-5): " nmap_option

        case $nmap_option in
            1)
                echo -e "${YELLOW}Performing intense scan on $target...${NC}"
                nmap -T4 -A -v "$target" && log_action "Performed intense scan on $target successfully." || echo -e "${RED}Failed to perform intense scan on $target.${NC}"
                ;;
            2)
                echo -e "${YELLOW}Performing OS detection on $target...${NC}"
                nmap -O "$target" && log_action "Performed OS detection on $target successfully." || echo -e "${RED}Failed to perform OS detection on $target.${NC}"
                ;;
            3)
                echo -e "${YELLOW}Performing version detection on $target...${NC}"
                nmap -sV "$target" && log_action "Performed version detection on $target successfully." || echo -e "${RED}Failed to perform version detection on $target.${NC}"
                ;;
            4)
                echo -e "${YELLOW}Performing aggressive scan on $target...${NC}"
                nmap -T4 -A -v "$target" && log_action "Performed aggressive scan on $target successfully." || echo -e "${RED}Failed to perform aggressive scan on $target.${NC}"
                ;;
            5)
                read -p "Enter custom Nmap arguments (e.g., -sS -p 80,443): " custom_args
                echo -e "${YELLOW}Performing custom scan on $target with arguments: $custom_args...${NC}"
                nmap $custom_args "$target" && log_action "Performed custom scan on $target successfully." || echo -e "${RED}Failed to perform custom scan on $target.${NC}"
                ;;
            *)
                echo -e "${RED}Invalid option. Returning to main menu.${NC}"
                ;;
        esac
    fi
}

# Function to check network interfaces
check_interfaces() {
    echo -e "${YELLOW}Network interfaces:${NC}"
    ip addr show && log_action "Checked network interfaces." || echo -e "${RED}Failed to check network interfaces.${NC}"
}

# Function to check public IP address
check_public_ip() {
    echo -e "${YELLOW}Fetching public IP address...${NC}"
    curl ifconfig.me && log_action "Fetched public IP address." || echo -e "${RED}Failed to fetch public IP address.${NC}"
    echo
}

# Function to get IP address of the running system or another system
get_ip_address() {
    echo -e "${YELLOW}[1] Get IP address of the running system${NC}"
    echo -e "${YELLOW}[2] Get IP address of another system${NC}"
    read -p "Choose an option (1-2): " ip_option

    case $ip_option in
        1)
            echo -e "${YELLOW}IP address of the running system:${NC}"
            hostname -I | awk '{print $1}' && log_action "Fetched IP address of the running system." || echo -e "${RED}Failed to get IP address.${NC}"
            ;;
        2)
            read -p "Enter the hostname or domain name (e.g., google.com): " host
            if validate_input "$host"; then
                echo -e "${YELLOW}IP address of $host:${NC}"
                nslookup "$host" | grep 'Address' | tail -n1 | awk '{print $2}' && log_action "Fetched IP address of $host." || echo -e "${RED}Failed to get IP address of $host.${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid option. Returning to main menu.${NC}"
            ;;
    esac
}

# Function to detect network range
detect_network_range() {
    local network_range
    network_range=$(ip route | grep default | awk '{print $3}' | cut -d'.' -f1-3)
    echo "${network_range}.0/24"
}

# Function to list all devices on the network
list_devices() {
    echo -e "${YELLOW}Listing all devices on the network...${NC}"
    echo -e "${YELLOW}Select a tool to scan the network:${NC}"
    echo -e "${YELLOW}[1] Nmap${NC}"
    echo -e "${YELLOW}[2] arp-scan${NC}"
    read -p "Choose an option (1-2): " scan_option

    case $scan_option in
        1)
            echo -e "${YELLOW}Scanning network with Nmap...${NC}"
            nmap -sn "$(detect_network_range)" && log_action "Scanned network with Nmap successfully." || echo -e "${RED}Failed to scan network with Nmap.${NC}"
            ;;
        2)
            echo -e "${YELLOW}Scanning network with arp-scan...${NC}"
            sudo arp-scan --localnet && log_action "Scanned network with arp-scan successfully." || echo -e "${RED}Failed to scan network with arp-scan.${NC}"
            ;;
        *)
            echo -e "${RED}Invalid option. Returning to main menu.${NC}"
            ;;
    esac
}

# Function to block/unblock a device
block_device() {
    read -p "Enter the IP address to block/unblock: " ip
    if validate_input "$ip"; then
        echo -e "${YELLOW}[1] Block $ip${NC}"
        echo -e "${YELLOW}[2] Unblock $ip${NC}"
        read -p "Choose an option (1-2): " block_option

        case $block_option in
            1)
                echo -e "${YELLOW}Blocking $ip...${NC}"
                sudo iptables -A INPUT -s "$ip" -j DROP && sudo iptables-save > /etc/iptables/rules.v4 && log_action "Blocked $ip successfully." || echo -e "${RED}Failed to block $ip.${NC}"
                ;;
            2)
                echo -e "${YELLOW}Unblocking $ip...${NC}"
                sudo iptables -D INPUT -s "$ip" -j DROP && sudo iptables-save > /etc/iptables/rules.v4 && log_action "Unblocked $ip successfully." || echo -e "${RED}Failed to unblock $ip.${NC}"
                ;;
            *)
                echo -e "${RED}Invalid option. Returning to main menu.${NC}"
                ;;
        esac
    fi
}

# Function to save scan results to a file
save_scan_results() {
    read -p "Enter the filename to save the results (e.g., scan_results.txt): " filename
    if validate_input "$filename"; then
        echo -e "${YELLOW}Saving scan results to $filename...${NC}"
        list_devices > "$filename" && log_action "Saved scan results to $filename." || echo -e "${RED}Failed to save results.${NC}"
    fi
}

# Function to show device details
show_device_details() {
    read -p "Enter the IP address of the device: " ip
    if validate_input "$ip"; then
        echo -e "${YELLOW}Fetching details for $ip...${NC}"
        nmap -A "$ip" && log_action "Fetched details for $ip successfully." || echo -e "${RED}Failed to fetch details for $ip.${NC}"
    fi
}

# Main script logic
while true; do
    show_menu
    read -p "Choose an option (1-15): " choice  # Updated to 15 options

    case $choice in
        1)
            ping_host
            ;;
        2)
            scan_ports
            ;;
        3)
            check_connections
            ;;
        4)
            trace_route
            ;;
        5)
            dns_lookup
            ;;
        6)
            check_open_ports
            ;;
        7)
            advanced_nmap_scan
            ;;
        8)
            check_interfaces
            ;;
        9)
            check_public_ip
            ;;
        10)
            get_ip_address
            ;;
        11)
            list_devices
            ;;
        12)
            block_device
            ;;
        13)
            save_scan_results
            ;;
        14)
            show_device_details
            ;;
        15)
            read -p "Are you sure you want to exit? (y/n): " confirm_exit
            if [[ "$confirm_exit" == "y" || "$confirm_exit" == "Y" ]]; then
                echo -e "${RED}Exiting...${NC}"
                exit 0
            fi
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            ;;
    esac

    read -p "Press Enter to continue..."
done
EOF
)"
}

# Main execution with improved error handling and initialization
main() {
    # Check terminal capabilities
    if ! tput colors &>/dev/null; then
        error "Terminal does not support colors"
        exit 1
    fi
    
    # Initialize
    trap cleanup EXIT
    mkdir -p "$CONFIG_DIR" "$CACHE_DIR"
    : > "$LOG_FILE"
    log "INFO" "Starting $SCRIPT_NAME version $VERSION"
    
    # Check for required commands
    local required_commands=(top free df ip ss awk sed grep bc)
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Start dashboard
    clear
    draw_flag  # Display the Yemeni flag at the start
    show_menu
}

# Start the script
main "$@"