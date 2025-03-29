#!/bin/bash

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

SERVER_IP=""
SCRIPT_VERSION="1.3.1"
SELECTED_VERSION=""
# Default versions if API fetch fails
VERSIONS=()

# Improved user prompt
ask_user() {
    echo -e "${CYAN}${1}${NC}"
    echo -ne "${YELLOW}> ${NC}"
    read -r -n 1 response
    echo
    [[ $response =~ ^[Yy]$ ]]
}

# Print section header
print_header() {
    local text="$1"
    local width=80
    local padding=$(( (width - ${#text}) / 2 ))
    
    echo
    echo -e "${BLUE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    echo -e "${BLUE}$(printf ' %.0s' $(seq 1 $padding))${WHITE}${BOLD}${text}${NC}"
    echo -e "${BLUE}$(printf '═%.0s' $(seq 1 $width))${NC}"
    echo
}

# Print status message
print_status() {
    local status="$1"
    local message="$2"
    local icon=""
    
    case $status in
        "success") 
            icon="✓"
            echo -e "${GREEN}${icon} ${message}${NC}"
            ;;
        "error") 
            icon="✗"
            echo -e "${RED}${icon} ${message}${NC}"
            ;;
        "warning") 
            icon="⚠"
            echo -e "${YELLOW}${icon} ${message}${NC}"
            ;;
        "info") 
            icon="ℹ"
            echo -e "${BLUE}${icon} ${message}${NC}"
            ;;
        *) 
            echo -e "${message}"
            ;;
    esac
}

# Let user select a version
select_version() {
    print_header "Unbound Version Selection"
    
    echo -e "${CYAN}Available Unbound versions:${NC}"
    for i in {0..2}; do
        echo -e "  ${GREEN}$((i+1))${NC}. ${VERSIONS[$i]}"
    done
    
    echo
    echo -ne "${YELLOW}> Please select a version (1-3): ${NC}"
    read -r version_choice
    
    case $version_choice in
        1) SELECTED_VERSION=${VERSIONS[0]} ;;
        2) SELECTED_VERSION=${VERSIONS[1]} ;;
        3) SELECTED_VERSION=${VERSIONS[2]} ;;
        *) 
            print_status "warning" "Invalid choice. Using the latest version."
            SELECTED_VERSION=${VERSIONS[0]}
            ;;
    esac
    
    print_status "info" "Selected Unbound version: ${SELECTED_VERSION}"
    return 0
}

# Then modify the fetch_latest_versions function to handle empty VERSIONS array:
fetch_latest_versions() {
    print_status "info" "Fetching the latest Unbound versions..."
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_status "warning" "jq is not installed. Installing it for JSON parsing..."
        apt update && apt install -y jq
        if ! command -v jq &> /dev/null; then
            print_status "error" "Failed to install jq. Fallback to manual version entry."
            prompt_for_versions
            return 0
        fi
    fi
    
    # Fetch releases with proper error handling
    local api_response
    api_response=$(curl -s -f https://api.github.com/repos/NLnetLabs/unbound/releases)
    if [ $? -ne 0 ] || [ -z "$api_response" ]; then
        print_status "warning" "Failed to fetch version information from GitHub API."
        prompt_for_versions
        return 0
    fi
    
    # Parse the JSON response to extract version numbers
    local fetch_result
    fetch_result=$(echo "$api_response" | jq -r '.[].tag_name' | sed 's/release-//' | head -n 3)
    
    if [ -z "$fetch_result" ]; then
        print_status "warning" "Failed to parse version information."
        prompt_for_versions
        return 0
    else
        # Update the VERSIONS array with the fetched versions
        VERSIONS=($(echo "$fetch_result" | tr '\n' ' '))
        print_status "success" "Successfully fetched latest Unbound versions: ${VERSIONS[0]}, ${VERSIONS[1]}, ${VERSIONS[2]}"
    fi
    
    return 0
}

# Add a new function to prompt the user for versions if API fails
prompt_for_versions() {
    print_status "info" "Please enter Unbound versions manually:"
    
    echo -ne "${YELLOW}Enter latest version (e.g., 1.22.0): ${NC}"
    read -r version1
    
    echo -ne "${YELLOW}Enter second latest version (e.g., 1.21.1): ${NC}"
    read -r version2
    
    echo -ne "${YELLOW}Enter third latest version (e.g., 1.21.0): ${NC}"
    read -r version3
    
    VERSIONS=("$version1" "$version2" "$version3")
    print_status "info" "Using manually entered versions: ${VERSIONS[0]}, ${VERSIONS[1]}, ${VERSIONS[2]}"
}

get_server_ip() {
    print_header "Server IP Configuration"
    
    # Get primary IP address
    SERVER_IP=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
    if [ -z "$SERVER_IP" ]; then
        print_status "warning" "Could not detect server IP automatically."
        echo -ne "${YELLOW}Please enter your server's IP address: ${NC}"
        read -r SERVER_IP
    else
        print_status "info" "Detected server IP: ${BOLD}${SERVER_IP}${NC}"
        if ! ask_user "Is this your server's correct internal IP? [y/n]"; then
            echo -ne "${YELLOW}Please enter your server's IP address: ${NC}"
            read -r SERVER_IP
        fi
    fi
}

# Create individual configuration files
create_main_conf() {
    print_status "info" "Creating main configuration file..."
    
    cat << EOF > /etc/unbound/unbound.conf
# Main configuration file for Unbound DNS Server
# Generated by Unbound Manager v${SCRIPT_VERSION}
include: "/etc/unbound/unbound.conf.d/*.conf"
EOF
    
    chmod 644 /etc/unbound/unbound.conf
    chown unbound:unbound /etc/unbound/unbound.conf
    print_status "success" "Main configuration file created"
}

create_server_conf() {
    print_status "info" "Creating server configuration..."
    
    cat << EOF > /etc/unbound/unbound.conf.d/server.conf
server:
    # Basic setup
    chroot: ""
    verbosity: 1
    interface: ${SERVER_IP}
    interface: 127.0.0.1
    port: 53
    ip-freebind: yes
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    prefer-ip6: no
    use-syslog: yes
    
    # Performance tuning
    num-threads: $(nproc)
    msg-cache-size: 64m
    rrset-cache-size: 128m
    cache-min-ttl: 300
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    
    # Security
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    aggressive-nsec: yes
    
    # Access Control
    access-control: 127.0.0.0/8 allow
    access-control: 172.16.0.0/16 allow
    access-control: 192.168.0.0/16 allow
    
    # Private Addresses
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    
    # Module Configuration
    module-config: "validator cachedb iterator"
EOF
    
    chmod 644 /etc/unbound/unbound.conf.d/server.conf
    chown unbound:unbound /etc/unbound/unbound.conf.d/server.conf
    print_status "success" "Server configuration created"
}

create_control_conf() {
    print_status "info" "Creating control configuration..."
    
    cat << EOF > /etc/unbound/unbound.conf.d/control.conf
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "/etc/unbound/unbound_server.key"
    server-cert-file: "/etc/unbound/unbound_server.pem"
    control-key-file: "/etc/unbound/unbound_control.key"
    control-cert-file: "/etc/unbound/unbound_control.pem"
EOF
    
    chmod 644 /etc/unbound/unbound.conf.d/control.conf
    chown unbound:unbound /etc/unbound/unbound.conf.d/control.conf
    print_status "success" "Control configuration created"
}

create_dnssec_conf() {
    print_status "info" "Creating DNSSEC configuration..."
    
    cat << EOF > /etc/unbound/unbound.conf.d/dnssec.conf
server:
    # DNSSEC Configuration
    auto-trust-anchor-file: "/etc/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    trust-anchor-signaling: yes
    val-log-level: 1
    val-nsec3-keysize-iterations: "1024 150 2048 500 4096 2500"
EOF
    
    chmod 644 /etc/unbound/unbound.conf.d/dnssec.conf
    chown unbound:unbound /etc/unbound/unbound.conf.d/dnssec.conf
    print_status "success" "DNSSEC configuration created"
}

create_redis_conf() {
    print_status "info" "Creating Redis configuration..."
    
    cat << EOF > /etc/unbound/unbound.conf.d/redis.conf
cachedb:
    backend: redis
    redis-server-path: "/var/run/redis/redis.sock"
    redis-timeout: 500
    redis-expire-records: no
EOF
    
    chmod 644 /etc/unbound/unbound.conf.d/redis.conf
    chown unbound:unbound /etc/unbound/unbound.conf.d/redis.conf
    print_status "success" "Redis configuration created"
}

create_root_hints_conf() {
    print_status "info" "Creating root hints configuration..."
    
    cat << EOF > /etc/unbound/unbound.conf.d/root-hints.conf
server:
    # Root Hints and TLS certificates
    root-hints: "/etc/unbound/root.hints"
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
EOF
    
    chmod 644 /etc/unbound/unbound.conf.d/root-hints.conf
    chown unbound:unbound /etc/unbound/unbound.conf.d/root-hints.conf
    print_status "success" "Root hints configuration created"
}

setup_root_hints() {
    print_status "info" "Setting up root hints..."
    
    if [ ! -f "/etc/unbound/root.hints" ]; then
        if ! curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache; then
            print_status "error" "Failed to download root hints file. Trying alternative source..."
            if ! curl -o /etc/unbound/root.hints https://www.dns.icann.org/services/tools/internic/domain/named.cache; then
                print_status "error" "Failed to download root hints from alternative source"
                print_status "warning" "Creating empty root hints file. You'll need to populate it manually."
                touch /etc/unbound/root.hints
            fi
        fi
        
        chown unbound:unbound /etc/unbound/root.hints
        chmod 644 /etc/unbound/root.hints
        print_status "success" "Root hints configured successfully"
    else
        print_status "info" "Root hints file already exists, checking for updates..."
        mv /etc/unbound/root.hints /etc/unbound/root.hints.bak
        if curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache; then
            chown unbound:unbound /etc/unbound/root.hints
            chmod 644 /etc/unbound/root.hints
            rm /etc/unbound/root.hints.bak
            print_status "success" "Root hints updated successfully"
        else
            print_status "error" "Failed to update root hints, restoring backup"
            mv /etc/unbound/root.hints.bak /etc/unbound/root.hints
        fi
    fi
}

setup_trust_anchor() {
    print_status "info" "Setting up DNSSEC trust anchor..."
    
    # Create initial root.key file with known trust anchors if it doesn't exist
    if [ ! -f "/etc/unbound/root.key" ]; then
        cat << EOF > /etc/unbound/root.key
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
EOF
        chown unbound:unbound /etc/unbound/root.key
        chmod 644 /etc/unbound/root.key
        print_status "success" "Created initial trust anchor file"
    fi
    
    # Run unbound-anchor to update the root key
    print_status "info" "Updating trust anchor..."
    if unbound-anchor -a "/etc/unbound/root.key" -c /etc/ssl/certs/ca-certificates.crt; then
        chown unbound:unbound /etc/unbound/root.key
        chmod 644 /etc/unbound/root.key
        print_status "success" "Trust anchor updated successfully"
    else
        print_status "error" "Failed to update trust anchor automatically"
        print_status "warning" "Will continue with existing trust anchor"
    fi
}

generate_control_keys() {
    print_status "info" "Generating control keys..."
    
    if [ ! -f "/etc/unbound/unbound_server.key" ] || [ ! -f "/etc/unbound/unbound_control.key" ]; then
        if ! unbound-control-setup -d /etc/unbound; then
            print_status "error" "Failed to generate control keys. Trying alternative method..."
            cd /etc/unbound || return 1
            openssl req -newkey rsa:2048 -nodes -keyout unbound_server.key -x509 -days 3650 -out unbound_server.pem -subj "/CN=unbound-server"
            openssl req -newkey rsa:2048 -nodes -keyout unbound_control.key -x509 -days 3650 -out unbound_control.pem -subj "/CN=unbound-control"
            
            if [ -f "/etc/unbound/unbound_server.key" ] && [ -f "/etc/unbound/unbound_control.key" ]; then
                print_status "success" "Generated control keys using OpenSSL"
            else
                print_status "error" "Failed to generate control keys"
                return 1
            fi
        else
            print_status "success" "Generated control keys using unbound-control-setup"
        fi
        
        chown unbound:unbound /etc/unbound/unbound_*.key /etc/unbound/unbound_*.pem
        chmod 640 /etc/unbound/unbound_*.key /etc/unbound/unbound_*.pem
    else
        print_status "info" "Control keys already exist"
    fi
}

configure_redis() {
    print_status "info" "Configuring Redis..."
    
    # Check if Redis is installed
    if ! command -v redis-server &> /dev/null; then
        print_status "warning" "Redis is not installed. Installing..."
        apt update
        apt install -y redis-server
    fi
    
    # Backup original Redis configuration
    if [ -f "/etc/redis/redis.conf" ] && [ ! -f "/etc/redis/redis.conf.bak" ]; then
        cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
    fi
    
    # Configure Redis to use Unix socket
    sed -i 's/^port .*/port 0/' /etc/redis/redis.conf
    
    # Check if the socket configuration already exists
    if ! grep -q "unixsocket /var/run/redis/redis.sock" /etc/redis/redis.conf; then
        echo "unixsocket /var/run/redis/redis.sock" >> /etc/redis/redis.conf
        echo "unixsocketperm 770" >> /etc/redis/redis.conf
    fi
    
    # Create the Redis run directory if it doesn't exist
    mkdir -p /var/run/redis
    chown redis:redis /var/run/redis
    chmod 775 /var/run/redis
    
    # Add unbound user to redis group
    usermod -a -G redis unbound
    
    # Restart Redis
    systemctl restart redis-server
    
    # Check if Redis is running
    if systemctl is-active --quiet redis-server; then
        print_status "success" "Redis configured and started successfully"
    else
        print_status "error" "Failed to start Redis. Check logs with: journalctl -xe -u redis-server"
    fi
}

create_systemd_service() {
    print_status "info" "Creating systemd service file..."
    
    cat << EOF > /etc/systemd/system/unbound.service
[Unit]
Description=Unbound DNS server
Documentation=man:unbound(8)
After=network.target redis-server.service
Wants=nss-lookup.target
Before=nss-lookup.target

[Service]
Type=simple
Restart=on-failure
EnvironmentFile=-/etc/default/unbound
ExecStartPre=/usr/sbin/unbound-checkconf
ExecStart=/usr/sbin/unbound -d
ExecReload=/usr/sbin/unbound-control reload
PIDFile=/run/unbound.pid

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_status "success" "Systemd service file created"
}

setup_directories() {
    print_status "info" "Setting up directories..."
    
    mkdir -p /etc/unbound/unbound.conf.d
    mkdir -p /etc/unbound/backups
    
    chown -R unbound:unbound /etc/unbound
    chmod 755 /etc/unbound
    chmod 755 /etc/unbound/unbound.conf.d
    chmod 755 /etc/unbound/backups
    
    print_status "success" "Directories setup completed"
}

install_dependencies() {
    print_status "info" "Installing dependencies..."
    
    apt update
    apt install -y build-essential libssl-dev libexpat1-dev libevent-dev \
                   libhiredis-dev curl jq libnghttp2-dev python3-dev \
                   libsystemd-dev swig protobuf-c-compiler libprotobuf-c-dev \
                   redis-server ca-certificates openssl ntpdate
    
    # Ensure time is synchronized
    print_status "info" "Synchronizing system time..."
    ntpdate -u pool.ntp.org
}

verify_installation() {
    print_status "info" "Verifying Unbound installation..."
    
    # Check if unbound is installed
    if ! command -v unbound &> /dev/null; then
        print_status "error" "Unbound is not installed"
        return 1
    fi
    
    # Check configuration
    print_status "info" "Checking configuration..."
    if ! unbound-checkconf; then
        print_status "error" "Unbound configuration is invalid"
        return 1
    fi
    
    # Try to start the service
    print_status "info" "Starting Unbound service..."
    systemctl restart unbound
    
    # Wait a moment for service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet unbound; then
        print_status "success" "Unbound service is running"
    else
        print_status "error" "Unbound service failed to start. Checking logs..."
        journalctl -xe -u unbound | tail -n 30
        return 1
    fi
    
    # Test DNS resolution
    print_status "info" "Testing DNS resolution..."
    if dig @127.0.0.1 google.com +short | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$'; then
        print_status "success" "DNS resolution is working"
    else
        print_status "error" "DNS resolution failed"
        return 1
    fi
    
    return 0
}

install_unbound() {
    print_header "Installing Unbound DNS Server"
    
    print_status "info" "Installing dependencies..."
    install_dependencies
    
    if ask_user "Do you want to use the recommended configuration? [y/n]"; then
        get_server_ip
    fi
    
    # Fetch and select version
    fetch_latest_versions
    select_version
    
    print_status "info" "Installing Unbound version: ${SELECTED_VERSION}"
    
    # Download and extract
    if ! wget "https://nlnetlabs.nl/downloads/unbound/unbound-${SELECTED_VERSION}.tar.gz"; then
        print_status "error" "Failed to download Unbound. Check your internet connection."
        return 1
    fi
    
    tar -xzvf "unbound-${SELECTED_VERSION}.tar.gz"
    cd "unbound-${SELECTED_VERSION}" || return 1
    
    # Configure
    print_status "info" "Configuring Unbound..."
    ./configure --prefix=/usr \
                --sysconfdir=/etc \
                --with-libevent \
                --with-libhiredis \
                --with-libnghttp2 \
                --with-pidfile=/run/unbound.pid \
                --with-rootkey-file=/etc/unbound/root.key \
                --enable-subnet \
                --enable-tfo-client \
                --enable-tfo-server
    
    if [ $? -ne 0 ]; then
        print_status "error" "Configuration failed"
        return 1
    fi
    
    # Compile and install
    print_status "info" "Compiling and installing Unbound..."
    make && make install
    if [ $? -ne 0 ]; then
        print_status "error" "Compilation failed"
        return 1
    fi
    
    ldconfig
    
    # Create unbound user if not exists
    if ! id -u unbound &>/dev/null; then
        useradd -r -s /bin/false unbound
    fi
    
    # Setup directories
    setup_directories
    
    # Setup components
    if ask_user "Do you want to use the recommended configuration? [y/n]"; then
        create_main_conf
        create_server_conf
        create_control_conf
        create_dnssec_conf
        create_redis_conf
        create_root_hints_conf
    else
        # Use minimal configuration
        cat << EOF > /etc/unbound/unbound.conf
include: "/etc/unbound/unbound.conf.d/*.conf"
EOF
        chmod 644 /etc/unbound/unbound.conf
        chown unbound:unbound /etc/unbound/unbound.conf
    fi
    
    setup_root_hints
    setup_trust_anchor
    generate_control_keys
    configure_redis
    create_systemd_service
    
    # Enable and start the service
    systemctl enable unbound
    systemctl restart unbound
    
    # Verify installation
    if verify_installation; then
        print_status "success" "Unbound installed and configured successfully"
    else
        print_status "error" "Unbound installation encountered issues"
        print_status "warning" "Check the logs above for details"
    fi
    
    # Clean up
    cd .. || return 1
    rm -rf "unbound-${SELECTED_VERSION}" "unbound-${SELECTED_VERSION}.tar.gz"
}

backup_configuration() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/etc/unbound/backups/backup_${timestamp}"
    
    print_status "info" "Creating backup in ${backup_dir}"
    mkdir -p "${backup_dir}"
    
    # Copy all configuration files
    cp -r /etc/unbound/unbound.conf "${backup_dir}/"
    if [ -d "/etc/unbound/unbound.conf.d" ]; then
        mkdir -p "${backup_dir}/unbound.conf.d"
        cp -r /etc/unbound/unbound.conf.d/* "${backup_dir}/unbound.conf.d/"
    fi
    
    # Copy keys and other important files
    for file in root.key root.hints unbound_*.key unbound_*.pem; do
        if [ -f "/etc/unbound/${file}" ]; then
            cp "/etc/unbound/${file}" "${backup_dir}/"
        fi
    done
    
    print_status "success" "Backup created in ${backup_dir}"
}

troubleshoot_unbound() {
    print_status "info" "Troubleshooting Unbound..."
    
    # Check permissions
    print_status "info" "Checking permissions..."
    find /etc/unbound -type f -exec ls -l {} \;
    
    # Check configuration
    print_status "info" "Checking configuration..."
    unbound-checkconf -v
    
    # Check logs
    print_status "info" "Checking logs..."
    journalctl -xe -u unbound | tail -n 50
    
    # Check if Redis is accessible
    print_status "info" "Checking Redis..."
    if ! systemctl is-active --quiet redis-server; then
        print_status "error" "Redis is not running. Starting Redis..."
        systemctl start redis-server
    fi
    
    # Check socket permissions
    print_status "info" "Checking Redis socket..."
    ls -la /var/run/redis/
    
    # Ensure unbound user is in redis group
    print_status "info" "Ensuring unbound is in redis group..."
    usermod -a -G redis unbound
    id unbound
    
    # Ensure the proper root.key exists
    print_status "info" "Checking DNSSEC trust anchor..."
    if [ ! -f "/etc/unbound/root.key" ]; then
        print_status "error" "root.key is missing. Recreating..."
        setup_trust_anchor
    fi
    
    # Try restarting unbound with additional verbosity
    if [ -f "/etc/unbound/unbound.conf.d/server.conf" ]; then
        print_status "info" "Temporarily increasing verbosity for troubleshooting..."
        sed -i 's/verbosity: [0-9]/verbosity: 3/' /etc/unbound/unbound.conf.d/server.conf 2>/dev/null
        systemctl restart unbound
        sleep 2
        
        # Show service status
        systemctl status unbound
        
        # Restore verbosity
        sed -i 's/verbosity: [0-9]/verbosity: 1/' /etc/unbound/unbound.conf.d/server.conf 2>/dev/null
    else
        systemctl status unbound
    fi
    
    print_status "info" "Troubleshooting complete. Check the above output for issues."
}

test_unbound() {
    print_header "Unbound DNS System - Interactive Test Suite"
    
    # Function to pause and wait for user input between tests
    pause_for_user() {
        echo
        echo -e "${YELLOW}Press Enter to continue to the next test...${NC}"
        read -r
        clear
    }
    
    # Check if bc is installed
    check_bc_installed() {
        if ! command -v bc &> /dev/null; then
            print_status "warning" "The 'bc' command is not installed. Some calculations may not work correctly."
            print_status "info" "You can install it with: apt-get install bc"
            return 1
        fi
        return 0
    }
    
    # 1. SERVICE STATUS CHECKS
    print_header "Step 1/8: Service Status Checks"
    for service in unbound redis-server; do
        print_status "info" "Checking ${service} status..."
        if systemctl is-active --quiet $service; then
            print_status "success" "${service} service is running"
            systemctl status $service | head -n 3
        else
            print_status "error" "${service} service is not running"
            print_status "info" "Detailed status:"
            systemctl status $service | head -n 10
        fi
    done
    pause_for_user
    
    # 2. DNS RESOLUTION TESTS
    print_header "Step 2/8: DNS Resolution Tests"
    
    # IPv4 resolution
    print_status "info" "Testing IPv4 DNS resolution..."
    echo -e "${CYAN}Running: dig @127.0.0.1 A google.com +short${NC}"
    ipv4_result=$(dig @127.0.0.1 A google.com +short)
    if echo "$ipv4_result" | grep -q "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$"; then
        print_status "success" "IPv4 resolution working"
        echo "$ipv4_result" | head -n 4  # Show first 4 IPs to keep it clean
    else
        print_status "error" "IPv4 resolution failed"
    fi
    
    # IPv6 resolution (if enabled)
    if grep -q "do-ip6: yes" /etc/unbound/unbound.conf.d/server.conf 2>/dev/null; then
        print_status "info" "Testing IPv6 DNS resolution..."
        echo -e "${CYAN}Running: dig @127.0.0.1 AAAA google.com +short${NC}"
        dig @127.0.0.1 AAAA google.com +short
    fi
    
    # MX record test
    print_status "info" "Testing MX record resolution..."
    echo -e "${CYAN}Running: dig @127.0.0.1 MX gmail.com${NC}"
    mx_result=$(dig @127.0.0.1 MX gmail.com)
    if echo "$mx_result" | grep -q "IN[[:space:]]\+MX"; then
        print_status "success" "MX record resolution working"
        echo "$mx_result" | grep "IN[[:space:]]\+MX" | head -n 3
    else
        # Try alternative MX test with example.com which is more likely to work
        print_status "warning" "MX record test with gmail.com didn't return expected results, trying example.com..."
        alt_mx_result=$(dig @127.0.0.1 MX example.com)
        if echo "$alt_mx_result" | grep -q "IN[[:space:]]\+MX"; then
            print_status "success" "MX record resolution working with example.com"
            echo "$alt_mx_result" | grep "IN[[:space:]]\+MX" | head -n 3
        else
            print_status "error" "MX record resolution failed for both gmail.com and example.com"
        fi
    fi
    
    # TXT record test
    print_status "info" "Testing TXT record resolution..."
    echo -e "${CYAN}Running: dig @127.0.0.1 TXT google.com +short${NC}"
    txt_result=$(dig @127.0.0.1 TXT google.com +short | head -n 5)  # Limit to 5 records
    if [ -n "$txt_result" ]; then
        print_status "success" "TXT record resolution working"
        echo "$txt_result"
    else
        print_status "error" "TXT record resolution failed"
    fi
    pause_for_user
    
    # 3. DNSSEC VALIDATION TESTS
    print_header "Step 3/8: DNSSEC Validation Tests"
    
    # DNSSEC positive validation
    print_status "info" "Testing DNSSEC validation with a signed domain..."
    echo -e "${CYAN}Running: dig @127.0.0.1 +dnssec iana.org${NC}"
    dnssec_result=$(dig @127.0.0.1 +dnssec iana.org)
    if echo "$dnssec_result" | grep -q "flags:.*ad"; then
        print_status "success" "DNSSEC validation successful for iana.org (AD flag present)"
        echo "$dnssec_result" | grep -E "flags:|RRSIG" | head -n 3
    else
        print_status "warning" "DNSSEC validation for iana.org did not return AD flag"
        print_status "info" "This might be normal if DNSSEC validation is not enabled"
        echo "$dnssec_result" | grep "flags:" | head -n 1
    fi
    
    # DNSSEC negative validation (should fail)
    print_status "info" "Testing DNSSEC failure detection..."
    echo -e "${CYAN}Running: dig @127.0.0.1 dnssec-failed.org${NC}"
    dnssec_fail_result=$(dig @127.0.0.1 dnssec-failed.org)
    if echo "$dnssec_fail_result" | grep -q "SERVFAIL"; then
        print_status "success" "DNSSEC correctly rejected invalid signatures"
        echo "$dnssec_fail_result" | head -n 6
    else
        print_status "error" "DNSSEC failed to reject invalid signatures - this indicates DNSSEC may not be working properly"
        echo "$dnssec_fail_result" | head -n 6
    fi
    
    # DNSSEC root key check
    print_status "info" "Checking DNSSEC root trust anchor..."
    if [ -f "/etc/unbound/root.key" ]; then
        print_status "success" "DNSSEC root trust anchor exists"
        head -n 5 /etc/unbound/root.key
    else
        print_status "error" "DNSSEC root trust anchor is missing"
    fi
    pause_for_user
    
    # 4. REDIS INTEGRATION TESTS
    print_header "Step 4/8: Redis Integration Tests"
    
    # Check Redis service
    print_status "info" "Checking Redis status..."
    if systemctl is-active --quiet redis-server; then
        print_status "success" "Redis service is running"
    else
        print_status "error" "Redis service is not running"
        print_status "info" "Attempting to start Redis..."
        systemctl start redis-server
        sleep 2
        if systemctl is-active --quiet redis-server; then
            print_status "success" "Redis service started successfully"
        else
            print_status "error" "Failed to start Redis service"
            systemctl status redis-server | head -n 10
        fi
    fi
    
    # Check Redis connection
    print_status "info" "Testing Redis connection..."
    if redis-cli -s /var/run/redis/redis.sock ping 2>/dev/null | grep -q "PONG"; then
        print_status "success" "Redis connection successful via Unix socket"
    else
        print_status "error" "Redis connection failed via Unix socket"
        print_status "info" "Checking socket file permissions:"
        ls -la /var/run/redis/
    fi
    
    # Test Redis caching
    print_status "info" "Testing DNS caching with Redis..."
    
    # Clear Redis cache
    print_status "info" "Clearing Redis cache..."
    redis-cli -s /var/run/redis/redis.sock flushall >/dev/null 2>&1
    
    # Make first query to cache
    print_status "info" "Making initial query to populate cache..."
    time dig @127.0.0.1 example.com >/dev/null 2>&1
    
    # Check if items stored in Redis
    REDIS_KEYS=$(redis-cli -s /var/run/redis/redis.sock keys "*" 2>/dev/null | wc -l)
    if [ "$REDIS_KEYS" -gt 0 ]; then
        print_status "success" "Redis cache populated with $REDIS_KEYS keys"
        print_status "info" "Sample of cached keys:"
        redis-cli -s /var/run/redis/redis.sock keys "*" 2>/dev/null | head -n 3
    else
        print_status "warning" "No keys found in Redis cache. Cache integration may not be working."
    fi
    
    # Test cache hit - should be faster
    print_status "info" "Testing query speed with cache (should be faster)..."
    time dig @127.0.0.1 example.com >/dev/null 2>&1
    
    # Redis statistics
    print_status "info" "Redis cache statistics:"
    echo -e "${CYAN}Running: redis-cli -s /var/run/redis/redis.sock info | grep -E 'used_memory|keys|connected'${NC}"
    redis_stats=$(redis-cli -s /var/run/redis/redis.sock info | grep -E "used_memory|keys|connected|db0")
    echo "$redis_stats" | head -n 15
    pause_for_user
    
    # 5. UNBOUND PERFORMANCE TESTS
    print_header "Step 5/8: Unbound Performance Tests"
    
    # Check if bc is installed
    print_status "info" "Checking for bc calculator utility..."
    if command -v bc &> /dev/null; then
        bc_installed=true
        print_status "success" "bc utility is available for calculations"
    else
        bc_installed=false
        print_status "warning" "bc utility is not installed - some calculations will be skipped"
        print_status "info" "You can install it with: apt-get install bc"
    fi
    
    # Query performance test
    print_status "info" "Testing query performance (10 sequential queries)..."
    if $bc_installed; then
        start_time=$(date +%s.%N)
        for i in {1..10}; do
            dig @127.0.0.1 +short example.com >/dev/null 2>&1
        done
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc 2>/dev/null)
        avg_time=$(echo "$duration / 10" | bc -l 2>/dev/null)
        
        if [ -n "$avg_time" ]; then
            avg_time_ms=$(echo "$avg_time * 1000" | bc 2>/dev/null)
            print_status "success" "Average query time: ${avg_time_ms} milliseconds"
        else
            print_status "info" "Total time for 10 queries: ${duration} seconds"
        fi
    else
        # Fallback if bc is not installed
        print_status "info" "Running time measurement without precise calculation:"
        time for i in {1..10}; do dig @127.0.0.1 +short example.com >/dev/null 2>&1; done
    fi
    
    # Concurrent query test
    print_status "info" "Testing concurrent query performance (10 parallel queries)..."
    echo -e "${CYAN}Running 10 parallel dig queries with time measurement...${NC}"
    time (for i in {1..10}; do dig @127.0.0.1 +short example$i.com >/dev/null 2>&1 & done; wait)
    pause_for_user
    
    # 6. UNBOUND CONTROL & STATISTICS
    print_header "Step 6/8: Unbound Control & Statistics"
    
    # Check control interface
    print_status "info" "Testing unbound-control..."
    unbound_status=$(unbound-control status 2>&1)
    if echo "$unbound_status" | grep -q "is running"; then
        print_status "success" "Unbound control interface is working"
        echo "$unbound_status"
    else
        print_status "error" "Unbound control interface failed"
        print_status "info" "Checking control keys and certificates:"
        ls -la /etc/unbound/unbound_*.key /etc/unbound/unbound_*.pem 2>/dev/null
    fi
    
    # Retrieve statistics
    print_status "info" "Retrieving Unbound statistics..."
    echo -e "${CYAN}Running: unbound-control stats${NC}"
    stats_output=$(unbound-control stats 2>&1)
    if [ $? -eq 0 ]; then
        print_status "success" "Statistics retrieved successfully"
        echo "$stats_output" | grep -E "thread0|num.queries|cachehits|cachemiss|recursion.time" | head -n 15
    else
        print_status "error" "Failed to retrieve statistics"
        echo "$stats_output"
    fi
    
    # Memory usage
    print_status "info" "Checking Unbound memory usage..."
    echo -e "${CYAN}Unbound memory usage:${NC}"
    ps -o pid,user,%mem,rss,vsz,cmd -p $(pidof unbound)
    pause_for_user
    
    # 7. CONFIGURATION VALIDATION
    print_header "Step 7/8: Configuration Validation"
    
    # Check main config file syntax
    print_status "info" "Validating configuration syntax..."
    config_check=$(unbound-checkconf 2>&1)
    if [ $? -eq 0 ]; then
        print_status "success" "Configuration syntax is valid"
    else
        print_status "error" "Configuration syntax is invalid"
        echo "$config_check"
    fi
    
    # Check config files permissions
    print_status "info" "Checking configuration file permissions..."
    permission_issues=$(find /etc/unbound -type f -name "*.conf" -exec ls -l {} \; | grep -v "^-rw-r--r--")
    if [ -n "$permission_issues" ]; then
        print_status "warning" "Some configuration files have incorrect permissions"
        echo "$permission_issues"
    else
        print_status "success" "All configuration files have correct permissions"
    fi
    
    # Check configuration options
    print_status "info" "Checking key configuration settings..."
    echo -e "${CYAN}DNSSEC enabled:${NC} $(grep -q "auto-trust-anchor-file" /etc/unbound/unbound.conf.d/*.conf 2>/dev/null && echo "Yes" || echo "No")"
    echo -e "${CYAN}Cache size:${NC} $(grep "cache-size\|msg-cache-size\|rrset-cache-size" /etc/unbound/unbound.conf.d/*.conf 2>/dev/null | head -n 2)"
    echo -e "${CYAN}Number of threads:${NC} $(grep "num-threads" /etc/unbound/unbound.conf.d/*.conf 2>/dev/null)"
    echo -e "${CYAN}Redis integration:${NC} $(grep -q "backend: redis" /etc/unbound/unbound.conf.d/*.conf 2>/dev/null && echo "Enabled" || echo "Not enabled")"
    pause_for_user
    
    # 8. NETWORK AND SYSTEM TESTS
    print_header "Step 8/8: Network and System Tests"
    
    # Check listening ports
    print_status "info" "Checking listening ports..."
    echo -e "${CYAN}Running: ss -tuln | grep ':53'${NC}"
    dns_ports=$(ss -tuln | grep ':53')
    if [ -n "$dns_ports" ]; then
        print_status "success" "DNS port (53) is open and listening"
        echo "$dns_ports" | head -n 8
        if [ $(echo "$dns_ports" | wc -l) -gt 8 ]; then
            print_status "info" "...and $(( $(echo "$dns_ports" | wc -l) - 8 )) more"
        fi
    else
        print_status "error" "DNS port (53) is not listening"
    fi
    
    # Check network interfaces
    print_status "info" "Checking network interfaces..."
    echo -e "${CYAN}Network interfaces:${NC}"
    ip -4 addr | grep -E 'inet '
    
    # Check system resources
    print_status "info" "Checking system resources..."
    echo -e "${CYAN}Memory usage:${NC}"
    free -h
    
    echo -e "${CYAN}Disk usage:${NC}"
    df -h | grep -E '/$|/var'
    
    # Final test summary
    print_header "Test Summary Report"
    
    # Collect key indicators
    dns_resolving=$(dig @127.0.0.1 +short example.com | grep -q "^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$" && echo "Working" || echo "Failed")
    dnssec_status=$(dig @127.0.0.1 +dnssec iana.org | grep -q "flags:.*ad" && echo "Validated" || echo "Not validated")
    redis_connected=$(redis-cli -s /var/run/redis/redis.sock ping 2>/dev/null | grep -q "PONG" && echo "Connected" || echo "Not connected")
    unbound_control=$(unbound-control status 2>/dev/null | grep -q "is running" && echo "Working" || echo "Not working")
    
    # Display the summary
    echo -e "${CYAN}DNS Resolution:${NC} $dns_resolving"
    echo -e "${CYAN}DNSSEC Validation:${NC} $dnssec_status"
    echo -e "${CYAN}Redis Caching:${NC} $redis_connected"
    echo -e "${CYAN}Unbound Control:${NC} $unbound_control"
    echo -e "${CYAN}Configuration:${NC} $([ $? -eq 0 ] && echo "Valid" || echo "Invalid")"
    
    print_status "info" "Comprehensive system testing completed."
    echo
    echo -e "${CYAN}If any tests failed, use the troubleshooting option (Option 7) in the main menu.${NC}"
}

fix_existing_installation() {
    print_header "Fixing Existing Unbound Installation"
    
    # Backup current configuration
    backup_configuration
    
    # Create proper directory structure
    setup_directories
    
    # Fix configuration files
    create_main_conf
    
    # Check if config files exist and create them if not
    if [ ! -f "/etc/unbound/unbound.conf.d/server.conf" ]; then
        get_server_ip
        create_server_conf
    fi
    
    if [ ! -f "/etc/unbound/unbound.conf.d/control.conf" ]; then
        create_control_conf
    fi
    
    if [ ! -f "/etc/unbound/unbound.conf.d/dnssec.conf" ]; then
        create_dnssec_conf
    fi
    
    if [ ! -f "/etc/unbound/unbound.conf.d/redis.conf" ]; then
        create_redis_conf
    fi
    
    if [ ! -f "/etc/unbound/unbound.conf.d/root-hints.conf" ]; then
        create_root_hints_conf
    fi
    
    # Check and fix root.hints
    if [ ! -f "/etc/unbound/root.hints" ]; then
        setup_root_hints
    fi
    
    # Check and fix root.key
    if [ ! -f "/etc/unbound/root.key" ]; then
        setup_trust_anchor
    fi
    
    # Check and fix control keys
    if [ ! -f "/etc/unbound/unbound_server.key" ] || [ ! -f "/etc/unbound/unbound_control.key" ]; then
        generate_control_keys
    fi
    
    # Configure Redis
    configure_redis
    
    # Create/fix systemd service
    create_systemd_service
    
    # Restart services
    systemctl restart redis-server
    systemctl restart unbound
    
    # Verify installation
    if systemctl is-active --quiet unbound; then
        print_status "success" "Unbound service is now running"
    else
        print_status "error" "Unbound service failed to start after fixes"
        print_status "warning" "Running troubleshooter..."
        troubleshoot_unbound
    fi
}

show_banner() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}║${WHITE}${BOLD}                UNBOUND DNS SERVER MANAGER                  ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║${CYAN}                         Version ${SCRIPT_VERSION}                        ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}║                                                                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}A complete solution for Unbound DNS server management${NC}"
    echo -e "${CYAN}Secure, Reliable, and Easy to Configure${NC}"
    echo
}

show_menu() {
    show_banner
    
    echo -e "${WHITE}${BOLD} [ INSTALLATION & SETUP ]${NC}"
    echo -e "  ${GREEN}1${NC}. Install Unbound (Fresh Installation)"
    echo -e "  ${GREEN}2${NC}. Fix Existing Installation"
    echo
    echo -e "${WHITE}${BOLD} [ MAINTENANCE ]${NC}"
    echo -e "  ${GREEN}3${NC}. Backup Current Configuration" 
    echo -e "  ${GREEN}4${NC}. Update DNSSEC Trust Anchor"
    echo -e "  ${GREEN}5${NC}. Configure Redis Integration"
    echo -e "  ${GREEN}6${NC}. Regenerate Control Keys"
    echo
    echo -e "${WHITE}${BOLD} [ TROUBLESHOOTING ]${NC}"
    echo -e "  ${GREEN}7${NC}. Troubleshoot Existing Installation"
    echo -e "  ${GREEN}8${NC}. Test Unbound Functionality"
    echo
    echo -e "${WHITE}${BOLD} [ SYSTEM ]${NC}"
    echo -e "  ${GREEN}9${NC}. Exit"
    echo
    echo -e "${BLUE}$(printf '─%.0s' $(seq 1 64))${NC}"
    echo -ne "${YELLOW}> Please select an option (1-9): ${NC}"
    read -r choice
}

# Main function
main() {
    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
    
    while true; do
        show_menu
        
        case $choice in
            1)
                # Call install function directly without progress wrapper
                install_unbound
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            2)
                fix_existing_installation
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            3)
                backup_configuration
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            4)
                setup_trust_anchor
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            5)
                configure_redis
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            6)
                generate_control_keys
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            7)
                troubleshoot_unbound
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            8)
                test_unbound
                echo -e "${CYAN}Press Enter to continue...${NC}"
                read -r
                ;;
            9)
                print_status "info" "Exiting"
                exit 0
                ;;
            *)
                print_status "error" "Invalid option. Please try again."
                sleep 1
                ;;
        esac
    done
}

# Run the main function
main
