#!/bin/bash

# A comprehensive script to set up and manage a WireGuard VPN server
# with multiple public IPs.
#
# Features:
# - Routes client traffic through the public IP they connected via.
# - Manages public IPs, clients, and server configuration.
# - Starts WireGuard on boot.

set -e # Exit immediately if a command exits with a non-zero status.

CONFIG_DIR="/etc/wireguard"
SERVER_CONFIG="${CONFIG_DIR}/wg0.conf"
IP_MAPPING_FILE="${CONFIG_DIR}/ip_mappings.conf"
CLIENT_DIR="${CONFIG_DIR}/clients"
LOGIN_USER=$(logname)
DEST_DIR=$(eval echo "~$LOGIN_USER/wireguard_clients")

# --- Utility Functions ---

function is_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "❌ This script must be run as root. Please use 'sudo'."
        exit 1
    fi
}

function install_dependencies() {
    echo "▶️ Installing required packages (wireguard, qrencode, iptables-persistent)..."
    apt-get update
    if ! command -v wg &> /dev/null; then
        apt-get install -y wireguard
    fi
    if ! command -v qrencode &> /dev/null; then
        apt-get install -y qrencode
    fi
    if ! dpkg -s iptables-persistent &> /dev/null; then
        apt-get install -y iptables-persistent
    fi
    echo "✅ Dependencies checked and installed as needed."
}

function get_next_client_ip() {
    # Generates the next client IP in the range 10.126.0.1 to 10.126.255.254
    local base_network="10.126."
    local last_ip_str
    
    # Grep for all server and client IPs (e.g., 10.126.x.y) and find the highest one
    last_ip_str=$(grep -oE "${base_network}[0-9]+\.[0-9]+" "$SERVER_CONFIG" | sort -t '.' -k 3,3n -k 4,4n | tail -1)

    # Break the last IP into its 3rd and 4th octets
    local octet3 octet4
    octet3=$(echo "$last_ip_str" | cut -d'.' -f3)
    octet4=$(echo "$last_ip_str" | cut -d'.' -f4)

    # Increment the IP address
    octet4=$((octet4 + 1))
    if [ "$octet4" -gt 254 ]; then
        octet4=1
        octet3=$((octet3 + 1))
        if [ "$octet3" -gt 255 ]; then
            echo "ERROR: IP address range (10.126.0.0/16) has been exhausted!" >&2
            exit 1
        fi
    fi

    echo "${base_network}${octet3}.${octet4}"
}

function set_client_isolation() {
    read -rp "🔒 Prevent clients from seeing each other? (recommended) [y/n, default: y]: " choice
    choice=${choice,,} # lower case
    choice=${choice:-y}

    if [[ "$choice" == "n" || "$choice" == "no" ]]; then
        echo "⚠️ Client-to-client communication will be allowed."
        iptables -D FORWARD -i wg0 -o wg0 -s 10.126.0.0/16 -d 10.126.0.0/16 -j DROP 2>/dev/null || true
    else
        echo "🔒 Enabling client isolation (blocking wg0 to wg0 forwarding)..."
        iptables -C FORWARD -i wg0 -o wg0 -s 10.126.0.0/16 -d 10.126.0.0/16 -j DROP 2>/dev/null || \
        iptables -I FORWARD -i wg0 -o wg0 -s 10.126.0.0/16 -d 10.126.0.0/16 -j DROP
    fi

    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent
}

function show_wg_status() {
    local interfaces
    interfaces=$(wg show interfaces)

    if [ -z "$interfaces" ]; then
        echo "🔴 No active WireGuard interface found"
    else
        for iface in $interfaces; do
            local port
            port=$(wg show "$iface" | grep 'listening port' | awk '{print $3}')
            echo "🟢 $iface is UP (Listening on port $port)"
        done
    fi
}

# --- Initial Setup ---

function initial_setup() {
    echo "🚀 Starting WireGuard initial setup..."

    install_dependencies
    mkdir -p "$CONFIG_DIR" "$CLIENT_DIR"
    touch "$IP_MAPPING_FILE"

    # Prompt for WireGuard port
    read -rp "Enter WireGuard port [default: 51820]: " server_port
    server_port=${server_port:-51820}
    echo "$server_port" > "${CONFIG_DIR}/server_port"

    # Generate Server Keys
    if [ ! -f "${CONFIG_DIR}/server_private.key" ]; then
        echo "🔑 Generating server keys..."
        wg genkey | tee "${CONFIG_DIR}/server_private.key" | wg pubkey > "${CONFIG_DIR}/server_public.key"
        chmod 600 "${CONFIG_DIR}/server_private.key"
    else
        echo "✅ Server keys already exist."
    fi

    # Enable IP Forwarding
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        echo "✅ IP forwarding enabled."
    else
        echo "✅ IP forwarding is already enabled."
    fi

    # Allow all forwarded traffic to and from the wireguard interface
    iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent

    # Add the first public IP
    echo "--------------------------------------------------"
    echo "Detecting and adding the first public IP."
    echo "--------------------------------------------------"
    AUTO_INTERFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
    AUTO_PRIVATE_IP=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
    AUTO_PUBLIC_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)

    if [[ -n "$AUTO_PUBLIC_IP" && -n "$AUTO_PRIVATE_IP" && -n "$AUTO_INTERFACE" ]]; then
        add_public_ip
        unset AUTO_PUBLIC_IP AUTO_PRIVATE_IP AUTO_INTERFACE
    else
        echo "❌ Auto-detection failed. Please add first public IP manually."
        add_public_ip
    fi

    # Create server config
    local server_private_key
    server_private_key=$(cat "${CONFIG_DIR}/server_private.key")
    local first_private_ip
    first_private_ip=$(head -n 1 "$IP_MAPPING_FILE" | cut -d' ' -f2)

    cat > "$SERVER_CONFIG" <<-EOF
[Interface]
Address = 10.126.0.1/16
SaveConfig = false
PrivateKey = ${server_private_key}
ListenPort = ${server_port}
EOF
    echo "✅ Server configuration file created at ${SERVER_CONFIG}"

    # Enable and start the WireGuard service
    if ! systemctl is-enabled --quiet wg-quick@wg0; then
        systemctl enable wg-quick@wg0
        echo "✅ WireGuard service enabled to start on boot."
    fi

    if ! systemctl is-active --quiet wg-quick@wg0; then
        systemctl start wg-quick@wg0
        echo "✅ WireGuard service started."
    else
        # If already active, restart to apply changes
        systemctl restart wg-quick@wg0
        echo "✅ WireGuard service restarted to apply new configuration."
    fi

    echo "✅ WireGuard server will listen on UDP port ${server_port}. Make sure to open it in your firewall."
    echo "🎉 Initial setup complete! Your WireGuard server is running."
}

# --- IP Management Functions ---

function add_public_ip() {
    echo "➕ Adding a new Public IP..."
    local public_ip private_ip interface

    if [ -n "$AUTO_PUBLIC_IP" ] && [ -n "$AUTO_PRIVATE_IP" ] && [ -n "$AUTO_INTERFACE" ]; then
        public_ip="$AUTO_PUBLIC_IP"
        private_ip="$AUTO_PRIVATE_IP"
        interface="$AUTO_INTERFACE"
        echo "⚙️ Auto-adding public IP: $public_ip via $interface ($private_ip)"
    else
        read -rp "Enter Public IP: " public_ip
        read -rp "Enter corresponding Private IP (from 'ip a'): " private_ip
        read -rp "Enter the main network interface name (default: eth0): " interface
    fi

    # Trim extra spaces
    public_ip=$(echo "$public_ip" | xargs)
    private_ip=$(echo "$private_ip" | xargs)
    interface=$(echo "${interface:-eth0}" | xargs)

    # Validate IP addresses
    if ! [[ "$public_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "❌ Invalid public IP format."
        return
    fi

    if ! [[ "$private_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "❌ Invalid private IP format."
        return
    fi

    # Check for duplicate public entries
    if awk '{print $1}' "$IP_MAPPING_FILE" | grep -Fxq "$public_ip"; then
        echo "⚠️ This public IP is already configured."
        return
    fi
    
    # Check for duplicate private IP
    if awk '{print $2}' "$IP_MAPPING_FILE" | grep -Fxq "$private_ip"; then
        echo "⚠️ This private IP is already assigned to another public IP."
        return
    fi
    
    # Add the IP to the mappings file
    echo "${public_ip} ${private_ip} ${interface}" >> "$IP_MAPPING_FILE"

    echo "✅ Public IP ${public_ip} added."
}

function delete_public_ip() {
    echo "➖ Deleting a Public IP..."
    if [ ! -s "$IP_MAPPING_FILE" ]; then
        echo "ℹ️ No public IPs configured yet."
        return
    fi

    local ip_to_delete
    mapfile -t lines < "$IP_MAPPING_FILE"
    select choice in "${lines[@]}" "Cancel"; do
        case "$choice" in
            "Cancel") echo "Cancelled."; return ;;
            *) ip_to_delete="$choice"; break ;;
        esac
    done

    if [ -z "$ip_to_delete" ]; then
        echo "❌ Invalid selection."
        return
    fi

    local public_ip private_ip interface
    public_ip=$(echo "$ip_to_delete" | cut -d' ' -f1)

    # Remove from mappings file
    awk -v ip="$public_ip" '$1 != ip' "$IP_MAPPING_FILE" > "${IP_MAPPING_FILE}.tmp" && mv "${IP_MAPPING_FILE}.tmp" "$IP_MAPPING_FILE"

    echo "✅ Public IP ${public_ip} and its NAT rule have been deleted."
}

function show_public_ips() {
    echo "📃 Configured Public IPs and NAT Mappings:"
    if [ ! -s "$IP_MAPPING_FILE" ]; then
        echo "ℹ️ No public IPs configured yet."
        return
    fi
    echo "------------------------------------------------"
    echo "Public IP       | Private IP      | Interface"
    echo "------------------------------------------------"
    awk '{printf "%-15s | %-15s | %s\n", $1, $2, $3}' "$IP_MAPPING_FILE"
    echo "------------------------------------------------"
}

# --- Client Management Functions ---

function add_client() {
    echo "➕ Adding a new VPN client..."
    if [ ! -s "$IP_MAPPING_FILE" ]; then
        echo "❌ Cannot add a client. Please add a public IP first."
        return
    fi

    local client_name
    read -rp "Enter client name (no spaces, e.g., 'work_laptop'): " client_name
    client_name=$(echo "$client_name" | xargs)

    if [ -d "${CLIENT_DIR}/${client_name}" ]; then
        echo "⚠️ Client '${client_name}' already exists."
        return
    fi

    echo "Please choose the public IP this client will connect to:"
    mapfile -t lines < <(awk '{print $1 " (" $2 ")"}' "$IP_MAPPING_FILE")
    select endpoint_choice in "${lines[@]}"; do
        if [[ -n "$endpoint_choice" ]]; then
            endpoint_ip=$(echo "$endpoint_choice" | awk '{print $1}')
            break
        else
            echo "Invalid selection."
        fi
    done

    read -rp "Enter comma separated DNS server(s) to use [default: -1.1.1.1, 1.0.0.1]: " dns_servers
    dns_servers="${dns_servers:-1.1.1.1, 1.0.0.1}"

    mkdir -p "${CLIENT_DIR}/${client_name}"
    wg genkey | tee "${CLIENT_DIR}/${client_name}/${client_name}.private" | wg pubkey > "${CLIENT_DIR}/${client_name}/${client_name}.public"
    local client_private_key client_public_key server_public_key
    client_private_key=$(cat "${CLIENT_DIR}/${client_name}/${client_name}.private")
    client_public_key=$(cat "${CLIENT_DIR}/${client_name}/${client_name}.public")
    server_public_key=$(cat "${CONFIG_DIR}/server_public.key")
    local server_port
    server_port=$(cat "${CONFIG_DIR}/server_port")
    local client_vpn_ip
    client_vpn_ip=$(get_next_client_ip)

    # Add peer to server config
    cat >> "$SERVER_CONFIG" <<-EOF

[Peer]
# Client: ${client_name}
PublicKey = ${client_public_key}
AllowedIPs = ${client_vpn_ip}/32
EOF

    # Create client config file
    cat > "${CLIENT_DIR}/${client_name}/${client_name}.conf" <<-EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_vpn_ip}/32
DNS = ${dns_servers}

# To avoid routing responses to incoming requests (i.e SSH, HTTP, etc.) through the VPN,
# replace the example below with your real network's private IP or subnet in CIDR format
# PostUp = ip rule add from 10.0.0.0/24 table main
# PreDown = ip rule del from 10.0.0.0/24 table main

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${endpoint_ip}:${server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Add the SNAT rules to iptables
    local interface
    local private_ip
    interface=$(awk -v ip="$endpoint_ip" '$1 == ip {print $3}' "$IP_MAPPING_FILE")
    private_ip=$(awk -v ip="$endpoint_ip" '$1 == ip {print $2}' "$IP_MAPPING_FILE")
    
    if ! iptables -t nat -C POSTROUTING -s "${client_vpn_ip}/32" -o "$interface" -j SNAT --to-source "$private_ip" 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "${client_vpn_ip}/32" -o "$interface" -j SNAT --to-source "$private_ip"
    fi

    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent

    # Sync changes with running interface
    wg set wg0 peer "${client_public_key}" allowed-ips "${client_vpn_ip}/32"

    echo "✅ Client '${client_name}' added."
    echo "--------------------------------------------------"
    echo "📱 Scan this QR code with the WireGuard mobile app:"
    qrencode -t ansiutf8 < "${CLIENT_DIR}/${client_name}/${client_name}.conf"
    echo "--------------------------------------------------"
    echo "Or find the config file and QR code at: ${CLIENT_DIR}/${client_name}/ directory"

    # Save a copy of the config and QR code to user's home
    mkdir -p "$DEST_DIR"
    cp -r "${CLIENT_DIR}/${client_name}" "$DEST_DIR"
    qrencode -o "${DEST_DIR}/${client_name}/${client_name}_qrcode.png" < "${CLIENT_DIR}/${client_name}/${client_name}.conf"
    chown -R "${LOGIN_USER}:${LOGIN_USER}" "$DEST_DIR"
}

function delete_client() {
    echo "➖ Deleting a VPN client..."
    local clients
    clients=($(ls -d "${CLIENT_DIR}"/*/ | xargs -n 1 basename))
    if [ ${#clients[@]} -eq 0 ]; then
        echo "ℹ️ No clients to delete."
        return
    fi

    select client_name in "${clients[@]}" "Cancel"; do
        case "$client_name" in
            "Cancel") echo "Cancelled."; return ;;
            *) break ;;
        esac
    done

    if [ -z "$client_name" ]; then
        echo "❌ Invalid selection."
        return
    fi

    # Remove iptables rule
    local client_vpn_ip interface private_ip endpoint_ip
    client_vpn_ip=$(grep '^Address' "${CLIENT_DIR}/${client_name}/${client_name}.conf" | awk '{print $3}' | cut -d'/' -f1)
    endpoint_ip=$(grep '^Endpoint' "${CLIENT_DIR}/${client_name}/${client_name}.conf" | awk '{print $3}' | cut -d':' -f1)
    interface=$(awk -v ip="$endpoint_ip" '$1 == ip {print $3}' "$IP_MAPPING_FILE")
    private_ip=$(awk -v ip="$endpoint_ip" '$1 == ip {print $2}' "$IP_MAPPING_FILE")

    if [ -n "$client_vpn_ip" ] && [ -n "$interface" ] && [ -n "$private_ip" ]; then
        iptables -t nat -D POSTROUTING -s "${client_vpn_ip}/32" -o "$interface" -j SNAT --to-source "$private_ip" 2>/dev/null || true
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        systemctl restart netfilter-persistent
    fi

    local client_public_key
    client_public_key=$(cat "${CLIENT_DIR}/${client_name}/${client_name}.public")

    # Remove peer from running interface
    wg set wg0 peer "${client_public_key}" remove

    # Remove peer from config file
    # Uses a temp file to be safe
    sed "/^# Client: ${client_name}$/,+2d" "$SERVER_CONFIG" > "${SERVER_CONFIG}.tmp"
    mv "${SERVER_CONFIG}.tmp" "$SERVER_CONFIG"

    # Delete client directory
    rm -rf "${CLIENT_DIR}/${client_name}"
    rm -rf "${DEST_DIR}/${client_name}"

    echo "✅ Client '${client_name}' has been deleted."
}

function show_clients() {
    echo "👥 Configured VPN Clients:"
    if [ ! -d "$CLIENT_DIR" ] || [ -z "$(ls -A "$CLIENT_DIR")" ]; then
        echo "ℹ️ No clients configured yet."
        return
    fi

    echo "-----------------------------------------------------------------------------------------------------"
    printf "%-20s | %-15s | %-22s | %-22s | %s\n" "Client" "VPN IP" "Endpoint" "Last Handshake" "RX / TX"
    echo "-----------------------------------------------------------------------------------------------------"

    declare -a rows

    for client_dir in "$CLIENT_DIR"/*; do
        client_name=$(basename "$client_dir")
        conf="${client_dir}/${client_name}.conf"
        public_key=$(cat "${client_dir}/${client_name}.public")
        vpn_ip=$(grep '^Address' "$conf" | awk '{print $3}')
        endpoint=$(grep '^Endpoint' "$conf" | awk '{print $3}')
        
        handshake=$(wg show wg0 latest-handshakes | grep "$public_key" | awk '{print $2}')
        if [[ "$handshake" == "0" ]]; then
            handshake_str="Never"
            sort_key=0
        else
            handshake_str=$(date -d @"$handshake" "+%Y-%m-%d %H:%M:%S")
            sort_key=$handshake
        fi

        rx=$(wg show wg0 transfer | grep "$public_key" | awk '{print $2}')
        tx=$(wg show wg0 transfer | grep "$public_key" | awk '{print $3}')

        hr_rx=$(numfmt --to=iec --suffix=B "$rx" 2>/dev/null || echo "${rx}B")
        hr_tx=$(numfmt --to=iec --suffix=B "$tx" 2>/dev/null || echo "${tx}B")

        rows+=("$sort_key|$(printf "%-20s | %-15s | %-22s | %-22s | %s" "$client_name" "$vpn_ip" "$endpoint" "$handshake_str" "${hr_rx} / ${hr_tx}")")
    done

    printf "%s\n" "${rows[@]}" | sort -t'|' -k1,1nr | cut -d'|' -f2-
    echo "-----------------------------------------------------------------------------------------------------"
}

# --- Maintenance Functions ---

function uninstall_wireguard() {
    echo "⚠️ This will completely remove all WireGuard configs, clients, NAT rules, and uninstall packages!"
    read -rp "Are you sure you want to continue? Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "❌ Uninstallation cancelled."
        return
    fi

    echo "🛑 Stopping WireGuard..."
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true

    echo "🧹 Removing iptables NAT rules for all clients..."
    # Remove client-to-client isolation rule if it exists
    iptables -D FORWARD -i wg0 -o wg0 -s 10.126.0.0/16 -d 10.126.0.0/16 -j DROP 2>/dev/null || true

    # Remove SNAT rules for the clients
    if [ -d "$CLIENT_DIR" ]; then
        for client_dir in "$CLIENT_DIR"/*; do
            [ -d "$client_dir" ] || continue
            client_name=$(basename "$client_dir")
            conf="${client_dir}/${client_name}.conf"
            if [ -f "$conf" ]; then
                client_vpn_ip=$(grep '^Address' "$conf" | awk '{print $3}' | cut -d'/' -f1)
                endpoint_ip=$(grep '^Endpoint' "$conf" | awk '{print $3}' | cut -d':' -f1)
                interface=$(awk -v ip="$endpoint_ip" '$1 == ip {print $3}' "$IP_MAPPING_FILE")
                private_ip=$(awk -v ip="$endpoint_ip" '$1 == ip {print $2}' "$IP_MAPPING_FILE")
                if [ -n "$client_vpn_ip" ] && [ -n "$interface" ] && [ -n "$private_ip" ]; then
                    iptables -t nat -D POSTROUTING -s "${client_vpn_ip}/32" -o "$interface" -j SNAT --to-source "$private_ip" 2>/dev/null || true
                fi
            fi
        done
    fi
    
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent 2>/dev/null || true

    echo "🗑️ Removing WireGuard configuration and keys..."
    rm -rf "$CLIENT_DIR"
    rm -rf "$DEST_DIR"
    rm -f "$IP_MAPPING_FILE" "$SERVER_CONFIG"
    rm -f "${CONFIG_DIR}/server_private.key" "${CONFIG_DIR}/server_public.key"

    echo "🧽 Disabling IP forwarding..."
    sed -i '/^net\.ipv4\.ip_forward=1$/d' /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=0

    echo "🧼 Removing WireGuard and dependencies..."
    apt-get remove --purge -y wireguard qrencode
    apt-get clean

    echo "✅ Uninstallation complete. System is restored to pre-script state."
}

# --- Main Menu ---

function main_menu() {
    is_root
    if [ ! -f "$SERVER_CONFIG" ]; then
        initial_setup
        set_client_isolation
    fi

    GREEN='\033[0;32m'
    BLUE='\033[1;34m'
    CYAN='\033[0;36m'
    RED='\033[0;31m'
    NC='\033[0m' # No Color

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗"
    echo -e "║        ${CYAN}WireGuard Multi-IP VPN Manager${BLUE}      ║"
    echo -e "╠════════════════════════════════════════════╣"
    echo -e "║${GREEN} 1)${NC} Add VPN Client                          ${BLUE}║"
    echo -e "║${GREEN} 2)${NC} Show VPN Clients                        ${BLUE}║"
    echo -e "║${GREEN} 3)${NC} Delete VPN Client                       ${BLUE}║"
    echo -e "║${GREEN} 4)${NC} Add Public IP                           ${BLUE}║"
    echo -e "║${GREEN} 5)${NC} Show Public IPs                         ${BLUE}║"
    echo -e "║${GREEN} 6)${NC} Delete Public IP                        ${BLUE}║"
    echo -e "║${GREEN} 7)${RED} Uninstall Everything${NC}                    ${BLUE}║"
    echo -e "║${GREEN} 8)${NC} Exit                                    ${BLUE}║"
    echo -e "╚════════════════════════════════════════════╝${NC}"
    show_wg_status
    echo ""

    read -rp "Enter your choice [1-8]: " reply
    case $reply in
        1) add_client ;;
        2) show_clients ;;
        3) delete_client ;;
        4) add_public_ip ;;
        5) show_public_ips ;;
        6) delete_public_ip ;;
        7) uninstall_wireguard ;;
        8) exit 0 ;;
        *) echo -e "${RED}❌ Invalid option: $reply${NC}" ;;
    esac
}

# --- Script Entry Point ---
main_menu
