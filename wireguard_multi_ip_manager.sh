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

# --- Utility Functions ---

function is_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "❌ This script must be run as root. Please use 'sudo'."
        exit 1
    fi
}

function install_dependencies() {
    echo "▶️ Installing required packages (wireguard, qrencode)..."
    if ! command -v wg &> /dev/null; then
        apt-get update
        apt-get install -y wireguard qrencode
        echo "✅ Dependencies installed."
    else
        echo "✅ Dependencies are already installed."
    fi
}

function get_next_client_ip() {
    local base_network="10.0."
    local last_ip_str
    
    # Grep for all server and client IPs (e.g., 10.0.x.y) and find the highest one
    last_ip_str=$(grep -oE "${base_network}[0-9]+\.[0-9]+" "$SERVER_CONFIG" | sort -t '.' -k 3,3n -k 4,4n | tail -1)

    if [ -z "$last_ip_str" ]; then
        # This should not happen after initial setup, but as a fallback.
        last_ip_str="10.0.0.1"
    fi

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
            echo "ERROR: IP address range (10.0.0.0/16) has been exhausted!" >&2
            exit 1
        fi
    fi

    echo "${base_network}${octet3}.${octet4}"
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

    # Add the first public IP
    echo "--------------------------------------------------"
    echo "You need to add your first public IP information."
    echo "--------------------------------------------------"
    add_public_ip

    # Create server config
    local server_private_key
    server_private_key=$(cat "${CONFIG_DIR}/server_private.key")
    local first_private_ip
    first_private_ip=$(head -n 1 "$IP_MAPPING_FILE" | cut -d' ' -f2)

    cat > "$SERVER_CONFIG" <<-EOF
[Interface]
Address = 10.0.0.1/16
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

    echo "✅ WireGuard server will listen on UDP port ${server_port}"
    echo "📣 Make sure to open UDP port ${server_port} in your firewall."
    echo "🎉 Initial setup complete! Your WireGuard server is running."
}

# --- IP Management Functions ---

function add_public_ip() {
    echo "➕ Adding a new Public IP..."
    local public_ip private_ip interface
    read -rp "Enter Public IP: " public_ip
    read -rp "Enter corresponding Private IP (from 'ip a'): " private_ip
    read -rp "Enter the main network interface name (default: eth0): " interface

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

    # Add the SNAT rule to iptables
    local rule="POSTROUTING -s 10.0.0.0/16 -o ${interface} -j SNAT --to-source ${private_ip}"
    iptables -t nat -C ${rule} &>/dev/null || iptables -t nat -A ${rule}

    # Save iptables rules
    if ! command -v iptables-persistent &> /dev/null; then
        apt-get update && apt-get install -y iptables-persistent
    fi
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent

    echo "✅ Public IP ${public_ip} added and NAT rule configured."
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
    private_ip=$(echo "$ip_to_delete" | cut -d' ' -f2)
    interface=$(echo "$ip_to_delete" | cut -d' ' -f3)

    # Remove iptables rule
    local rule="POSTROUTING -s 10.0.0.0/16 -o ${interface} -j SNAT --to-source ${private_ip}"
    iptables -t nat -D ${rule}
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent

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
    echo "--------------------------------------------------"
    echo "Public IP       | Private IP      | Interface"
    echo "--------------------------------------------------"
    awk '{printf "%-15s | %-15s | %s\n", $1, $2, $3}' "$IP_MAPPING_FILE"
    echo "--------------------------------------------------"
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
    mapfile -t lines < <(awk '{print $1}' "$IP_MAPPING_FILE")
    select endpoint_ip in "${lines[@]}"; do
        if [[ -n "$endpoint_ip" ]]; then
            break
        else
            echo "Invalid selection."
        fi
    done

    # Detect DNS from server's current config
    suggested_dns=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
    suggested_dns=${suggested_dns:-"1.1.1.1,1.0.0.1"}
    read -rp "Enter comma separated DNS server(s) to use [default: $suggested_dns]: " dns_servers
    dns_servers="${dns_servers:-$suggested_dns}"

    mkdir -p "${CLIENT_DIR}/${client_name}"
    wg genkey | tee "${CLIENT_DIR}/${client_name}/${client_name}.private" | wg pubkey > "${CLIENT_DIR}/${client_name}/${client_name}.public"
    local client_private_key client_public_key server_public_key
    client_private_key=$(cat "${CLIENT_DIR}/${client_name}/${client_name}.private")
    client_public_key=$(cat "${CLIENT_DIR}/${client_name}/${client_name}.public")
    server_public_key=$(cat "${CONFIG_DIR}/server_public.key")
    server_port=$(cat "${CONFIG_DIR}/server_port")
    local client_vpn_ip
    client_vpn_ip=$(get_next_client_ip)
    local server_port

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

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${endpoint_ip}:${server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Sync changes with running interface
    wg set wg0 peer "${client_public_key}" allowed-ips "${client_vpn_ip}/32"

    echo "✅ Client '${client_name}' added."
    echo "--------------------------------------------------"
    echo "📱 Scan this QR code with the WireGuard mobile app:"
    qrencode -t ansiutf8 < "${CLIENT_DIR}/${client_name}/${client_name}.conf"
    echo "--------------------------------------------------"
    echo "Or find the config file at: ${CLIENT_DIR}/${client_name}/${client_name}.conf"
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

    echo "✅ Client '${client_name}' has been deleted."
}

function show_clients() {
    echo "👥 Configured Clients:"
    if [ ! -d "$CLIENT_DIR" ] || [ -z "$(ls -A $CLIENT_DIR)" ]; then
        echo "ℹ️ No clients configured yet."
        return
    fi
    
    echo "--------------------------------------------------"
    grep -E "^# Client:" "$SERVER_CONFIG" | cut -d' ' -f3
    echo "--------------------------------------------------"
    
    echo "Active connections:"
    echo "--------------------------------------------------"
    wg show wg0
    echo "--------------------------------------------------"
}

function clean_setup() {
    echo "⚠️ This will completely remove all WireGuard configs, clients, NAT rules, and uninstall packages!"
    read -rp "Are you sure you want to continue? Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "❌ Cleanup cancelled."
        return
    fi

    echo "🛑 Stopping WireGuard..."
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true

    echo "🧹 Removing iptables NAT rules..."
    if [[ -f "$IP_MAPPING_FILE" ]]; then
        while read -r _ private_ip interface; do
            iptables -t nat -D POSTROUTING -s 10.0.0.0/16 -o "$interface" -j SNAT --to-source "$private_ip" 2>/dev/null || true
        done < "$IP_MAPPING_FILE"
    fi
    iptables-save > /etc/iptables/rules.v4
    systemctl restart netfilter-persistent 2>/dev/null || true

    echo "🗑️ Removing WireGuard configuration and keys..."
    rm -rf "$CLIENT_DIR"
    rm -f "$IP_MAPPING_FILE" "$SERVER_CONFIG"
    rm -f "${CONFIG_DIR}/server_private.key" "${CONFIG_DIR}/server_public.key"

    echo "🧽 Disabling IP forwarding..."
    sed -i '/^net\.ipv4\.ip_forward=1$/d' /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=0

    echo "🧼 Removing WireGuard and dependencies..."
    apt-get remove --purge -y wireguard qrencode iptables-persistent
    apt-get clean

    echo "✅ Cleanup complete. System is restored to pre-script state."
}

# --- Main Menu ---

function main_menu() {
    is_root
    if [ ! -f "$SERVER_CONFIG" ]; then
        initial_setup
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
    echo -e "║${GREEN} 1)${NC} Add Public IP                           ${BLUE}║"
    echo -e "║${GREEN} 2)${NC} Delete Public IP                        ${BLUE}║"
    echo -e "║${GREEN} 3)${NC} Show Public IPs                         ${BLUE}║"
    echo -e "║${GREEN} 4)${NC} Add VPN Client                          ${BLUE}║"
    echo -e "║${GREEN} 5)${NC} Delete VPN Client                       ${BLUE}║"
    echo -e "║${GREEN} 6)${NC} Show VPN Clients                        ${BLUE}║"
    echo -e "║${GREEN} 7)${RED} Clean/Reset Everything${NC}                  ${BLUE}║"
    echo -e "║${GREEN} 8)${NC} Exit                                    ${BLUE}║"
    echo -e "╚════════════════════════════════════════════╝${NC}"
    echo ""

    read -rp "Enter your choice [1-8]: " reply
    case $reply in
        1) add_public_ip ;;
        2) delete_public_ip ;;
        3) show_public_ips ;;
        4) add_client ;;
        5) delete_client ;;
        6) show_clients ;;
        7) clean_setup ;;
        8) exit 0 ;;
        *) echo -e "${RED}❌ Invalid option: $reply${NC}" ;;
    esac
}

# --- Script Entry Point ---
main_menu
