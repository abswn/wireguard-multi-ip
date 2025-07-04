# WireGuard Multi-IP VPN Manager

**IMPORTANT:** Running the client on a remote server may disrupt SSH and lock you out. Before starting the VPN, edit the client config file to add these lines under `[Interface]`, replacing *10.0.0.0/24* with the remote server's private IP or subnet in CIDR format.

```ini
PostUp = ip rule add from 10.0.0.0/24 table main
PreDown = ip rule del from 10.0.0.0/24 table main
```

If you do get locked out, stop the vpn using your server provider's console, kvm, rescue mode, etc. If that is not possible and vpn has not been set to auto start on boot, you can reboot using server provider's API or control panel to regain SSH access.

## Features

- Support multiple public IPs
- Add/remove VPN clients
- Client-to-client isolation enabled by default
- Clean uninstallation (removes configs, NAT rules, and packages)

## Installation and Usage

```bash
chmod +x wireguard_multi_ip_manager.sh
sudo ./wireguard_multi_ip_manager.sh
```

## Client Configuration

- Client configs and QR codes are saved to: `~/wireguard_clients/<client_name>/`
- QR codes are also shown in the terminal for easy mobile setup

**To preserve direct access to client services (like SSH or HTTP):**

Uncomment and edit these lines in the client config `[Interface]` section:

```ini
# PostUp = ip rule add from 10.0.0.0/24 table main
# PreDown = ip rule del from 10.0.0.0/24 table main
```

Replace `10.0.0.0/24` with your real network's private IP or subnet.


## On the Client Side

### 1. Install WireGuard:

```bash
sudo apt install wireguard
```

### 2. Start the VPN:

```bash
sudo wg-quick up /full/path/to/client.conf
```

### 3. Stop the VPN:

```bash
sudo wg-quick down /full/path/to/client.conf
```

### 4. Auto-connect at boot:

```bash
sudo mv client.conf /etc/wireguard/client.conf
sudo systemctl enable wg-quick@client
```

### 5. Manual start:

```bash
sudo systemctl start|stop|status|restart|enable|disable wg-quick@client
```

## Starting System Services After VPN Is Up

If you have a systemd service that should only run after VPN is active:

```ini
[Unit]
After=wg-quick@client.service
Requires=wg-quick@client.service
```

## License

MIT License