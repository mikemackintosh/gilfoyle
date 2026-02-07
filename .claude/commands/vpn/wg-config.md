# WireGuard Config Generator

Generate a complete WireGuard configuration file with `[Interface]` and `[Peer]` sections.

## Arguments

$ARGUMENTS should include:
- `--server` or `--client` to indicate the role
- For server: optional `--port <port>` (default: 51820), `--address <CIDR>` (default: 10.0.0.1/24), `--interface <name>` (default: eth0)
- For client: `--endpoint <host:port>`, optional `--dns <server>` (default: 1.1.1.1), optional `--address <CIDR>` (default: 10.0.0.2/24)
- Optional `--allowed-ips <CIDRs>` (default: 0.0.0.0/0, ::/0 for client; peer-specific /32 for server)
- Optional `--psk` to include a PresharedKey field
- Optional `--keepalive <seconds>` for PersistentKeepalive (default: 25 for client)

Examples:
- `--server`
- `--server --port 51820 --address 10.0.0.1/24`
- `--client --endpoint vpn.example.com:51820`
- `--client --endpoint vpn.example.com:51820 --dns 9.9.9.9 --allowed-ips 10.0.0.0/24,192.168.1.0/24`
- `--client --endpoint vpn.example.com:51820 --psk`

## Workflow

1. Parse the role (`--server` or `--client`) and parameters from `$ARGUMENTS`.
2. Show the user the exact configuration that will be generated.

### Server Configuration

Generate a server config file (`wg0.conf`):

```ini
[Interface]
PrivateKey = <server private key>
Address = <address CIDR>
ListenPort = <port>
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <interface> -j MASQUERADE

[Peer]
# Client
PublicKey = <client public key>
AllowedIPs = <client tunnel IP>/32
```

3. Remind the user to enable IP forwarding:

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
```

### Client Configuration

Generate a client config file (`wg0.conf`):

```ini
[Interface]
PrivateKey = <client private key>
Address = <address CIDR>
DNS = <dns server>

[Peer]
PublicKey = <server public key>
Endpoint = <endpoint host:port>
AllowedIPs = <allowed IPs>
PersistentKeepalive = <keepalive>
```

4. If `--psk` is specified, include `PresharedKey` in the `[Peer]` section:

```ini
[Peer]
PublicKey = <peer public key>
PresharedKey = <pre-shared key>
```

5. Show how to deploy the configuration:

```bash
# Copy config to WireGuard directory
sudo cp wg0.conf /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf

# Bring up the tunnel
sudo wg-quick up wg0

# Enable at boot (systemd)
sudo systemctl enable wg-quick@wg0
```

6. If generating a server config, remind the user to:
   - Open the ListenPort in the firewall (`sudo ufw allow 51820/udp`)
   - Enable IP forwarding
   - Add `[Peer]` sections for each client

7. If generating a client config, note whether the `AllowedIPs` setting creates a full tunnel or split tunnel.

## Security Notes

- **Never embed actual private keys in configs shared over insecure channels.** Generate keys on the target host and reference them in place.
- The `PostUp`/`PostDown` iptables rules enable NAT masquerading, which is required for clients to reach the internet through the server. Adjust the outbound interface name (`eth0`) to match the server's actual interface.
- `AllowedIPs = 0.0.0.0/0, ::/0` creates a **full tunnel** — all traffic routes through the VPN. This is more secure on untrusted networks but increases latency.
- `AllowedIPs` with specific subnets creates a **split tunnel** — only matching traffic goes through the VPN. This is faster but increases the risk of DNS leaks.
- `PersistentKeepalive = 25` is recommended for clients behind NAT to keep the UDP mapping alive.
- Config files should have permissions `600` and be owned by `root`.
- The `DNS` directive in `[Interface]` only applies when using `wg-quick`. It modifies the system resolver while the tunnel is active.
