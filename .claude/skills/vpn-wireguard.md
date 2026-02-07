---
name: VPN & WireGuard
description: VPN configuration, WireGuard key management, tunnel setup, and debugging for secure network connectivity.
instructions: |
  Use this skill when the user is working with VPN tunnels, WireGuard configuration, IPsec/IKEv2,
  OpenVPN, or troubleshooting VPN connectivity issues such as DNS leaks, split tunneling, or kill
  switch configuration. Provide commands, context, and security guidance. Always show commands
  before executing them.
---

# VPN & WireGuard Skill

## Related Commands
- `/vpn-wg-keygen` — Generate WireGuard key pairs
- `/vpn-wg-config` — Generate WireGuard configuration files
- `/vpn-status` — Check VPN tunnel status
- `/vpn-leak-test` — Test for DNS and IP leaks

## WireGuard Key Generation

WireGuard uses Curve25519 for key exchange. Keys are 32 bytes, Base64-encoded.

### Generate a Key Pair

```bash
# Generate private key
wg genkey > private.key

# Derive public key from private key
cat private.key | wg pubkey > public.key

# Generate both in one line
wg genkey | tee private.key | wg pubkey > public.key

# Set secure permissions on private key
chmod 600 private.key
```

### Generate a Pre-Shared Key (PSK)

Pre-shared keys add a layer of symmetric-key cryptography on top of Curve25519, providing post-quantum resistance.

```bash
wg genpsk > preshared.key
chmod 600 preshared.key
```

## WireGuard Config File Structure

WireGuard configuration files live in `/etc/wireguard/` and use an INI-like format.

### [Interface] Section

Defines the local side of the tunnel.

```ini
[Interface]
# Private key for this host (never share)
PrivateKey = <base64-encoded private key>

# Tunnel IP address (choose from a private range)
Address = 10.0.0.1/24

# Listening port (server) — clients usually omit this
ListenPort = 51820

# DNS servers to use while tunnel is active (client-side)
DNS = 1.1.1.1, 9.9.9.9

# Optional: run commands when the interface comes up/down
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
```

### [Peer] Section

Defines a remote peer.

```ini
[Peer]
# Public key of the remote peer
PublicKey = <base64-encoded public key>

# Optional: pre-shared key for additional security
PresharedKey = <base64-encoded PSK>

# Which IPs to route through this peer
# 0.0.0.0/0 = route all traffic (full tunnel)
# 10.0.0.0/24 = route only this subnet (split tunnel)
AllowedIPs = 0.0.0.0/0, ::/0

# Server endpoint (required on client, optional on server)
Endpoint = vpn.example.com:51820

# Keep NAT mappings alive (useful behind NAT)
PersistentKeepalive = 25
```

## WireGuard Server Setup

### 1. Generate server keys

```bash
wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key
chmod 600 /etc/wireguard/server-private.key
```

### 2. Create server config (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
PrivateKey = <server private key>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client 1
PublicKey = <client public key>
AllowedIPs = 10.0.0.2/32
```

### 3. Enable IP forwarding

```bash
# Enable immediately
sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
```

### 4. Start the tunnel

```bash
# Bring up the interface
sudo wg-quick up wg0

# Enable at boot
sudo systemctl enable wg-quick@wg0
```

## WireGuard Client Setup

### 1. Generate client keys

```bash
wg genkey | tee client-private.key | wg pubkey > client-public.key
chmod 600 client-private.key
```

### 2. Create client config (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
PrivateKey = <client private key>
Address = 10.0.0.2/24
DNS = 1.1.1.1, 9.9.9.9

[Peer]
PublicKey = <server public key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### 3. Connect

```bash
sudo wg-quick up wg0
```

## Tunnel Status & Debugging

### Check tunnel status

```bash
# Show all WireGuard interfaces
sudo wg show

# Show a specific interface
sudo wg show wg0

# Show only the latest handshake times
sudo wg show wg0 latest-handshakes

# Show transfer stats
sudo wg show wg0 transfer

# Show endpoints
sudo wg show wg0 endpoints
```

### Key diagnostics from `wg show`

| Field | Healthy | Problem |
|-------|---------|---------|
| `latest handshake` | Within last 2-3 minutes | "None" or very old timestamp |
| `transfer` | Non-zero rx/tx bytes | 0 bytes received = traffic not flowing |
| `endpoint` | Shows peer IP:port | Missing = peer not reachable |
| `allowed ips` | Matches expected routes | Misconfigured = traffic routing issues |

### Debugging connectivity

```bash
# Check if the WireGuard interface exists
ip link show wg0

# Check the IP address assigned
ip addr show wg0

# Check routing table for WireGuard routes
ip route show | grep wg0

# Ping through the tunnel
ping -c 3 10.0.0.1

# Check if UDP port is reachable (from client to server)
nc -zuv vpn.example.com 51820

# Check firewall rules for WireGuard port
sudo iptables -L -n | grep 51820
```

## IPsec / IKEv2 Concepts

### Overview

| Component | Purpose |
|-----------|---------|
| **IKE (Internet Key Exchange)** | Negotiates security associations (SAs) between peers |
| **IKEv1** | Legacy, complex, supports aggressive mode (insecure) |
| **IKEv2** | Modern, supports MOBIKE (mobility), EAP authentication, simpler |
| **ESP (Encapsulating Security Payload)** | Encrypts and authenticates the data payload |
| **AH (Authentication Header)** | Authenticates but does not encrypt (rarely used) |
| **SA (Security Association)** | Agreed-upon encryption parameters between two peers |

### IPsec Modes

- **Transport mode:** Encrypts only the payload; original IP header preserved. Used for host-to-host.
- **Tunnel mode:** Encrypts the entire original IP packet and wraps it in a new IP header. Used for site-to-site VPNs and remote access.

### Common IPsec Tools

```bash
# strongSwan status
sudo ipsec statusall

# List SAs
sudo ip xfrm state
sudo ip xfrm policy

# Restart IPsec
sudo ipsec restart

# Debug IKE negotiation
sudo ipsec stroke loglevel ike 4
```

## OpenVPN Config Review Basics

### Key Config Directives

```
# Protocol and port
proto udp
port 1194

# Tunnel type (tun = layer 3, tap = layer 2)
dev tun

# Encryption (modern)
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256

# TLS authentication (HMAC firewall)
tls-auth ta.key 0          # Legacy
tls-crypt ta.key            # Modern (encrypts control channel)

# Certificate verification
remote-cert-tls server
verify-x509-name vpn.example.com name

# Prevent downgrade attacks
tls-version-min 1.2

# Compression (disable — VORACLE attack)
compress
```

### Review Checklist

- [ ] `cipher` uses AEAD (AES-GCM or CHACHA20-POLY1305)
- [ ] `tls-version-min 1.2` is set
- [ ] `tls-auth` or `tls-crypt` is enabled
- [ ] `remote-cert-tls server` is set (prevents MITM)
- [ ] Compression is disabled (mitigates VORACLE)
- [ ] `auth` uses SHA-256 or better (not MD5 or SHA-1)
- [ ] `dev tun` is used (not `tap` unless bridging is required)

## Split Tunneling

Split tunneling routes only specific traffic through the VPN, while the rest uses the local internet connection.

### WireGuard Split Tunnel

```ini
[Peer]
# Route only internal subnets through VPN (split tunnel)
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24

# vs. Route ALL traffic through VPN (full tunnel)
AllowedIPs = 0.0.0.0/0, ::/0
```

### Security Trade-offs

| | Full Tunnel | Split Tunnel |
|---|---|---|
| **Privacy** | All traffic encrypted via VPN | Only specified traffic encrypted |
| **Speed** | Slower (all traffic goes through VPN) | Faster (local traffic stays local) |
| **DNS leaks** | Lower risk (DNS through VPN) | Higher risk (local DNS resolver used) |
| **Access** | Cannot access local LAN resources | Can access both VPN and local resources |
| **Use case** | Privacy, untrusted networks | Corporate access while keeping local internet |

## DNS Leak Concepts

A DNS leak occurs when DNS queries bypass the VPN tunnel and are sent to the ISP's or system default DNS resolver, revealing browsing activity.

### Common Causes

- System DNS resolver not updated when VPN connects
- Split tunnel without DNS override
- IPv6 DNS queries leaking outside IPv4-only tunnel
- Captive portal / DHCP overriding DNS settings
- Browser DoH/DoT bypassing system DNS

### Prevention

- Set `DNS = <VPN DNS>` in WireGuard config
- Block non-VPN DNS at the firewall level
- Disable IPv6 if the VPN does not tunnel IPv6
- Use `resolvconf` or `systemd-resolved` to manage DNS properly

```bash
# Check which DNS resolver is being used
cat /etc/resolv.conf                  # Linux
scutil --dns | head -20               # macOS

# Test for DNS leaks
dig +short txt whoami.ds.akahelp.net @ns1-1.akamaitech.net
dig +short myip.opendns.com @resolver1.opendns.com
```

## Kill Switch Concepts

A kill switch prevents any network traffic from leaving the host if the VPN tunnel goes down, preventing accidental exposure.

### WireGuard Kill Switch (iptables)

```bash
# Allow traffic only through WireGuard interface
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PostDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
```

### WireGuard Kill Switch (nftables)

```bash
PostUp = nft add table inet kill_switch; nft add chain inet kill_switch output { type filter hook output priority 0 \; policy drop \; }; nft add rule inet kill_switch output oifname "%i" accept; nft add rule inet kill_switch output ct state established,related accept
PostDown = nft delete table inet kill_switch
```

### Key Principles

- Block all traffic that does not go through the VPN interface
- Allow traffic to the VPN server endpoint itself (otherwise the tunnel cannot establish)
- Allow local/loopback traffic
- Implement as firewall rules in `PostUp`/`PostDown` hooks

## VPN Protocol Comparison

| Feature | WireGuard | OpenVPN | IPsec/IKEv2 |
|---------|-----------|---------|-------------|
| **Codebase** | ~4,000 lines | ~100,000 lines | ~400,000 lines (strongSwan) |
| **Protocol** | UDP only | UDP or TCP | UDP (ESP) + UDP 500/4500 (IKE) |
| **Encryption** | ChaCha20-Poly1305, Curve25519 | Configurable (AES-GCM, ChaCha20) | Configurable (AES-GCM, ChaCha20) |
| **Key Exchange** | Noise protocol (Curve25519) | TLS/PKI | IKEv2 (DH/ECDH) |
| **Performance** | Excellent (kernel-space) | Good (user-space) | Good (kernel-space) |
| **Roaming** | Built-in (stateless) | Reconnect required | MOBIKE (IKEv2) |
| **NAT Traversal** | Built-in | Built-in | NAT-T (UDP encapsulation) |
| **Audit surface** | Small, auditable | Large, complex | Very large, complex |
| **Authentication** | Public keys only | Certs, username/password, keys | Certs, EAP, PSK |
| **OS Support** | Linux, macOS, Windows, iOS, Android | All platforms | All platforms (native on iOS/macOS/Windows) |
| **Best for** | Modern deployments, speed | Legacy compatibility, flexibility | Enterprise, native mobile clients |
