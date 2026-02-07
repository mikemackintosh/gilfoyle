# VPN Status Check

Check the status of a WireGuard VPN tunnel, including active handshakes, data transfer, connected peers, routing, and DNS resolution.

## Arguments

$ARGUMENTS is optional:
- An interface name (default: `wg0`)
- `--all` to show all WireGuard interfaces

Examples:
- (no args — check `wg0` status)
- `wg0`
- `wg1`
- `--all`

## Workflow

1. Parse the interface name from `$ARGUMENTS`. Default to `wg0` if not specified.
2. Show the user the exact commands before executing.

### Check if WireGuard interface exists

```bash
ip link show <interface> 2>/dev/null || echo "Interface <interface> not found"
```

### Show WireGuard tunnel status

```bash
# Full status of a specific interface
sudo wg show <interface>

# All interfaces
sudo wg show
```

### Check latest handshakes

```bash
sudo wg show <interface> latest-handshakes
```

A healthy tunnel should show a handshake within the last 2-3 minutes. If the latest handshake shows "None" or a timestamp older than 5 minutes, the tunnel may be down.

### Check data transfer

```bash
sudo wg show <interface> transfer
```

Non-zero `received` and `sent` byte counts indicate the tunnel is passing traffic. Zero `received` bytes with non-zero `sent` bytes suggests outbound packets are being sent but the peer is not responding.

### Check connected peers

```bash
sudo wg show <interface> peers
sudo wg show <interface> endpoints
sudo wg show <interface> allowed-ips
```

### Check interface IP address

```bash
ip addr show <interface>
```

### Check routing table for VPN routes

```bash
# Linux
ip route show | grep <interface>

# macOS
netstat -rn | grep <interface>
```

3. Verify DNS resolution is working through the tunnel:

```bash
# Check current DNS resolver
cat /etc/resolv.conf                    # Linux
scutil --dns | head -20                 # macOS

# Test DNS resolution
dig +short example.com
```

4. Test tunnel connectivity:

```bash
# Ping the tunnel gateway
ping -c 3 <tunnel gateway IP>

# Ping through the tunnel to the internet
ping -c 3 1.1.1.1
```

5. Present a summary table:

| Check | Status | Details |
|-------|--------|---------|
| Interface | Up/Down | IP address, MTU |
| Latest Handshake | Healthy/Stale/None | Timestamp |
| Data Transfer | Active/Inactive | RX/TX bytes |
| Connected Peers | Count | Endpoints |
| Routing | Correct/Missing | VPN routes present |
| DNS | Correct/Misconfigured | Active resolver |

6. Flag any issues:
   - Interface not found or down
   - No recent handshake (tunnel not established)
   - Zero received bytes (peer not responding)
   - Missing VPN routes in routing table
   - DNS resolver not pointing to VPN DNS

## Security Notes

- `wg show` displays public keys and endpoints but never private keys. It is safe to share its output.
- A stale handshake (older than 5 minutes) could indicate the peer is unreachable, the firewall is blocking UDP traffic, or the keys are misconfigured.
- If the routing table shows `0.0.0.0/0` via the WireGuard interface, the tunnel is operating in full-tunnel mode (all traffic routed through VPN).
- If DNS is not configured to use the VPN's DNS server, DNS queries may leak to the local ISP resolver even while the tunnel is active.
