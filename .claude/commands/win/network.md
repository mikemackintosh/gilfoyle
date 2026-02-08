# Network Configuration

Review Windows network configuration, adapters, DNS, routing, active connections, and listening ports.

## Arguments

$ARGUMENTS is optional:
- `--connections` — focus on active connections
- `--listening` — focus on listening ports
- `--dns` — focus on DNS configuration
- (no args — full network overview)

Examples:
- (no args — full network review)
- `--connections`
- `--listening`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Adapter and IP configuration

```powershell
Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
Get-NetAdapter | Format-Table Name, Status, MacAddress, LinkSpeed
```

### Step 2 — DNS configuration

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses
Get-DnsClientCache | Select-Object -First 20 Entry, RecordName, Data | Format-Table
```

### Step 3 — Active connections and listening ports

```powershell
# Established connections with process names
Get-NetTCPConnection -State Established | Sort-Object RemotePort |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Format-Table

# Listening ports with process names
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
  Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
  Format-Table
```

### Step 4 — Routing and hosts file

```powershell
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -ne '255.255.255.255/32' } |
  Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# Hosts file entries
Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' }
```

3. Flag suspicious findings:
   - Unexpected listening ports
   - Connections to known-bad IP ranges
   - Modified hosts file entries
   - Non-standard DNS servers

## Security Notes

- Unexpected listening ports may indicate backdoors or unauthorized services.
- Modified hosts file entries can redirect traffic (DNS poisoning).
- DNS servers pointing to non-corporate IPs on domain-joined machines could indicate compromise.
- Connections to high-numbered ephemeral ports on external IPs warrant investigation.
