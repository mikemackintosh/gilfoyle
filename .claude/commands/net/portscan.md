# Port Scan

Scan a host for open ports using `nmap`.

## Arguments

$ARGUMENTS should include:
- A hostname or IP address
- Optionally specific ports: `80,443` or `1-1024`
- Optionally `--full` for all 65535 ports
- Optionally `--service` for service version detection

Examples:
- `example.com`
- `10.0.0.1 80,443,8080`
- `10.0.0.1 1-1024`
- `10.0.0.1 --full`
- `example.com 22,80,443 --service`

## Workflow

1. Parse the target, port specification, and flags from `$ARGUMENTS`.
2. Show the user the exact command before executing.
3. **Confirm authorisation:** Remind the user that port scanning should only be performed against hosts they own or have explicit written permission to test.

### Basic scan (top 1000 ports)

```bash
nmap <host>
```

### Specific ports

```bash
nmap -p <ports> <host>
```

### Full port scan

```bash
nmap -p- <host>
```

### With service version detection

```bash
nmap -sV -p <ports> <host>
```

4. Present results in a table:
   - Port | State | Service | Version (if `--service`)
   - Total open/closed/filtered counts

## Security Notes

- **Only scan hosts you own or have explicit written authorisation to test.** Unauthorised scanning may violate laws and acceptable use policies.
- A basic `nmap` scan sends TCP SYN packets — this is visible in firewall and IDS logs on the target.
- `nmap` may require `sudo` for SYN scans (`-sS`) and OS detection (`-O`).
- Filtered ports indicate a firewall is silently dropping packets.
