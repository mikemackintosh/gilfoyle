# Network Connection Audit

Audit active network connections on a host to identify suspicious outbound connections, unexpected listeners, or C2 communication.

## Arguments

$ARGUMENTS is optional:
- `--established` — show only established connections
- `--listening` — show only listening ports
- `--suspicious` — flag connections to unusual ports or unknown destinations

Examples:
- (no args — show all connections with owning processes)
- `--established`
- `--listening`
- `--suspicious`

## Workflow

1. Parse options from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### All connections with owning processes

```bash
# Linux
sudo ss -tunapl

# macOS
sudo lsof -i -P -n
```

### Established connections only

```bash
# Linux
sudo ss -tnp state established

# macOS
sudo lsof -i -P -n | grep ESTABLISHED
```

### Listening ports only

```bash
# Linux
sudo ss -tlnp

# macOS
sudo lsof -i -P -n | grep LISTEN
```

### Suspicious port check

Flag connections on commonly abused ports:

```bash
# Check for connections on known C2/backdoor ports
sudo lsof -i -P -n | grep -E ':(4444|5555|6666|8888|1337|31337|9001|9002|1234)'
```

### DNS activity (live)

```bash
sudo tcpdump -i any port 53 -nn -c 20
```

### ARP table (check for spoofing)

```bash
arp -a
```

3. For each connection, identify:
   - Local address:port
   - Remote address:port
   - State (ESTABLISHED, LISTEN, etc.)
   - Owning process (PID and name)

4. Flag as suspicious:
   - Connections to non-standard ports from system processes
   - Outbound connections from processes that shouldn't need network access
   - Connections to IP addresses in unusual geographies (check with whois/ipinfo if needed)
   - Multiple connections to the same external IP
   - Processes with deleted binaries holding network connections

5. Present a summary table and any findings.

## Security Notes

- Established outbound connections to unknown IPs warrant investigation — check the owning process and destination IP reputation.
- A process with a deleted binary (`/proc/<pid>/exe -> (deleted)`) holding a network connection is a strong indicator of compromise.
- C2 frameworks often use ports 443, 8443, or 8080 to blend with normal traffic — process name matters more than port number.
- DNS tunnelling shows as high-volume DNS queries with long subdomain labels — check with `tcpdump port 53`.
