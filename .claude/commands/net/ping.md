# Connectivity Test

Test network connectivity to a host using `ping` and `curl`.

## Arguments

$ARGUMENTS should include:
- A hostname or IP address
- Optionally a port number (triggers TCP check instead of ICMP)
- Optionally `--http` to perform an HTTP timing test

Examples:
- `example.com`
- `10.0.0.1`
- `example.com 443`
- `example.com --http`

## Workflow

1. Parse the target host and options from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### ICMP ping (default)

```bash
ping -c 5 <host>
```

### TCP port check (when port is specified)

```bash
nc -zv -w 5 <host> <port>
```

### HTTP timing (when `--http` is specified or port is 80/443)

```bash
curl -o /dev/null -s -w "DNS:        %{time_namelookup}s\nConnect:    %{time_connect}s\nTLS:        %{time_appconnect}s\nTTFB:       %{time_starttransfer}s\nTotal:      %{time_total}s\nHTTP Code:  %{http_code}\n" https://<host>
```

3. Summarise the results:
   - Reachable: yes/no
   - Latency: min/avg/max
   - Packet loss percentage
   - For HTTP: timing breakdown and status code

## Security Notes

- ICMP may be blocked by firewalls — a failed ping does not necessarily mean the host is down.
- Use TCP checks (`nc -zv`) for a more reliable connectivity test to specific services.
- Avoid flooding targets with large packet counts; 5 packets is sufficient for a quick check.
