# Traceroute

Trace the network path to a host, showing each hop along the route.

## Arguments

$ARGUMENTS should include:
- A hostname or IP address
- Optionally `--tcp` and a port number to use TCP instead of UDP (better through firewalls)
- Optionally `--mtr` for continuous monitoring with `mtr`

Examples:
- `example.com`
- `example.com --tcp 443`
- `example.com --mtr`

## Workflow

1. Parse the target and options from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Standard traceroute (UDP)

```bash
traceroute <host>
```

### TCP traceroute (better through firewalls)

```bash
sudo traceroute -T -p <port> <host>
```

### MTR (combined ping + traceroute, report mode)

```bash
mtr -r -c 10 <host>
```

3. Explain the output:
   - Each hop number, IP, hostname, and round-trip times
   - `* * *` means the hop did not respond (firewall or ICMP rate-limiting)
   - Sudden latency jumps indicate congestion or geographic distance
   - Asymmetric routing means the return path may differ

## Security Notes

- TCP traceroute (`-T`) is more reliable through firewalls that block UDP/ICMP.
- `* * *` hops are common and don't necessarily indicate a problem — many routers are configured to not respond to traceroute probes.
- `mtr` requires installation on some systems (`brew install mtr` on macOS, `apt install mtr` on Debian/Ubuntu).
