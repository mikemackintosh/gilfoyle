# Packet Capture

Capture network packets using `tcpdump`.

## Arguments

$ARGUMENTS should include a filter expression. Common patterns:
- `host <ip>` — traffic to/from a specific host
- `port <port>` — traffic on a specific port
- `dns` — shorthand for port 53 (DNS traffic)
- `<interface>` — capture on a specific interface (e.g., `en0`, `eth0`)

Optionally:
- `--write <file>` — write capture to a pcap file
- `--count <n>` — limit to n packets (default: 100)

Examples:
- `port 443`
- `host 10.0.0.1`
- `host 10.0.0.1 port 22`
- `dns`
- `port 80 --write capture.pcap`
- `port 443 --count 50`

## Workflow

1. Parse the filter, interface, count, and write options from `$ARGUMENTS`.
2. If no interface is specified, list available interfaces first:

```bash
tcpdump -D
```

3. Show the user the exact command before executing.

### Basic capture

```bash
sudo tcpdump -i <interface> -nn -c <count> '<filter>'
```

### Capture to file

```bash
sudo tcpdump -i <interface> -nn -c <count> -w <file> '<filter>'
```

### DNS shorthand

```bash
sudo tcpdump -i <interface> -nn -c <count> 'port 53'
```

4. After capture completes, summarise:
   - Packets captured
   - Key observations (source/destination patterns, protocols seen)
   - If saved to file, remind user they can open it in Wireshark

## Security Notes

- `tcpdump` requires root/sudo privileges.
- Capturing network traffic may be subject to legal restrictions. Only capture traffic on networks you are authorised to monitor.
- Use `-c` to limit capture size — unbounded captures can fill disk space.
- Captured pcap files may contain sensitive data (credentials, session tokens). Handle them securely.
