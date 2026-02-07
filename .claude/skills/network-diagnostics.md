---
name: Network Diagnostics
description: Network troubleshooting, reconnaissance, and connectivity debugging for security engineers and IT support.
instructions: |
  Use this skill when the user needs to diagnose network issues, perform DNS lookups, test
  connectivity, scan ports, trace routes, inspect firewall rules, capture packets, or perform
  whois/IP lookups. Always show commands before executing them and explain security implications.
---

# Network Diagnostics Skill

## DNS Lookups

### dig (preferred)

```bash
# Basic A record lookup
dig example.com

# Specific record types
dig example.com MX
dig example.com TXT
dig example.com AAAA
dig example.com NS
dig example.com SOA
dig example.com CNAME

# Short output (just the answer)
dig +short example.com
dig +short example.com MX

# Query a specific nameserver
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com

# Reverse DNS lookup
dig -x 93.184.216.34

# Trace delegation path
dig +trace example.com

# Show all records for a domain
dig example.com ANY

# Check if a record has propagated (query authoritative NS)
dig +short example.com NS
dig @ns1.example.com example.com
```

### nslookup

```bash
# Basic lookup
nslookup example.com

# Specific record type
nslookup -type=MX example.com

# Use a specific nameserver
nslookup example.com 8.8.8.8
```

### host

```bash
# Simple lookup
host example.com

# Reverse lookup
host 93.184.216.34

# Specific record type
host -t MX example.com
```

## Connectivity Testing

### ping

```bash
# Basic ping (Ctrl+C to stop)
ping example.com

# Limit count
ping -c 5 example.com

# Set interval (seconds)
ping -i 0.5 -c 10 example.com

# Set packet size (bytes)
ping -s 1400 -c 5 example.com

# Don't resolve hostnames (faster)
ping -n -c 5 example.com
```

### curl

```bash
# Basic HTTP request with status code
curl -o /dev/null -s -w "%{http_code}\n" https://example.com

# Verbose connection details (TLS, headers)
curl -v https://example.com

# Show timing breakdown
curl -o /dev/null -s -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\n" https://example.com

# Follow redirects
curl -L -v https://example.com

# Test with specific HTTP method and headers
curl -X POST -H "Content-Type: application/json" -d '{"test":true}' https://example.com/api

# Check if a port is open via HTTP
curl -s --connect-timeout 3 http://host:8080/health

# Download response headers only
curl -I https://example.com
```

### nc (netcat)

```bash
# Test if a TCP port is open
nc -zv host 443

# Test a range of ports
nc -zv host 80-443

# Set timeout
nc -zv -w 3 host 443

# Send data to a port
echo "test" | nc host 12345

# Listen on a port (for testing)
nc -l 12345
```

### telnet

```bash
# Test TCP connectivity
telnet host 443

# SMTP test
telnet mail.example.com 25
```

## Port Scanning

### nmap

```bash
# Basic TCP scan (top 1000 ports)
nmap host

# Scan specific ports
nmap -p 22,80,443,8080 host

# Scan a port range
nmap -p 1-1024 host

# Scan all 65535 ports
nmap -p- host

# Service version detection
nmap -sV -p 22,80,443 host

# OS detection (requires root)
sudo nmap -O host

# TCP SYN scan (faster, requires root)
sudo nmap -sS host

# UDP scan (slow, requires root)
sudo nmap -sU -p 53,123,161 host

# Scan a subnet
nmap -sn 192.168.1.0/24

# Script scan (common vulnerabilities)
nmap --script=default -p 80,443 host

# Output to file
nmap -oN scan.txt -p- host
nmap -oX scan.xml -p- host
```

> **Note:** Only scan hosts you own or have explicit written authorisation to test. Unauthorised port scanning may violate laws and acceptable use policies.

## Traceroute / Path Analysis

```bash
# Basic traceroute
traceroute example.com

# Use TCP instead of UDP (better through firewalls)
sudo traceroute -T -p 443 example.com

# Use ICMP
sudo traceroute -I example.com

# macOS: use built-in traceroute
traceroute example.com

# MTR — combines ping + traceroute (real-time)
mtr example.com
mtr -r -c 10 example.com    # report mode, 10 cycles

# Paris traceroute (avoids load-balancer artifacts)
# Install: brew install paris-traceroute (macOS) or apt install paris-traceroute
paris-traceroute example.com
```

## Firewall Rule Inspection

### iptables (Linux)

```bash
# List all rules with line numbers
sudo iptables -L -n -v --line-numbers

# List rules for a specific chain
sudo iptables -L INPUT -n -v --line-numbers

# List NAT rules
sudo iptables -t nat -L -n -v

# Check if a specific port is allowed
sudo iptables -L -n | grep 443
```

### nftables (Linux, modern)

```bash
# List all rules
sudo nft list ruleset

# List a specific table
sudo nft list table inet filter
```

### pfctl (macOS / BSD)

```bash
# Show current rules
sudo pfctl -sr

# Show state table (active connections)
sudo pfctl -ss

# Show statistics
sudo pfctl -si

# Show NAT rules
sudo pfctl -sn

# Test rule syntax
sudo pfctl -nf /etc/pf.conf
```

### ufw (Ubuntu/Debian)

```bash
# Show status and rules
sudo ufw status verbose

# Show numbered rules
sudo ufw status numbered
```

## Packet Capture

### tcpdump

```bash
# Capture on an interface (list interfaces first)
tcpdump -D
sudo tcpdump -i en0

# Capture with readable output
sudo tcpdump -i en0 -nn

# Filter by host
sudo tcpdump -i en0 host 10.0.0.1

# Filter by port
sudo tcpdump -i en0 port 443
sudo tcpdump -i en0 port 53

# Filter by protocol
sudo tcpdump -i en0 tcp
sudo tcpdump -i en0 udp
sudo tcpdump -i en0 icmp

# Combine filters
sudo tcpdump -i en0 'host 10.0.0.1 and port 443'
sudo tcpdump -i en0 'src host 10.0.0.1 and dst port 22'

# Capture to file (for Wireshark analysis)
sudo tcpdump -i en0 -w capture.pcap -c 1000

# Read a pcap file
tcpdump -r capture.pcap
tcpdump -r capture.pcap -nn -A   # ASCII output

# Capture DNS traffic
sudo tcpdump -i en0 port 53 -nn

# Capture only SYN packets (new connections)
sudo tcpdump -i en0 'tcp[tcpflags] & tcp-syn != 0'

# Limit capture size per packet
sudo tcpdump -i en0 -s 96 -w capture.pcap
```

## Whois and IP Lookups

```bash
# Domain whois
whois example.com

# IP whois
whois 93.184.216.34

# ARIN-specific lookup
whois -h whois.arin.net 93.184.216.34

# Check ASN
whois -h whois.radb.net AS13335

# IP geolocation (using external services)
curl -s https://ipinfo.io/93.184.216.34
curl -s https://ipinfo.io/93.184.216.34/json | python3 -m json.tool

# Your own public IP
curl -s https://ifconfig.me
curl -s https://ipinfo.io/ip

# DNS-based blacklist check
dig +short 34.216.184.93.zen.spamhaus.org
# (reverse the IP octets, append the DNSBL zone)
```

## Common Debugging Workflows

### "Can't reach a service"

1. **DNS resolution:**
   ```bash
   dig +short target-host
   ```
2. **Basic connectivity (ICMP):**
   ```bash
   ping -c 3 target-host
   ```
3. **TCP port check:**
   ```bash
   nc -zv -w 3 target-host 443
   ```
4. **Route path:**
   ```bash
   traceroute -T -p 443 target-host
   ```
5. **Local firewall:**
   ```bash
   sudo iptables -L -n | grep 443   # Linux
   sudo pfctl -sr | grep 443        # macOS
   ```
6. **Application layer:**
   ```bash
   curl -v https://target-host
   ```

### "DNS isn't working"

1. **Check current resolver:**
   ```bash
   cat /etc/resolv.conf                    # Linux
   scutil --dns | head -20                 # macOS
   ```
2. **Test against a known-good resolver:**
   ```bash
   dig @8.8.8.8 example.com
   dig @1.1.1.1 example.com
   ```
3. **Check for DNS interception:**
   ```bash
   dig +short txt whoami.ds.akahelp.net @ns1-1.akamaitech.net
   ```

### "Connection is slow"

1. **Measure latency:**
   ```bash
   ping -c 10 target-host
   ```
2. **Check path:**
   ```bash
   mtr -r -c 10 target-host
   ```
3. **HTTP timing:**
   ```bash
   curl -o /dev/null -s -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\n" https://target-host
   ```
4. **Check for packet loss:**
   ```bash
   ping -c 100 -i 0.2 target-host
   ```

## Network Interface Information

```bash
# List interfaces and IPs
ifconfig                  # macOS / older Linux
ip addr show              # Linux (modern)

# Show routing table
netstat -rn               # macOS / Linux
ip route show             # Linux (modern)

# Show active connections
netstat -an               # macOS
ss -tunapl                # Linux (modern)

# Show listening ports
lsof -i -P -n | grep LISTEN    # macOS
ss -tlnp                        # Linux

# ARP table
arp -a
```
