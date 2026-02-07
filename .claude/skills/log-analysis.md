---
name: Log Analysis
description: Security log analysis — parsing auth logs, syslog, web server logs, brute-force detection, and IOC identification.
instructions: |
  Use this skill when the user needs to analyse security logs, detect suspicious activity, parse
  auth or web server logs, correlate timestamps, or identify indicators of compromise. Always
  show commands before executing them and explain what patterns to look for.
---

# Log Analysis Skill

## Auth Log Parsing

### Linux Auth Logs

```bash
# Location varies by distro
# Debian/Ubuntu: /var/log/auth.log
# RHEL/CentOS:  /var/log/secure

# Recent SSH logins (successful)
grep 'Accepted' /var/log/auth.log | tail -20

# Failed SSH logins
grep 'Failed password' /var/log/auth.log | tail -20

# Failed logins by IP (sorted by count)
grep 'Failed password' /var/log/auth.log | \
  grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -20

# Failed logins by username
grep 'Failed password' /var/log/auth.log | \
  grep -oP 'for (invalid user )?\K\S+' | sort | uniq -c | sort -rn | head -20

# sudo usage
grep 'sudo:' /var/log/auth.log | tail -20

# Failed sudo attempts
grep 'sudo:.*authentication failure' /var/log/auth.log

# User additions / modifications
grep -E 'useradd|usermod|groupadd|passwd' /var/log/auth.log

# SSH key authentication
grep 'Accepted publickey' /var/log/auth.log | tail -20
```

### macOS Auth

```bash
# Recent authentication events
log show --predicate 'subsystem == "com.apple.Authorization"' --last 1h

# Login window events
log show --predicate 'process == "loginwindow"' --last 1h

# SSH events on macOS
log show --predicate 'process == "sshd"' --last 1h

# Sudo events
log show --predicate 'process == "sudo"' --last 1h
```

## Syslog and journalctl

### journalctl (systemd systems)

```bash
# Show all logs since boot
journalctl -b

# Follow logs in real-time
journalctl -f

# Filter by unit
journalctl -u sshd
journalctl -u nginx
journalctl -u docker

# Filter by time range
journalctl --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
journalctl --since "1 hour ago"
journalctl --since today

# Filter by priority (0=emerg through 7=debug)
journalctl -p err          # errors and above
journalctl -p warning      # warnings and above

# Show kernel messages
journalctl -k

# Show logs for a specific PID
journalctl _PID=1234

# JSON output (for processing with jq)
journalctl -u sshd -o json | jq '.MESSAGE'

# Show disk usage
journalctl --disk-usage
```

### Traditional syslog

```bash
# Common log files
# /var/log/syslog      — general messages (Debian/Ubuntu)
# /var/log/messages     — general messages (RHEL/CentOS)
# /var/log/kern.log     — kernel messages
# /var/log/daemon.log   — daemon messages
# /var/log/cron.log     — cron job logs

# Tail syslog in real-time
tail -f /var/log/syslog

# Search for errors
grep -i error /var/log/syslog | tail -50

# Search by service
grep 'dhclient' /var/log/syslog | tail -20
```

### macOS Unified Logging

```bash
# Show recent logs
log show --last 30m

# Filter by subsystem
log show --predicate 'subsystem == "com.apple.network"' --last 1h

# Filter by process
log show --predicate 'process == "kernel"' --last 1h

# Filter by message content
log show --predicate 'eventMessage contains "error"' --last 1h

# Stream logs in real-time
log stream
log stream --predicate 'subsystem == "com.apple.network"'

# Combine predicates
log show --predicate 'subsystem == "com.apple.network" AND eventMessage contains "denied"' --last 1h

# Output as JSON
log show --last 1h --style json
```

## Web Server Logs

### Apache Access Log

```bash
# Default locations
# /var/log/apache2/access.log   (Debian/Ubuntu)
# /var/log/httpd/access_log     (RHEL/CentOS)

# Top 20 IPs by request count
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# Top requested URLs
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# All 4xx/5xx errors
awk '$9 ~ /^[45]/' /var/log/apache2/access.log | tail -50

# Requests from a specific IP
grep '^10.0.0.1 ' /var/log/apache2/access.log

# Requests per hour
awk '{print $4}' /var/log/apache2/access.log | cut -d: -f1,2 | sort | uniq -c

# POST requests (potential form abuse / injection)
grep '"POST ' /var/log/apache2/access.log | tail -50

# Large response sizes (potential data exfil)
awk '$10 > 1000000 {print $1, $7, $10}' /var/log/apache2/access.log
```

### Nginx Access Log

```bash
# Default location: /var/log/nginx/access.log

# Same awk patterns as Apache (default combined log format)
# Top IPs
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Status code distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# 403/404 errors (recon / scanning indicators)
awk '$9 == 403 || $9 == 404' /var/log/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Error log
tail -50 /var/log/nginx/error.log
```

### JSON-formatted Logs

```bash
# If logs are in JSON format (common with modern setups)
# Parse with jq

# Top IPs
cat access.json | jq -r '.remote_addr' | sort | uniq -c | sort -rn | head -20

# Filter by status code
cat access.json | jq 'select(.status >= 400)'

# Filter by time range
cat access.json | jq 'select(.timestamp >= "2024-01-01T00:00:00")'

# Extract specific fields
cat access.json | jq '{ip: .remote_addr, path: .request_uri, status: .status}'
```

## Brute-Force Detection

### SSH Brute-Force Indicators

```bash
# More than 10 failed logins from a single IP in 5 minutes
grep 'Failed password' /var/log/auth.log | \
  awk '{print $1,$2,$3,$NF}' | sort | uniq -c | sort -rn | head -20

# Check for dictionary usernames
grep 'Failed password for invalid user' /var/log/auth.log | \
  grep -oP 'user \K\S+' | sort | uniq -c | sort -rn | head -20

# Rapid connection attempts (connection rate)
grep 'Connection from' /var/log/auth.log | \
  awk '{print $1,$2,$3,$(NF-1)}' | sort | uniq -c | sort -rn | head -20
```

### Web Login Brute-Force Indicators

```bash
# Repeated POST to login endpoint from one IP
grep '"POST /login' /var/log/nginx/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# 401 responses (failed auth)
awk '$9 == 401 {print $1}' /var/log/nginx/access.log | \
  sort | uniq -c | sort -rn | head -20
```

## Log Filtering Toolkit

### Essential Commands

| Command | Purpose |
|---------|---------|
| `grep` | Pattern matching |
| `grep -E` | Extended regex |
| `grep -oP` | Perl regex, output match only |
| `awk` | Column extraction and filtering |
| `cut -d' ' -f1,7` | Delimiter-based field extraction |
| `sort \| uniq -c \| sort -rn` | Frequency counting |
| `sed` | Stream editing / substitution |
| `jq` | JSON parsing |
| `wc -l` | Line counting |

### Useful One-Liners

```bash
# Count lines matching a pattern
grep -c 'pattern' logfile

# Extract IPs from any log
grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' logfile | \
  sort | uniq -c | sort -rn | head -20

# Extract timestamps and group by hour
awk '{print $4}' logfile | cut -d: -f1,2 | sort | uniq -c | sort -rn

# Find lines between two timestamps (assumes sorted log)
awk '/Jan 15 10:00:00/,/Jan 15 11:00:00/' /var/log/syslog

# Unique values in a specific column
awk '{print $5}' logfile | sort -u

# Multi-file search
grep -r 'pattern' /var/log/

# Decompress and search rotated logs
zgrep 'pattern' /var/log/auth.log.*.gz

# Combine multiple log files chronologically
sort -k1,3M /var/log/auth.log /var/log/auth.log.1
```

## Common IOC Patterns in Logs

### Suspicious Patterns to Search For

```bash
# Known web shells / backdoor filenames
grep -rE '(c99|r57|b374k|webshell|cmd\.php|shell\.php|upload\.php)' /var/log/nginx/access.log

# Command injection attempts in URLs
grep -E '(%7C|%26|%3B|;|\||&&)' /var/log/nginx/access.log
grep -E '(/etc/passwd|/etc/shadow|/proc/self)' /var/log/nginx/access.log

# SQL injection attempts
grep -iE "(union.*select|or.*1.*=.*1|drop.*table|insert.*into|--)" /var/log/nginx/access.log

# Path traversal
grep -E '(\.\./|\.\.\\|%2e%2e)' /var/log/nginx/access.log

# Suspicious user-agents
grep -iE '(sqlmap|nikto|nmap|dirbuster|gobuster|masscan|zgrab)' /var/log/nginx/access.log

# Base64 encoded payloads in URLs
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' /var/log/nginx/access.log

# Unusual outbound connections (from system logs)
grep -E 'connect to [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /var/log/syslog
```

## Timestamp Correlation

### Converting Timestamps

```bash
# Unix epoch to human-readable
date -d @1704067200                    # Linux
date -r 1704067200                     # macOS

# Human-readable to epoch
date -d "2024-01-01 00:00:00" +%s      # Linux
date -j -f "%Y-%m-%d %H:%M:%S" "2024-01-01 00:00:00" +%s   # macOS

# Convert between timezones
TZ=UTC date -d "2024-01-01 10:00:00 EST"   # Linux
```

### Correlating Across Log Sources

```bash
# Step 1: Identify the event time from the first log
grep 'suspicious_event' /var/log/auth.log
# Note the timestamp: Jan 15 10:32:15

# Step 2: Search other logs within a window around that time
awk '/Jan 15 10:3[0-5]/' /var/log/syslog
awk '/Jan 15 10:3[0-5]/' /var/log/nginx/access.log

# Step 3: Build a timeline
# Combine relevant entries and sort
grep 'Jan 15 10:3' /var/log/auth.log /var/log/syslog | sort -k1,3M
```

### Log Formats Quick Reference

| Source | Timestamp Format | Example |
|--------|-----------------|---------|
| syslog | `MMM DD HH:MM:SS` | `Jan 15 10:32:15` |
| Apache/Nginx | `DD/MMM/YYYY:HH:MM:SS +ZZZZ` | `15/Jan/2024:10:32:15 +0000` |
| journalctl | `YYYY-MM-DD HH:MM:SS` | `2024-01-15 10:32:15` |
| macOS unified | `YYYY-MM-DD HH:MM:SS.ffffff` | `2024-01-15 10:32:15.123456` |
| ISO 8601 | `YYYY-MM-DDTHH:MM:SSZ` | `2024-01-15T10:32:15Z` |
