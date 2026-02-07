---
name: Incident Response
description: Incident response procedures — triage, process inspection, file integrity, user auditing, and evidence preservation.
instructions: |
  Use this skill when the user is responding to a security incident, investigating a potentially
  compromised host, auditing user activity, or preserving forensic evidence. Always show commands
  before executing them, emphasise evidence preservation, and remind the user to follow their
  organisation's IR plan.
---

# Incident Response Skill

## Initial Triage Checklist

When responding to an incident, work through these steps in order:

1. **Confirm the alert** — Is this a true positive?
2. **Assess scope** — What systems/data are affected?
3. **Contain** — Isolate affected systems if necessary
4. **Preserve evidence** — Capture volatile data before it's lost
5. **Investigate** — Determine root cause and attack vector
6. **Eradicate** — Remove the threat
7. **Recover** — Restore normal operations
8. **Document** — Record timeline, actions taken, lessons learned

> **Important:** Volatile data (running processes, network connections, memory) should be captured first — it disappears on reboot. Follow the order of volatility.

### Order of Volatility

| Priority | Data | Persistence |
|----------|------|-------------|
| 1 | CPU registers, cache | Nanoseconds |
| 2 | Memory (RAM) | Power-dependent |
| 3 | Network connections, routing tables | Session-dependent |
| 4 | Running processes | Session-dependent |
| 5 | Disk (filesystem) | Persistent |
| 6 | Remote logging, monitoring | Persistent |
| 7 | Backups, archives | Persistent |

## Process Inspection

### List Running Processes

```bash
# All processes with full details
ps auxf                         # Linux (tree view)
ps aux                          # macOS

# Sort by CPU usage
ps aux --sort=-%cpu | head -20

# Sort by memory usage
ps aux --sort=-%mem | head -20

# Show process tree (parent-child)
pstree -p                       # Linux
ps -ejH                         # macOS fallback

# Find a specific process
ps aux | grep -i suspicious
pgrep -la suspicious

# Show process environment variables
cat /proc/<PID>/environ | tr '\0' '\n'    # Linux
ps eww -p <PID>                            # macOS

# Show process command line
cat /proc/<PID>/cmdline | tr '\0' ' '     # Linux

# Show process open files
ls -la /proc/<PID>/fd/                     # Linux
```

### Investigate Specific Processes

```bash
# Full details for a PID
ps -p <PID> -o pid,ppid,user,stat,start,etime,cmd

# What files does this process have open?
lsof -p <PID>

# What network connections does this process have?
lsof -i -p <PID>

# What is the binary on disk?
ls -la /proc/<PID>/exe          # Linux (symlink to binary)
lsof -p <PID> | grep txt       # macOS

# Check if binary has been deleted (still running from memory)
ls -la /proc/<PID>/exe 2>&1 | grep deleted    # Linux
```

### Network-Active Processes

```bash
# All network connections with owning processes
sudo lsof -i -P -n              # macOS + Linux
sudo ss -tunapl                  # Linux (modern)
sudo netstat -tunapl             # Linux (legacy)

# Listening ports
sudo lsof -i -P -n | grep LISTEN
sudo ss -tlnp                    # Linux

# Established connections
sudo lsof -i -P -n | grep ESTABLISHED
sudo ss -tnp state established  # Linux

# Connections to a specific IP
sudo lsof -i @10.0.0.1

# Connections on a specific port
sudo lsof -i :4444
```

## File Integrity Checks

### Hash Verification

```bash
# Hash a file (SHA-256)
shasum -a 256 /path/to/file
openssl dgst -sha256 /path/to/file

# Hash all files in a directory
find /path/to/dir -type f -exec shasum -a 256 {} \;

# Compare against known-good hashes
echo "<expected_hash>  /path/to/file" | shasum -a 256 -c

# Hash critical system binaries
for bin in /usr/bin/ssh /usr/bin/sudo /usr/bin/passwd /usr/sbin/sshd; do
  shasum -a 256 "$bin"
done
```

### Timestamps and Metadata

```bash
# Show all timestamps (access, modify, change)
stat /path/to/file

# Find recently modified files
find / -mtime -1 -type f 2>/dev/null          # modified in last 24h
find / -mmin -60 -type f 2>/dev/null           # modified in last 60 min
find /tmp -mtime -1 -type f 2>/dev/null        # focus on /tmp

# Find files modified in a specific time range (Linux)
find / -newermt "2024-01-15 10:00" ! -newermt "2024-01-15 12:00" -type f 2>/dev/null

# Find files with recent ctime changes (metadata/permission changes)
find / -ctime -1 -type f 2>/dev/null
```

### Permission Anomalies

```bash
# Find SUID binaries (run as owner)
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries (run as group)
find / -perm -2000 -type f 2>/dev/null

# Find world-writable files
find / -perm -0002 -type f 2>/dev/null

# Find world-writable directories without sticky bit
find / -perm -0002 -type d ! -perm -1000 2>/dev/null

# Find files owned by root that are writable by others
find / -user root -perm -o+w -type f 2>/dev/null

# Find files with no owner
find / -nouser -o -nogroup 2>/dev/null
```

## User Account Auditing

### Login History

```bash
# Recent logins
last | head -30

# Failed login attempts
lastb | head -30                # Linux (requires root)

# Currently logged-in users
who
w

# Login history for a specific user
last username

# Last login time for all users
lastlog                         # Linux
```

### User Account Investigation

```bash
# List all users
cat /etc/passwd
getent passwd

# List users with shells (potential interactive users)
grep -v '/nologin\|/false' /etc/passwd

# List users with UID 0 (root-level)
awk -F: '$3 == 0 {print}' /etc/passwd

# Check for recently created accounts
# Sort by UID (newest usually have highest UIDs)
sort -t: -k3 -n /etc/passwd | tail -10

# Check sudo group membership
getent group sudo              # Debian/Ubuntu
getent group wheel             # RHEL/CentOS

# Check sudoers rules
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
```

### Sudo Logs

```bash
# Recent sudo activity (Linux)
grep 'sudo:' /var/log/auth.log | tail -30        # Debian/Ubuntu
grep 'sudo:' /var/log/secure | tail -30           # RHEL/CentOS

# Sudo with command detail
grep 'COMMAND=' /var/log/auth.log | tail -30

# macOS sudo
log show --predicate 'process == "sudo"' --last 24h
```

### SSH Authorized Keys Audit

```bash
# Check all users' authorized_keys
for dir in /home/*/.ssh /root/.ssh; do
  if [ -f "$dir/authorized_keys" ]; then
    echo "=== $dir/authorized_keys ==="
    cat "$dir/authorized_keys"
  fi
done

# Look for recently modified authorized_keys
find /home -name "authorized_keys" -mtime -7 2>/dev/null
find /root -name "authorized_keys" -mtime -7 2>/dev/null
```

## Suspicious File Analysis

```bash
# Determine file type
file /path/to/suspicious-file

# Extract printable strings
strings /path/to/suspicious-file | head -100
strings -n 10 /path/to/suspicious-file     # minimum 10 chars

# Look for URLs or IPs in strings
strings /path/to/suspicious-file | grep -oE 'https?://[^ ]+'
strings /path/to/suspicious-file | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# Hex dump
xxd /path/to/suspicious-file | head -50

# Check ELF binary details (Linux)
readelf -h /path/to/suspicious-file        # header
readelf -d /path/to/suspicious-file        # dynamic section (shared libraries)

# Check Mach-O binary details (macOS)
otool -L /path/to/suspicious-file          # linked libraries
codesign -dvvv /path/to/suspicious-file    # code signing info

# Check if binary is packed/obfuscated
file /path/to/suspicious-file              # look for "stripped", "UPX"
strings /path/to/suspicious-file | grep -i upx

# Compute hash for VirusTotal / threat intel lookup
shasum -a 256 /path/to/suspicious-file
```

## Network Connection Auditing

```bash
# Current connections snapshot
sudo ss -tunapl > /tmp/connections_$(date +%Y%m%d_%H%M%S).txt      # Linux
sudo lsof -i -P -n > /tmp/connections_$(date +%Y%m%d_%H%M%S).txt   # macOS

# Unusual outbound connections
sudo lsof -i -P -n | grep ESTABLISHED | grep -v '127.0.0.1\|::1'

# Connections to unusual ports
sudo lsof -i -P -n | grep -E ':(4444|5555|6666|8888|1337|31337)'

# DNS queries (capture for analysis)
sudo tcpdump -i any port 53 -nn -c 100

# ARP table (look for duplicates indicating ARP spoofing)
arp -a

# Routing table (look for unexpected routes)
netstat -rn                      # macOS
ip route show                    # Linux
```

## Evidence Preservation

### Principles

- **Do not modify** the original evidence
- **Document everything** — who, what, when, where, why
- **Hash everything** — before and after copying
- **Maintain chain of custody** — log every access

### Volatile Data Collection Script

```bash
#!/bin/bash
# Volatile data collection — run on live system BEFORE shutdown
# Save output to an external/network drive

OUTDIR="/path/to/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo "=== Collection started: $(date -u) ===" | tee "$OUTDIR/collection.log"

# System info
uname -a > "$OUTDIR/uname.txt"
date -u > "$OUTDIR/date.txt"
uptime > "$OUTDIR/uptime.txt"

# Network
ifconfig -a > "$OUTDIR/ifconfig.txt" 2>/dev/null
ip addr > "$OUTDIR/ip_addr.txt" 2>/dev/null
netstat -rn > "$OUTDIR/routes.txt" 2>/dev/null
arp -a > "$OUTDIR/arp.txt"
ss -tunapl > "$OUTDIR/connections.txt" 2>/dev/null || \
  lsof -i -P -n > "$OUTDIR/connections.txt"

# Processes
ps auxf > "$OUTDIR/processes.txt" 2>/dev/null || ps aux > "$OUTDIR/processes.txt"
lsof -nP > "$OUTDIR/lsof.txt"

# Users
who > "$OUTDIR/who.txt"
w > "$OUTDIR/w.txt"
last > "$OUTDIR/last.txt"

# Cron jobs
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null && echo "=== $user ===" >> "$OUTDIR/crontabs.txt"
done
ls -la /etc/cron.* > "$OUTDIR/cron_dirs.txt" 2>/dev/null

# Hash the evidence
shasum -a 256 "$OUTDIR"/* > "$OUTDIR/checksums.sha256"

echo "=== Collection complete: $(date -u) ===" | tee -a "$OUTDIR/collection.log"
```

### Disk Image (if needed)

```bash
# Create a forensic image (Linux)
sudo dd if=/dev/sda of=/mnt/evidence/disk.img bs=4M status=progress
sudo shasum -a 256 /mnt/evidence/disk.img > /mnt/evidence/disk.img.sha256

# Create a forensic image (macOS — unmount first)
sudo diskutil unmountDisk /dev/disk2
sudo dd if=/dev/rdisk2 of=/Volumes/Evidence/disk.img bs=4m
sudo shasum -a 256 /Volumes/Evidence/disk.img > /Volumes/Evidence/disk.img.sha256
```

## Common IR Scenarios

### Compromised Host

1. **Contain:** Isolate from network (if possible without losing evidence)
2. **Capture volatile data:** Run collection script above
3. **Check for:** Unusual processes, network connections, cron jobs, authorized_keys, new users
4. **Look for persistence:** Crontabs, systemd services, rc.local, shell profiles, launchd plists
5. **Check logs:** auth.log, syslog, web logs for entry point
6. **Hash and preserve:** Image disk if full forensics needed

### Phishing Investigation

1. **Collect the email:** Full headers, body, attachments
2. **Analyse headers:** Trace the sending path, check SPF/DKIM/DMARC
3. **Check URLs:** Expand shortened URLs, check domain age and reputation
4. **Analyse attachments:** Hash, check on VirusTotal, sandbox if needed
5. **Check for clicks:** Web proxy logs, DNS logs for the phishing domain
6. **Check for credential compromise:** Auth logs for the targeted user(s)

### Data Exfiltration

1. **Identify the data:** What was accessed/copied?
2. **Network logs:** Unusual outbound traffic volumes, connections to unknown IPs
3. **DNS logs:** DNS tunneling indicators (long subdomain queries, high query volume)
4. **File access logs:** `auditd` rules, macOS endpoint security logs
5. **Cloud logs:** Cloud storage access, API calls, email attachments

### Persistence Mechanisms to Check

```bash
# Crontabs (all users)
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
  crontab -l -u "$u" 2>/dev/null
done
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# Systemd services and timers (Linux)
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all

# rc.local / init scripts
cat /etc/rc.local 2>/dev/null
ls /etc/init.d/

# Shell profile scripts
ls -la /etc/profile.d/
cat ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc 2>/dev/null

# SSH authorized_keys (all users)
find / -name "authorized_keys" 2>/dev/null

# macOS Launch Agents/Daemons
ls -la ~/Library/LaunchAgents/ 2>/dev/null
ls -la /Library/LaunchAgents/
ls -la /Library/LaunchDaemons/
ls -la /System/Library/LaunchDaemons/

# Docker containers (could be backdoor)
docker ps -a 2>/dev/null
```
