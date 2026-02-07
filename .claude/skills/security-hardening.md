---
name: Security Hardening
description: System and service hardening — SSH, firewalls, file permissions, kernel tuning, macOS security, and CIS benchmark checks.
instructions: |
  Use this skill when the user needs to harden systems or services, audit file permissions,
  configure firewalls, tune kernel security parameters, or run CIS benchmark checks. Always
  show commands before executing them and explain the security rationale behind each recommendation.
---

# Security Hardening Skill

## SSH Hardening Checklist

| Setting | Recommended Value | Why |
|---------|------------------|-----|
| `PermitRootLogin` | `no` | Prevent direct root access |
| `PasswordAuthentication` | `no` | Force key-based auth |
| `ChallengeResponseAuthentication` | `no` | Disable PAM challenge-response |
| `MaxAuthTries` | `3` | Limit brute-force attempts |
| `X11Forwarding` | `no` | Reduce attack surface |
| `AllowTcpForwarding` | `no` (unless needed) | Prevent tunnel abuse |
| `AllowAgentForwarding` | `no` (unless needed) | Prevent agent hijacking |
| `PermitEmptyPasswords` | `no` | Never allow empty passwords |
| `LoginGraceTime` | `30` | Limit unauthenticated connections |
| `ClientAliveInterval` | `300` | Disconnect idle sessions |
| `LogLevel` | `VERBOSE` | Better audit trail |

### Apply SSH Hardening

```bash
# Edit sshd_config
sudo vi /etc/ssh/sshd_config

# Validate before reloading
sudo sshd -t

# Reload (keeps existing connections)
sudo systemctl reload sshd        # Linux
sudo launchctl kickstart -k system/com.openssh.sshd   # macOS
```

### Strong Algorithms Only

Add to `/etc/ssh/sshd_config`:

```sshd_config
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
```

## Firewall Setup

### ufw (Ubuntu/Debian)

```bash
# Enable firewall
sudo ufw enable

# Default deny incoming, allow outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow SSH from specific subnet only
sudo ufw allow from 10.0.0.0/24 to any port 22 proto tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Allow a specific port range
sudo ufw allow 8000:8100/tcp

# Deny a specific IP
sudo ufw deny from 203.0.113.50

# Show rules with numbers
sudo ufw status numbered

# Delete a rule by number
sudo ufw delete 3

# Rate limiting (SSH brute-force protection)
sudo ufw limit 22/tcp

# Logging
sudo ufw logging on
```

### iptables (Linux)

```bash
# Flush existing rules (CAREFUL — may lock you out over SSH)
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established/related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ICMP (ping)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Rate limit SSH
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 4

# Save rules
sudo iptables-save > /etc/iptables/rules.v4          # Debian/Ubuntu
sudo service iptables save                             # RHEL/CentOS

# List rules
sudo iptables -L -n -v --line-numbers
```

### pfctl (macOS / BSD)

```bash
# Check status
sudo pfctl -si

# Show current rules
sudo pfctl -sr

# Enable pf
sudo pfctl -e

# Disable pf
sudo pfctl -d

# Load rules from file
sudo pfctl -f /etc/pf.conf

# Test rules (syntax check only)
sudo pfctl -nf /etc/pf.conf
```

Example `/etc/pf.conf`:

```pf
# Macros
ext_if = "en0"

# Options
set block-policy drop
set skip on lo0

# Normalisation
scrub in all

# Default deny
block in all

# Allow established
pass out quick on $ext_if proto { tcp, udp, icmp } keep state

# Allow SSH from trusted network
pass in on $ext_if proto tcp from 10.0.0.0/24 to any port 22

# Allow ICMP
pass in on $ext_if proto icmp
```

## File Permission Auditing

### SUID/SGID Audit

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Compare against known-good list
# Normal SUID binaries include: passwd, sudo, ping, su, mount, umount
# Investigate any that are unexpected

# Find SUID binaries not owned by root
find / -perm -4000 ! -user root -type f 2>/dev/null

# Find SUID/SGID in home directories (suspicious)
find /home -perm -4000 -o -perm -2000 2>/dev/null
find /tmp -perm -4000 -o -perm -2000 2>/dev/null
```

### World-Writable Files and Directories

```bash
# World-writable files (excluding /proc, /sys)
find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print 2>/dev/null

# World-writable directories without sticky bit
find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type d ! -perm -1000 -print 2>/dev/null

# Files with no owner or group
find / -nouser -o -nogroup 2>/dev/null
```

### Sensitive File Permissions

```bash
# Check critical file permissions
ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
ls -la /etc/ssh/sshd_config
ls -la /etc/sudoers

# Expected permissions
# /etc/passwd      644
# /etc/shadow      640 or 000
# /etc/group       644
# /etc/gshadow     640 or 000
# /etc/ssh/sshd_config  600
# /etc/sudoers     440
```

## User and Group Management

### Audit Users

```bash
# Users with login shells
grep -v '/nologin\|/false' /etc/passwd

# Users with UID 0 (root equivalent)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Users in sudo/wheel group
getent group sudo 2>/dev/null
getent group wheel 2>/dev/null

# Users with empty passwords
sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null

# Locked accounts
sudo passwd -S -a 2>/dev/null | grep ' L '           # Linux
```

### Disable Unused Accounts

```bash
# Lock an account
sudo usermod -L username

# Set shell to nologin
sudo usermod -s /usr/sbin/nologin username

# Set account expiry
sudo usermod -e 2024-12-31 username

# Remove from sudo group
sudo gpasswd -d username sudo
```

### Password Policy (Linux)

```bash
# Check password aging
sudo chage -l username

# Set password policy
sudo chage -M 90 -m 7 -W 14 username
# -M 90  = max days between changes
# -m 7   = min days between changes
# -W 14  = warning days before expiry

# PAM password quality (/etc/security/pwquality.conf)
# minlen = 14
# dcredit = -1
# ucredit = -1
# ocredit = -1
# lcredit = -1
```

## Service Minimisation

```bash
# List enabled services (systemd)
systemctl list-unit-files --type=service --state=enabled

# List running services
systemctl list-units --type=service --state=running

# Disable unnecessary services
sudo systemctl disable --now service-name

# Common services to review for disabling:
# avahi-daemon    — mDNS (usually not needed on servers)
# cups            — printing (usually not needed on servers)
# bluetooth       — Bluetooth
# rpcbind         — NFS/NIS (if not used)
# telnet          — use SSH instead

# Check listening ports
sudo ss -tlnp                    # Linux
sudo lsof -i -P -n | grep LISTEN   # macOS
```

## Kernel / Sysctl Security Tuning

### Network Security (Linux)

Add to `/etc/sysctl.d/99-security.conf`:

```ini
# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Log suspicious packets (martians)
net.ipv4.conf.all.log_martians = 1

# Ignore broadcast pings (smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP timestamps
net.ipv4.tcp_timestamps = 1
```

```bash
# Apply changes
sudo sysctl --system

# Verify a specific setting
sysctl net.ipv4.ip_forward
```

### Memory Protection (Linux)

```ini
# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Enable ASLR
kernel.randomize_va_space = 2

# Restrict ptrace (process tracing)
kernel.yama.ptrace_scope = 2

# Restrict kernel module loading (after boot)
# kernel.modules_disabled = 1   # WARNING: permanent until reboot
```

## macOS-Specific Hardening

### System Integrity Protection (SIP)

```bash
# Check SIP status
csrutil status

# SIP should be ENABLED
# Only disable temporarily for specific needs, then re-enable
```

### Gatekeeper

```bash
# Check Gatekeeper status
spctl --status

# Enable Gatekeeper
sudo spctl --master-enable

# Check if an app is allowed
spctl -a -v /Applications/SomeApp.app
```

### FileVault (Full Disk Encryption)

```bash
# Check FileVault status
fdesetup status

# List FileVault users
sudo fdesetup list

# Enable FileVault
sudo fdesetup enable

# Check for recovery key
sudo fdesetup haspersonalrecoverykey
sudo fdesetup hasinstitutionalrecoverykey
```

### macOS Firewall

```bash
# Check application firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Enable application firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Enable stealth mode (don't respond to probes)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Block all incoming (except essential services)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

# List allowed applications
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

### Other macOS Checks

```bash
# Check for remote login (SSH)
sudo systemsetup -getremotelogin

# Check for screen sharing
sudo launchctl list | grep -i screensharing

# Check for remote management (ARD)
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -configure -activate -access -off

# Auto-update status
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload

# Check for unsigned kexts
kextstat | grep -v com.apple
```

## CIS Benchmark Quick Checks

These are quick spot-checks inspired by CIS benchmarks. For full compliance, use a proper CIS scanning tool.

### Linux Quick Checks

```bash
# 1. Filesystem — are tmp partitions mounted with noexec?
mount | grep /tmp

# 2. Is a bootloader password set?
grep "^set superusers" /etc/grub.d/* 2>/dev/null
grep "^password" /etc/grub.d/* 2>/dev/null

# 3. Core dumps disabled?
grep -r "hard core" /etc/security/limits.conf /etc/security/limits.d/

# 4. ASLR enabled?
sysctl kernel.randomize_va_space

# 5. No unconfined services (AppArmor/SELinux)?
aa-status 2>/dev/null || sestatus 2>/dev/null

# 6. NTP configured?
timedatectl status
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null

# 7. Audit daemon running?
systemctl is-active auditd

# 8. Cron restricted to authorised users?
ls -la /etc/cron.allow /etc/cron.deny 2>/dev/null
ls -la /etc/at.allow /etc/at.deny 2>/dev/null

# 9. Banner configured?
cat /etc/issue
cat /etc/issue.net
cat /etc/motd
```

### macOS Quick Checks

```bash
# 1. FileVault enabled?
fdesetup status

# 2. SIP enabled?
csrutil status

# 3. Gatekeeper enabled?
spctl --status

# 4. Firewall enabled?
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# 5. Auto-updates enabled?
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled

# 6. Screen lock timeout
sysadminctl -screenLock status 2>/dev/null

# 7. Remote login disabled?
sudo systemsetup -getremotelogin

# 8. Guest account disabled?
sudo dscl . -read /Users/Guest 2>/dev/null

# 9. AirDrop restricted?
defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null
```
