# CIS Benchmark Quick Check

Run quick spot-checks inspired by CIS benchmarks for the local system.

## Arguments

$ARGUMENTS is optional:
- `linux` or `macos` (default: auto-detect)

Examples:
- (no args — auto-detect OS)
- `linux`
- `macos`

## Workflow

1. Detect the operating system or use the value from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. Run the appropriate checks for the detected OS.

### Linux Checks

```bash
echo "=== 1. ASLR ==="
sysctl kernel.randomize_va_space

echo "=== 2. Core dumps restricted ==="
grep -r "hard core" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null

echo "=== 3. IP forwarding disabled ==="
sysctl net.ipv4.ip_forward

echo "=== 4. SYN cookies enabled ==="
sysctl net.ipv4.tcp_syncookies

echo "=== 5. ICMP redirects disabled ==="
sysctl net.ipv4.conf.all.accept_redirects

echo "=== 6. Source routing disabled ==="
sysctl net.ipv4.conf.all.accept_source_route

echo "=== 7. Reverse path filtering ==="
sysctl net.ipv4.conf.all.rp_filter

echo "=== 8. SSH root login ==="
grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null

echo "=== 9. SSH password auth ==="
grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null

echo "=== 10. Audit daemon ==="
systemctl is-active auditd 2>/dev/null

echo "=== 11. NTP configured ==="
timedatectl status 2>/dev/null | grep -i sync

echo "=== 12. /tmp mount options ==="
mount | grep /tmp

echo "=== 13. SUID in /tmp ==="
find /tmp -perm -4000 -type f 2>/dev/null

echo "=== 14. World-writable files in /etc ==="
find /etc -perm -0002 -type f 2>/dev/null

echo "=== 15. Users with UID 0 ==="
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo "=== 16. Empty passwords ==="
sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null
```

### macOS Checks

```bash
echo "=== 1. FileVault ==="
fdesetup status

echo "=== 2. System Integrity Protection ==="
csrutil status

echo "=== 3. Gatekeeper ==="
spctl --status

echo "=== 4. Application Firewall ==="
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

echo "=== 5. Stealth Mode ==="
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

echo "=== 6. Auto-updates ==="
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null

echo "=== 7. Remote Login (SSH) ==="
sudo systemsetup -getremotelogin 2>/dev/null

echo "=== 8. Screen Sharing ==="
sudo launchctl list 2>/dev/null | grep -i screensharing

echo "=== 9. Guest Account ==="
sudo dscl . -read /Users/Guest 2>/dev/null | grep -i "AuthenticationAuthority"

echo "=== 10. Unsigned Kernel Extensions ==="
kextstat 2>/dev/null | grep -v com.apple

echo "=== 11. SUID in /tmp ==="
find /tmp -perm -4000 -type f 2>/dev/null

echo "=== 12. SSH config ==="
grep -E "^(PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config 2>/dev/null
```

4. Present results as a scorecard:

| # | Check | Status | Detail |
|---|-------|--------|--------|
| 1 | ASLR / FileVault | PASS/FAIL | ... |

Count: X passed, Y failed, Z warnings.

5. For each FAIL, provide the remediation command.

## Security Notes

- These are quick spot-checks, not a full CIS benchmark audit. For comprehensive compliance, use a dedicated CIS scanning tool (e.g., CIS-CAT, OpenSCAP, Lynis).
- Some checks require root/sudo privileges.
- A PASS here does not guarantee full CIS compliance — each benchmark has dozens of additional controls.
- Remediation commands should be tested in a non-production environment first.
