# Boot Process, GRUB, and Kernel

Manage the Linux boot process — GRUB configuration, kernel parameters, initramfs, modules, and boot targets.

## Arguments

$ARGUMENTS is optional:
- `--grub` — show GRUB configuration
- `--kernel` — show kernel version and parameters
- `--modules` — list loaded kernel modules
- `--targets` — show systemd boot targets
- (no args — full boot overview)

Examples:
- (no args — boot overview)
- `--grub`
- `--kernel`
- `--modules`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Kernel info

```bash
echo "=== Kernel Version ==="
uname -r

echo ""
echo "=== Boot Parameters ==="
cat /proc/cmdline

echo ""
echo "=== Installed Kernels ==="
# Debian/Ubuntu
dpkg --list 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2, $3}'
# RHEL/CentOS
rpm -qa kernel 2>/dev/null
```

### Step 2 — GRUB configuration

```bash
echo "=== GRUB Defaults ==="
cat /etc/default/grub 2>/dev/null | grep -v '^#' | grep -v '^$'

echo ""
echo "=== GRUB Entries ==="
# Debian/Ubuntu
grep -E 'menuentry|submenu' /boot/grub/grub.cfg 2>/dev/null | head -20
# RHEL
grep -E 'menuentry|submenu' /boot/grub2/grub.cfg 2>/dev/null | head -20
```

### Step 3 — Kernel modules

```bash
echo "=== Loaded Modules ($(lsmod | wc -l) total) ==="
lsmod | sort | head -30

echo ""
echo "=== Network Modules ==="
lsmod | grep -iE 'net|eth|wifi|wl|iwl|ath'

echo ""
echo "=== Filesystem Modules ==="
lsmod | grep -iE 'ext4|xfs|btrfs|zfs|nfs|cifs'
```

### Step 4 — Boot target

```bash
echo "=== Current Default Target ==="
systemctl get-default

echo ""
echo "=== Last Boot Time ==="
systemd-analyze

echo ""
echo "=== Slowest Boot Services ==="
systemd-analyze blame | head -15
```

3. Present findings and flag:
   - Old kernels that can be cleaned up
   - Suspicious kernel parameters
   - Slow boot services

## Security Notes

- GRUB should be password-protected to prevent booting into single-user mode (root shell without password).
- Kernel parameters like `init=/bin/bash` on the boot command line give root access — physical security matters.
- Disable unused kernel modules (e.g., `usb-storage`, `firewire`) to reduce attack surface: add to `/etc/modprobe.d/blacklist.conf`.
- `systemd-analyze security <service>` scores a service's sandboxing — useful for hardening.
- Old kernels should be removed to save `/boot` space and reduce the surface for known CVEs.
