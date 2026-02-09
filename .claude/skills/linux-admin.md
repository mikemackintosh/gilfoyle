---
name: Linux Administration
description: Linux system administration — disk/storage management, package management, user/group administration, systemd services, process management, file permissions, performance monitoring, and boot/kernel operations.
instructions: |
  Use this skill when the user needs help with Linux system administration tasks — managing disks,
  packages, users, services, processes, permissions, performance, or boot configuration. Commands
  cover Debian/Ubuntu (apt) and RHEL/CentOS/Fedora (yum/dnf) where applicable. Always show commands
  before executing and explain what each does. Prefer non-destructive approaches and warn before
  any data-loss operations.
---

# Linux Administration Skill

## Related Commands
- `/linux:disk` — Disk and storage management (df, du, lvm, mount, fstab, RAID)
- `/linux:packages` — Package management (apt, yum, dnf, snap, brew)
- `/linux:users` — User and group management (useradd, sudoers, PAM)
- `/linux:systemd` — Systemd services, timers, and unit files
- `/linux:processes` — Process management (ps, top, kill, cgroups, nohup)
- `/linux:permissions` — File permissions, ACLs, umask, sticky bits
- `/linux:performance` — Performance monitoring and tuning (vmstat, iostat, sysctl)
- `/linux:boot` — Boot process, GRUB, initramfs, kernel parameters

## Disk & Storage

### Filesystem Usage

```bash
# Disk usage summary
df -hT

# Directory size
du -sh /var/log/*
du -sh --max-depth=1 /

# Find largest files
find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | sort -k5 -rh | head -20

# Inode usage (can run out before disk space)
df -i
```

### LVM Management

```bash
# Physical volumes
pvs
pvdisplay

# Volume groups
vgs
vgdisplay

# Logical volumes
lvs
lvdisplay

# Extend a logical volume
lvextend -L +10G /dev/vg0/lv_data
resize2fs /dev/vg0/lv_data        # ext4
xfs_growfs /dev/vg0/lv_data       # xfs
```

### Mount & fstab

```bash
# Show all mounts
mount | column -t
findmnt --fstab

# Mount a filesystem
mount /dev/sdb1 /mnt/data

# fstab entry format
# <device>  <mountpoint>  <type>  <options>  <dump>  <pass>
# UUID=xxxx /data         ext4    defaults   0       2

# Get UUID of a device
blkid /dev/sdb1

# Test fstab without rebooting
mount -a
```

### RAID

```bash
# Check RAID status
cat /proc/mdstat
mdadm --detail /dev/md0

# RAID levels quick reference
# RAID 0: Striping, no redundancy, max performance
# RAID 1: Mirroring, 50% capacity, read performance
# RAID 5: Striping with parity, 1 disk fault tolerance
# RAID 6: Striping with double parity, 2 disk fault tolerance
# RAID 10: Mirrored stripes, best performance + redundancy
```

## Package Management

### Debian/Ubuntu (apt)

```bash
apt update                           # Refresh package index
apt upgrade                          # Upgrade all packages
apt install <package>                # Install a package
apt remove <package>                 # Remove (keep config)
apt purge <package>                  # Remove + delete config
apt search <keyword>                 # Search packages
apt show <package>                   # Package details
apt list --installed                 # List installed packages
apt list --upgradable                # List available upgrades
dpkg -l | grep <package>            # Check if installed
apt autoremove                       # Remove unused dependencies
```

### RHEL/CentOS/Fedora (dnf/yum)

```bash
dnf check-update                     # Check for updates
dnf upgrade                          # Upgrade all packages
dnf install <package>                # Install a package
dnf remove <package>                 # Remove a package
dnf search <keyword>                 # Search packages
dnf info <package>                   # Package details
dnf list installed                   # List installed packages
dnf history                          # Transaction history
dnf history undo <id>               # Undo a transaction
rpm -qa | grep <package>            # Check if installed
```

## User & Group Management

```bash
# Create user
useradd -m -s /bin/bash <username>
passwd <username>

# Create system user (no login)
useradd -r -s /usr/sbin/nologin <username>

# Modify user
usermod -aG <group> <username>       # Add to group
usermod -L <username>                # Lock account
usermod -U <username>                # Unlock account

# Delete user
userdel -r <username>                # Remove user + home dir

# Groups
groupadd <groupname>
groupdel <groupname>
groups <username>                    # Show user's groups
id <username>                        # Show UID/GID

# Sudoers (use visudo, never edit directly)
visudo
# username ALL=(ALL:ALL) ALL
# %groupname ALL=(ALL:ALL) NOPASSWD: ALL
```

## Systemd

```bash
# Service management
systemctl start <service>
systemctl stop <service>
systemctl restart <service>
systemctl reload <service>           # Reload config without restart
systemctl status <service>
systemctl enable <service>           # Start on boot
systemctl disable <service>
systemctl is-active <service>
systemctl is-enabled <service>

# List services
systemctl list-units --type=service
systemctl list-units --type=service --state=failed

# Logs
journalctl -u <service>             # Logs for a service
journalctl -u <service> --since "1 hour ago"
journalctl -f                       # Follow (tail)
journalctl -p err                   # Only errors
journalctl --disk-usage             # Journal disk usage

# Timers (cron replacement)
systemctl list-timers --all
```

## Process Management

```bash
# Process listing
ps aux                               # All processes
ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | head -20
pstree -p                           # Process tree

# Real-time monitoring
top
htop                                 # Interactive (if installed)

# Kill processes
kill <pid>                           # SIGTERM (graceful)
kill -9 <pid>                        # SIGKILL (force)
killall <name>                       # Kill by name
pkill -f <pattern>                   # Kill by pattern

# Background processes
nohup command &                      # Survive terminal close
disown %1                            # Detach job from terminal

# Resource limits
ulimit -a                            # Show current limits
cat /proc/<pid>/limits               # Limits for a process
```

## File Permissions

```bash
# Numeric permissions
# 4=read, 2=write, 1=execute
chmod 755 file                       # rwxr-xr-x
chmod 600 file                       # rw-------
chmod 644 file                       # rw-r--r--

# Symbolic permissions
chmod u+x file                       # Add execute for owner
chmod g-w file                       # Remove write for group
chmod o= file                        # Remove all for others

# Ownership
chown user:group file
chown -R user:group directory

# Special bits
chmod u+s file                       # SUID
chmod g+s directory                  # SGID
chmod +t directory                   # Sticky bit

# ACLs
getfacl file
setfacl -m u:username:rw file
setfacl -m g:groupname:r file
setfacl -x u:username file          # Remove ACL entry

# Default umask
umask                                # Show current
umask 022                            # Set (files=644, dirs=755)
```

## Performance Monitoring

```bash
# Memory
free -h
vmstat 1 5                           # 5 samples, 1 second apart
cat /proc/meminfo

# CPU
mpstat 1 5                           # Per-CPU stats
uptime                               # Load average

# Disk I/O
iostat -xz 1 5                       # Disk I/O stats
iotop                                # I/O by process

# Network
ss -s                                # Socket statistics summary
sar -n DEV 1 5                       # Network throughput

# Sysctl tuning
sysctl -a                            # All kernel parameters
sysctl vm.swappiness                 # Check specific setting
sysctl -w vm.swappiness=10           # Set temporarily
# /etc/sysctl.conf or /etc/sysctl.d/*.conf for persistent changes
```

## Boot & Kernel

```bash
# Kernel version
uname -r
uname -a

# GRUB
cat /etc/default/grub
update-grub                          # Debian/Ubuntu
grub2-mkconfig -o /boot/grub2/grub.cfg  # RHEL

# Kernel parameters (runtime)
cat /proc/cmdline                    # Boot parameters
sysctl -a                            # All tunable parameters

# Kernel modules
lsmod                                # Loaded modules
modprobe <module>                    # Load module
modprobe -r <module>                 # Unload module
modinfo <module>                     # Module details

# initramfs
lsinitrd                             # RHEL: list contents
lsinitramfs /boot/initrd*            # Debian: list contents
dracut -f                            # RHEL: rebuild
update-initramfs -u                  # Debian: rebuild

# Runlevels / targets
systemctl get-default
systemctl set-default multi-user.target   # No GUI
systemctl set-default graphical.target    # With GUI
```
