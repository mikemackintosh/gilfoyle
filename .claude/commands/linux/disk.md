# Disk and Storage Management

Manage disks, filesystems, LVM, mounts, fstab, and RAID on Linux systems.

## Arguments

$ARGUMENTS is optional:
- `--usage` — show disk and inode usage
- `--lvm` — show LVM layout (PVs, VGs, LVs)
- `--mounts` — show mounted filesystems and fstab
- `--large` — find largest files and directories
- `<path>` — check usage for a specific path
- (no args — full disk overview)

Examples:
- (no args — disk overview)
- `--usage`
- `--lvm`
- `--large`
- `/var/log`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Filesystem usage

```bash
echo "=== Filesystem Usage ==="
df -hT

echo ""
echo "=== Inode Usage ==="
df -i | awk '$5+0 > 50 {print}'
```

### Step 2 — Largest consumers

```bash
echo "=== Top-Level Directory Sizes ==="
du -sh /* 2>/dev/null | sort -rh | head -15

echo ""
echo "=== Largest Files (>100MB) ==="
find / -xdev -type f -size +100M -exec ls -lh {} \; 2>/dev/null | sort -k5 -rh | head -20
```

### Step 3 — LVM layout (if applicable)

```bash
echo "=== Physical Volumes ==="
pvs 2>/dev/null || echo "(no LVM)"

echo ""
echo "=== Volume Groups ==="
vgs 2>/dev/null

echo ""
echo "=== Logical Volumes ==="
lvs 2>/dev/null
```

### Step 4 — Mount points and fstab

```bash
echo "=== Current Mounts ==="
findmnt --fstab 2>/dev/null || mount | column -t

echo ""
echo "=== fstab ==="
cat /etc/fstab | grep -v '^#' | grep -v '^$'
```

3. Flag findings:
   - Filesystems above 85% usage
   - Inode usage above 80%
   - `/tmp` or `/var` nearly full
   - Missing `noexec`/`nosuid` options on `/tmp`

## Security Notes

- `/tmp` should be mounted with `noexec,nosuid,nodev` to prevent execution of malicious binaries.
- Full `/var` or `/var/log` can cause logging to stop, which masks attack activity.
- Running out of inodes (even with free disk space) is a common overlooked issue, especially with many small files.
- LVM snapshots are useful for backups but consume space in the volume group — monitor free PE.
