# SUID/SGID Audit

Scan the filesystem for SUID and SGID binaries and identify any that are unexpected or potentially dangerous.

## Arguments

$ARGUMENTS is optional:
- A path to scan (default: `/` — the entire filesystem)
- `--compare` — compare against a known-good baseline

Examples:
- (no args — scan entire filesystem)
- `/usr/local`
- `--compare`

## Workflow

1. Parse the scan path from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Find SUID binaries

```bash
find <path> -perm -4000 -type f 2>/dev/null
```

### Find SGID binaries

```bash
find <path> -perm -2000 -type f 2>/dev/null
```

### SUID binaries not owned by root (suspicious)

```bash
find <path> -perm -4000 ! -user root -type f 2>/dev/null
```

### SUID/SGID in unusual locations (suspicious)

```bash
find /tmp /home /var/tmp /dev/shm -perm -4000 -o -perm -2000 2>/dev/null
```

### World-writable files (bonus check)

```bash
find <path> -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print 2>/dev/null | head -50
```

### World-writable directories without sticky bit

```bash
find <path> -path /proc -prune -o -path /sys -prune -o -perm -0002 -type d ! -perm -1000 -print 2>/dev/null
```

3. Classify each SUID/SGID binary:

### Known-legitimate SUID binaries (common on Linux)

| Binary | Purpose |
|--------|---------|
| `/usr/bin/passwd` | Password changes |
| `/usr/bin/sudo` | Privilege escalation (authorised) |
| `/usr/bin/su` | Switch user |
| `/usr/bin/mount`, `/usr/bin/umount` | Filesystem mounting |
| `/usr/bin/ping` | ICMP (older systems) |
| `/usr/bin/chfn`, `/usr/bin/chsh` | User info changes |
| `/usr/bin/newgrp` | Group changes |
| `/usr/bin/pkexec` | PolicyKit execution |

4. Present results:
   - Total SUID binaries found
   - Total SGID binaries found
   - Any in unexpected locations (CRITICAL)
   - Any not owned by root (CRITICAL)
   - Any not in the known-legitimate list (REVIEW)
   - World-writable files found

## Security Notes

- SUID binaries run with the file owner's privileges — a SUID-root binary with a vulnerability can give an attacker root access.
- SUID binaries in `/tmp`, `/home`, or `/var/tmp` are almost always malicious.
- SUID binaries not owned by root are unusual and should be investigated.
- Consider removing SUID from binaries that don't need it: `chmod u-s /path/to/binary`.
- GTFOBins (https://gtfobins.github.io/) lists SUID binaries that can be abused for privilege escalation.
