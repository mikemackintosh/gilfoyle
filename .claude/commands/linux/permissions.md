# File Permissions and ACLs

Manage Linux file permissions, ownership, ACLs, umask, and special permission bits.

## Arguments

$ARGUMENTS is optional:
- `check <path>` — show permissions for a file/directory
- `audit` — scan for common permission problems
- `acl <path>` — show ACLs for a file/directory
- `fix <path>` — suggest permission fixes
- (no args — permission audit of common sensitive paths)

Examples:
- (no args — audit)
- `check /etc/shadow`
- `audit`
- `acl /var/www`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Permission overview

```bash
echo "=== Critical File Permissions ==="
ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers 2>/dev/null

echo ""
echo "=== SSH Directory Permissions ==="
ls -la ~/.ssh/ 2>/dev/null
ls -la /etc/ssh/ 2>/dev/null

echo ""
echo "=== /tmp Permissions ==="
ls -ld /tmp /var/tmp
mount | grep -E '/tmp|/var/tmp'
```

### Step 2 — Permission audit

```bash
echo "=== World-Writable Files (excluding /tmp and /proc) ==="
find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/tmp/*' -not -path '/var/tmp/*' 2>/dev/null | head -20

echo ""
echo "=== World-Writable Directories (without sticky bit) ==="
find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/proc/*' 2>/dev/null | head -20

echo ""
echo "=== Files with No Owner ==="
find / -xdev -nouser -o -nogroup 2>/dev/null | head -20
```

### Step 3 — Special bits

```bash
echo "=== SUID Binaries ==="
find / -xdev -type f -perm -4000 2>/dev/null | head -20

echo ""
echo "=== SGID Binaries ==="
find / -xdev -type f -perm -2000 2>/dev/null | head -20
```

### Step 4 — ACL details

```bash
# Show ACLs
getfacl <path>

# Set ACL
setfacl -m u:<user>:rw <path>
setfacl -m g:<group>:r <path>

# Set default ACL (for new files in directory)
setfacl -d -m u:<user>:rw <directory>

# Remove ACL
setfacl -x u:<user> <path>

# Remove all ACLs
setfacl -b <path>
```

3. Present findings with severity.

### Permission Reference

| Numeric | Symbolic | Meaning |
|---------|----------|---------|
| 755 | rwxr-xr-x | Standard for directories and executables |
| 644 | rw-r--r-- | Standard for regular files |
| 600 | rw------- | Private files (keys, configs with passwords) |
| 700 | rwx------ | Private directories (.ssh) |
| 400 | r-------- | Read-only sensitive files |

### Special Bits

| Bit | Numeric | Effect |
|-----|---------|--------|
| SUID | 4000 | File executes as the file owner |
| SGID | 2000 | File executes as the group; new files in directory inherit group |
| Sticky | 1000 | Only file owner can delete files in directory (e.g., /tmp) |

## Security Notes

- `/etc/shadow` must be `640` or `600` owned by `root:shadow` — it contains password hashes.
- World-writable directories without the sticky bit allow any user to delete other users' files.
- SUID root binaries are privilege escalation targets. Compare against a known-good baseline.
- Files owned by nobody or a deleted user (`nouser`/`nogroup`) may indicate compromise or poor hygiene.
- The `umask` defaults to `022` (files=644, dirs=755). For sensitive environments, use `027` (files=640, dirs=750).
