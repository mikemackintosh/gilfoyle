# Package Management

Manage packages on Debian/Ubuntu (apt) and RHEL/CentOS/Fedora (dnf/yum) systems.

## Arguments

$ARGUMENTS describes the operation:

Examples:
- `install <package>` — install a package
- `remove <package>` — remove a package
- `search <keyword>` — search for packages
- `update` — update package index and list upgradable
- `upgrade` — upgrade all packages
- `info <package>` — show package details
- `list installed` — list all installed packages
- `history` — show package transaction history
- `security` — show available security updates
- (no args — show system package manager info and pending updates)

## Workflow

1. Parse the operation from `$ARGUMENTS`.
2. Auto-detect the package manager (apt vs dnf/yum).
3. Show the user the exact commands before executing.

### Step 1 — Detect package manager

```bash
if command -v apt &>/dev/null; then
  echo "Package manager: apt (Debian/Ubuntu)"
elif command -v dnf &>/dev/null; then
  echo "Package manager: dnf (Fedora/RHEL 8+)"
elif command -v yum &>/dev/null; then
  echo "Package manager: yum (RHEL 7/CentOS 7)"
elif command -v brew &>/dev/null; then
  echo "Package manager: brew (macOS)"
fi
```

### Step 2 — Execute operation

**Update / check for updates:**

```bash
# Debian/Ubuntu
sudo apt update && apt list --upgradable

# RHEL/Fedora
sudo dnf check-update
```

**Install:**

```bash
# Debian/Ubuntu
sudo apt install <package>

# RHEL/Fedora
sudo dnf install <package>
```

**Security updates only:**

```bash
# Debian/Ubuntu
sudo apt list --upgradable 2>/dev/null | grep -i security

# RHEL/Fedora
sudo dnf updateinfo list security
sudo dnf upgrade --security
```

**Package history / audit:**

```bash
# Debian/Ubuntu
grep " install " /var/log/dpkg.log | tail -20
zgrep " install " /var/log/dpkg.log.*.gz | tail -20

# RHEL/Fedora
dnf history
dnf history info <id>
```

3. Present results and flag:
   - Number of pending security updates
   - Packages with known CVEs (if available)
   - Orphaned packages that can be removed

## Security Notes

- **Always apply security updates promptly.** `apt upgrade` or `dnf upgrade --security` should be run regularly.
- Pin critical packages to prevent unintended upgrades: `apt-mark hold <package>` or `dnf versionlock add <package>`.
- Check GPG key verification is enabled — packages without valid signatures may be tampered with.
- `apt autoremove` and `dnf autoremove` clean up unused dependencies that may have known vulnerabilities.
