# Persistence Mechanism Check

Scan a host for common persistence mechanisms that an attacker may have installed.

## Arguments

$ARGUMENTS is optional:
- `--full` — check all persistence locations (slower, more thorough)
- `--remote user@host` — check a remote host over SSH

Examples:
- (no args — check common persistence locations on localhost)
- `--full`
- `--remote admin@10.0.0.50`

## Workflow

1. Parse options from `$ARGUMENTS`.
2. Detect the operating system.
3. Show the user the exact commands before executing.

### Cron jobs (all users)

```bash
# Current user
crontab -l 2>/dev/null

# All users (Linux)
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
  echo "=== $u ==="
  sudo crontab -l -u "$u" 2>/dev/null
done

# System cron directories
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
```

### Systemd services and timers (Linux)

```bash
# Enabled services
systemctl list-unit-files --type=service --state=enabled

# Running timers
systemctl list-timers --all

# Recently created service files
find /etc/systemd/system/ /usr/lib/systemd/system/ ~/.config/systemd/user/ -name '*.service' -mtime -30 2>/dev/null
```

### Init scripts (Linux)

```bash
cat /etc/rc.local 2>/dev/null
ls -la /etc/init.d/
```

### Shell profile scripts

```bash
# System-wide
ls -la /etc/profile.d/
cat /etc/profile 2>/dev/null | tail -10

# Per-user (check all users)
find /home /root -maxdepth 1 -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' -o -name '.zshrc' 2>/dev/null | while read f; do
  echo "=== $f ==="
  tail -5 "$f"
done
```

### SSH authorized_keys

```bash
find / -name "authorized_keys" -type f 2>/dev/null
find / -name "authorized_keys2" -type f 2>/dev/null
```

### macOS Launch Agents/Daemons

```bash
echo "=== User Launch Agents ==="
ls -la ~/Library/LaunchAgents/ 2>/dev/null

echo "=== System Launch Agents ==="
ls -la /Library/LaunchAgents/ 2>/dev/null

echo "=== System Launch Daemons ==="
ls -la /Library/LaunchDaemons/ 2>/dev/null

# Recently modified plists
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name '*.plist' -mtime -30 2>/dev/null
```

### At jobs

```bash
atq 2>/dev/null
ls -la /var/spool/at/ 2>/dev/null
```

### Docker containers (if installed)

```bash
docker ps -a 2>/dev/null
```

4. Flag any suspicious findings:
   - Recently modified persistence files (last 30 days)
   - Cron jobs running scripts from `/tmp`, `/dev/shm`, or user home directories
   - Unknown systemd services
   - Unfamiliar SSH keys in `authorized_keys`
   - LaunchAgents with unusual binary paths
   - Base64-encoded or obfuscated commands in shell profiles

5. Present findings grouped by category with timestamps.

## Security Notes

- Attackers commonly use cron, systemd services, shell profiles, and SSH authorized_keys for persistence.
- On macOS, LaunchAgents and LaunchDaemons are the primary persistence mechanisms.
- Recently created or modified files in persistence locations are the strongest indicators.
- Check the contents of suspicious scripts/plists — not just their existence.
- A clean persistence check does not guarantee the host is clean — kernel-level rootkits and memory-only malware won't appear here.
