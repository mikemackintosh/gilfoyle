# Collect Evidence

Collect volatile and system data from a host for forensic analysis, following the order of volatility.

## Arguments

$ARGUMENTS should include:
- An output directory for evidence files

Examples:
- `/mnt/evidence`
- `/tmp/evidence`
- `~/Desktop/evidence`

## Workflow

1. Parse the output directory from `$ARGUMENTS`.
2. **Confirm with the user** before proceeding — this will run multiple commands and write files.
3. Show the user the exact commands before executing.

### Create evidence directory

```bash
OUTDIR="<output_dir>/$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
echo "Evidence collection started: $(date -u)" > "$OUTDIR/collection.log"
```

### 1. System info

```bash
uname -a > "$OUTDIR/01_uname.txt"
date -u > "$OUTDIR/01_date_utc.txt"
uptime > "$OUTDIR/01_uptime.txt"
hostname > "$OUTDIR/01_hostname.txt"
```

### 2. Network state (volatile)

```bash
ifconfig -a > "$OUTDIR/02_interfaces.txt" 2>/dev/null
ip addr > "$OUTDIR/02_ip_addr.txt" 2>/dev/null
netstat -rn > "$OUTDIR/02_routes.txt" 2>/dev/null
ip route > "$OUTDIR/02_ip_route.txt" 2>/dev/null
arp -a > "$OUTDIR/02_arp.txt"
ss -tunapl > "$OUTDIR/02_connections.txt" 2>/dev/null || lsof -i -P -n > "$OUTDIR/02_connections.txt"
```

### 3. Processes (volatile)

```bash
ps auxf > "$OUTDIR/03_processes.txt" 2>/dev/null || ps aux > "$OUTDIR/03_processes.txt"
lsof -nP > "$OUTDIR/03_lsof.txt" 2>/dev/null
```

### 4. Users and logins

```bash
who > "$OUTDIR/04_who.txt"
w > "$OUTDIR/04_w.txt"
last > "$OUTDIR/04_last.txt"
lastb > "$OUTDIR/04_lastb.txt" 2>/dev/null
cat /etc/passwd > "$OUTDIR/04_passwd.txt" 2>/dev/null
```

### 5. Scheduled tasks

```bash
crontab -l > "$OUTDIR/05_crontab_current.txt" 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ > "$OUTDIR/05_cron_dirs.txt" 2>/dev/null
systemctl list-timers --all > "$OUTDIR/05_timers.txt" 2>/dev/null
ls -la ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ > "$OUTDIR/05_launchd.txt" 2>/dev/null
```

### 6. SSH keys

```bash
find / -name "authorized_keys" -type f -exec echo "=== {} ===" \; -exec cat {} \; > "$OUTDIR/06_authorized_keys.txt" 2>/dev/null
```

### 7. Log snapshots

```bash
cp /var/log/auth.log "$OUTDIR/07_auth.log" 2>/dev/null
cp /var/log/secure "$OUTDIR/07_secure.log" 2>/dev/null
cp /var/log/syslog "$OUTDIR/07_syslog.log" 2>/dev/null
dmesg > "$OUTDIR/07_dmesg.txt" 2>/dev/null
```

### 8. Compute checksums

```bash
echo "Evidence collection complete: $(date -u)" >> "$OUTDIR/collection.log"
shasum -a 256 "$OUTDIR"/* > "$OUTDIR/00_checksums.sha256"
```

4. Display:
   - List of all files collected
   - SHA-256 checksums
   - Total evidence size
   - Reminder to preserve chain of custody documentation

## Security Notes

- **Write evidence to an external or network drive** — not to the suspect host's disk, as this modifies the filesystem.
- All evidence files are hashed with SHA-256 for integrity verification.
- Document who collected the evidence, when (UTC), and from which host.
- Do not open or modify evidence files after collection — work on copies.
- For full forensic images (disk clones), use `dd` or a dedicated forensic tool — this command collects live system data only.
