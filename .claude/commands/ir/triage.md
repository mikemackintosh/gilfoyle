# Incident Triage

Perform initial triage on a potentially compromised host — capture volatile data, running processes, network connections, and logged-in users.

## Arguments

$ARGUMENTS is optional:
- `--save <directory>` — save output to files for evidence (default: display only)
- `--remote user@host` — triage a remote host over SSH

Examples:
- (no args — triage local host, display only)
- `--save /tmp/evidence`
- `--remote admin@10.0.0.50`

## Workflow

1. Parse options from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. **Remind the user:** Follow the order of volatility — capture volatile data first. Do not reboot the host until evidence is preserved.

### System identification

```bash
uname -a
hostname
date -u
uptime
```

### Logged-in users

```bash
who
w
last | head -20
```

### Running processes (sorted by start time)

```bash
ps aux --sort=start_time    # Linux
ps aux                      # macOS
```

### Network connections

```bash
ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null    # Linux
lsof -i -P -n                                             # macOS
```

### Listening ports

```bash
ss -tlnp 2>/dev/null || lsof -i -P -n | grep LISTEN
```

### Recent logins and sudo activity

```bash
last | head -30
grep 'sudo:' /var/log/auth.log 2>/dev/null | tail -20     # Linux
log show --predicate 'process == "sudo"' --last 1h 2>/dev/null   # macOS
```

### Scheduled tasks

```bash
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
```

4. If `--save` is specified, write each section to a separate file in the output directory and compute SHA-256 checksums:

```bash
shasum -a 256 <output_dir>/*
```

5. Summarise findings:
   - System uptime and current time (UTC)
   - Number of logged-in users
   - Total processes / any suspicious processes
   - Open network connections (especially outbound to unknown IPs)
   - Any unusual cron jobs or scheduled tasks
   - Recommended next steps

## Security Notes

- **Do not modify the system** during triage unless necessary for containment.
- Capture volatile data (memory, connections, processes) before persistent data (disk).
- If saving evidence, use an external or network drive — do not write to the suspect system's disk.
- Document the time (UTC) and who performed each action for chain of custody.
- If this is a production incident, follow your organisation's IR playbook and notify your IR team.
