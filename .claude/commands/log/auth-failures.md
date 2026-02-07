# Auth Failure Analysis

Analyse authentication failures from system logs.

## Arguments

$ARGUMENTS is optional:
- A log file path (default: auto-detect based on OS)
- `--last <duration>` for macOS unified logs (e.g., `--last 24h`, `--last 7d`)

Examples:
- (no args — auto-detect)
- `/var/log/auth.log`
- `/var/log/secure`
- `--last 24h`

## Workflow

1. Detect the operating system and locate the appropriate log source.
2. Show the user the exact commands before executing.

### Linux (Debian/Ubuntu)

```bash
# Failed password attempts
grep 'Failed password' /var/log/auth.log | tail -50

# Top source IPs
grep 'Failed password' /var/log/auth.log | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -20

# Top targeted usernames
grep 'Failed password' /var/log/auth.log | grep -oP 'for (invalid user )?\K\S+' | sort | uniq -c | sort -rn | head -20

# Failed sudo attempts
grep 'sudo:.*authentication failure' /var/log/auth.log | tail -20
```

### Linux (RHEL/CentOS)

Same commands but use `/var/log/secure` instead of `/var/log/auth.log`.

### macOS

```bash
# SSH failures
log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Failed"' --last <duration>

# Sudo failures
log show --predicate 'process == "sudo" AND eventMessage CONTAINS "incorrect password"' --last <duration>

# General auth failures
log show --predicate 'subsystem == "com.apple.Authorization" AND eventMessage CONTAINS "deny"' --last <duration>
```

3. Present a summary:
   - Total failed attempts in the time window
   - Top 10 source IPs (with count)
   - Top 10 targeted usernames (with count)
   - Any patterns (time clustering, dictionary usernames, single IP hammering)
   - Successful logins from the same IPs (to check for credential compromise)

## Security Notes

- A high volume of failed logins from one IP is a brute-force indicator. Consider blocking with `fail2ban` or firewall rules.
- Failed logins for `invalid user` with common names (admin, root, test, oracle) indicate automated scanning.
- Check if any failed-login IPs also have successful logins — this may indicate a compromised credential.
- On macOS, `log show` queries are in-memory and may be slow for large time ranges.
