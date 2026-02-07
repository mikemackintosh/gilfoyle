# Brute-Force Detection

Detect brute-force login attempts across SSH and web application logs.

## Arguments

$ARGUMENTS is optional:
- `ssh` (default) — analyse SSH brute-force attempts
- `web <logfile>` — analyse web login brute-force attempts
- `--threshold <n>` — minimum attempts to flag (default: 10)

Examples:
- (no args — SSH brute-force on default auth log)
- `ssh /var/log/auth.log`
- `web /var/log/nginx/access.log`
- `ssh --threshold 5`

## Workflow

1. Parse the mode, log file, and threshold from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### SSH brute-force detection

```bash
# IPs with more than <threshold> failed attempts
grep 'Failed password' <logfile> | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | awk '$1 >= <threshold>'

# Timeline: failed attempts per hour
grep 'Failed password' <logfile> | awk '{print $1,$2,$3}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Check if any brute-force IPs succeeded
for ip in $(grep 'Failed password' <logfile> | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | awk '$1 >= <threshold> {print $2}'); do
  echo "=== $ip ==="
  grep "$ip" <logfile> | grep 'Accepted'
done
```

### Web login brute-force detection

```bash
# IPs with many POST requests to login endpoint
grep '"POST.*/login' <logfile> | awk '{print $1}' | sort | uniq -c | sort -rn | awk '$1 >= <threshold>'

# IPs with many 401 responses
awk '$9 == 401 {print $1}' <logfile> | sort | uniq -c | sort -rn | awk '$1 >= <threshold>'

# Timeline of attempts
grep '"POST.*/login' <logfile> | awk '{print $4}' | cut -d: -f1,2 | sort | uniq -c
```

3. Present findings:
   - IPs exceeding the threshold (with attempt counts)
   - Whether any brute-force IPs achieved a successful login (critical finding)
   - Attack timeline (bursts vs sustained)
   - Usernames targeted
   - Recommended actions (block IPs, enable fail2ban, enforce MFA)

## Security Notes

- A successful login after many failures from the same IP is a strong indicator of credential compromise.
- Distributed brute-force attacks (low attempts per IP, many IPs) are harder to detect — look for unusual username patterns instead.
- Consider implementing `fail2ban`, rate limiting, or account lockout policies.
- MFA is the most effective defence against brute-force attacks.
