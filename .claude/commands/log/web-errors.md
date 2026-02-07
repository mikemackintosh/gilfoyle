# Web Server Error Analysis

Analyse web server logs for errors, scanning activity, and suspicious requests.

## Arguments

$ARGUMENTS should include:
- A path to a web server access log
- Optionally `--errors` to focus on 4xx/5xx responses
- Optionally `--scanners` to detect scanning/recon tools

Examples:
- `/var/log/nginx/access.log`
- `/var/log/apache2/access.log --errors`
- `/var/log/nginx/access.log --scanners`

## Workflow

1. Parse the log file path and mode from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Status code distribution

```bash
awk '{print $9}' <logfile> | sort | uniq -c | sort -rn
```

### 4xx/5xx errors by IP

```bash
awk '$9 ~ /^[45]/ {print $1, $9, $7}' <logfile> | sort | uniq -c | sort -rn | head -30
```

### Top IPs generating 403/404 (recon indicators)

```bash
awk '$9 == 403 || $9 == 404 {print $1}' <logfile> | sort | uniq -c | sort -rn | head -20
```

### Scanning tool detection

```bash
grep -iE '(sqlmap|nikto|nmap|dirbuster|gobuster|masscan|zgrab|wpscan|nuclei|burp)' <logfile> | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Suspicious URL patterns

```bash
# Path traversal
grep -E '(\.\./|%2e%2e)' <logfile> | head -20

# Command injection
grep -E '(%7C|%26|%3B|;|\|)' <logfile> | head -20

# SQL injection
grep -iE "(union.*select|or.*1.*=.*1|drop.*table)" <logfile> | head -20

# Web shell access
grep -iE '(c99|r57|webshell|cmd\.php|shell\.php)' <logfile> | head -20
```

### Large responses (potential data exfiltration)

```bash
awk '$10 > 1000000 {print $1, $7, $10}' <logfile> | sort -t' ' -k3 -rn | head -20
```

3. Summarise findings:
   - Error rate (4xx/5xx as % of total)
   - Top error-producing IPs
   - Scanner activity detected
   - Attack patterns found (SQLi, traversal, etc.)
   - Unusually large responses
   - Recommended actions

## Security Notes

- A high volume of 404s from one IP typically indicates directory brute-forcing or vulnerability scanning.
- 403s may indicate an attacker probing for restricted resources.
- SQL injection and path traversal patterns in logs indicate active exploitation attempts.
- Large response sizes to unusual endpoints may indicate data exfiltration — correlate with the actual content served.
