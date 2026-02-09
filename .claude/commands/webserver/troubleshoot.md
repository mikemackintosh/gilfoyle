# Web Server Troubleshooting

Diagnose and fix common web server issues — connection failures, 502/504 errors, permission problems, SSL errors, and performance bottlenecks.

## Arguments

$ARGUMENTS describes the symptom:

Examples:
- `502` — diagnose 502 Bad Gateway
- `504` — diagnose 504 Gateway Timeout
- `403` — diagnose 403 Forbidden
- `ssl` — diagnose SSL/TLS errors
- `slow` — diagnose slow response times
- `down` — web server not responding at all
- (no args — general health check)

## Workflow

1. Parse the symptom from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — General health check

```bash
echo "=== Web Server Status ==="
systemctl status nginx --no-pager 2>/dev/null
systemctl status apache2 --no-pager 2>/dev/null || systemctl status httpd --no-pager 2>/dev/null

echo ""
echo "=== Listening Ports ==="
ss -tlnp | grep -E ':80|:443|nginx|apache|httpd'

echo ""
echo "=== Config Test ==="
nginx -t 2>&1 || apachectl configtest 2>&1

echo ""
echo "=== Recent Errors ==="
tail -20 /var/log/nginx/error.log 2>/dev/null
tail -20 /var/log/apache2/error.log 2>/dev/null || tail -20 /var/log/httpd/error_log 2>/dev/null
```

### Common Issues

#### 502 Bad Gateway
```bash
# Backend is down or unreachable
echo "=== Backend Check ==="
# Check if backend process is running
ss -tlnp | grep <backend_port>
# Check backend logs
# Test backend directly
curl -s http://127.0.0.1:<backend_port>/health
```
Causes: backend crashed, wrong proxy_pass address, backend taking too long to start.

#### 504 Gateway Timeout
```bash
# Backend is too slow
echo "=== Timeout Check ==="
# Test backend response time
time curl -s http://127.0.0.1:<backend_port>/
# Check proxy timeout settings
nginx -T 2>/dev/null | grep -i timeout
```
Fix: increase `proxy_read_timeout` or fix the slow backend.

#### 403 Forbidden
```bash
# Permission issues
echo "=== Permission Check ==="
namei -l /var/www/example.com/index.html
# Check SELinux (RHEL)
getenforce 2>/dev/null
ls -Z /var/www/ 2>/dev/null
# Check nginx user
grep 'user ' /etc/nginx/nginx.conf
```
Causes: wrong file ownership, SELinux blocking access, missing index file, `deny all` in config.

#### SSL Errors
```bash
# Certificate issues
echo "=== Certificate Check ==="
openssl s_client -connect localhost:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer
# Check cert files exist and are readable
ls -la /etc/letsencrypt/live/example.com/ 2>/dev/null
# Check key matches cert
openssl x509 -noout -modulus -in cert.pem 2>/dev/null | md5sum
openssl rsa -noout -modulus -in key.pem 2>/dev/null | md5sum
```

#### Slow Performance
```bash
echo "=== Performance Check ==="
# Connection count
ss -s
# Worker process count
ps aux | grep -E 'nginx|apache|httpd' | grep -v grep | wc -l
# Response time
time curl -s -o /dev/null -w "%{time_total}s" https://example.com/
# Check for disk I/O issues (access logs on slow disk)
iostat -x 1 3 2>/dev/null
```

3. Diagnose based on the symptom and provide targeted fix.

## Security Notes

- Error logs may contain stack traces with sensitive information. Don't expose them to clients.
- A 502 on a previously working site could indicate the backend was compromised and crashed, or an attacker killed it.
- Repeated 403s from a single IP may indicate scanning or brute-force attempts.
- SSL certificate expiry is the #1 cause of unexpected HTTPS failures. Monitor expiry dates proactively.
