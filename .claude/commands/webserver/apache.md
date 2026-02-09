# Apache / httpd Configuration and Management

Configure, manage, and troubleshoot Apache (httpd) — virtual hosts, modules, and common patterns.

## Arguments

$ARGUMENTS is optional:
- `status` — show Apache status and running config
- `vhost <domain>` — generate a VirtualHost for a domain
- `ssl <domain>` — generate an SSL VirtualHost
- `modules` — list enabled modules
- `test` — test configuration syntax
- `logs [access|error]` — tail Apache logs
- (no args — Apache status and configuration overview)

Examples:
- (no args — overview)
- `status`
- `vhost example.com`
- `modules`
- `test`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Detect whether this is Debian (apache2) or RHEL (httpd).
3. Show the user the exact commands before executing.

### Step 1 — Status check

```bash
echo "=== Apache Status ==="
systemctl status apache2 --no-pager 2>/dev/null || systemctl status httpd --no-pager

echo ""
echo "=== Version ==="
apache2 -v 2>/dev/null || httpd -v

echo ""
echo "=== Config Test ==="
apachectl configtest 2>&1

echo ""
echo "=== Listening Ports ==="
ss -tlnp | grep -E 'apache|httpd'
```

### Step 2 — Configuration overview

```bash
echo "=== Enabled Sites (Debian) ==="
ls -la /etc/apache2/sites-enabled/ 2>/dev/null

echo ""
echo "=== Config Files (RHEL) ==="
ls -la /etc/httpd/conf.d/ 2>/dev/null

echo ""
echo "=== Enabled Modules ==="
apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null
```

### Step 3 — Module management (Debian)

```bash
# Enable modules
a2enmod ssl rewrite headers proxy proxy_http

# Disable modules
a2dismod autoindex status

# Enable/disable sites
a2ensite example.com.conf
a2dissite 000-default.conf
```

### Step 4 — Management

```bash
# Test before reload (always)
apachectl configtest && systemctl reload apache2

# View logs
tail -f /var/log/apache2/error.log      # Debian
tail -f /var/log/httpd/error_log         # RHEL
```

3. When generating configs, include security headers, disable directory listing, and use modern TLS.

## Security Notes

- **Always run `apachectl configtest` before reloading.** A syntax error prevents Apache from starting.
- Disable `ServerSignature` and set `ServerTokens Prod` to hide version info.
- Disable `Options Indexes` to prevent directory listing.
- Disable unused modules to reduce attack surface (`mod_status`, `mod_info`, `mod_autoindex`).
- Use `<Directory>` blocks with `Require all denied` as default, then explicitly allow paths.
