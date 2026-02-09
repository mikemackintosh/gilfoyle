# nginx Configuration and Management

Configure, manage, and troubleshoot nginx — server blocks, virtual hosts, modules, and common patterns.

## Arguments

$ARGUMENTS is optional:
- `status` — show nginx status and running config
- `vhost <domain>` — generate a server block for a domain
- `ssl <domain>` — generate an SSL server block
- `test` — test configuration syntax
- `logs [access|error]` — tail nginx logs
- (no args — nginx status and configuration overview)

Examples:
- (no args — overview)
- `status`
- `vhost example.com`
- `ssl example.com`
- `test`
- `logs error`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Status check

```bash
echo "=== nginx Status ==="
systemctl status nginx --no-pager

echo ""
echo "=== Version and Modules ==="
nginx -V 2>&1

echo ""
echo "=== Config Test ==="
nginx -t

echo ""
echo "=== Listening Ports ==="
ss -tlnp | grep nginx
```

### Step 2 — Configuration overview

```bash
echo "=== Main Config ==="
cat /etc/nginx/nginx.conf | grep -v '^\s*#' | grep -v '^$'

echo ""
echo "=== Enabled Sites ==="
ls -la /etc/nginx/sites-enabled/ 2>/dev/null || ls -la /etc/nginx/conf.d/

echo ""
echo "=== Server Names ==="
nginx -T 2>/dev/null | grep -E 'server_name|listen' | sed 's/^\s*//'
```

### Step 3 — Generate configs

Generate appropriate server block configuration based on the request (plain HTTP, HTTPS, reverse proxy).

### Step 4 — Management

```bash
# Test before reload (always)
nginx -t && systemctl reload nginx

# View access log
tail -f /var/log/nginx/access.log

# View error log
tail -f /var/log/nginx/error.log

# Show compiled config (all includes resolved)
nginx -T
```

3. When generating configs, include security headers and modern TLS settings by default.

## Security Notes

- **Always run `nginx -t` before reloading.** A syntax error in any included file will prevent nginx from starting.
- Hide nginx version: `server_tokens off;` in the `http` block.
- Deny access to hidden files: `location ~ /\. { deny all; }`.
- Set `client_max_body_size` to prevent large upload abuse.
- Use `limit_req_zone` to rate-limit API endpoints and login pages.
