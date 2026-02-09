# SSL/TLS Certificate Deployment

Deploy SSL/TLS certificates using certbot (Let's Encrypt ACME), manual deployment, and auto-renewal configuration.

## Arguments

$ARGUMENTS describes the deployment:

Examples:
- `certbot nginx <domain>` — auto-configure nginx with Let's Encrypt
- `certbot apache <domain>` — auto-configure Apache with Let's Encrypt
- `certbot standalone <domain>` — standalone mode (no web server integration)
- `certbot webroot <domain> <webroot>` — webroot mode (no downtime)
- `manual <domain>` — guide for manual certificate deployment
- `renew` — check and renew all certificates
- `status` — show installed certificates and expiry dates
- (no args — show certificate status)

## Workflow

1. Parse the deployment method from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Check current certificates

```bash
echo "=== Certbot Certificates ==="
certbot certificates 2>/dev/null || echo "(certbot not installed)"

echo ""
echo "=== Certificate Files ==="
ls -la /etc/letsencrypt/live/ 2>/dev/null
ls -la /etc/ssl/certs/ 2>/dev/null | head -10
```

### Step 2 — Install certbot (if needed)

```bash
# Debian/Ubuntu
sudo apt install certbot python3-certbot-nginx    # For nginx
sudo apt install certbot python3-certbot-apache   # For Apache

# RHEL/Fedora
sudo dnf install certbot python3-certbot-nginx
sudo dnf install certbot python3-certbot-apache
```

### Step 3 — Obtain certificate

```bash
# nginx (auto-configures server block)
sudo certbot --nginx -d example.com -d www.example.com

# Apache (auto-configures VirtualHost)
sudo certbot --apache -d example.com -d www.example.com

# Standalone (stops/starts its own web server on port 80)
sudo certbot certonly --standalone -d example.com

# Webroot (no downtime, works with running web server)
sudo certbot certonly --webroot -w /var/www/example.com -d example.com

# Dry run (test without actually obtaining)
sudo certbot certonly --dry-run --nginx -d example.com
```

### Step 4 — Auto-renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Check timer (certbot auto-installs this)
systemctl list-timers | grep certbot

# Manual renewal
sudo certbot renew

# Renewal with hooks (reload web server after renewal)
sudo certbot renew --deploy-hook "systemctl reload nginx"
```

### Step 5 — Manual certificate deployment

```bash
# Copy cert files to standard location
sudo cp fullchain.pem /etc/ssl/certs/example.com.pem
sudo cp privkey.pem /etc/ssl/private/example.com.key
sudo chmod 600 /etc/ssl/private/example.com.key

# nginx config
# ssl_certificate /etc/ssl/certs/example.com.pem;
# ssl_certificate_key /etc/ssl/private/example.com.key;

# Apache config
# SSLCertificateFile /etc/ssl/certs/example.com.pem
# SSLCertificateKeyFile /etc/ssl/private/example.com.key

# Test and reload
nginx -t && systemctl reload nginx
```

3. Verify the deployment works.

## Security Notes

- Let's Encrypt certificates are valid for 90 days. Auto-renewal should be configured and tested.
- Private keys should be `600` permissions owned by root. Never make them world-readable.
- Use `fullchain.pem` (not just `cert.pem`) to include the intermediate CA — many clients require the full chain.
- Test renewal with `--dry-run` before relying on it — DNS changes, firewall rules, or port conflicts can break renewal.
- Let's Encrypt rate limits: 50 certificates per registered domain per week. Use `--staging` for testing.
