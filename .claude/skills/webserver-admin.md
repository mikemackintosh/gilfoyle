---
name: Web Server Administration
description: Web server configuration and management — nginx, Apache/httpd, reverse proxy setup, SSL/TLS certificate deployment with ACME/certbot, and troubleshooting.
instructions: |
  Use this skill when the user needs help configuring, managing, or troubleshooting web servers.
  Covers nginx and Apache (httpd) configuration, reverse proxy and load balancing setup, SSL/TLS
  certificate deployment using certbot/ACME, and diagnosing common web server issues. Always show
  commands and config changes before executing. Warn about config syntax errors and recommend
  testing before reloading.
---

# Web Server Administration Skill

## Related Commands
- `/webserver:nginx` — nginx configuration, virtual hosts, and management
- `/webserver:apache` — Apache/httpd configuration and management
- `/webserver:reverse-proxy` — Reverse proxy and load balancing setup
- `/webserver:ssl-deploy` — SSL/TLS certificate deployment with certbot/ACME
- `/webserver:troubleshoot` — Web server troubleshooting and diagnostics

## nginx

### Configuration Structure

```
/etc/nginx/
├── nginx.conf              # Main config
├── conf.d/                 # Additional configs (auto-included)
│   └── default.conf
├── sites-available/        # Virtual host configs (Debian)
├── sites-enabled/          # Symlinks to active vhosts (Debian)
├── snippets/               # Reusable config fragments
└── mime.types              # MIME type mappings
```

### Common Operations

```bash
# Test config syntax
nginx -t

# Reload (graceful — no downtime)
systemctl reload nginx

# Restart (drops connections)
systemctl restart nginx

# Show compiled config
nginx -T

# Show version and modules
nginx -V
```

### Basic Server Block

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    root /var/www/example.com;
    index index.html;

    # Logging
    access_log /var/log/nginx/example.com.access.log;
    error_log /var/log/nginx/example.com.error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }
}
```

### SSL Server Block

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Modern TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    root /var/www/example.com;
    index index.html;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
```

### Reverse Proxy

```nginx
upstream backend {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
    # Load balancing methods: round-robin (default), least_conn, ip_hash
    # least_conn;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Security Headers

```nginx
# Add to server or http block
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### Rate Limiting

```nginx
# Define rate limit zone (in http block)
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# Apply rate limit (in location block)
location /api/ {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://backend;
}
```

## Apache / httpd

### Configuration Structure

```
# Debian/Ubuntu
/etc/apache2/
├── apache2.conf
├── sites-available/
├── sites-enabled/
├── mods-available/
├── mods-enabled/
└── conf-available/

# RHEL/CentOS
/etc/httpd/
├── conf/httpd.conf
├── conf.d/
└── conf.modules.d/
```

### Common Operations

```bash
# Test config syntax
apachectl configtest         # or httpd -t

# Reload
systemctl reload apache2     # Debian
systemctl reload httpd       # RHEL

# Enable/disable sites (Debian)
a2ensite example.com.conf
a2dissite 000-default.conf

# Enable/disable modules (Debian)
a2enmod ssl rewrite proxy proxy_http headers
a2dismod autoindex
```

### Basic VirtualHost

```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com

    <Directory /var/www/example.com>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/example.com-error.log
    CustomLog ${APACHE_LOG_DIR}/example.com-access.log combined
</VirtualHost>
```

### SSL VirtualHost

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    # Modern TLS
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder off

    # Security headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
</VirtualHost>

# HTTP redirect
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

### Reverse Proxy

```apache
<VirtualHost *:443>
    ServerName app.example.com

    SSLEngine on
    SSLProxyEngine on

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
</VirtualHost>
```

## Certbot / ACME

```bash
# Install certbot
apt install certbot python3-certbot-nginx    # Debian + nginx
apt install certbot python3-certbot-apache   # Debian + Apache
dnf install certbot python3-certbot-nginx    # RHEL + nginx

# Obtain certificate (auto-configures web server)
certbot --nginx -d example.com -d www.example.com
certbot --apache -d example.com -d www.example.com

# Obtain certificate (standalone — stops web server briefly)
certbot certonly --standalone -d example.com

# Obtain certificate (webroot — no downtime)
certbot certonly --webroot -w /var/www/example.com -d example.com

# Renew all certificates
certbot renew
certbot renew --dry-run    # Test renewal

# Auto-renewal (certbot installs a timer/cron automatically)
systemctl list-timers | grep certbot

# Revoke a certificate
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

# List certificates
certbot certificates
```

## Troubleshooting

```bash
# Check if web server is listening
ss -tlnp | grep -E ':80|:443'

# Test a specific vhost
curl -H "Host: example.com" http://127.0.0.1/

# Follow redirects
curl -LI https://example.com

# Check response headers
curl -I https://example.com

# Test SSL
openssl s_client -connect example.com:443 -servername example.com

# Check error logs
tail -f /var/log/nginx/error.log
tail -f /var/log/apache2/error.log
tail -f /var/log/httpd/error_log

# Check for config syntax errors
nginx -t
apachectl configtest

# Permission issues
namei -l /var/www/example.com/index.html
# Check SELinux context (RHEL)
ls -Z /var/www/example.com/
```
