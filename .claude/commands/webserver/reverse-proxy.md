# Reverse Proxy and Load Balancing

Set up reverse proxy and load balancing with nginx or Apache — proxying to application backends, WebSocket support, health checks, and upstream configuration.

## Arguments

$ARGUMENTS describes the setup:

Examples:
- `nginx <domain> <backend:port>` — nginx reverse proxy to a backend
- `apache <domain> <backend:port>` — Apache reverse proxy to a backend
- `load-balance <domain> <backend1:port> <backend2:port>` — load balanced setup
- `websocket <domain> <backend:port>` — reverse proxy with WebSocket support
- (no args — guide for choosing and configuring a reverse proxy)

## Workflow

1. Parse the setup from `$ARGUMENTS`.
2. Show the user the exact commands and configs before executing.

### nginx Reverse Proxy

```nginx
upstream backend {
    server 127.0.0.1:3000;
    # Load balancing options:
    # least_conn;           # Fewest active connections
    # ip_hash;              # Sticky sessions by client IP
    # server 127.0.0.1:3001;  # Add more backends
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }

    # Health check endpoint (don't log)
    location /health {
        proxy_pass http://backend;
        access_log off;
    }
}
```

### Apache Reverse Proxy

```apache
<VirtualHost *:443>
    ServerName app.example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/app.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/app.example.com/privkey.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"

    # Load balancing
    # <Proxy "balancer://backend">
    #     BalancerMember http://127.0.0.1:3000
    #     BalancerMember http://127.0.0.1:3001
    #     ProxySet lbmethod=byrequests
    # </Proxy>
    # ProxyPass / balancer://backend/
    # ProxyPassReverse / balancer://backend/

    # WebSocket
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule /(.*) ws://127.0.0.1:3000/$1 [P,L]
</VirtualHost>
```

3. Test the config and reload.

## Security Notes

- **Always set `X-Forwarded-For` and `X-Real-IP` headers** so the backend sees the real client IP, not the proxy's IP.
- **Use `proxy_set_header Host $host`** to preserve the original Host header — backends often rely on it for routing.
- Backend health checks prevent sending traffic to crashed backends. nginx Plus has built-in health checks; the open-source version relies on passive checks.
- Set appropriate timeouts — overly long timeouts can lead to connection exhaustion under load.
- WebSocket proxying requires `proxy_http_version 1.1` and the Upgrade/Connection headers in nginx.
