---
name: Web Application Security
description: Web application security analysis — HTTP security headers, CORS, CSP, cookie flags, and response inspection.
instructions: |
  Use this skill when the user needs to audit web application security headers, test CORS
  configuration, analyse Content Security Policy, inspect cookie security flags, or perform
  detailed HTTP request/response inspection. Always show commands before executing them
  and explain the security implications of each finding.
---

# Web Application Security Skill

## HTTP Security Headers

### Header Reference

| Header | Purpose | Recommended Value |
|--------|---------|-------------------|
| `Strict-Transport-Security` | Force HTTPS (HSTS) | `max-age=63072000; includeSubDomains; preload` |
| `Content-Security-Policy` | Control resource loading | See CSP section below |
| `X-Content-Type-Options` | Prevent MIME sniffing | `nosniff` |
| `X-Frame-Options` | Prevent clickjacking | `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | Control referer header | `strict-origin-when-cross-origin` or `no-referrer` |
| `Permissions-Policy` | Restrict browser features | `camera=(), microphone=(), geolocation=()` |
| `X-XSS-Protection` | Legacy XSS filter | `0` (disable — CSP is the modern replacement) |
| `Cross-Origin-Opener-Policy` | Isolate browsing context | `same-origin` |
| `Cross-Origin-Embedder-Policy` | Require CORS for embeds | `require-corp` |
| `Cross-Origin-Resource-Policy` | Restrict resource loading | `same-origin` |

### Quick Header Check

```bash
# Fetch response headers only
curl -sI https://example.com

# Fetch with redirect following
curl -sIL https://example.com

# Verbose (includes TLS and request headers)
curl -sv https://example.com -o /dev/null 2>&1 | grep -E '^[<>]'

# Check a specific header
curl -sI https://example.com | grep -i 'strict-transport-security'
curl -sI https://example.com | grep -i 'content-security-policy'

# Check all security headers at once
curl -sI https://example.com | grep -iE '(strict-transport|content-security|x-content-type|x-frame|referrer-policy|permissions-policy|x-xss|cross-origin)'
```

### Headers to Flag as Missing

These headers should be present on every production web application:

1. **Strict-Transport-Security** — Without HSTS, users can be downgraded to HTTP
2. **Content-Security-Policy** — Without CSP, XSS attacks are easier
3. **X-Content-Type-Options** — Without `nosniff`, browsers may MIME-sniff responses
4. **X-Frame-Options** or CSP `frame-ancestors` — Without these, clickjacking is possible

### Headers to Flag as Dangerous

| Header / Value | Risk |
|----------------|------|
| `Access-Control-Allow-Origin: *` | Any site can make cross-origin requests |
| `X-Frame-Options` missing | Clickjacking possible |
| HSTS `max-age` < 31536000 | Too short, reduces protection window |
| `X-Powered-By` present | Leaks server technology |
| `Server` with version | Leaks server version |

## CORS (Cross-Origin Resource Sharing)

### How CORS Works

1. Browser sends `Origin` header with cross-origin requests
2. Server responds with `Access-Control-Allow-*` headers
3. Browser enforces the server's policy

### CORS Headers

| Header | Purpose | Values |
|--------|---------|--------|
| `Access-Control-Allow-Origin` | Allowed origins | Specific origin, `*`, or `null` |
| `Access-Control-Allow-Methods` | Allowed HTTP methods | `GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | Allowed request headers | `Content-Type, Authorization` |
| `Access-Control-Allow-Credentials` | Allow cookies/auth | `true` / absent |
| `Access-Control-Max-Age` | Preflight cache (seconds) | `86400` |
| `Access-Control-Expose-Headers` | Headers readable by JS | `X-Request-Id` |

### Testing CORS

```bash
# Simple CORS request
curl -sI -H "Origin: https://evil.com" https://example.com/api

# Preflight request (OPTIONS)
curl -sI -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization" \
  https://example.com/api

# Check if origin is reflected (dangerous misconfiguration)
curl -sI -H "Origin: https://evil.com" https://example.com/api | grep -i 'access-control-allow-origin'

# Test with credentials
curl -sI -H "Origin: https://evil.com" https://example.com/api | grep -i 'access-control-allow-credentials'

# Test null origin (can be exploited via sandboxed iframes)
curl -sI -H "Origin: null" https://example.com/api | grep -i 'access-control-allow-origin'
```

### Dangerous CORS Configurations

| Configuration | Risk |
|---------------|------|
| `Allow-Origin: *` + `Allow-Credentials: true` | **Invalid** but sometimes misconfigured at proxy level |
| Origin reflection (echoes back any origin) | Any site can make authenticated requests |
| `Allow-Origin: null` | Exploitable via sandboxed iframes |
| Regex bypass on origin (e.g., `*.example.com` matches `evilexample.com`) | Subdomain matching bugs |

## Content Security Policy (CSP)

### CSP Directives

| Directive | Controls | Example |
|-----------|----------|---------|
| `default-src` | Fallback for all resource types | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-abc123'` |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR, WebSocket, fetch | `'self' https://api.example.com` |
| `frame-src` | iframe sources | `'none'` |
| `frame-ancestors` | Who can embed this page | `'none'` (replaces X-Frame-Options) |
| `object-src` | Flash, Java, etc. | `'none'` |
| `base-uri` | `<base>` tag | `'self'` |
| `form-action` | Form submission targets | `'self'` |
| `report-uri` / `report-to` | Where to send violations | `/csp-report` |

### CSP Source Values

| Value | Meaning |
|-------|---------|
| `'self'` | Same origin |
| `'none'` | Block all |
| `'unsafe-inline'` | Allow inline scripts/styles (weakens CSP significantly) |
| `'unsafe-eval'` | Allow `eval()` (weakens CSP significantly) |
| `'nonce-<value>'` | Allow specific inline script by nonce |
| `'strict-dynamic'` | Trust scripts loaded by trusted scripts |
| `https:` | Any HTTPS source |
| `data:` | Data URIs |
| `blob:` | Blob URIs |
| Specific domain | `https://cdn.example.com` |

### Analyse CSP

```bash
# Extract CSP header
curl -sI https://example.com | grep -i 'content-security-policy'

# Extract CSP meta tag from HTML
curl -s https://example.com | grep -oP 'content="[^"]*content-security-policy[^"]*"'

# Check for report-only mode (monitoring without enforcement)
curl -sI https://example.com | grep -i 'content-security-policy-report-only'
```

### CSP Weaknesses to Flag

| Issue | Risk |
|-------|------|
| `'unsafe-inline'` in `script-src` | Allows XSS via inline scripts |
| `'unsafe-eval'` in `script-src` | Allows XSS via `eval()` |
| `*` or `https:` in `script-src` | Too broad — allows scripts from any HTTPS host |
| Missing `object-src` | Flash/plugin-based attacks possible |
| Missing `base-uri` | Base tag injection possible |
| Missing `frame-ancestors` | Clickjacking possible |
| Report-only without enforcement | No actual protection |

### Strong Starter CSP

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
```

## Cookie Security

### Cookie Flags

| Flag | Purpose | Recommended |
|------|---------|-------------|
| `Secure` | Only sent over HTTPS | Always set for auth cookies |
| `HttpOnly` | Not accessible via JavaScript | Always set for session cookies |
| `SameSite=Strict` | Not sent on cross-site requests | Best CSRF protection |
| `SameSite=Lax` | Sent on top-level navigations | Good default |
| `SameSite=None` | Sent on all cross-site requests | Requires `Secure` flag |
| `Path=/` | Cookie scope | Set appropriately |
| `Domain` | Cookie domain scope | Omit to restrict to exact domain |
| `Max-Age` / `Expires` | Cookie lifetime | Set reasonable expiry |
| `__Host-` prefix | Requires Secure, no Domain, Path=/ | Strongest cookie protection |
| `__Secure-` prefix | Requires Secure flag | Strong cookie protection |

### Inspect Cookies

```bash
# Show Set-Cookie headers
curl -sI https://example.com | grep -i 'set-cookie'

# Follow redirects and show all Set-Cookie headers
curl -sIL https://example.com 2>&1 | grep -i 'set-cookie'

# Full cookie jar dump (follow login flow)
curl -v -c cookies.txt https://example.com/login 2>&1 | grep -i 'set-cookie'

# Show cookie contents
cat cookies.txt

# Check cookie flags specifically
curl -sI https://example.com | grep -i 'set-cookie' | grep -ivE '(secure|httponly|samesite)'
```

### Cookie Issues to Flag

| Issue | Risk |
|-------|------|
| Missing `Secure` flag | Cookie sent over HTTP (interceptable) |
| Missing `HttpOnly` flag | Cookie accessible via XSS |
| `SameSite=None` without `Secure` | Invalid, may be rejected |
| Missing `SameSite` | Browser defaults vary, CSRF risk |
| Session cookie with no expiry | Persists indefinitely |
| Sensitive data in cookie value | Information exposure |
| Overly broad `Domain` | Cookie sent to subdomains |

## HTTP Response Inspection

### Detailed Request/Response

```bash
# Full verbose output
curl -v https://example.com 2>&1

# Show request and response headers only
curl -sv https://example.com -o /dev/null 2>&1 | grep -E '^[<>]'

# Follow redirects with verbose
curl -svL https://example.com -o /dev/null 2>&1

# Custom headers
curl -sI -H "X-Forwarded-For: 127.0.0.1" https://example.com

# Test different HTTP methods
curl -sI -X OPTIONS https://example.com
curl -sI -X TRACE https://example.com
curl -sI -X DELETE https://example.com

# HTTP timing breakdown
curl -o /dev/null -s -w "DNS:        %{time_namelookup}s\nConnect:    %{time_connect}s\nTLS:        %{time_appconnect}s\nTTFB:       %{time_starttransfer}s\nTotal:      %{time_total}s\nHTTP Code:  %{http_code}\nRedirects:  %{num_redirects}\n" https://example.com
```

### Information Leakage to Check

```bash
# Server version disclosure
curl -sI https://example.com | grep -i '^server:'

# Technology disclosure
curl -sI https://example.com | grep -i 'x-powered-by'

# Debug/error headers
curl -sI https://example.com | grep -iE '(x-debug|x-trace|x-error|x-aspnet)'

# Sensitive paths that should return 404/403 (not 200)
for path in /.env /.git/config /wp-admin /phpinfo.php /server-status /.well-known/security.txt /robots.txt /sitemap.xml; do
  code=$(curl -o /dev/null -s -w "%{http_code}" "https://example.com$path")
  echo "$code $path"
done

# Check for TRACE method (should be disabled)
curl -sI -X TRACE https://example.com | head -1
```

### HTTP Method Testing

```bash
# Test which methods are allowed
for method in GET HEAD POST PUT DELETE PATCH OPTIONS TRACE; do
  code=$(curl -o /dev/null -s -w "%{http_code}" -X "$method" https://example.com)
  echo "$method: $code"
done
```

## HTTPS Redirect Behaviour

```bash
# Check HTTP → HTTPS redirect
curl -sI http://example.com | head -5

# Check for HSTS header on HTTPS response
curl -sI https://example.com | grep -i strict-transport

# Check HSTS preload status
# (manually check: https://hstspreload.org/?domain=example.com)

# Check for mixed content potential (HTTP resources on HTTPS page)
curl -s https://example.com | grep -oP 'http://[^"'"'"' >]+' | sort -u
```

## Security.txt

```bash
# Check for security.txt (RFC 9116)
curl -s https://example.com/.well-known/security.txt
curl -s https://example.com/security.txt

# Expected fields: Contact, Expires, Encryption, Preferred-Languages
```
