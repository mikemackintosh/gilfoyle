# HTTP Request Inspector

Make a detailed HTTP request and inspect the full request/response cycle, including timing, TLS, headers, and redirects.

## Arguments

$ARGUMENTS should include:
- A URL
- Optionally a method: `GET` (default), `POST`, `PUT`, `DELETE`, `OPTIONS`, `HEAD`, `TRACE`
- Optionally `--timing` for detailed timing breakdown
- Optionally `--redirects` to follow and show all redirects
- Optionally `--methods` to test all HTTP methods

Examples:
- `https://example.com`
- `https://example.com POST`
- `https://example.com --timing`
- `https://example.com --redirects`
- `https://example.com --methods`

## Workflow

1. Parse the URL, method, and flags from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Standard request with full headers

```bash
curl -sv -X <method> <url> -o /dev/null 2>&1
```

### Response headers only

```bash
curl -sI -X <method> <url>
```

### Timing breakdown

```bash
curl -o /dev/null -s -w "\
DNS Lookup:      %{time_namelookup}s\n\
TCP Connect:     %{time_connect}s\n\
TLS Handshake:   %{time_appconnect}s\n\
TTFB:            %{time_starttransfer}s\n\
Total:           %{time_total}s\n\
\n\
HTTP Code:       %{http_code}\n\
Redirects:       %{num_redirects}\n\
Download Size:   %{size_download} bytes\n\
Remote IP:       %{remote_ip}:%{remote_port}\n\
TLS Version:     %{ssl_verify_result} (0=ok)\n\
" <url>
```

### Follow redirects

```bash
curl -svL <url> -o /dev/null 2>&1 | grep -E '(^[<>] |^< HTTP/|^< [Ll]ocation:)'
```

### Test all HTTP methods

```bash
for method in GET HEAD POST PUT DELETE PATCH OPTIONS TRACE; do
  code=$(curl -o /dev/null -s -w "%{http_code}" -X "$method" <url>)
  echo "$method: $code"
done
```

### Check sensitive paths

```bash
for path in /.env /.git/config /.git/HEAD /wp-admin /phpinfo.php /server-status /server-info /.well-known/security.txt /robots.txt /sitemap.xml /.DS_Store /web.config; do
  code=$(curl -o /dev/null -s -w "%{http_code}" "<base_url>$path")
  echo "$code  $path"
done
```

3. Present results:
   - HTTP status code and reason
   - Response headers (highlight security-relevant ones)
   - Timing breakdown (if requested)
   - Redirect chain (if requested)
   - HTTP methods allowed (if requested)
   - Sensitive path exposure (if found)
   - Any notable findings

## Security Notes

- `TRACE` method should be disabled — it can be used for Cross-Site Tracing (XST) attacks to steal credentials.
- `OPTIONS` responses reveal allowed methods, which aids reconnaissance.
- `PUT` and `DELETE` methods exposed on endpoints that shouldn't support them can indicate misconfiguration.
- Sensitive paths returning `200` (like `/.env`, `/.git/config`) is a critical finding — these often contain credentials.
- Timing data can reveal whether the server is performing expensive operations (useful for timing attacks).
- Always check both HTTP and HTTPS versions — the HTTP version should redirect to HTTPS.
