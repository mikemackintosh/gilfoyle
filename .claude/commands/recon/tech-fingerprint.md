# Technology Fingerprint

Identify technologies used by a web application by analysing HTTP response headers, HTML content, JavaScript libraries, cookie names, and common framework paths.

## Arguments

$ARGUMENTS should be a URL.

Examples:
- `https://example.com`
- `https://example.com/app`
- `http://10.0.0.1:8080`

## Workflow

1. Parse the URL from `$ARGUMENTS`. Ensure it includes a scheme (`https://` or `http://`).
2. Show the user the exact commands before executing.

### Check Server and technology headers

```bash
URL=<url>

echo "=== Response Headers ==="
curl -sIL "$URL"
```

### Extract technology-revealing headers

```bash
URL=<url>

echo "=== Technology Headers ==="
curl -sI "$URL" | grep -iE '(^server:|x-powered-by|x-aspnet|x-generator|x-drupal|x-varnish|x-cache|x-amz|x-cdn|x-shopify|x-wix|via|x-request-id|x-runtime|x-frame-options)'
```

### Analyse cookies for technology indicators

```bash
URL=<url>

echo "=== Cookie Analysis ==="
COOKIES=$(curl -sI "$URL" | grep -i 'set-cookie')
echo "$COOKIES"
echo ""
echo "=== Technology Indicators from Cookies ==="
echo "$COOKIES" | grep -qi 'PHPSESSID' && echo "  -> PHP detected (PHPSESSID)"
echo "$COOKIES" | grep -qi 'JSESSIONID' && echo "  -> Java detected (JSESSIONID)"
echo "$COOKIES" | grep -qi 'ASP.NET_SessionId' && echo "  -> ASP.NET detected (ASP.NET_SessionId)"
echo "$COOKIES" | grep -qi 'connect.sid' && echo "  -> Node.js Express detected (connect.sid)"
echo "$COOKIES" | grep -qi '_rails_session' && echo "  -> Ruby on Rails detected (_rails_session)"
echo "$COOKIES" | grep -qi 'laravel_session' && echo "  -> Laravel detected (laravel_session)"
echo "$COOKIES" | grep -qi 'CFID\|CFTOKEN' && echo "  -> ColdFusion detected (CFID/CFTOKEN)"
echo "$COOKIES" | grep -qi 'wp-settings' && echo "  -> WordPress detected (wp-settings)"
echo "$COOKIES" | grep -qi 'csrftoken' && echo "  -> Django detected (csrftoken)"
echo "$COOKIES" | grep -qi '__cfduid\|__cf_bm' && echo "  -> Cloudflare detected (__cf cookie)"
```

### Analyse HTML content for meta generators and frameworks

```bash
URL=<url>

echo "=== HTML Analysis ==="
HTML=$(curl -sL "$URL")

# Meta generator tags
echo "--- Meta Generators ---"
echo "$HTML" | grep -ioE '<meta[^>]*name="generator"[^>]*content="[^"]*"[^>]*>' || echo "  No meta generator found"

# WordPress indicators
echo "$HTML" | grep -qiE 'wp-content|wp-includes' && echo "  -> WordPress detected (wp-content/wp-includes paths)"

# Drupal indicators
echo "$HTML" | grep -qi 'drupal' && echo "  -> Drupal detected"

# Joomla indicators
echo "$HTML" | grep -qi '/media/jui\|/components/com_' && echo "  -> Joomla detected"

# React indicators
echo "$HTML" | grep -qiE 'react\.js|react\.min\.js|react-dom|__NEXT_DATA__|_next/' && echo "  -> React / Next.js detected"

# Angular indicators
echo "$HTML" | grep -qiE 'ng-app|ng-controller|angular\.js|angular\.min\.js' && echo "  -> Angular detected"

# Vue.js indicators
echo "$HTML" | grep -qiE 'vue\.js|vue\.min\.js|__NUXT__|nuxt' && echo "  -> Vue.js / Nuxt detected"

# jQuery
echo "$HTML" | grep -qiE 'jquery[^"]*\.js' && echo "  -> jQuery detected"

# Bootstrap
echo "$HTML" | grep -qiE 'bootstrap[^"]*\.css\|bootstrap[^"]*\.js' && echo "  -> Bootstrap detected"
```

### Check JavaScript library paths

```bash
URL=<url>

echo "=== JavaScript Libraries ==="
curl -sL "$URL" | grep -ioE 'src="[^"]*\.js[^"]*"' | sort -u | head -30
```

### Probe common framework paths

```bash
URL=<url>

echo "=== Framework Path Probing ==="
for path in /wp-login.php /wp-admin /wp-json/wp/v2/ /administrator /user/login /admin /xmlrpc.php /api /graphql /swagger /api-docs /elmah.axd /phpinfo.php /server-status /server-info /.well-known/security.txt /robots.txt /sitemap.xml /favicon.ico /humans.txt; do
  code=$(curl -o /dev/null -s -w "%{http_code}" --connect-timeout 5 "${URL%/}$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "  $code $path"
  fi
done
```

3. Consolidate all findings into a technology profile:

| Category | Technology | Confidence | Evidence |
|----------|-----------|------------|----------|
| Web Server | nginx 1.x | High | Server header |
| Language | PHP | High | PHPSESSID cookie |
| Framework | WordPress | High | wp-content paths, wp-login.php returns 200 |
| CDN | Cloudflare | High | cf-ray header |
| JS Library | jQuery 3.x | Medium | Script src path |

4. Note any information leakage findings (version numbers, debug headers).

## Security Notes

- Technology fingerprinting uses only standard HTTP requests that any web browser would make. However, path probing generates multiple requests that may appear in server logs.
- Version disclosure in `Server` and `X-Powered-By` headers helps attackers identify known vulnerabilities. Recommend suppressing version information in production.
- Exposed paths like `/phpinfo.php`, `/server-status`, `/elmah.axd`, or `/swagger` should be restricted in production environments.
- The presence of `/xmlrpc.php` on WordPress sites is a common brute-force attack vector and should be disabled if not needed.
- Fingerprinting results should be used to prioritise vulnerability research against the identified technology stack.
