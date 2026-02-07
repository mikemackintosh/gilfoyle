# Security Headers Check

Analyse the HTTP security headers of a web application and identify missing or misconfigured protections.

## Arguments

$ARGUMENTS should be a URL.

Examples:
- `https://example.com`
- `https://example.com/app`

## Workflow

1. Parse the URL from `$ARGUMENTS`. Ensure it starts with `https://` (or `http://`).
2. Show the user the exact commands before executing.

### Fetch response headers

```bash
curl -sIL <url>
```

### Extract security-relevant headers

```bash
curl -sI <url> | grep -iE '(strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|referrer-policy|permissions-policy|x-xss-protection|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|access-control-allow|set-cookie|server|x-powered-by)'
```

### Check for information leakage

```bash
curl -sI <url> | grep -iE '(^server:|x-powered-by|x-aspnet|x-debug)'
```

3. Assess each header against the checklist:

| Header | Expected | Status |
|--------|----------|--------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | PASS/FAIL |
| `Content-Security-Policy` | Present, no `unsafe-inline` in `script-src` | PASS/WARN/FAIL |
| `X-Content-Type-Options` | `nosniff` | PASS/FAIL |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | PASS/FAIL |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | PASS/WARN/FAIL |
| `Permissions-Policy` | Present, restrictive | PASS/WARN/FAIL |
| `X-XSS-Protection` | `0` or absent (CSP replaces this) | PASS/INFO |
| `Server` | No version disclosed | PASS/WARN |
| `X-Powered-By` | Absent | PASS/WARN |

4. Present a summary scorecard and detailed findings for each header.

## Security Notes

- HSTS with `includeSubDomains` applies to all subdomains — ensure all subdomains support HTTPS before enabling.
- HSTS `preload` submits the domain to browser preload lists — this is difficult to undo.
- A missing CSP is the most impactful gap — it leaves the application open to XSS.
- `X-Frame-Options` is superseded by CSP `frame-ancestors`, but should still be set for older browser support.
- Information leakage via `Server` and `X-Powered-By` helps attackers fingerprint the technology stack.
