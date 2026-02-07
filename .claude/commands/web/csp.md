# CSP Analysis

Analyse the Content Security Policy (CSP) of a web application and identify weaknesses.

## Arguments

$ARGUMENTS should be a URL.

Examples:
- `https://example.com`
- `https://example.com/app`

## Workflow

1. Parse the URL from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Fetch CSP header

```bash
# CSP header
curl -sI <url> | grep -i 'content-security-policy'

# CSP Report-Only header (monitoring mode)
curl -sI <url> | grep -i 'content-security-policy-report-only'
```

### Check for CSP meta tag in HTML (fallback)

```bash
curl -s <url> | grep -ioP '<meta[^>]*content-security-policy[^>]*content="[^"]*"'
```

3. Parse the CSP into individual directives and analyse each one:

### Directive Audit

| Directive | Value | Assessment |
|-----------|-------|------------|
| `default-src` | | Fallback — should be `'self'` or more restrictive |
| `script-src` | | **Critical** — check for `unsafe-inline`, `unsafe-eval`, wildcards |
| `style-src` | | Check for `unsafe-inline` |
| `img-src` | | Usually more permissive is OK |
| `connect-src` | | XHR/fetch/WebSocket targets |
| `font-src` | | Font loading sources |
| `frame-src` | | iframe sources |
| `frame-ancestors` | | Who can embed this page (clickjacking protection) |
| `object-src` | | Should be `'none'` (Flash/plugins) |
| `base-uri` | | Should be `'self'` or `'none'` |
| `form-action` | | Form submission targets |
| `report-uri` / `report-to` | | Violation reporting endpoint |

### Key Checks

```
Check 1: Does script-src contain 'unsafe-inline'?
  → YES: XSS protection significantly weakened

Check 2: Does script-src contain 'unsafe-eval'?
  → YES: eval()-based XSS possible

Check 3: Does script-src allow wildcards or broad domains?
  → *.example.com, https:, * → Too permissive

Check 4: Is object-src set to 'none'?
  → Missing or permissive → Plugin-based attacks possible

Check 5: Is base-uri restricted?
  → Missing → Base tag injection possible

Check 6: Is frame-ancestors set?
  → Missing → Clickjacking possible

Check 7: Is this Report-Only (not enforced)?
  → Report-Only → No actual protection, monitoring only
```

4. Present results:
   - Full CSP policy (formatted, one directive per line)
   - Weaknesses found (with severity)
   - Missing directives
   - Overall rating: Strong / Moderate / Weak / Missing
   - Recommended improvements

## Security Notes

- `'unsafe-inline'` in `script-src` is the most common CSP weakness — it allows inline `<script>` tags and event handlers, which are the primary XSS attack vector.
- `'unsafe-eval'` allows `eval()`, `Function()`, `setTimeout("string")` — all exploitable for XSS.
- A CSP in `Report-Only` mode does not block anything — it only sends violation reports. This is useful for testing but provides no protection.
- CSP via `<meta>` tag does not support `frame-ancestors` or `report-uri` — use the HTTP header instead.
- Nonce-based CSP (`'nonce-<random>'`) is stronger than allowlist-based CSP, but requires server-side nonce generation per request.
- `'strict-dynamic'` allows scripts loaded by trusted scripts to execute, simplifying CSP for applications with complex script loading.
