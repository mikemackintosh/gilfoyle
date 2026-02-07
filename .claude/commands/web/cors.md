# CORS Test

Test the Cross-Origin Resource Sharing (CORS) configuration of a web endpoint.

## Arguments

$ARGUMENTS should include:
- A URL to test
- Optionally a test origin (default: `https://evil.com`)

Examples:
- `https://api.example.com`
- `https://api.example.com/v1/users https://attacker.com`

## Workflow

1. Parse the URL and test origin from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Simple CORS request

```bash
curl -sI -H "Origin: <test_origin>" <url>
```

### Extract CORS headers

```bash
curl -sI -H "Origin: <test_origin>" <url> | grep -i 'access-control'
```

### Preflight request (OPTIONS)

```bash
curl -sI -X OPTIONS \
  -H "Origin: <test_origin>" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization" \
  <url>
```

### Test null origin

```bash
curl -sI -H "Origin: null" <url> | grep -i 'access-control-allow-origin'
```

### Test origin reflection

```bash
# Send one origin
curl -sI -H "Origin: https://evil.com" <url> | grep -i 'access-control-allow-origin'

# Send a different origin — if both are reflected, it's origin reflection
curl -sI -H "Origin: https://attacker.example.com" <url> | grep -i 'access-control-allow-origin'
```

### Check credentials support

```bash
curl -sI -H "Origin: <test_origin>" <url> | grep -i 'access-control-allow-credentials'
```

3. Assess the configuration:

| Finding | Severity | Meaning |
|---------|----------|---------|
| `Allow-Origin: *` | Medium | Any origin can read responses (no credentials) |
| Origin reflected back | **High** | Server echoes any origin — cross-site data theft possible |
| `Allow-Origin: null` | **High** | Exploitable via sandboxed iframes |
| `Allow-Credentials: true` + reflected origin | **Critical** | Authenticated cross-site requests possible |
| Specific trusted origin | OK | Properly configured |
| No CORS headers | OK | Cross-origin requests are blocked (default) |

4. Present results:
   - CORS headers returned
   - Whether origin is reflected
   - Whether credentials are allowed
   - Risk assessment
   - Recommendations

## Security Notes

- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` is invalid per the spec, but misconfigured proxies or servers may behave unpredictably.
- Origin reflection (echoing back whatever Origin is sent) is functionally equivalent to `*` but also works with credentials — this is a serious vulnerability.
- `null` origin can be triggered by sandboxed iframes (`<iframe sandbox>`), `data:` URIs, and local files — allowing `null` is dangerous.
- CORS only protects browser-based requests. APIs should also use authentication tokens for server-to-server calls.
