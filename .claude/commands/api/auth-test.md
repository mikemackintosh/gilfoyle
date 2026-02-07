# API Auth Test

Test API authentication mechanisms by verifying that endpoints correctly enforce authentication, reject invalid credentials, and return appropriate HTTP status codes.

## Arguments

$ARGUMENTS should include:
- A URL to test
- An auth type: `bearer`, `apikey`, or `basic`
- Credentials to use for the valid test (token, key, or user:password)

Examples:
- `https://api.example.com/users bearer eyJhbGciOi...`
- `https://api.example.com/data apikey sk-test-abc123`
- `https://api.example.com/resource basic admin:secretpass`

## Workflow

1. Parse the URL, auth type, and credentials from `$ARGUMENTS`.
2. Show the user the exact commands before executing them.
3. **Remind the user:** Only test APIs you own or have explicit authorisation to test.

### Step 1: Test with valid credentials

#### Bearer token

```bash
curl -sv -H "Authorization: Bearer <token>" <url> -o /dev/null 2>&1
```

Also fetch the full response to inspect the body:

```bash
curl -s -H "Authorization: Bearer <token>" <url> | python3 -m json.tool 2>/dev/null || curl -s -H "Authorization: Bearer <token>" <url>
```

#### API key (header)

```bash
curl -sv -H "X-API-Key: <key>" <url> -o /dev/null 2>&1
```

Also fetch the full response:

```bash
curl -s -H "X-API-Key: <key>" <url> | python3 -m json.tool 2>/dev/null || curl -s -H "X-API-Key: <key>" <url>
```

#### Basic auth

```bash
curl -sv -u "<user>:<password>" <url> -o /dev/null 2>&1
```

Also fetch the full response:

```bash
curl -s -u "<user>:<password>" <url> | python3 -m json.tool 2>/dev/null || curl -s -u "<user>:<password>" <url>
```

### Step 2: Test without credentials (expect 401)

```bash
curl -sI <url>
```

Check the response code and the `WWW-Authenticate` header:

```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" <url>
curl -sI <url> | grep -i 'www-authenticate'
```

### Step 3: Test with invalid credentials (expect 401 or 403)

#### Bearer — malformed token

```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -H "Authorization: Bearer invalid_token_value" <url>
```

#### Bearer — empty token

```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -H "Authorization: Bearer " <url>
```

#### API key — invalid key

```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -H "X-API-Key: invalid_key_value" <url>
```

#### Basic — wrong password

```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -u "invaliduser:invalidpass" <url>
```

### Step 4: Test authentication edge cases

#### Test with auth header but wrong scheme

```bash
# Send Basic when Bearer is expected (and vice versa)
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -H "Authorization: Basic dGVzdDp0ZXN0" <url>
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -H "Authorization: Bearer dGVzdDp0ZXN0" <url>
```

#### Check for information leakage in error responses

```bash
# Capture the full error response body
curl -s <url>
curl -s -H "Authorization: Bearer invalid_token_value" <url>
```

### Step 5: Check response headers

```bash
curl -sI -H "Authorization: Bearer <token>" <url> | grep -iE '(www-authenticate|x-content-type|cache-control|strict-transport|server|x-powered-by|x-request-id|content-type)'
```

4. Present results in a summary table:

| Test | Expected | Actual Status | Result |
|------|----------|---------------|--------|
| Valid credentials | 200 | `<actual>` | PASS/FAIL |
| No credentials | 401 | `<actual>` | PASS/FAIL |
| Invalid credentials | 401 or 403 | `<actual>` | PASS/FAIL |
| Empty token/key | 401 | `<actual>` | PASS/FAIL |
| Wrong auth scheme | 401 | `<actual>` | PASS/FAIL |

5. Flag any issues:
   - Endpoint returns 200 without credentials (broken auth)
   - Endpoint returns 200 with invalid credentials (broken auth)
   - Error response leaks stack traces, internal paths, or technology details
   - Missing `WWW-Authenticate` header on 401 responses
   - Sensitive data returned without `Cache-Control: no-store`

## Security Notes

- **Only test APIs you own or have explicit written authorisation to test.** Unauthorised testing may violate laws and terms of service.
- API keys in query parameters are logged in server access logs, proxy logs, and browser history — header-based auth is preferred.
- Basic authentication sends credentials base64-encoded (not encrypted) — it must only be used over HTTPS.
- A 200 response to unauthenticated requests is the most critical finding — it means the endpoint is completely unprotected.
- Error responses should not reveal whether a username exists (use generic "invalid credentials" messages).
- Look for `WWW-Authenticate` headers on 401 responses — they reveal the expected auth scheme.
- Never log or display the full valid credentials in output. Mask them where possible.
