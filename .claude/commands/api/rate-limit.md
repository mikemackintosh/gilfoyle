# Rate Limit Test

Test API rate limiting by sending rapid requests and observing response codes, rate limit headers, and throttling behaviour.

## Arguments

$ARGUMENTS should include:
- A URL to test
- Optionally a request count (default: 20)
- Optionally `--auth <token>` to include a Bearer token with requests

Examples:
- `https://api.example.com/users`
- `https://api.example.com/users 50`
- `https://api.example.com/users 30 --auth eyJhbGciOi...`

## Workflow

1. Parse the URL, request count, and optional auth token from `$ARGUMENTS`. Default count is 20.
2. Show the user the exact commands before executing them.
3. **Remind the user:** Only test APIs you own or have explicit authorisation to test. Rapid requests may trigger security alerts or temporary bans.

### Step 1: Check rate limit headers on a single request

```bash
curl -sI <url> | grep -iE '(x-ratelimit|ratelimit|retry-after|x-rate-limit)'
```

If an auth token is provided:

```bash
curl -sI -H "Authorization: Bearer <token>" <url> | grep -iE '(x-ratelimit|ratelimit|retry-after|x-rate-limit)'
```

### Step 2: Send rapid requests and track responses

```bash
URL="<url>"
COUNT=<count>

echo "Sending $COUNT requests to $URL"
echo "---"

for i in $(seq 1 "$COUNT"); do
  START=$(python3 -c "import time; print(f'{time.time():.3f}')")
  HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$URL")
  END=$(python3 -c "import time; print(f'{time.time():.3f}')")
  ELAPSED=$(python3 -c "print(f'{$END - $START:.3f}')")
  echo "Request $i: HTTP $HTTP_CODE (${ELAPSED}s)"
done
```

With auth token:

```bash
URL="<url>"
COUNT=<count>
TOKEN="<token>"

echo "Sending $COUNT requests to $URL (authenticated)"
echo "---"

for i in $(seq 1 "$COUNT"); do
  START=$(python3 -c "import time; print(f'{time.time():.3f}')")
  HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$URL")
  END=$(python3 -c "import time; print(f'{time.time():.3f}')")
  ELAPSED=$(python3 -c "print(f'{$END - $START:.3f}')")
  echo "Request $i: HTTP $HTTP_CODE (${ELAPSED}s)"
done
```

### Step 3: Capture rate limit headers as they change

```bash
URL="<url>"
COUNT=<count>

for i in $(seq 1 "$COUNT"); do
  HEADERS=$(curl -sI "$URL")
  CODE=$(echo "$HEADERS" | head -1 | awk '{print $2}')
  LIMIT=$(echo "$HEADERS" | grep -i 'x-ratelimit-limit\|ratelimit-limit' | head -1 | awk '{print $2}' | tr -d '\r')
  REMAINING=$(echo "$HEADERS" | grep -i 'x-ratelimit-remaining\|ratelimit-remaining' | head -1 | awk '{print $2}' | tr -d '\r')
  RESET=$(echo "$HEADERS" | grep -i 'x-ratelimit-reset\|ratelimit-reset' | head -1 | awk '{print $2}' | tr -d '\r')
  RETRY=$(echo "$HEADERS" | grep -i 'retry-after' | head -1 | awk '{print $2}' | tr -d '\r')
  echo "Request $i: HTTP $CODE | Limit: ${LIMIT:-N/A} | Remaining: ${REMAINING:-N/A} | Reset: ${RESET:-N/A} | Retry-After: ${RETRY:-N/A}"
done
```

### Step 4: Capture the 429 response body (if rate limited)

```bash
# After hitting the rate limit, inspect the full response
curl -s -w "\n\nHTTP Status: %{http_code}\n" <url>
```

### Step 5: Test rate limit bypass techniques

```bash
URL="<url>"

# Test with X-Forwarded-For header (IP-based rate limit bypass)
curl -s -o /dev/null -w "X-Forwarded-For bypass: HTTP %{http_code}\n" \
  -H "X-Forwarded-For: 1.2.3.4" "$URL"

# Test with X-Real-IP header
curl -s -o /dev/null -w "X-Real-IP bypass: HTTP %{http_code}\n" \
  -H "X-Real-IP: 1.2.3.4" "$URL"

# Test with different URL casing
curl -s -o /dev/null -w "URL case variation: HTTP %{http_code}\n" \
  "$(echo "$URL" | sed 's|/api/|/API/|')"

# Test with trailing slash
curl -s -o /dev/null -w "Trailing slash: HTTP %{http_code}\n" \
  "${URL}/"
```

4. Present results:

**Rate Limit Header Summary:**

| Header | Value |
|--------|-------|
| `X-RateLimit-Limit` | `<value or N/A>` |
| `X-RateLimit-Remaining` | `<value or N/A>` |
| `X-RateLimit-Reset` | `<value or N/A>` |
| `Retry-After` | `<value or N/A>` |

**Request Results:**

| Metric | Value |
|--------|-------|
| Total requests sent | `<count>` |
| Successful (2xx) | `<count>` |
| Rate limited (429) | `<count>` |
| Other errors | `<count>` |
| Request at which 429 first appeared | `<number or N/A>` |

**Bypass Test Results:**

| Technique | Result |
|-----------|--------|
| X-Forwarded-For | Bypassed / Blocked |
| X-Real-IP | Bypassed / Blocked |
| URL case variation | Bypassed / Blocked |
| Trailing slash | Bypassed / Blocked |

5. Flag any issues:
   - No rate limit headers present (potential unrestricted access)
   - No 429 responses after many requests (no rate limiting enforced)
   - Rate limit bypass techniques that succeed
   - Missing `Retry-After` header on 429 responses
   - Rate limit window too generous for sensitive endpoints (e.g., login, password reset)

## Security Notes

- **Only test APIs you own or have explicit written authorisation to test.** Sending rapid requests to third-party APIs may violate terms of service and trigger IP bans.
- Rate limiting is a key defence against brute-force attacks, credential stuffing, and API abuse (OWASP API4: Unrestricted Resource Consumption).
- Authentication endpoints (`/login`, `/token`, `/password-reset`) should have stricter rate limits than general API endpoints.
- Rate limits based solely on IP address can be bypassed by distributed attackers or via proxy headers — token-based or account-based limits are more robust.
- A 429 response without a `Retry-After` header is not standards-compliant (RFC 6585) and makes it harder for well-behaved clients to back off correctly.
- Rate limit headers are informational — the actual enforcement matters more than the headers themselves.
