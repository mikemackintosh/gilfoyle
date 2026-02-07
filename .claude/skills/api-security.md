---
name: API Security
description: API authentication testing, OWASP API Security Top 10 analysis, OAuth/OIDC inspection, rate limiting, and common API vulnerability assessment.
instructions: |
  Use this skill when the user needs to test API authentication mechanisms, assess APIs against
  the OWASP API Security Top 10, inspect OAuth2/OIDC configurations, test rate limiting, analyse
  GraphQL security, enumerate API endpoints, or review API response headers. Always show commands
  before executing them and explain the security implications of each finding.
---

# API Security Skill

## Related Commands
- `/api-auth-test` — Test API authentication mechanisms
- `/api-rate-limit` — Test API rate limiting behaviour
- `/api-enumerate` — Probe common API endpoint paths
- `/api-oauth-inspect` — Inspect OAuth/OIDC configuration

## Authentication Methods

### Bearer Token (OAuth2 Access Token)

```bash
# Request with Bearer token
curl -s -H "Authorization: Bearer <token>" https://api.example.com/resource

# Test without token (expect 401)
curl -sI https://api.example.com/resource

# Test with invalid token (expect 401 or 403)
curl -sI -H "Authorization: Bearer invalid_token_here" https://api.example.com/resource
```

### API Key

```bash
# API key in header
curl -s -H "X-API-Key: <key>" https://api.example.com/resource

# API key in query parameter (less secure — logged in URLs)
curl -s "https://api.example.com/resource?api_key=<key>"

# Common API key header names
# X-API-Key, Authorization: ApiKey <key>, X-Auth-Token, api-key
```

### Basic Authentication

```bash
# Basic auth (user:password base64-encoded)
curl -s -u "username:password" https://api.example.com/resource

# Equivalent manual header
curl -s -H "Authorization: Basic $(echo -n 'username:password' | base64)" https://api.example.com/resource

# Test with empty credentials
curl -sI -u ":" https://api.example.com/resource
```

### OAuth2 Client Credentials

```bash
# Client credentials grant (machine-to-machine)
curl -s -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=read"
```

### Mutual TLS (mTLS)

```bash
# Request with client certificate
curl -s --cert client.pem --key client-key.pem https://api.example.com/resource

# With CA bundle verification
curl -s --cert client.pem --key client-key.pem --cacert ca.pem https://api.example.com/resource

# Test without client cert (expect 403 or TLS handshake failure)
curl -sv https://api.example.com/resource 2>&1 | grep -E '(SSL|HTTP/)'
```

## OWASP API Security Top 10 (2023)

| # | Risk | Description | What to Check |
|---|------|-------------|---------------|
| API1 | **Broken Object Level Authorization (BOLA)** | Accessing other users' objects by changing IDs | Change resource IDs in requests (e.g., `/users/123` to `/users/124`) |
| API2 | **Broken Authentication** | Weak or missing authentication | Test endpoints without auth, weak tokens, no expiry |
| API3 | **Broken Object Property Level Authorization** | Exposing or modifying restricted properties | Check if response includes fields the user shouldn't see; try adding admin fields in PUT/PATCH |
| API4 | **Unrestricted Resource Consumption** | No rate limiting or resource limits | Send rapid requests, large payloads, expensive queries |
| API5 | **Broken Function Level Authorization** | Accessing admin functions as regular user | Try admin endpoints (`/admin/*`, `/api/v1/users/delete`) with regular user token |
| API6 | **Unrestricted Access to Sensitive Business Flows** | Abuse of business logic at scale | Automated purchasing, mass account creation, data scraping |
| API7 | **Server-Side Request Forgery (SSRF)** | Making the server fetch arbitrary URLs | Supply internal URLs in parameters (`http://169.254.169.254/`, `http://localhost`) |
| API8 | **Security Misconfiguration** | Default configs, verbose errors, missing headers | Check debug mode, stack traces, CORS, missing security headers |
| API9 | **Improper Inventory Management** | Exposed old/debug API versions | Check `/api/v1`, `/api/v2`, `/api/beta`, `/api/internal`, `/api/debug` |
| API10 | **Unsafe Consumption of APIs** | Trusting third-party API data without validation | Check if downstream API data is sanitised before use |

### BOLA Testing Pattern

```bash
# Fetch your own resource
curl -s -H "Authorization: Bearer <your_token>" https://api.example.com/users/YOUR_ID

# Attempt to fetch another user's resource with your token
curl -s -H "Authorization: Bearer <your_token>" https://api.example.com/users/OTHER_ID

# If both return 200 with data, BOLA is present
```

### Broken Function Level Authorization Testing

```bash
# Test admin endpoints with regular user token
for endpoint in /admin /admin/users /api/v1/admin /internal /debug /management; do
  code=$(curl -o /dev/null -s -w "%{http_code}" -H "Authorization: Bearer <regular_user_token>" "https://api.example.com$endpoint")
  echo "$code  $endpoint"
done
```

## Rate Limiting

### Rate Limit Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `X-RateLimit-Limit` | Max requests per window | `100` |
| `X-RateLimit-Remaining` | Requests left in window | `95` |
| `X-RateLimit-Reset` | Window reset time (Unix timestamp or seconds) | `1704067200` |
| `Retry-After` | Seconds to wait (returned with 429) | `60` |
| `RateLimit-Limit` | IETF draft standard variant | `100` |
| `RateLimit-Remaining` | IETF draft standard variant | `95` |
| `RateLimit-Reset` | IETF draft standard variant | `60` |

### Testing Rate Limits

```bash
# Send rapid requests and check for 429
for i in $(seq 1 50); do
  code=$(curl -o /dev/null -s -w "%{http_code}" https://api.example.com/resource)
  echo "Request $i: $code"
done

# Extract rate limit headers
curl -sI https://api.example.com/resource | grep -iE '(ratelimit|retry-after|x-rate)'
```

### Rate Limiting Bypass Techniques to Test

| Technique | How | Risk if it works |
|-----------|-----|------------------|
| IP rotation headers | `X-Forwarded-For: <random_ip>`, `X-Real-IP` | Rate limit per IP is bypassable |
| Case variation | `/API/Resource` vs `/api/resource` | Path-based limits may be case-sensitive |
| Trailing slashes | `/api/resource/` vs `/api/resource` | Different cache/limit keys |
| HTTP method switching | `GET` vs `HEAD` | Method-specific limits |
| API version switching | `/v1/resource` vs `/v2/resource` | Version-specific limits |
| Unicode encoding | `/api/%75sers` instead of `/api/users` | Encoding-based bypass |

## Common API Vulnerabilities

### Mass Assignment / Excessive Data Exposure

```bash
# Check if API returns more fields than expected
curl -s -H "Authorization: Bearer <token>" https://api.example.com/users/me | python3 -m json.tool

# Look for fields like: role, is_admin, permissions, internal_id, password_hash, ssn, etc.

# Test mass assignment by sending extra fields in update
curl -s -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "role": "admin", "is_admin": true}' \
  https://api.example.com/users/me
```

### Injection Points

```bash
# SQL injection in query parameters
curl -s "https://api.example.com/users?id=1'%20OR%201=1--"

# NoSQL injection in JSON body
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}' \
  https://api.example.com/login

# Command injection in parameters
curl -s "https://api.example.com/lookup?host=example.com;id"
```

### Verbose Error Messages

```bash
# Trigger errors and check for stack traces
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"invalid": }' \
  https://api.example.com/resource

# Check debug endpoints
for path in /debug /debug/pprof /debug/vars /actuator /actuator/env /actuator/health; do
  code=$(curl -o /dev/null -s -w "%{http_code}" "https://api.example.com$path")
  echo "$code  $path"
done
```

## OAuth2 / OIDC Flows

### OAuth2 Grant Types

| Grant Type | Use Case | Token Endpoint |
|------------|----------|----------------|
| Authorization Code | Server-side apps | `POST /token` with `code` + `client_secret` |
| Authorization Code + PKCE | SPAs, mobile apps | `POST /token` with `code` + `code_verifier` |
| Client Credentials | Machine-to-machine | `POST /token` with `client_id` + `client_secret` |
| Device Code | IoT / limited-input devices | `POST /device/code` then poll `/token` |
| Refresh Token | Token renewal | `POST /token` with `refresh_token` |
| **Implicit** (deprecated) | Legacy SPAs | Token in redirect fragment (insecure) |
| **ROPC** (deprecated) | Legacy apps | `POST /token` with `username` + `password` |

### OpenID Connect Discovery

```bash
# Fetch OIDC discovery document
curl -s https://auth.example.com/.well-known/openid-configuration | python3 -m json.tool

# Key fields to inspect:
# issuer, authorization_endpoint, token_endpoint, userinfo_endpoint
# jwks_uri, scopes_supported, response_types_supported
# grant_types_supported, id_token_signing_alg_values_supported
```

### JWKS Inspection

```bash
# Fetch the JSON Web Key Set
curl -s https://auth.example.com/.well-known/jwks.json | python3 -m json.tool

# Check key sizes and algorithms
curl -s https://auth.example.com/.well-known/jwks.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for key in data.get('keys', []):
    print(f\"kid={key.get('kid', 'N/A')}  alg={key.get('alg', 'N/A')}  kty={key.get('kty', 'N/A')}  use={key.get('use', 'N/A')}\")
"
```

### OAuth2 Security Checks

| Check | What to Look For | Risk |
|-------|-----------------|------|
| State parameter | Missing or predictable `state` | CSRF on OAuth flow |
| PKCE enforcement | Authorization code flow without PKCE | Authorization code interception |
| Redirect URI validation | Open redirect in `redirect_uri` | Token theft via redirect |
| Token in URL | Access token in query string or fragment | Token leakage via logs/referrer |
| Scope escalation | Requesting broader scopes than granted | Privilege escalation |
| Token expiry | Long-lived access tokens | Extended attack window |
| Refresh token rotation | Refresh tokens not rotated | Replay attacks |

## GraphQL Security

### GraphQL Discovery

```bash
# Test common GraphQL endpoints
for path in /graphql /graphiql /v1/graphql /api/graphql /query /gql; do
  code=$(curl -o /dev/null -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __typename }"}' \
    "https://api.example.com$path")
  echo "$code  $path"
done
```

### Introspection Query

```bash
# Full introspection (should be disabled in production)
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' \
  https://api.example.com/graphql | python3 -m json.tool
```

### GraphQL Vulnerabilities

| Vulnerability | Test | Risk |
|---------------|------|------|
| Introspection enabled | Send `__schema` query | Full API schema disclosure |
| Query depth abuse | Deeply nested queries | DoS via recursive resolution |
| Batch query abuse | Array of queries in single request | Rate limit bypass |
| Field suggestion | Send misspelled field names | Schema enumeration via error messages |
| Alias-based DoS | Many aliases for expensive field | Resource exhaustion |

### Batch Query Test

```bash
# Test batch queries (array of operations)
curl -s -X POST -H "Content-Type: application/json" \
  -d '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]' \
  https://api.example.com/graphql
```

## API Endpoint Enumeration

### Common Paths to Probe

```bash
BASE="https://api.example.com"

for path in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /v3 \
  /graphql /graphiql /playground \
  /swagger /swagger.json /swagger/ui /swagger-ui /swagger-ui.html \
  /openapi.json /openapi.yaml /api-docs /redoc \
  /docs /documentation \
  /health /healthz /health/live /health/ready /status /ping /version /info \
  /metrics /prometheus/metrics \
  /admin /admin/api /management /internal \
  /debug /debug/pprof /debug/vars \
  /actuator /actuator/env /actuator/health /actuator/info \
  /.well-known/openid-configuration /.well-known/jwks.json \
  /robots.txt /sitemap.xml /.well-known/security.txt; do
  code=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$code" != "404" ] && echo "$code  $path"
done
```

## API Response Header Analysis

### Security Headers to Check on APIs

| Header | Expected | Risk if Missing |
|--------|----------|-----------------|
| `Content-Type` | `application/json` with charset | MIME sniffing, encoding attacks |
| `X-Content-Type-Options` | `nosniff` | MIME confusion attacks |
| `Cache-Control` | `no-store` for sensitive data | Sensitive data cached by proxies/browsers |
| `Strict-Transport-Security` | Present with long `max-age` | Downgrade attacks |
| `X-Request-Id` / `X-Correlation-Id` | Present (for tracing) | Harder to debug and correlate issues |
| `Access-Control-Allow-Origin` | Specific origin or absent | Overly permissive CORS |
| `Server` | Absent or generic | Technology fingerprinting |
| `X-Powered-By` | Absent | Technology fingerprinting |

### Check API Response Headers

```bash
curl -sI -H "Authorization: Bearer <token>" https://api.example.com/resource | grep -iE '(content-type|x-content-type|cache-control|strict-transport|x-request-id|access-control|server|x-powered-by|x-ratelimit|ratelimit|retry-after)'
```

## Useful One-Liners

```bash
# Quick auth method detection — try common auth and see what the API expects
curl -sI https://api.example.com/resource | head -5

# Check for API versioning in response
curl -sI https://api.example.com/ | grep -iE '(api-version|x-api-version)'

# Test content type enforcement (send form data to JSON API)
curl -s -X POST -H "Content-Type: text/plain" -d 'not json' https://api.example.com/resource

# Test CORS on API
curl -sI -H "Origin: https://evil.com" https://api.example.com/resource | grep -i 'access-control'

# Check if API is behind a WAF
curl -sI https://api.example.com/ | grep -iE '(cf-ray|x-amzn|x-azure|x-cache|via|x-cdn)'
```
