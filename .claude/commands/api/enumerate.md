# API Endpoint Enumeration

Probe a target for common API paths, documentation endpoints, health checks, debug interfaces, and well-known configuration files to map the API attack surface.

## Arguments

$ARGUMENTS should be a base URL (no trailing slash).

Examples:
- `https://api.example.com`
- `https://example.com`
- `http://10.0.0.1:8080`

## Workflow

1. Parse the base URL from `$ARGUMENTS`. Strip any trailing slash.
2. Show the user the exact commands before executing them.
3. **Remind the user:** Only enumerate APIs you own or have explicit authorisation to test. Automated probing may trigger security alerts.

### Step 1: Probe common API base paths

```bash
BASE="<base_url>"

echo "=== API Base Paths ==="
for path in /api /api/v1 /api/v2 /api/v3 /api/v4 /v1 /v2 /v3 /rest /rest/v1 /graphql /gql; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 2: Probe API documentation and schema endpoints

```bash
BASE="<base_url>"

echo "=== API Documentation ==="
for path in /swagger /swagger.json /swagger.yaml /swagger/index.html /swagger-ui /swagger-ui.html /swagger-ui/index.html /swagger-resources /api-docs /api-docs.json /openapi.json /openapi.yaml /openapi/v3/api-docs /docs /redoc /documentation /api/docs /api/swagger.json; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 3: Probe GraphQL endpoints

```bash
BASE="<base_url>"

echo "=== GraphQL Endpoints ==="
for path in /graphql /graphiql /v1/graphql /v2/graphql /api/graphql /query /gql /playground /altair /voyager; do
  # Test with a simple POST query
  CODE=$(curl -o /dev/null -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' \
    "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path (POST)"

  # Also test with GET
  CODE_GET=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE_GET" != "404" ] && [ "$CODE_GET" != "000" ] && [ "$CODE_GET" != "$CODE" ] && echo "$CODE_GET  $path (GET)"
done
```

### Step 4: Probe health, status, and monitoring endpoints

```bash
BASE="<base_url>"

echo "=== Health & Status ==="
for path in /health /healthz /health/live /health/ready /health/startup /status /ping /pong /version /info /ready /alive /__health /_health; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 5: Probe metrics and debug endpoints

```bash
BASE="<base_url>"

echo "=== Metrics & Debug ==="
for path in /metrics /prometheus/metrics /debug /debug/pprof /debug/vars /debug/requests /trace /profiler /_debug; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 6: Probe admin and management endpoints

```bash
BASE="<base_url>"

echo "=== Admin & Management ==="
for path in /admin /admin/api /management /internal /console /dashboard /portal /actuator /actuator/env /actuator/health /actuator/info /actuator/beans /actuator/mappings /actuator/configprops /actuator/metrics; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 7: Probe well-known and configuration paths

```bash
BASE="<base_url>"

echo "=== Well-Known & Config ==="
for path in /.well-known/openid-configuration /.well-known/jwks.json /.well-known/oauth-authorization-server /.well-known/security.txt /.well-known/change-password /robots.txt /sitemap.xml /crossdomain.xml /clientaccesspolicy.xml /.env /.git/config /.git/HEAD /wp-json /wp-json/wp/v2; do
  CODE=$(curl -o /dev/null -s -w "%{http_code}" "$BASE$path")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "$CODE  $path"
done
```

### Step 8: Inspect discovered endpoints

For any endpoint that returned 200, fetch the response body:

```bash
# For documentation endpoints that returned 200
curl -s <base_url><discovered_path> | head -100

# For JSON endpoints
curl -s <base_url><discovered_path> | python3 -m json.tool 2>/dev/null || curl -s <base_url><discovered_path> | head -50
```

4. Present results organised by category:

**Discovered Endpoints:**

| Category | Path | Status | Notes |
|----------|------|--------|-------|
| API Base | `/api/v1` | 200 | Active API version |
| Documentation | `/swagger-ui.html` | 200 | API docs exposed |
| GraphQL | `/graphql` | 200 | GraphQL endpoint found |
| Health | `/health` | 200 | Health check exposed |
| Metrics | `/metrics` | 200 | **Sensitive — should be restricted** |
| Admin | `/actuator` | 200 | **Critical — should not be public** |
| Config | `/.env` | 200 | **Critical — secrets exposed** |

5. Flag severity of findings:
   - **Critical:** `/.env`, `/.git/config`, `/actuator/env`, `/debug` returning 200 (secrets/config exposure)
   - **High:** `/swagger`, `/openapi.json` accessible without auth (full API schema disclosure)
   - **Medium:** `/metrics`, `/health` with detailed info (internal state exposure)
   - **Low:** `/robots.txt`, `/security.txt`, `/version` (information disclosure)
   - **Info:** API versioning discovered, GraphQL endpoint found

## Security Notes

- **Only enumerate APIs you own or have explicit written authorisation to test.** Automated probing may violate terms of service and trigger security alerts.
- Exposed Swagger/OpenAPI documentation gives attackers a complete map of every endpoint, parameter, and data model — it should require authentication in production.
- Spring Boot Actuator endpoints (`/actuator/*`) can expose environment variables, database credentials, and heap dumps. These must be restricted or disabled in production.
- Debug endpoints (`/debug/pprof`, `/debug/vars`) expose profiling data and internal state. They must never be accessible in production.
- `/.env` and `/.git/config` returning 200 is a critical finding — these typically contain database credentials, API keys, and other secrets.
- Health and readiness endpoints are normally expected to be public, but should not expose internal implementation details.
- GraphQL introspection should be disabled in production — an exposed introspection endpoint reveals the entire API schema.
