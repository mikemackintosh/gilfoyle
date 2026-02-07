# Cookie Security Inspection

Inspect the cookies set by a web application and check their security flags.

## Arguments

$ARGUMENTS should be a URL.

Examples:
- `https://example.com`
- `https://example.com/login`

## Workflow

1. Parse the URL from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Fetch Set-Cookie headers

```bash
curl -sIL <url> | grep -i 'set-cookie'
```

### Fetch with verbose output (shows request cookies too)

```bash
curl -sv <url> -o /dev/null 2>&1 | grep -iE '(set-cookie|> cookie:)'
```

### Follow a login flow and dump cookie jar

```bash
curl -sIL -c - <url> 2>/dev/null
```

3. For each cookie found, check the security flags:

| Flag | Present? | Assessment |
|------|----------|------------|
| `Secure` | Yes/No | **FAIL** if missing on HTTPS site |
| `HttpOnly` | Yes/No | **FAIL** if missing on session/auth cookies |
| `SameSite` | `Strict`/`Lax`/`None`/Missing | **WARN** if missing, **FAIL** if `None` without `Secure` |
| `Path` | Value | **INFO** — check scope is appropriate |
| `Domain` | Value | **WARN** if overly broad |
| `Max-Age`/`Expires` | Value | **INFO** — flag very long lifetimes |
| `__Host-` prefix | Yes/No | **INFO** — strongest security, requires Secure + Path=/ + no Domain |
| `__Secure-` prefix | Yes/No | **INFO** — requires Secure flag |

4. Present results as a table:

```
Cookie: session_id
  Secure:     YES
  HttpOnly:   YES
  SameSite:   Lax
  Path:       /
  Domain:     (not set — good, restricted to exact host)
  Expires:    Session
  Verdict:    PASS
```

5. Flag any issues and provide recommendations.

## Security Notes

- Missing `Secure` flag means the cookie is sent over HTTP, where it can be intercepted on the network.
- Missing `HttpOnly` means JavaScript can read the cookie — if XSS is present, the session is compromised.
- `SameSite=None` requires the `Secure` flag. Without it, the cookie is rejected by modern browsers.
- Very long cookie lifetimes (weeks/months) increase the window for stolen cookie abuse.
- `__Host-` prefixed cookies provide the strongest protection: they must have `Secure`, must not have `Domain`, and must have `Path=/`.
- Cookie values that look like base64 or JSON may contain sensitive data — they are not encrypted.
