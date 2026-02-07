---
name: JWT & Token Analysis
description: JWT decoding, signature verification, claim inspection, and common token security analysis.
instructions: |
  Use this skill when the user needs to decode JWTs, verify signatures, inspect claims and
  expiry, or analyse token security. Always show commands before executing them. Never ask
  the user for secrets — if a signing key is needed, explain how they can provide it safely.
---

# JWT & Token Analysis Skill

## JWT Structure

A JWT (JSON Web Token) has three Base64URL-encoded parts separated by dots:

```
header.payload.signature
```

| Part | Contains | Example Fields |
|------|----------|---------------|
| **Header** | Algorithm, token type | `alg`, `typ`, `kid` |
| **Payload** | Claims (data) | `sub`, `iat`, `exp`, `iss`, `aud`, custom claims |
| **Signature** | Cryptographic signature | HMAC or RSA/EC signature |

## Decoding JWTs

### Decode with bash (no external tools)

```bash
# Decode a JWT — header and payload
JWT="eyJhbGci..."

# Header (part 1)
echo "$JWT" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool

# Payload (part 2)
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool

# One-liner: decode both
echo "$JWT" | awk -F. '{
  cmd1 = "echo " $1 " | tr \"_-\" \"/+\" | base64 -d 2>/dev/null | python3 -m json.tool"
  cmd2 = "echo " $2 " | tr \"_-\" \"/+\" | base64 -d 2>/dev/null | python3 -m json.tool"
  print "=== Header ===" ; system(cmd1)
  print "=== Payload ===" ; system(cmd2)
}'
```

### Decode with Python (more robust)

```bash
python3 -c "
import base64, json, sys

jwt = sys.argv[1]
parts = jwt.split('.')

def decode_part(part):
    padding = 4 - len(part) % 4
    part += '=' * padding
    return json.loads(base64.urlsafe_b64decode(part))

print('=== Header ===')
print(json.dumps(decode_part(parts[0]), indent=2))
print()
print('=== Payload ===')
print(json.dumps(decode_part(parts[1]), indent=2))
" "$JWT"
```

## JWT Header Fields

| Field | Meaning | Values |
|-------|---------|--------|
| `alg` | Signing algorithm | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `EdDSA`, `none` |
| `typ` | Token type | `JWT` |
| `kid` | Key ID | Identifies which key signed the token |
| `jku` | JWK Set URL | URL to signing keys (can be exploited) |
| `x5u` | X.509 URL | URL to signing certificate (can be exploited) |
| `x5c` | X.509 cert chain | Embedded certificate |
| `cty` | Content type | Used in nested JWTs |

### Algorithm Classification

| Algorithm | Type | Strength |
|-----------|------|----------|
| `none` | **No signature** | **CRITICAL — never accept** |
| `HS256` | HMAC + SHA-256 | Symmetric (shared secret) |
| `HS384` | HMAC + SHA-384 | Symmetric (shared secret) |
| `HS512` | HMAC + SHA-512 | Symmetric (shared secret) |
| `RS256` | RSA + SHA-256 | Asymmetric (key pair) |
| `RS384` | RSA + SHA-384 | Asymmetric (key pair) |
| `RS512` | RSA + SHA-512 | Asymmetric (key pair) |
| `PS256` | RSA-PSS + SHA-256 | Asymmetric (stronger RSA) |
| `ES256` | ECDSA + P-256 | Asymmetric (elliptic curve) |
| `ES384` | ECDSA + P-384 | Asymmetric (elliptic curve) |
| `ES512` | ECDSA + P-521 | Asymmetric (elliptic curve) |
| `EdDSA` | Ed25519/Ed448 | Asymmetric (modern, fast) |

## JWT Payload Claims

### Registered Claims (RFC 7519)

| Claim | Name | Purpose | Example |
|-------|------|---------|---------|
| `iss` | Issuer | Who issued the token | `https://auth.example.com` |
| `sub` | Subject | Who the token is about | `user:12345` |
| `aud` | Audience | Intended recipient | `https://api.example.com` |
| `exp` | Expiration | Token expiry (Unix timestamp) | `1704067200` |
| `nbf` | Not Before | Token valid from (Unix timestamp) | `1704063600` |
| `iat` | Issued At | When token was created | `1704063600` |
| `jti` | JWT ID | Unique token identifier | `a1b2c3d4` |

### Check Expiry

```bash
# Extract and convert exp claim
python3 -c "
import base64, json, sys, datetime

jwt = sys.argv[1]
payload = jwt.split('.')[1]
padding = 4 - len(payload) % 4
payload += '=' * padding
claims = json.loads(base64.urlsafe_b64decode(payload))

now = datetime.datetime.now(datetime.timezone.utc)

if 'exp' in claims:
    exp = datetime.datetime.fromtimestamp(claims['exp'], tz=datetime.timezone.utc)
    delta = exp - now
    status = 'VALID' if exp > now else 'EXPIRED'
    print(f'Expiry:  {exp.isoformat()}')
    print(f'Status:  {status}')
    print(f'Delta:   {delta}')
else:
    print('No exp claim — token never expires (dangerous)')

if 'iat' in claims:
    iat = datetime.datetime.fromtimestamp(claims['iat'], tz=datetime.timezone.utc)
    print(f'Issued:  {iat.isoformat()}')

if 'nbf' in claims:
    nbf = datetime.datetime.fromtimestamp(claims['nbf'], tz=datetime.timezone.utc)
    print(f'Not Before: {nbf.isoformat()}')
" "$JWT"
```

## Signature Verification

### Verify HMAC (HS256/HS384/HS512)

```bash
python3 -c "
import base64, hashlib, hmac, sys

jwt = sys.argv[1]
secret = sys.argv[2]

parts = jwt.split('.')
message = (parts[0] + '.' + parts[1]).encode()

signature = base64.urlsafe_b64decode(parts[2] + '==')
expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()

if hmac.compare_digest(signature, expected):
    print('Signature: VALID')
else:
    print('Signature: INVALID')
" "$JWT" "your-secret-key"
```

### Verify RSA (RS256) with public key

```bash
python3 -c "
import base64, json, sys, subprocess

jwt = sys.argv[1]
pubkey_file = sys.argv[2]

parts = jwt.split('.')
header_payload = (parts[0] + '.' + parts[1]).encode()
signature = base64.urlsafe_b64decode(parts[2] + '==')

# Write signature to temp file
with open('/tmp/jwt_sig.bin', 'wb') as f:
    f.write(signature)

# Write message to temp file
with open('/tmp/jwt_msg.bin', 'wb') as f:
    f.write(header_payload)

# Verify with openssl
import subprocess
result = subprocess.run([
    'openssl', 'dgst', '-sha256', '-verify', pubkey_file,
    '-signature', '/tmp/jwt_sig.bin', '/tmp/jwt_msg.bin'
], capture_output=True, text=True)

print(result.stdout.strip() or result.stderr.strip())
" "$JWT" public_key.pem
```

### Fetch JWKS (JSON Web Key Set) for verification

```bash
# If the JWT header has a jku or you know the JWKS endpoint
curl -s https://auth.example.com/.well-known/jwks.json | python3 -m json.tool

# Common JWKS locations
# https://example.com/.well-known/jwks.json
# https://example.com/.well-known/openid-configuration → jwks_uri
# https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
# https://www.googleapis.com/oauth2/v3/certs

# Fetch OpenID Configuration (includes jwks_uri)
curl -s https://auth.example.com/.well-known/openid-configuration | python3 -m json.tool
```

## Common JWT Vulnerabilities

### 1. Algorithm None Attack

```
Header: {"alg": "none", "typ": "JWT"}
```

If the server accepts `alg: none`, any payload can be forged without a signature. The server must reject `none` and validate the algorithm against an allowlist.

### 2. Algorithm Confusion (RS256 → HS256)

If a server uses RSA (RS256) but also accepts HMAC (HS256), an attacker can:
1. Obtain the RSA public key
2. Sign a forged token using HS256 with the public key as the HMAC secret
3. The server verifies using the public key as a symmetric key

**Mitigation:** Server must enforce the expected algorithm, never allow the token to dictate it.

### 3. Weak HMAC Secret

HMAC secrets can be brute-forced if they are short or common. Use at least 256 bits of random data.

```bash
# Generate a strong HMAC secret
openssl rand -base64 32
```

### 4. Missing Expiration

Tokens without `exp` never expire. Stolen tokens remain valid indefinitely.

### 5. Excessive Token Lifetime

Very long `exp` values (days/weeks) increase the window for stolen token abuse.

### 6. Sensitive Data in Payload

JWT payloads are **encoded, not encrypted**. Anyone with the token can read the claims. Never put passwords, credit card numbers, or secrets in JWT payloads.

### 7. JKU/X5U Header Injection

If the server follows `jku` or `x5u` headers to fetch verification keys, an attacker can point these to their own server and serve their own keys.

**Mitigation:** Never follow `jku`/`x5u` from the token itself. Use a hardcoded JWKS endpoint.

## Token Comparison: JWT vs Others

| Token Type | Format | Stateless | Revocable | Size |
|------------|--------|-----------|-----------|------|
| JWT | Base64URL JSON | Yes | No (without blocklist) | Medium |
| Opaque token | Random string | No (requires DB lookup) | Yes | Small |
| PASETO | Versioned binary | Yes | No (without blocklist) | Medium |
| Macaroon | Chained caveats | Partially | Via caveats | Variable |

## Useful One-Liners

```bash
# Count parts (should be 3 for a standard JWT)
echo "$JWT" | tr -cd '.' | wc -c

# Get the algorithm
echo "$JWT" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('alg','unknown'))"

# Check if expired
python3 -c "
import base64,json,sys,time
p = sys.argv[1].split('.')[1]
p += '=' * (4 - len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
exp = c.get('exp')
if exp:
    print('EXPIRED' if time.time() > exp else f'Valid for {int(exp - time.time())}s')
else:
    print('No expiry set')
" "$JWT"

# Pretty-print full token
python3 -c "
import base64,json,sys
t = sys.argv[1].split('.')
for i,name in enumerate(['Header','Payload']):
    p = t[i] + '=' * (4 - len(t[i]) % 4)
    print(f'=== {name} ===')
    print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))
" "$JWT"
```
