# JWT Full Inspection

Perform a comprehensive security inspection of a JSON Web Token — decode, analyse claims, check expiry, flag vulnerabilities.

## Arguments

$ARGUMENTS should be a JWT string.

Examples:
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

## Workflow

1. Parse the JWT from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Full inspection

```bash
python3 -c "
import base64, json, sys, datetime

jwt_token = sys.argv[1].strip()
parts = jwt_token.split('.')

if len(parts) != 3:
    print(f'ERROR: Expected 3 parts, got {len(parts)}')
    sys.exit(1)

def decode_part(part):
    padding = 4 - len(part) % 4
    part += '=' * padding
    return json.loads(base64.urlsafe_b64decode(part))

header = decode_part(parts[0])
payload = decode_part(parts[1])
now = datetime.datetime.now(datetime.timezone.utc)

findings = []

# === HEADER ===
print('=' * 50)
print('HEADER')
print('=' * 50)
print(json.dumps(header, indent=2))

alg = header.get('alg', 'MISSING')
print(f'\nAlgorithm: {alg}')

# Header checks
if alg == 'none':
    findings.append(('CRITICAL', 'Algorithm is \"none\" — token has no signature and can be forged by anyone'))
elif alg in ('HS256', 'HS384', 'HS512'):
    findings.append(('INFO', f'Symmetric algorithm ({alg}) — both parties share the same secret'))
elif alg in ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'):
    findings.append(('INFO', f'Asymmetric RSA algorithm ({alg}) — signed with private key, verified with public key'))
elif alg in ('ES256', 'ES384', 'ES512', 'EdDSA'):
    findings.append(('INFO', f'Asymmetric EC algorithm ({alg}) — signed with private key, verified with public key'))

if 'kid' in header:
    print(f'Key ID:    {header[\"kid\"]}')
if 'jku' in header:
    findings.append(('WARN', f'jku header present ({header[\"jku\"]}) — verify this URL is trusted. JKU injection is a known attack.'))
if 'x5u' in header:
    findings.append(('WARN', f'x5u header present ({header[\"x5u\"]}) — verify this URL is trusted. X5U injection is a known attack.'))

# === PAYLOAD ===
print()
print('=' * 50)
print('PAYLOAD')
print('=' * 50)
print(json.dumps(payload, indent=2))

# Standard claims
print()
for claim, label in [('iss', 'Issuer'), ('sub', 'Subject'), ('aud', 'Audience'), ('jti', 'Token ID')]:
    if claim in payload:
        print(f'{label:12s} {payload[claim]}')

# Time claims
print()
print('--- Time Analysis ---')
for claim, label in [('iat', 'Issued At'), ('nbf', 'Not Before'), ('exp', 'Expires')]:
    if claim in payload:
        ts = datetime.datetime.fromtimestamp(payload[claim], tz=datetime.timezone.utc)
        delta = ts - now
        extra = ''
        if claim == 'exp':
            if now > ts:
                extra = ' ** EXPIRED **'
                findings.append(('WARN', f'Token is expired (since {-delta})'))
            else:
                extra = f' (valid for {delta})'
                if delta.days > 30:
                    findings.append(('WARN', f'Token has a long lifetime ({delta.days} days). Stolen tokens remain valid for a long time.'))
        print(f'{label:12s} {ts.isoformat()}{extra}')
    elif claim == 'exp':
        findings.append(('WARN', 'No exp claim — token never expires. Stolen tokens remain valid indefinitely.'))
        print(f'Expires      NOT SET')

# Scope/permissions
if 'scope' in payload:
    print(f'\nScopes:      {payload[\"scope\"]}')
if 'roles' in payload or 'role' in payload:
    roles = payload.get('roles', payload.get('role'))
    print(f'Roles:       {roles}')
if 'permissions' in payload:
    print(f'Permissions: {payload[\"permissions\"]}')

# Check for sensitive data
sensitive_keys = ['password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'credit_card', 'ssn', 'private']
for key in payload:
    if any(s in key.lower() for s in sensitive_keys):
        findings.append(('WARN', f'Potentially sensitive field in payload: \"{key}\". JWT payloads are not encrypted.'))

# === SIGNATURE ===
print()
print('=' * 50)
print('SIGNATURE')
print('=' * 50)
sig = base64.urlsafe_b64decode(parts[2] + '==')
print(f'Length:     {len(sig)} bytes')
print(f'Hex:       {sig.hex()[:64]}...' if len(sig.hex()) > 64 else f'Hex:       {sig.hex()}')
if alg == 'none' and len(parts[2]) == 0:
    findings.append(('CRITICAL', 'Signature is empty — token is unsigned'))
print(f'\nNote: Signature not verified (no key provided). Use /jwt:verify to verify.')

# === FINDINGS ===
print()
print('=' * 50)
print('SECURITY FINDINGS')
print('=' * 50)
if not findings:
    print('No issues found.')
else:
    for severity, message in findings:
        print(f'[{severity:8s}] {message}')
" "<jwt>"
```

3. Present results in clear sections:
   - Decoded header and payload
   - Time analysis (issued, expiry, validity)
   - Scopes/roles/permissions
   - Security findings (CRITICAL/WARN/INFO)
   - Recommendation for next steps (verify signature, check expiry policy, etc.)

## Security Notes

- This command decodes and analyses but does **not verify the signature**. Use `/jwt:verify` with the appropriate key to verify authenticity.
- JWT payloads are readable by anyone with the token — never store secrets, passwords, or sensitive PII in claims.
- Tokens without `exp` are a security risk — they remain valid indefinitely if stolen.
- `jku` and `x5u` headers can be exploited to inject attacker-controlled signing keys — servers should never follow URLs from the token itself.
- Check `aud` (audience) — tokens accepted by the wrong service can lead to privilege escalation across services.
