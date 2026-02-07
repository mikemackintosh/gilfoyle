# JWT Decode

Decode a JSON Web Token and display its header and payload in readable format.

## Arguments

$ARGUMENTS should be a JWT string (the full `eyJ...` token).

Examples:
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`

## Workflow

1. Parse the JWT from `$ARGUMENTS`.
2. Validate that the token has 3 dot-separated parts.
3. Show the user the exact command before executing.

### Decode header and payload

```bash
python3 -c "
import base64, json, sys

jwt = sys.argv[1].strip()
parts = jwt.split('.')

if len(parts) != 3:
    print(f'Error: Expected 3 parts, got {len(parts)}. This may not be a valid JWT.')
    sys.exit(1)

def decode_part(part):
    padding = 4 - len(part) % 4
    part += '=' * padding
    return json.loads(base64.urlsafe_b64decode(part))

print('=== Header ===')
header = decode_part(parts[0])
print(json.dumps(header, indent=2))

print()
print('=== Payload ===')
payload = decode_part(parts[1])
print(json.dumps(payload, indent=2))

print()
print('=== Signature ===')
sig_bytes = base64.urlsafe_b64decode(parts[2] + '==')
print(f'Algorithm:  {header.get(\"alg\", \"unknown\")}')
print(f'Signature:  {sig_bytes.hex()[:64]}...' if len(sig_bytes.hex()) > 64 else f'Signature:  {sig_bytes.hex()}')

# Time-related claims
import datetime
now = datetime.datetime.now(datetime.timezone.utc)
print()
print('=== Time Analysis ===')
for claim, label in [('iat', 'Issued At'), ('nbf', 'Not Before'), ('exp', 'Expires')]:
    if claim in payload:
        ts = datetime.datetime.fromtimestamp(payload[claim], tz=datetime.timezone.utc)
        delta = ts - now
        status = ''
        if claim == 'exp':
            status = ' (EXPIRED)' if now > ts else f' (valid for {delta})'
        print(f'{label:12s} {ts.isoformat()} {status}')
    else:
        if claim == 'exp':
            print(f'{label:12s} NOT SET (token never expires)')
" "<jwt>"
```

4. Present a clean summary:
   - Algorithm used
   - Key claims (issuer, subject, audience)
   - Token validity (expired, valid, no expiry)
   - Any notable fields (roles, permissions, scopes)

## Security Notes

- JWT payloads are **Base64URL-encoded, not encrypted**. Anyone with the token can read the claims. Never put secrets in JWT payloads.
- Decoding does not verify the signature — a decoded token may have been tampered with. Use `/jwt:verify` to check signatures.
- `alg: none` in the header is a known attack vector — tokens with no algorithm should never be trusted.
- Check the `exp` claim — tokens without expiry remain valid indefinitely if stolen.
