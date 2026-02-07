# JWT Verify

Verify the cryptographic signature of a JSON Web Token.

## Arguments

$ARGUMENTS should include:
- A JWT string
- A secret key (for HMAC) or path to a public key file (for RSA/ECDSA)
- Optionally the expected algorithm: `HS256` (default for HMAC), `RS256`, `ES256`

Examples:
- `eyJhbG... mysecretkey`
- `eyJhbG... --key /path/to/public.pem`
- `eyJhbG... --jwks https://auth.example.com/.well-known/jwks.json`

## Workflow

1. Parse the JWT, key, and algorithm from `$ARGUMENTS`.
2. Decode the header to determine the algorithm.
3. Show the user the exact command before executing.

### HMAC verification (HS256/HS384/HS512)

```bash
python3 -c "
import base64, hashlib, hmac, json, sys

jwt_token = sys.argv[1]
secret = sys.argv[2]

parts = jwt_token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
alg = header.get('alg', 'HS256')

message = (parts[0] + '.' + parts[1]).encode()
signature = base64.urlsafe_b64decode(parts[2] + '==')

hash_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
if alg not in hash_map:
    print(f'Algorithm {alg} is not HMAC-based. Use a public key for verification.')
    sys.exit(1)

expected = hmac.new(secret.encode(), message, hash_map[alg]).digest()

if hmac.compare_digest(signature, expected):
    print(f'Signature:  VALID ({alg})')
else:
    print(f'Signature:  INVALID ({alg})')
    print('The token has been tampered with or the secret is wrong.')
" "<jwt>" "<secret>"
```

### RSA verification (RS256/RS384/RS512)

```bash
python3 -c "
import base64, json, sys, subprocess, tempfile, os

jwt_token = sys.argv[1]
pubkey_file = sys.argv[2]

parts = jwt_token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
alg = header.get('alg', 'RS256')

hash_map = {'RS256': 'sha256', 'RS384': 'sha384', 'RS512': 'sha512'}
if alg not in hash_map:
    print(f'Algorithm {alg} — use appropriate verification method.')
    sys.exit(1)

message = (parts[0] + '.' + parts[1]).encode()
signature = base64.urlsafe_b64decode(parts[2] + '==')

sig_file = tempfile.mktemp()
msg_file = tempfile.mktemp()

with open(sig_file, 'wb') as f: f.write(signature)
with open(msg_file, 'wb') as f: f.write(message)

result = subprocess.run(
    ['openssl', 'dgst', f'-{hash_map[alg]}', '-verify', pubkey_file, '-signature', sig_file, msg_file],
    capture_output=True, text=True
)

os.unlink(sig_file)
os.unlink(msg_file)

output = result.stdout.strip() or result.stderr.strip()
if 'Verified OK' in output:
    print(f'Signature:  VALID ({alg})')
else:
    print(f'Signature:  INVALID ({alg})')
    print('The token has been tampered with or the key is wrong.')
" "<jwt>" "<pubkey_path>"
```

### Fetch and display JWKS

```bash
curl -s <jwks_url> | python3 -m json.tool
```

4. Present results:
   - Algorithm from header
   - Verification result: VALID or INVALID
   - If INVALID: possible reasons (wrong key, tampered token, algorithm mismatch)

## Security Notes

- **Never use the `alg` from the JWT header to select the verification algorithm** in production code. Always enforce the expected algorithm server-side. The `alg` header is attacker-controlled.
- HMAC secrets should be at least 256 bits (32 bytes) of random data. Short or dictionary-word secrets can be brute-forced.
- For RSA/ECDSA, only the public key is needed for verification. Never share the private key.
- `alg: none` should always be rejected — it means no signature, and the token can be forged by anyone.
- If using JWKS, pin the JWKS URL — do not follow `jku` headers from the token itself.
