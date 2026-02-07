# Generate Key Pair

Generate a cryptographic key pair (RSA, EC, or Ed25519).

## Arguments

$ARGUMENTS should include:
- Algorithm: `rsa`, `ec`, or `ed25519`
- For RSA: optional bit size (2048, 3072, 4096). Default: 4096.
- For EC: optional curve name (P-256, P-384, P-521). Default: P-256.
- Optional output filename

Examples:
- `rsa 4096`
- `ec P-256`
- `ed25519`
- `rsa 2048 myserver-key.pem`

## Workflow

1. Parse algorithm, parameters, and optional output filename from `$ARGUMENTS`.
2. Default output filename: `<algorithm>-private.pem`
3. Show the user the exact command before executing.

### RSA

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:<bits> -out <output>.pem
```

Or traditional format:
```bash
openssl genrsa -out <output>.pem <bits>
```

### EC (ECDSA)

Map curve names:
- `P-256` → `prime256v1`
- `P-384` → `secp384r1`
- `P-521` → `secp521r1`

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:<curve> -out <output>.pem
```

### Ed25519

```bash
openssl genpkey -algorithm ED25519 -out <output>.pem
```

4. After generation, extract and display the public key:

```bash
openssl pkey -in <output>.pem -pubout -out <output>-pub.pem
```

5. Set secure file permissions:

```bash
chmod 600 <output>.pem
```

6. Display a summary:
   - Algorithm and parameters
   - Output file(s) and their paths
   - Public key fingerprint (SHA-256)
   - File permissions confirmation

## Security Notes

- RSA keys < 2048 bits should not be used. Recommend 4096 for long-lived keys.
- For EC, P-256 (prime256v1) is the most widely supported curve and is recommended for most use cases.
- Ed25519 is excellent for modern systems but has less legacy support.
- Private keys are generated without a passphrase by default. Suggest encrypting with `openssl pkey -aes256` for keys stored long-term.
- Always set restrictive file permissions (600) on private key files.
