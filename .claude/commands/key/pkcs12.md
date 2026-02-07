# PKCS#12 Operations

Create, extract from, or inspect PKCS#12 (.p12 / .pfx) bundles.

## Arguments

$ARGUMENTS should include an operation and relevant file paths:

Operations:
- `create <cert> <key> [chain]` — Bundle cert + key (+ optional chain) into .p12
- `extract <p12file>` — Extract cert, key, and chain from .p12
- `info <p12file>` — List contents of .p12 without extracting

Examples:
- `create server.pem server-key.pem ca-chain.pem`
- `extract bundle.p12`
- `info bundle.p12`

## Workflow

1. Parse the operation and file paths from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Create a PKCS#12 bundle

```bash
# With chain
openssl pkcs12 -export -in <cert> -inkey <key> -certfile <chain> -out <output>.p12 -name "friendly-name"

# Without chain
openssl pkcs12 -export -in <cert> -inkey <key> -out <output>.p12 -name "friendly-name"
```

The user will be prompted for an export password.

### Extract from PKCS#12

```bash
# Extract certificate
openssl pkcs12 -in <p12file> -clcerts -nokeys -out cert.pem

# Extract private key
openssl pkcs12 -in <p12file> -nocerts -out key.pem

# Extract CA/chain certificates
openssl pkcs12 -in <p12file> -cacerts -nokeys -out chain.pem

# Extract everything (single PEM)
openssl pkcs12 -in <p12file> -out all.pem -nodes
```

The user will be prompted for the import password.

### Inspect PKCS#12

```bash
openssl pkcs12 -in <p12file> -info -nokeys -noout
```

3. For `create`: confirm bundle was created and display its SHA-256 hash.
4. For `extract`: list extracted files and show subjects of extracted certs.
5. For `info`: display friendly name, certificate subjects, and key type.

## Security Notes

- PKCS#12 bundles contain private keys — treat them with the same care as raw key files.
- Use a strong password when creating bundles. Empty passwords are insecure.
- The `-nodes` flag outputs private keys unencrypted — use with caution.
- Modern systems prefer PKCS#12 with AES encryption. Legacy systems may need 3DES (`-legacy` flag with OpenSSL 3.x).
- After extracting keys, set restrictive permissions: `chmod 600 key.pem`.
