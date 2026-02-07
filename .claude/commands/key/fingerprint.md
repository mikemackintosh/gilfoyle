# Key Fingerprint

Compute the fingerprint of a cryptographic key file (public or private, RSA/EC/Ed25519).

## Arguments

$ARGUMENTS should be a path to a key file. Optionally specify hash algorithm (sha256, sha1, md5).

## Workflow

1. Parse the file path and optional hash algorithm from `$ARGUMENTS`. Default to SHA-256.
2. Detect the key type by inspecting the file header.
3. Show the user the exact commands before executing.

### Detect key type

```bash
head -1 <file>
```

Look for:
- `-----BEGIN RSA PRIVATE KEY-----` → PKCS#1 RSA private
- `-----BEGIN EC PRIVATE KEY-----` → SEC1 EC private
- `-----BEGIN PRIVATE KEY-----` → PKCS#8 private (any algorithm)
- `-----BEGIN PUBLIC KEY-----` → SPKI public key
- `-----BEGIN RSA PUBLIC KEY-----` → PKCS#1 RSA public
- `-----BEGIN CERTIFICATE-----` → X.509 certificate (extract public key)
- Binary (no PEM header) → try DER format

### RSA key fingerprint

```bash
# Private key — extract public key and fingerprint
openssl rsa -in <file> -pubout 2>/dev/null | openssl sha256

# Or get the modulus fingerprint (common for matching cert ↔ key)
openssl rsa -in <file> -noout -modulus | openssl sha256
```

### EC key fingerprint

```bash
openssl ec -in <file> -pubout 2>/dev/null | openssl sha256
```

### Generic (PKCS#8 / SPKI)

```bash
openssl pkey -in <file> -pubout 2>/dev/null | openssl sha256
```

### Certificate public key fingerprint

```bash
openssl x509 -in <file> -pubkey -noout | openssl sha256
```

### SSH-style fingerprint (if it's an SSH key)

```bash
ssh-keygen -lf <file>
```

4. Display fingerprints in multiple formats:
   - SHA-256 (hex, colon-separated)
   - SHA-1 (for legacy matching)
   - MD5 (for legacy matching, e.g., old SSH fingerprints)

5. If a certificate file is also provided, verify the key matches the certificate by comparing fingerprints.

## Security Notes

- MD5 fingerprints should only be used for identification, never for security verification.
- SHA-1 fingerprints are being phased out; prefer SHA-256.
- Always verify fingerprints over a trusted channel when exchanging keys.
