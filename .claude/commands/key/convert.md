# Key Convert

Convert cryptographic keys between formats: PEM ↔ DER, PKCS#1 ↔ PKCS#8, extract public from private.

## Arguments

$ARGUMENTS should include:
- Path to the input key file
- Target format or operation

Supported operations:
- `pem-to-der` — Convert PEM to DER encoding
- `der-to-pem` — Convert DER to PEM encoding
- `pkcs1-to-pkcs8` — Convert PKCS#1 (traditional) to PKCS#8
- `pkcs8-to-pkcs1` — Convert PKCS#8 to PKCS#1 (RSA only)
- `extract-pub` — Extract public key from private key
- `encrypt` — Encrypt a private key with a passphrase
- `decrypt` — Remove passphrase from a private key

Examples:
- `mykey.pem pem-to-der`
- `private.pem extract-pub`
- `key.pem encrypt`

## Workflow

1. Parse the input file and operation from `$ARGUMENTS`.
2. Detect the key type (RSA/EC/generic).
3. Show the user the exact command before executing.

### PEM to DER

```bash
# RSA
openssl rsa -in <file> -outform DER -out <output>.der

# EC
openssl ec -in <file> -outform DER -out <output>.der

# Generic (PKCS#8)
openssl pkey -in <file> -outform DER -out <output>.der
```

### DER to PEM

```bash
openssl pkey -in <file> -inform DER -outform PEM -out <output>.pem
```

### PKCS#1 to PKCS#8

```bash
openssl pkcs8 -topk8 -in <file> -out <output>.pem -nocrypt
```

### PKCS#8 to PKCS#1 (RSA only)

```bash
openssl rsa -in <file> -out <output>.pem -traditional
```

### Extract public key from private

```bash
# Generic (works for RSA, EC, Ed25519)
openssl pkey -in <file> -pubout -out <output>-pub.pem
```

### Encrypt private key

```bash
openssl pkey -in <file> -aes256 -out <output>-encrypted.pem
```

### Decrypt (remove passphrase)

```bash
openssl pkey -in <file> -out <output>-decrypted.pem
```

4. Confirm the output file was written and show its format header.
5. Warn the user about security implications of decrypting keys or writing unencrypted keys to disk.

## Security Notes

- Decrypted private keys on disk are a security risk. Ensure proper file permissions (chmod 600).
- PKCS#8 is the modern standard; prefer it over PKCS#1 for interoperability.
- When encrypting, AES-256-CBC is the default; this is acceptable.
