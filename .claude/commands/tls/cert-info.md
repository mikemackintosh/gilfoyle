# Certificate Info

Decode and inspect a local certificate file. Supports PEM and DER formats.

## Arguments

$ARGUMENTS should be a path to a certificate file. Optionally can include format hint (pem/der).

## Workflow

1. Parse the file path from `$ARGUMENTS`.
2. Detect the format by trying PEM first, then DER.
3. Show the user the exact command before executing.

### Try PEM format first

```bash
openssl x509 -in <file> -text -noout
```

If that fails (exit code != 0), try DER:

```bash
openssl x509 -in <file> -inform DER -text -noout
```

4. Extract and present the key information clearly:

| Field | Value |
|-------|-------|
| Subject | CN, O, OU, etc. |
| Issuer | CN, O of the issuing CA |
| Serial Number | hex serial |
| Not Before | start date |
| Not After | end date (flag if expired or < 30 days) |
| Signature Algorithm | e.g., sha256WithRSAEncryption |
| Public Key | algorithm + size |
| SANs | DNS names, IPs |
| Key Usage | digitalSignature, keyEncipherment, etc. |
| Extended Key Usage | serverAuth, clientAuth, etc. |
| Basic Constraints | CA:TRUE/FALSE, path length |

### Additional useful commands

**Fingerprints:**
```bash
openssl x509 -in <file> -noout -fingerprint -sha256
openssl x509 -in <file> -noout -fingerprint -sha1
```

**Check if cert matches a private key:**
```bash
# Compare modulus (RSA) or pub key hash
openssl x509 -in <cert> -noout -modulus | openssl sha256
openssl rsa -in <key> -noout -modulus | openssl sha256
```

5. Flag any security concerns:
   - Expired or expiring soon
   - Weak signature algorithm (SHA-1, MD5)
   - Small key size (RSA < 2048)
   - Missing SANs (CN-only certs are deprecated)
   - Self-signed (Issuer == Subject)
