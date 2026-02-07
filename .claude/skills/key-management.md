---
name: Key Management
description: Cryptographic key lifecycle management — generation, conversion, fingerprinting, storage, and security best practices.
instructions: |
  Use this skill when the user is working with cryptographic keys: generating, converting,
  inspecting, or managing key material. Provide commands, format explanations, and security
  guidance. Always show commands before executing and warn about private key exposure.
---

# Key Management Skill

## Related Commands
- `/gen-keypair` — Generate RSA, EC, or Ed25519 key pairs
- `/key-fingerprint` — Compute key fingerprints
- `/key-convert` — Convert between key formats
- `/pkcs12` — PKCS#12 bundle operations

## Key Types and Recommendations

| Algorithm | Key Size | Security Level | Recommendation |
|-----------|----------|---------------|----------------|
| RSA | 2048 bits | 112-bit | Minimum acceptable |
| RSA | 3072 bits | 128-bit | Good for medium-term |
| RSA | 4096 bits | ~140-bit | Recommended for long-lived keys |
| ECDSA P-256 | 256 bits | 128-bit | Recommended default for EC |
| ECDSA P-384 | 384 bits | 192-bit | High security requirements |
| ECDSA P-521 | 521 bits | 256-bit | Rarely needed |
| Ed25519 | 256 bits | ~128-bit | Modern, fast, recommended where supported |
| Ed448 | 448 bits | ~224-bit | Higher security Ed curve |

## Key Encoding Formats

### PEM (Privacy Enhanced Mail)
- Text format, Base64-encoded with header/footer
- Most common format for Unix/Linux tools
- Headers identify the content type

```
-----BEGIN RSA PRIVATE KEY-----     → PKCS#1 RSA private key
-----BEGIN EC PRIVATE KEY-----      → SEC1 EC private key
-----BEGIN PRIVATE KEY-----         → PKCS#8 private key (any algorithm)
-----BEGIN ENCRYPTED PRIVATE KEY----- → PKCS#8 encrypted private key
-----BEGIN PUBLIC KEY-----          → SPKI public key (any algorithm)
-----BEGIN RSA PUBLIC KEY-----      → PKCS#1 RSA public key
-----BEGIN CERTIFICATE-----         → X.509 certificate
-----BEGIN CERTIFICATE REQUEST----- → PKCS#10 CSR
```

### DER (Distinguished Encoding Rules)
- Binary format
- Used by Java keystores, Windows, and some embedded systems
- Same structures as PEM but without Base64 wrapping

### PKCS Standards Relevant to Keys

| Standard | Purpose |
|----------|---------|
| PKCS#1 | RSA-specific key format (traditional) |
| PKCS#5 | Password-based encryption (used to encrypt PKCS#8 keys) |
| PKCS#7 | Cryptographic message syntax (certificate bundles) |
| PKCS#8 | Generic private key format (all algorithms) |
| PKCS#10 | Certificate Signing Request (CSR) format |
| PKCS#12 | Key + certificate bundle (.p12 / .pfx) |

## Key Format Conversions

### Quick Reference

```bash
# PKCS#1 → PKCS#8
openssl pkcs8 -topk8 -in key-pkcs1.pem -out key-pkcs8.pem -nocrypt

# PKCS#8 → PKCS#1 (RSA only)
openssl rsa -in key-pkcs8.pem -out key-pkcs1.pem -traditional

# PEM → DER
openssl pkey -in key.pem -outform DER -out key.der

# DER → PEM
openssl pkey -in key.der -inform DER -out key.pem

# Extract public key from private
openssl pkey -in private.pem -pubout -out public.pem

# Encrypt private key
openssl pkey -in key.pem -aes256 -out key-enc.pem

# Decrypt private key
openssl pkey -in key-enc.pem -out key.pem

# PEM → OpenSSH format
ssh-keygen -f key.pem -y > key.pub

# OpenSSH → PEM
ssh-keygen -f id_rsa -e -m PEM > key.pem
```

## Fingerprinting Methods

```bash
# SHA-256 fingerprint of public key
openssl pkey -in key.pem -pubout -outform DER | openssl dgst -sha256

# SSH-style fingerprint
ssh-keygen -lf key.pem

# Certificate-key matching (compare these outputs)
openssl x509 -in cert.pem -noout -modulus | openssl sha256
openssl rsa -in key.pem -noout -modulus | openssl sha256

# SPKI pin (used for certificate pinning)
openssl pkey -in key.pem -pubout -outform DER | openssl dgst -sha256 -binary | base64
```

## Key Security Best Practices

### File Permissions
```bash
chmod 600 private-key.pem    # Owner read/write only
chmod 644 public-key.pem     # Public keys can be world-readable
chown root:root private-key.pem  # Owned by root where possible
```

### Storage Guidelines
- **Never** commit private keys to version control
- **Never** transmit private keys over unencrypted channels
- **Always** encrypt keys at rest for long-term storage (AES-256)
- **Consider** using HSMs or key management services (AWS KMS, HashiCorp Vault) for production keys
- **Rotate** keys on a regular schedule (annually for long-lived, more frequently for high-risk)

### Key Compromise Response
1. Revoke all certificates issued for the compromised key
2. Generate a new key pair
3. Issue new certificates with the new key
4. Update all systems using the old key/cert
5. Investigate how the key was compromised
6. Review and strengthen key storage practices

## Java KeyStore (JKS) Interop

```bash
# Import PKCS#12 into JKS
keytool -importkeystore -srckeystore bundle.p12 -srcstoretype PKCS12 \
  -destkeystore keystore.jks -deststoretype JKS

# Export from JKS to PKCS#12
keytool -importkeystore -srckeystore keystore.jks -srcstoretype JKS \
  -destkeystore bundle.p12 -deststoretype PKCS12

# List JKS contents
keytool -list -v -keystore keystore.jks
```
