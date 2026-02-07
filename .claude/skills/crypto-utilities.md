---
name: Crypto Utilities
description: Cryptographic utility operations — hashing, encoding/decoding, HMAC, key derivation, and general crypto helpers.
instructions: |
  Use this skill when the user needs to perform cryptographic utility operations: hashing files
  or strings, encoding/decoding data, computing HMACs, or deriving keys. Provide commands,
  explain algorithm choices, and note security implications.
---

# Crypto Utilities Skill

## Related Commands
- `/hash` — Compute cryptographic hash digests
- `/encode-decode` — Base64 and hex encoding/decoding

## Hash Algorithms

### Comparison

| Algorithm | Output Size | Status | Use Cases |
|-----------|------------|--------|-----------|
| MD5 | 128 bits (32 hex) | **Broken** | Legacy checksums only |
| SHA-1 | 160 bits (40 hex) | **Deprecated** | Git commits, legacy compat |
| SHA-224 | 224 bits (56 hex) | Current | Rarely used |
| SHA-256 | 256 bits (64 hex) | **Recommended** | General purpose, TLS, code signing |
| SHA-384 | 384 bits (96 hex) | Current | Higher security requirements |
| SHA-512 | 512 bits (128 hex) | Current | Faster on 64-bit, higher security |
| SHA-512/256 | 256 bits (64 hex) | Current | SHA-256 security with SHA-512 speed on 64-bit |
| SHA3-256 | 256 bits (64 hex) | Current | Alternative to SHA-2, different construction |
| BLAKE2b | Up to 512 bits | Current | Fast, modern, used in WireGuard |
| BLAKE3 | 256 bits | Current | Very fast, parallelisable |

### Quick Commands

```bash
# SHA-256 of a file
openssl dgst -sha256 file.txt
shasum -a 256 file.txt

# SHA-512 of a file
openssl dgst -sha512 file.txt

# MD5 (legacy only)
openssl dgst -md5 file.txt
md5 file.txt          # macOS
md5sum file.txt       # Linux

# SHA-256 of a string (note: -n to avoid trailing newline)
echo -n "hello" | openssl dgst -sha256
echo -n "hello" | shasum -a 256

# SHA3-256 (if supported by your OpenSSL)
openssl dgst -sha3-256 file.txt

# Hash multiple files
shasum -a 256 *.pem
```

## HMAC (Hash-based Message Authentication Code)

HMAC combines a hash function with a secret key for message authentication.

```bash
# HMAC-SHA256
echo -n "message" | openssl dgst -sha256 -hmac "secret-key"

# HMAC-SHA512
echo -n "message" | openssl dgst -sha512 -hmac "secret-key"

# HMAC of a file
openssl dgst -sha256 -hmac "secret-key" file.txt

# HMAC with hex key
echo -n "message" | openssl dgst -sha256 -mac HMAC -macopt hexkey:deadbeef
```

**When to use HMAC:**
- API request signing (e.g., AWS Signature V4)
- Webhook payload verification (e.g., GitHub, Stripe)
- Session token integrity
- Message authentication in protocols

## Encoding Schemes

### Base64

```bash
# Encode
echo -n "hello" | base64
openssl base64 -in file.bin

# Decode
echo -n "aGVsbG8=" | base64 -D       # macOS
echo -n "aGVsbG8=" | base64 -d       # Linux

# URL-safe Base64 (RFC 4648 §5)
echo -n "hello" | base64 | tr '+/' '-_' | tr -d '='

# Decode URL-safe Base64
echo -n "aGVsbG8" | tr '-_' '+/' | base64 -D
```

Properties:
- Expands data by ~33% (3 bytes → 4 characters)
- Alphabet: `A-Za-z0-9+/` with `=` padding
- URL-safe variant: `+` → `-`, `/` → `_`, no padding

### Hex (Hexadecimal)

```bash
# Encode
echo -n "hello" | xxd -p
echo -n "hello" | od -A n -t x1 | tr -d ' \n'

# Decode
echo -n "68656c6c6f" | xxd -r -p

# Hex dump with offsets (useful for binary inspection)
xxd file.bin
xxd file.bin | head -20

# Convert hex to base64
echo -n "68656c6c6f" | xxd -r -p | base64
```

Properties:
- Expands data by 100% (1 byte → 2 hex characters)
- Alphabet: `0-9a-f`
- More human-readable than Base64 for small values

### ASN.1 / DER Inspection

```bash
# Decode ASN.1 structure (certificates, keys)
openssl asn1parse -in cert.pem
openssl asn1parse -in cert.der -inform DER

# Decode with offset
openssl asn1parse -in cert.pem -strparse <offset>
```

## Key Derivation

### PBKDF2 (Password-Based Key Derivation Function 2)

```bash
# Derive a key from a password
openssl kdf -keylen 32 -kdfopt digest:SHA256 \
  -kdfopt pass:"mypassword" -kdfopt salt:"random-salt" \
  -kdfopt iter:600000 PBKDF2
```

NIST recommends >= 600,000 iterations for PBKDF2-HMAC-SHA256 (as of 2023).

### HKDF (HMAC-based Key Derivation Function)

```bash
# Extract-then-expand
openssl kdf -keylen 32 -kdfopt digest:SHA256 \
  -kdfopt key:"input-key-material" \
  -kdfopt salt:"optional-salt" \
  -kdfopt info:"context-info" HKDF
```

### scrypt / Argon2

- **scrypt**: Memory-hard KDF, good for password hashing
- **Argon2**: Winner of Password Hashing Competition, recommended for new applications
- Neither is directly available via `openssl` CLI; use dedicated tools or libraries

## Random Data Generation

```bash
# Generate random bytes (hex encoded)
openssl rand -hex 32

# Generate random bytes (base64 encoded)
openssl rand -base64 32

# Generate random bytes (binary)
openssl rand -out random.bin 32

# Generate a random password/token
openssl rand -base64 24 | tr -d '/+=' | head -c 32

# System random (Unix)
head -c 32 /dev/urandom | xxd -p
```

## Symmetric Encryption

```bash
# Encrypt a file with AES-256-CBC
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
  -in plaintext.txt -out encrypted.bin

# Decrypt
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
  -in encrypted.bin -out plaintext.txt

# Encrypt with explicit key and IV (not password-based)
openssl enc -aes-256-cbc -K <hex-key> -iv <hex-iv> \
  -in plaintext.txt -out encrypted.bin

# List available ciphers
openssl enc -list
```

**Always use:**
- `-salt` to prevent dictionary attacks
- `-pbkdf2` with high iteration count for password-based encryption
- AES-256-GCM or AES-256-CBC (GCM preferred for authenticated encryption)

## Useful One-Liners

```bash
# Compare two files by hash
diff <(shasum -a 256 file1) <(shasum -a 256 file2)

# Verify a downloaded file against a checksum
echo "<expected-hash>  filename" | shasum -a 256 -c

# Generate a UUID v4
python3 -c "import uuid; print(uuid.uuid4())"

# Timestamp a hash (poor man's timestamping)
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $(shasum -a 256 file.txt)" >> audit.log

# Check if openssl supports a specific algorithm
openssl dgst -list 2>&1 | grep sha3
openssl enc -list 2>&1 | grep aes
```
