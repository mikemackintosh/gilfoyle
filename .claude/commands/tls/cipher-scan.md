# Cipher Scan

Enumerate the cipher suites supported by a remote TLS server.

## Arguments

$ARGUMENTS should be a hostname or hostname:port (default port is 443).

## Workflow

1. Parse the target from `$ARGUMENTS`. Default port is 443.
2. Show the user the exact commands before executing.

### Method 1: OpenSSL cipher enumeration

Test each cipher individually:

```bash
HOST=<host>
PORT=<port>

for cipher in $(openssl ciphers 'ALL:eNULL' | tr ':' '\n'); do
  result=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -cipher "$cipher" 2>/dev/null)
  if echo "$result" | grep -q "Cipher is"; then
    echo "SUPPORTED: $cipher"
  fi
done
```

### Method 2: Test by protocol version (faster overview)

```bash
HOST=<host>
PORT=<port>

for proto in tls1_2 tls1_3; do
  echo "=== $proto ==="
  echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -"$proto" 2>/dev/null | grep "Cipher is"
done
```

### Method 3: nmap ssl-enum-ciphers (if available)

```bash
nmap --script ssl-enum-ciphers -p <port> <host>
```

This gives a graded output (A/B/C/D/F) per cipher suite and is the most comprehensive scan.

3. Present results organised by strength:

**Strong (recommended):**
- TLS 1.3 cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, etc.)
- TLS 1.2 ECDHE + AEAD suites

**Acceptable:**
- TLS 1.2 DHE + AEAD suites (with DH >= 2048 bits)

**Weak (flag as warning):**
- CBC-mode ciphers (vulnerable to padding oracle attacks)
- RSA key exchange (no forward secrecy)
- 3DES (Sweet32 vulnerability)

**Insecure (flag as critical):**
- RC4, DES, NULL ciphers
- Export-grade ciphers
- Anonymous (aNULL) ciphers
- MD5 MAC

## Security Notes

- Forward secrecy (ECDHE/DHE) should be preferred for all connections.
- TLS 1.3 only supports strong ciphers by design.
- BEAST, POODLE, Sweet32, ROBOT — note if server config is vulnerable based on supported ciphers.
