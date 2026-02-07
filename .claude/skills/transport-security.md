---
name: Transport Security
description: TLS/SSL analysis, troubleshooting, and best practices for securing network communications.
instructions: |
  Use this skill when the user is working with TLS/SSL connections, debugging handshake
  failures, analysing cipher suites, or securing transport-layer communications. Provide
  commands, context, and security guidance. Always show commands before executing them.
---

# Transport Security Skill

## Related Commands
- `/tls-inspect` — Inspect TLS configuration of a remote host
- `/cert-info` — Decode and inspect certificate files
- `/cert-chain-verify` — Verify certificate chain of trust
- `/cipher-scan` — Enumerate supported cipher suites

## TLS Protocol Versions

| Version | Status | Notes |
|---------|--------|-------|
| SSL 2.0 | **Prohibited** | Fundamentally broken (RFC 6176) |
| SSL 3.0 | **Prohibited** | POODLE attack (RFC 7568) |
| TLS 1.0 | **Deprecated** | RFC 8996 (March 2021) |
| TLS 1.1 | **Deprecated** | RFC 8996 (March 2021) |
| TLS 1.2 | **Current** | Still widely used; ensure strong cipher suites |
| TLS 1.3 | **Recommended** | Simplified handshake, only strong ciphers, 0-RTT support |

## TLS 1.3 Cipher Suites

TLS 1.3 only permits these five cipher suites (all AEAD):
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_CCM_SHA256`
- `TLS_AES_128_CCM_8_SHA256`

## TLS 1.2 Recommended Cipher Suites

Prioritise ECDHE key exchange + AEAD ciphers:
```
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
```

## Common TLS Errors & Troubleshooting

### Handshake Failures

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `no protocols available` | Client/server have no TLS version in common | Update client or server to support TLS 1.2+ |
| `no ciphers available` | No shared cipher suites | Check cipher configuration on both sides |
| `certificate verify failed` | Untrusted cert, expired, or hostname mismatch | Check chain, expiry, and SANs |
| `wrong version number` | Connecting to non-TLS port, or proxy interference | Verify port and check for MITM/proxy |
| `self signed certificate` | Server using self-signed cert | Add CA to trust store or use `--insecure` for testing |

### Debugging Steps

1. **Test basic connectivity:**
   ```bash
   openssl s_client -connect host:443 -servername host
   ```

2. **Force a specific TLS version:**
   ```bash
   openssl s_client -connect host:443 -tls1_2
   openssl s_client -connect host:443 -tls1_3
   ```

3. **Test with a specific cipher:**
   ```bash
   openssl s_client -connect host:443 -cipher ECDHE-RSA-AES256-GCM-SHA384
   ```

4. **Show full certificate chain:**
   ```bash
   openssl s_client -connect host:443 -showcerts
   ```

5. **Check OCSP stapling:**
   ```bash
   openssl s_client -connect host:443 -status
   ```

6. **Test with client certificate:**
   ```bash
   openssl s_client -connect host:443 -cert client.pem -key client-key.pem
   ```

## Security Headers Related to Transport

- **HSTS** (`Strict-Transport-Security`): Forces HTTPS for future visits. Recommended: `max-age=63072000; includeSubDomains; preload`
- **Certificate Transparency**: Expect-CT header (deprecated in favour of built-in CT enforcement in browsers)
- **HPKP** (HTTP Public Key Pinning): **Deprecated** — too risky in practice. Use Certificate Transparency instead.

## Certificate Pinning

When implementing certificate pinning in applications:
- Pin the **intermediate CA** certificate, not the leaf (allows rotation)
- Always include a **backup pin** from a different CA
- Use **SPKI hash** (Subject Public Key Info) for pins:
  ```bash
  openssl x509 -in cert.pem -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64
  ```

## Useful OpenSSL Commands for TLS Debugging

```bash
# Full connection dump with timing
openssl s_client -connect host:443 -servername host -msg -debug

# STARTTLS for mail protocols
openssl s_client -connect mail.example.com:587 -starttls smtp
openssl s_client -connect mail.example.com:993 -starttls imap

# Check ALPN negotiation (HTTP/2)
openssl s_client -connect host:443 -alpn h2,http/1.1

# Verify hostname matching
openssl s_client -connect host:443 -verify_hostname host

# Capture session for resumption testing
openssl s_client -connect host:443 -sess_out session.pem
openssl s_client -connect host:443 -sess_in session.pem
```
