# TLS Inspect

Inspect the TLS/SSL configuration of a remote host. Shows the certificate, protocol version, cipher suite, and certificate chain.

## Arguments

$ARGUMENTS should be a hostname or hostname:port (default port is 443).

## Workflow

1. Parse the target from `$ARGUMENTS`. If no port is specified, default to 443.
2. Show the user the exact commands that will run before executing them.
3. Run the following inspection commands:

### Connect and show certificate + chain

```bash
echo | openssl s_client -connect <host>:<port> -servername <host> 2>/dev/null
```

This reveals:
- Certificate chain (subject + issuer of each cert)
- Server certificate in PEM
- Protocol and cipher negotiated
- Session details

### Decode the server certificate

```bash
echo | openssl s_client -connect <host>:<port> -servername <host> 2>/dev/null | openssl x509 -noout -text
```

Key fields to highlight:
- **Subject / Issuer** — Who the cert is for and who signed it
- **Validity** — Not Before / Not After (flag if expired or expiring within 30 days)
- **SANs** — Subject Alternative Names
- **Signature Algorithm** — Flag weak algorithms (SHA-1, MD5)
- **Key size** — Flag if RSA < 2048 bits

### Check supported TLS versions

```bash
for v in tls1 tls1_1 tls1_2 tls1_3; do
  echo | openssl s_client -connect <host>:<port> -servername <host> -$v 2>/dev/null | grep -q "Cipher is" && echo "$v: supported" || echo "$v: not supported"
done
```

4. Summarise the findings in a clear table:
   - Protocol versions supported
   - Cipher suite negotiated
   - Certificate validity window
   - Certificate chain depth
   - Any warnings (weak cipher, expiring cert, self-signed, missing intermediate)

## Security Notes

- TLS 1.0 and 1.1 are deprecated (RFC 8996). Flag them as insecure.
- RSA key sizes below 2048 bits are considered weak.
- SHA-1 signed certificates should be flagged.
- Self-signed certificates or incomplete chains should be called out.
