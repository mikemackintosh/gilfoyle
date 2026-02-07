# Certificate Chain Verify

Verify a certificate chain of trust. Checks that a certificate is properly signed by its issuer up to a trusted root.

## Arguments

$ARGUMENTS should include:
- Path to the server/leaf certificate
- Path to the CA bundle or intermediate chain file
- Optionally a path to a trusted root CA file

Examples:
- `server.pem ca-chain.pem`
- `server.pem intermediate.pem --root root-ca.pem`
- `server.pem` (verify against system trust store)

## Workflow

1. Parse file paths from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Verify against a CA file

```bash
openssl verify -CAfile <ca-chain.pem> <server.pem>
```

### Verify with separate intermediate and root

```bash
openssl verify -CAfile <root-ca.pem> -untrusted <intermediate.pem> <server.pem>
```

### Verify against system trust store

```bash
openssl verify <server.pem>
```

### Show the chain details

```bash
# Display each cert in a bundle
openssl crl2pkcs7 -nocrl -certfile <ca-chain.pem> | openssl pkcs7 -print_certs -noout
```

Or iterate through certs in a bundle:
```bash
awk 'BEGIN {n=0} /-----BEGIN CERTIFICATE-----/{n++} {print > "cert-" n ".pem"}' <ca-chain.pem>
for f in cert-*.pem; do
  echo "=== $f ==="
  openssl x509 -in "$f" -noout -subject -issuer -dates
done
```

3. Present findings:
   - Verification result: OK or error code with explanation
   - Chain order: list each certificate (subject → issuer)
   - Flag issues: expired certs in chain, missing intermediates, self-signed roots, path length violations

## Common Verification Errors

| Error | Meaning |
|-------|---------|
| `unable to get local issuer certificate` | Missing intermediate or root CA |
| `certificate has expired` | A cert in the chain is past its Not After date |
| `self signed certificate` | Cert is self-signed and not in trust store |
| `unable to verify the first certificate` | Server sent leaf only, no intermediates |
| `path length constraint exceeded` | Too many intermediates for the CA's pathlen |
