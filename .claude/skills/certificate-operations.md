---
name: Certificate Operations
description: X.509 certificate lifecycle — creation, inspection, verification, CA operations, revocation, and chain of trust management.
instructions: |
  Use this skill when the user is working with X.509 certificates: creating, inspecting,
  verifying chains, managing CAs, or troubleshooting certificate issues. Provide commands,
  explain certificate fields, and highlight security implications.
---

# Certificate Operations Skill

## Related Commands
- `/cert-info` — Decode and inspect certificate files
- `/cert-chain-verify` — Verify certificate chain of trust
- `/gen-csr` — Generate Certificate Signing Requests
- `/gen-selfsigned` — Generate self-signed certificates
- `/pkcs12` — PKCS#12 bundle operations

## X.509 Certificate Structure

A v3 X.509 certificate contains:

```
Certificate
├── Version (v3)
├── Serial Number (unique per CA)
├── Signature Algorithm (e.g., sha256WithRSAEncryption)
├── Issuer (CA's Distinguished Name)
├── Validity
│   ├── Not Before
│   └── Not After
├── Subject (certificate holder's DN)
├── Subject Public Key Info
│   ├── Algorithm (RSA, EC, Ed25519)
│   └── Public Key
├── Extensions (v3)
│   ├── Basic Constraints (CA:TRUE/FALSE, pathlen)
│   ├── Key Usage (digitalSignature, keyEncipherment, etc.)
│   ├── Extended Key Usage (serverAuth, clientAuth, etc.)
│   ├── Subject Alternative Name (DNS names, IPs, emails)
│   ├── Authority Key Identifier
│   ├── Subject Key Identifier
│   ├── CRL Distribution Points
│   ├── Authority Information Access (OCSP, CA Issuers)
│   └── Certificate Policies
└── Signature (CA's signature over the above)
```

## Certificate Lifecycle

### 1. Generate a Key Pair
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.pem
chmod 600 key.pem
```

### 2. Create a CSR
```bash
openssl req -new -key key.pem -out request.csr \
  -subj "/CN=example.com/O=My Org/C=US"
```

### 3. Submit to CA / Self-Sign
```bash
# Self-sign (testing only)
openssl req -x509 -key key.pem -in request.csr -out cert.pem -days 365

# Sign with your own CA
openssl x509 -req -in request.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -days 365 -extfile extensions.cnf
```

### 4. Deploy
- Install cert + chain on server
- Verify chain: `openssl verify -CAfile chain.pem cert.pem`

### 5. Monitor & Renew
```bash
# Check expiry
openssl x509 -in cert.pem -noout -enddate

# Days until expiry
openssl x509 -in cert.pem -noout -enddate | \
  awk -F= '{print $2}' | \
  xargs -I{} date -d {} +%s | \
  xargs -I{} echo $(( ({} - $(date +%s)) / 86400 )) days
```

### 6. Revoke (when needed)
```bash
openssl ca -revoke cert.pem -config ca.cnf
openssl ca -gencrl -out crl.pem -config ca.cnf
```

## Chain of Trust

```
Root CA (self-signed, in trust stores)
  └── Intermediate CA (signed by Root)
        └── Leaf Certificate (signed by Intermediate)
```

**Verification rules:**
- Each certificate's issuer must match its parent's subject
- Each signature must verify with the parent's public key
- The root must be in the system trust store
- No certificate may be expired
- Path length constraints must be respected

### Building the Correct Chain

Servers should send: **leaf + intermediates** (NOT root).

```bash
cat leaf.pem intermediate.pem > fullchain.pem
```

### Verifying Chain Order

```bash
# Show chain subjects and issuers
for cert in leaf.pem intermediate.pem root.pem; do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject -issuer
done
```

## Subject Alternative Names (SANs)

Modern certificates MUST include SANs. Browsers no longer trust CN-only certs.

### SAN Types
- `DNS:example.com` — Domain name
- `DNS:*.example.com` — Wildcard (one level only)
- `IP:192.168.1.1` — IP address
- `email:admin@example.com` — Email (S/MIME)
- `URI:https://example.com` — URI

### Wildcard Rules
- `*.example.com` matches `www.example.com` but NOT `example.com`
- `*.example.com` does NOT match `sub.www.example.com`
- Cannot wildcard TLDs: `*.com` is not valid
- Cannot wildcard in the middle: `www.*.com` is not valid

## Revocation

### CRL (Certificate Revocation List)
```bash
# Download and inspect CRL
curl -o crl.der <CRL_URL>
openssl crl -in crl.der -inform DER -text -noout

# Check if a cert is on a CRL
openssl verify -crl_check -CAfile chain.pem -CRLfile crl.pem cert.pem
```

### OCSP (Online Certificate Status Protocol)
```bash
# Get OCSP responder URL from cert
openssl x509 -in cert.pem -noout -ocsp_uri

# Query OCSP
openssl ocsp -issuer intermediate.pem -cert cert.pem \
  -url <OCSP_URL> -resp_text
```

## Creating a Private CA

### 1. Generate CA key and certificate
```bash
# Generate CA key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ca-key.pem
chmod 600 ca-key.pem

# Create CA certificate
openssl req -x509 -new -key ca-key.pem -out ca-cert.pem -days 3650 \
  -subj "/CN=My Private CA/O=My Org" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### 2. Sign a server certificate
```bash
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 \
  -extfile <(cat <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:server.example.com
EOF
)
```

### 3. Distribute CA certificate
- Add to system trust stores on clients
- macOS: `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca-cert.pem`
- Linux: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`

## Common Certificate Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Expired cert | `certificate has expired` | Renew certificate |
| Missing intermediate | `unable to get local issuer certificate` | Include intermediate in chain |
| Hostname mismatch | `hostname mismatch` | Check SANs include the correct hostname |
| Self-signed | `self signed certificate` | Add to trust store or get CA-signed cert |
| Wrong chain order | `unable to verify the first certificate` | Reorder: leaf → intermediate(s) |
| Key mismatch | TLS handshake failure | Verify key matches cert (compare modulus hashes) |
| Weak algorithm | Browser warnings | Re-issue with SHA-256+ signature |
