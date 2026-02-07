---
name: PKI Operations
description: Certificate authority setup, CRL management, OCSP, trust store operations, and PKI lifecycle management.
instructions: |
  Use this skill when the user is working with public key infrastructure: setting up certificate
  authorities, managing certificate revocation lists, configuring trust stores, checking OCSP
  status, or managing certificate lifecycles. Provide commands, explain PKI concepts, and
  highlight security implications. Always show commands before executing them.
---

# PKI Operations Skill

## Related Commands
- `/pki:ca-setup` — Set up a root or intermediate certificate authority
- `/pki:crl` — Manage Certificate Revocation Lists
- `/pki:trust-store` — Manage system trust stores
- `/pki:ocsp` — Check certificate revocation status via OCSP

## CA Hierarchy Concepts

A PKI is built on a chain of trust rooted in a Certificate Authority (CA):

```
Root CA (self-signed, offline, in trust stores)
  └── Intermediate CA (signed by Root, used for day-to-day issuance)
        └── Issuing CA (optional, signed by Intermediate)
              └── Leaf Certificate (end-entity: server, client, email)
```

### Root CA
- Self-signed certificate at the top of the chain
- Must be distributed to all clients' trust stores
- Should be kept **offline** and only brought online to sign intermediate CA certificates
- Typical validity: 10-20 years
- Key ceremony should be documented and audited

### Intermediate CA
- Signed by the root CA (or another intermediate)
- Used for daily certificate issuance operations
- Limits blast radius if compromised (revoke the intermediate, root remains safe)
- Typical validity: 5-10 years
- `pathlen` constraint controls how many additional CAs can exist below it

## CA Setup with OpenSSL

### Directory Structure

A properly configured CA requires a specific directory layout:

```
ca/
├── certs/          # Issued certificates
├── crl/            # Certificate Revocation Lists
├── csr/            # Certificate Signing Requests
├── newcerts/       # New certificates (copies with serial number names)
├── private/        # CA private key (chmod 700)
├── index.txt       # Certificate database (initially empty)
├── serial          # Serial number counter (initialise with "01")
└── openssl.cnf     # CA configuration file
```

### Generate CA Key

```bash
# Root CA key (RSA 4096)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ca/private/ca-key.pem
chmod 600 ca/private/ca-key.pem

# Or with EC (P-384 recommended for CAs)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out ca/private/ca-key.pem
chmod 600 ca/private/ca-key.pem
```

### Self-Sign the Root CA Certificate

```bash
openssl req -x509 -new -key ca/private/ca-key.pem -out ca/certs/ca-cert.pem \
  -days 7300 -subj "/CN=My Root CA/O=My Organisation/C=US" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
```

### OpenSSL CA Configuration

A minimal `openssl.cnf` for CA operations:

```ini
[ca]
default_ca = CA_default

[CA_default]
dir               = ./ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/ca-key.pem
certificate       = $dir/certs/ca-cert.pem
crl               = $dir/crl/ca-crl.pem
crlnumber         = $dir/crl/crlnumber
default_md        = sha256
default_days      = 365
default_crl_days  = 30
policy            = policy_match
copy_extensions   = none
unique_subject    = no

[policy_match]
countryName             = match
stateOrProvinceName     = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[policy_anything]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
```

## CRL Generation and Management

### Generate a CRL

```bash
# Generate initial CRL
openssl ca -gencrl -config ca/openssl.cnf -out ca/crl/ca-crl.pem

# Convert CRL to DER for distribution
openssl crl -in ca/crl/ca-crl.pem -outform DER -out ca/crl/ca-crl.der
```

### Revoke a Certificate

```bash
# Revoke with reason
openssl ca -revoke ca/newcerts/<serial>.pem -config ca/openssl.cnf -crl_reason keyCompromise

# Regenerate CRL after revocation
openssl ca -gencrl -config ca/openssl.cnf -out ca/crl/ca-crl.pem
```

### Inspect a CRL

```bash
openssl crl -in ca/crl/ca-crl.pem -text -noout
```

### Revocation Reasons (RFC 5280)
- `unspecified`
- `keyCompromise`
- `CACompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold` (temporary)

## OCSP Responder Basics

OCSP provides real-time certificate status checks without downloading full CRLs.

### OCSP Response Statuses
- **good** — Certificate is not revoked
- **revoked** — Certificate has been revoked
- **unknown** — Responder does not know about the certificate

### Run a Local OCSP Responder (Testing)

```bash
openssl ocsp -index ca/index.txt -port 8888 \
  -rsigner ca/certs/ca-cert.pem -rkey ca/private/ca-key.pem \
  -CA ca/certs/ca-cert.pem -text
```

### Query an OCSP Responder

```bash
openssl ocsp -issuer ca/certs/ca-cert.pem -cert leaf.pem \
  -url http://localhost:8888 -resp_text
```

### OCSP Stapling

Servers can staple OCSP responses to TLS handshakes, reducing latency and improving privacy:

```bash
# Check if a server supports OCSP stapling
echo | openssl s_client -connect host:443 -status 2>/dev/null | grep -A 5 "OCSP Response"
```

## Certificate Lifecycle

### 1. Issuance
- Generate key pair on the end entity
- Create CSR with appropriate subject and SANs
- Submit CSR to CA for signing
- CA validates identity and signs the certificate
- Certificate is delivered to the requestor

### 2. Renewal
- Generate a new CSR (ideally with a new key pair)
- Submit to CA before the existing certificate expires
- Plan for overlap period to avoid outages
- Automate where possible (ACME/Let's Encrypt)

### 3. Revocation
- Required when: key compromise, change of affiliation, certificate superseded, CA compromise
- Publish revocation via CRL and/or OCSP
- Notify affected parties
- Issue replacement certificate with a new key

## Trust Store Management by Platform

### macOS (Keychain)

```bash
# Add a trusted root certificate
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca-cert.pem

# Remove a trusted certificate
sudo security remove-trusted-cert -d ca-cert.pem

# List certificates in the System keychain
security find-certificate -a /Library/Keychains/System.keychain

# Verify a certificate against the system trust store
security verify-cert -c leaf.pem
```

### Linux (update-ca-certificates)

```bash
# Add a trusted CA certificate
sudo cp ca-cert.pem /usr/local/share/ca-certificates/my-ca.crt
sudo update-ca-certificates

# Remove a trusted CA certificate
sudo rm /usr/local/share/ca-certificates/my-ca.crt
sudo update-ca-certificates --fresh

# List trusted CAs
ls /etc/ssl/certs/

# Verify against system store
openssl verify -CApath /etc/ssl/certs/ cert.pem
```

### Java (keytool)

```bash
# Import a CA certificate into the Java trust store
keytool -importcert -alias my-ca -file ca-cert.pem \
  -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit

# Remove a CA certificate
keytool -delete -alias my-ca \
  -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit

# List trusted certificates
keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit

# List with details
keytool -list -v -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit
```

## Certificate Templates / Profiles

### Server Certificate Profile

```ini
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names
authorityInfoAccess    = OCSP;URI:http://ocsp.example.com, caIssuers;URI:http://ca.example.com/ca.pem
crlDistributionPoints  = URI:http://ca.example.com/crl.pem
```

### Client Certificate Profile

```ini
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectAltName         = email:user@example.com
```

### Intermediate CA Profile

```ini
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer
```

### Code Signing Profile

```ini
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = codeSigning
```

## Cross-Signing Concepts

Cross-signing allows a CA certificate to be trusted through multiple paths:

```
Old Root CA ──signs──> Cross-Signed Intermediate
                            │
New Root CA ──signs──> Same Intermediate (new signature)
```

- **Purpose**: Allows new CAs to be trusted by clients that only have the old root in their trust store
- **Example**: Let's Encrypt's ISRG Root X1 was cross-signed by IdenTrust DST Root CA X3
- Cross-signed certificates have the same subject and public key but different issuers
- Clients choose the chain path that leads to a root they trust

### Verify Cross-Signed Chain

```bash
# Verify using the old root
openssl verify -CAfile old-root.pem -untrusted cross-signed-intermediate.pem leaf.pem

# Verify using the new root
openssl verify -CAfile new-root.pem -untrusted intermediate.pem leaf.pem
```

## Certificate Transparency (CT)

Certificate Transparency is a framework for publicly logging all issued certificates:

- All publicly trusted CAs must submit certificates to CT logs
- Browsers require Signed Certificate Timestamps (SCTs) from multiple logs
- SCTs can be embedded in the certificate, delivered via TLS extension, or OCSP stapling

### Submit a Certificate to a CT Log

```bash
# View SCTs embedded in a certificate
openssl x509 -in cert.pem -noout -text | grep -A 10 "CT Precertificate"

# Check CT status of a live host
echo | openssl s_client -connect host:443 -ct 2>/dev/null | grep -A 5 "SCT"
```

### CT Monitoring

- Monitor CT logs for unexpected certificates for your domains
- Tools: crt.sh, certspotter, Facebook CT monitor
- API: `https://crt.sh/?q=%.example.com&output=json`

## ACME Protocol Basics (Let's Encrypt)

ACME (Automatic Certificate Management Environment) automates certificate issuance:

### How ACME Works
1. **Account creation** — Client registers with the CA
2. **Order** — Client requests a certificate for specific identifiers
3. **Authorization** — Client proves control of the identifier via challenges
4. **Challenge types**:
   - `http-01` — Place a file at `/.well-known/acme-challenge/`
   - `dns-01` — Create a `_acme-challenge` TXT record (supports wildcards)
   - `tls-alpn-01` — Present a self-signed cert with ACME ALPN extension
5. **Finalization** — Client submits CSR, CA issues certificate
6. **Renewal** — Repeat before expiry (certs are 90 days)

### Common ACME Clients

```bash
# Certbot (most common)
sudo certbot certonly --standalone -d example.com

# Certbot with DNS challenge (for wildcards)
sudo certbot certonly --manual --preferred-challenges dns -d "*.example.com"

# acme.sh (lightweight alternative)
acme.sh --issue -d example.com --webroot /var/www/html
```

### ACME Best Practices
- Automate renewal with cron or systemd timers
- Use DNS challenges for internal/non-web services
- Test with the staging endpoint first (`--staging`)
- Monitor certificate expiry independently of the renewal process
