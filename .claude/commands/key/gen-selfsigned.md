# Generate Self-Signed Certificate

Generate a self-signed X.509 certificate, optionally with SANs.

## Arguments

$ARGUMENTS should include:
- Path to a private key file (or `--new-key <algorithm>` to generate one)
- Subject string (e.g., `/CN=localhost`)
- Optional: `--days <N>` for validity period (default: 365)
- Optional: `--sans <names>` comma-separated SANs

Examples:
- `mykey.pem /CN=localhost`
- `mykey.pem /CN=dev.local --days 730 --sans dev.local,*.dev.local`
- `--new-key ec:P-256 /CN=test.local --sans test.local`

## Workflow

1. Parse arguments from `$ARGUMENTS`.
2. If `--new-key` is specified, generate the key first (see /gen-keypair).
3. Show the user the exact commands before executing.

### Basic self-signed certificate

```bash
openssl req -x509 -new -key <keyfile> -out <output>.pem -days <days> -subj "<subject>"
```

### Self-signed with SANs

Create a temporary config:

```bash
cat > /tmp/selfsigned-san.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = <common_name>

[v3_ca]
subjectAltName = @alt_names
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = example.com
DNS.2 = *.example.com
IP.1 = 127.0.0.1
EOF
```

Then generate:

```bash
openssl req -x509 -new -key <keyfile> -out <output>.pem -days <days> -config /tmp/selfsigned-san.cnf
```

4. Verify the certificate:

```bash
openssl x509 -in <output>.pem -noout -text
```

5. Display a summary:
   - Subject and Issuer (same for self-signed)
   - Validity period
   - SANs
   - Key type and size
   - Fingerprint (SHA-256)

6. Clean up temporary config files.

## Security Notes

- Self-signed certificates trigger browser warnings and should only be used for development/testing.
- For internal services, consider creating a private CA instead.
- Set a reasonable validity period — extremely long-lived certs (10+ years) are a risk.
- Include `basicConstraints = CA:FALSE` to prevent misuse as a CA certificate.
- Always include SANs; browsers no longer trust CN-only certificates.
