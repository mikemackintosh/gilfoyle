# Generate CSR

Generate a Certificate Signing Request (CSR) from a private key.

## Arguments

$ARGUMENTS should include:
- Path to the private key file
- Subject string (e.g., `/CN=example.com/O=My Org/C=US`)
- Optional: comma-separated SANs (e.g., `--sans example.com,www.example.com,192.168.1.1`)

Examples:
- `mykey.pem /CN=example.com`
- `mykey.pem /CN=example.com/O=Acme/C=US --sans example.com,www.example.com`
- `mykey.pem /CN=internal.local --sans internal.local,10.0.0.1`

## Workflow

1. Parse the key path, subject, and optional SANs from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Basic CSR (no SANs)

```bash
openssl req -new -key <keyfile> -out <output>.csr -subj "<subject>"
```

### CSR with Subject Alternative Names

Create a temporary config file:

```bash
cat > /tmp/csr-san.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = <common_name>

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 192.168.1.1
EOF
```

Then generate:

```bash
openssl req -new -key <keyfile> -out <output>.csr -config /tmp/csr-san.cnf
```

3. Verify the CSR:

```bash
openssl req -in <output>.csr -noout -text
```

4. Display a summary:
   - Subject fields
   - SANs included
   - Signature algorithm
   - Public key info (algorithm, size)

5. Clean up temporary config files.

## Security Notes

- Modern CAs require SANs; CN-only certificates are deprecated by browsers.
- Ensure the private key used is adequately strong (RSA >= 2048, EC >= P-256).
- Never share the private key when submitting a CSR to a CA — only the `.csr` file.
- Verify the CSR contents before submitting to a CA.
