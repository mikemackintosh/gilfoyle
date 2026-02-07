# CA Setup

Set up a certificate authority (root or intermediate) with proper directory structure, key generation, and certificate creation.

## Arguments

$ARGUMENTS should include:
- CA type: `--root` or `--intermediate`
- Subject string (e.g., `/CN=My Root CA/O=My Org/C=US`)
- For intermediate: path to root CA directory or root CA cert + key
- Optional: `--dir <path>` for CA directory location (default: `./ca`)
- Optional: `--algorithm <rsa|ec>` (default: RSA 4096 for root, EC P-384 for intermediate)
- Optional: `--days <N>` for validity period (default: 7300 for root, 3650 for intermediate)

Examples:
- `--root "/CN=My Root CA/O=My Org/C=US"`
- `--root "/CN=Test Root CA/O=Test/C=US" --dir ./test-ca --algorithm ec`
- `--intermediate "/CN=My Issuing CA/O=My Org/C=US" --root-cert ./ca/certs/ca-cert.pem --root-key ./ca/private/ca-key.pem`
- `--intermediate "/CN=Signing CA/O=My Org/C=US" --root-dir ./root-ca --days 1825`

## Workflow

1. Parse the CA type, subject, and optional parameters from `$ARGUMENTS`.
2. Show the user the exact commands that will run before executing them.

### Create directory structure

```bash
mkdir -p <ca-dir>/{certs,crl,csr,newcerts,private}
chmod 700 <ca-dir>/private
touch <ca-dir>/index.txt
echo '01' > <ca-dir>/serial
echo '01' > <ca-dir>/crl/crlnumber
```

### Generate the OpenSSL CA configuration

```bash
cat > <ca-dir>/openssl.cnf << 'EOF'
[ca]
default_ca = CA_default

[CA_default]
dir               = <ca-dir>
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

[req]
default_bits       = 4096
default_md         = sha256
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[req_distinguished_name]

[v3_ca]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[v3_intermediate_ca]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer

[server_cert]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer

[client_cert]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
EOF
```

### Generate the CA private key

For RSA:
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out <ca-dir>/private/ca-key.pem
chmod 600 <ca-dir>/private/ca-key.pem
```

For EC:
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out <ca-dir>/private/ca-key.pem
chmod 600 <ca-dir>/private/ca-key.pem
```

### Create the CA certificate

#### Root CA (self-signed)

```bash
openssl req -x509 -new -key <ca-dir>/private/ca-key.pem \
  -out <ca-dir>/certs/ca-cert.pem \
  -days <days> \
  -subj "<subject>" \
  -config <ca-dir>/openssl.cnf \
  -extensions v3_ca
```

#### Intermediate CA (signed by root)

First, generate a CSR:
```bash
openssl req -new -key <ca-dir>/private/ca-key.pem \
  -out <ca-dir>/csr/ca-csr.pem \
  -subj "<subject>" \
  -config <ca-dir>/openssl.cnf
```

Then sign with the root CA:
```bash
openssl ca -config <root-ca-dir>/openssl.cnf \
  -extensions v3_intermediate_ca \
  -days <days> \
  -notext \
  -in <ca-dir>/csr/ca-csr.pem \
  -out <ca-dir>/certs/ca-cert.pem
```

Build the chain file:
```bash
cat <ca-dir>/certs/ca-cert.pem <root-ca-dir>/certs/ca-cert.pem > <ca-dir>/certs/ca-chain.pem
```

3. Generate an initial (empty) CRL:

```bash
openssl ca -gencrl -config <ca-dir>/openssl.cnf -out <ca-dir>/crl/ca-crl.pem
```

4. Verify the setup:

```bash
# For root CA
openssl x509 -in <ca-dir>/certs/ca-cert.pem -noout -subject -issuer -dates

# For intermediate CA
openssl verify -CAfile <root-ca-dir>/certs/ca-cert.pem <ca-dir>/certs/ca-cert.pem
```

5. Display a summary:
   - CA type (root or intermediate)
   - Subject and Issuer
   - Validity period
   - Key algorithm and size
   - Directory structure created
   - Configuration file path
   - Next steps (how to issue certificates from this CA)

## Security Notes

- Root CA private keys should be kept offline in a secure location (air-gapped system or HSM).
- Use a strong passphrase to encrypt the CA key for production use: add `-aes256` to the `genpkey` command.
- Set `pathlen:0` on intermediate CAs to prevent further sub-CA creation unless explicitly needed.
- The default `policy_match` requires country and organisation to match the CA. Use `policy_anything` for testing or when signing certificates from different organisations.
- Keep the `index.txt` database and `serial` file backed up; they are critical for CRL generation and certificate tracking.
- Consider using RSA 4096 or EC P-384 for CA keys to provide a higher security margin than leaf certificates.
- Never set `copy_extensions = copy` in production without careful review; it allows CSR requestors to inject arbitrary extensions.
