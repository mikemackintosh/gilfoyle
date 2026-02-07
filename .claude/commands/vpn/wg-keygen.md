# WireGuard Key Generation

Generate a WireGuard key pair (private key + public key), with an optional pre-shared key for post-quantum resistance.

## Arguments

$ARGUMENTS is optional:
- `--psk` — Also generate a pre-shared key (PresharedKey)
- Optionally a name/label for the key files (e.g., `server`, `client1`)

Examples:
- (no args — generate a key pair with default naming)
- `--psk`
- `server`
- `client1 --psk`

## Workflow

1. Parse options from `$ARGUMENTS`. Extract the optional name label and `--psk` flag.
2. Default file naming: `<name>-private.key` and `<name>-public.key`. If no name is provided, use `wg-private.key` and `wg-public.key`.
3. Show the user the exact commands before executing.

### Generate the private key

```bash
wg genkey > <name>-private.key
```

### Derive the public key

```bash
cat <name>-private.key | wg pubkey > <name>-public.key
```

### Combined one-liner

```bash
wg genkey | tee <name>-private.key | wg pubkey > <name>-public.key
```

### Set secure file permissions

```bash
chmod 600 <name>-private.key
```

### Generate pre-shared key (if `--psk` is specified)

```bash
wg genpsk > <name>-preshared.key
chmod 600 <name>-preshared.key
```

4. Display a summary:
   - Private key file path and permissions
   - Public key file path
   - Public key value (safe to share)
   - Pre-shared key file path (if generated)

5. Show how to use the keys in a WireGuard config:

```ini
[Interface]
PrivateKey = <contents of private key file>

[Peer]
PublicKey = <contents of peer's public key file>
PresharedKey = <contents of pre-shared key file>  # if --psk was used
```

## Security Notes

- **Private keys must never be shared or transmitted.** They stay on the host that generated them.
- **Public keys are safe to share** — they are derived from the private key using Curve25519 and cannot be reversed.
- **Pre-shared keys (PSK)** add symmetric-key cryptography on top of the asymmetric Curve25519 exchange, providing defence against future quantum computing attacks.
- Always set restrictive file permissions (`600`) on private key and pre-shared key files.
- WireGuard keys are 32 bytes (256 bits), Base64-encoded. There is no way to set a custom key size.
- Consider generating keys directly in `/etc/wireguard/` to avoid leaving key material in temporary locations.
