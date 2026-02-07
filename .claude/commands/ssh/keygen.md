# SSH Key Generation

Generate an SSH key pair.

## Arguments

$ARGUMENTS should include:
- Optionally an algorithm: `ed25519` (default), `rsa`, `ecdsa`
- Optionally a comment: `user@host`
- Optionally a custom path: `~/.ssh/id_ed25519_work`

Examples:
- (no args — generates Ed25519 with default settings)
- `ed25519 user@workstation`
- `rsa user@legacy-server`
- `ed25519 deploy@prod ~/.ssh/id_ed25519_prod`

## Workflow

1. Parse the algorithm (default: `ed25519`), comment, and path from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Ed25519 (recommended)

```bash
ssh-keygen -t ed25519 -C "<comment>" -f <path>
```

### RSA-4096 (wider compatibility)

```bash
ssh-keygen -t rsa -b 4096 -C "<comment>" -f <path>
```

### ECDSA P-256

```bash
ssh-keygen -t ecdsa -b 256 -C "<comment>" -f <path>
```

3. After generation, display:
   - Private key path
   - Public key path
   - Key fingerprint (SHA-256)
   - The public key contents (for copying to `authorized_keys` or GitHub)

4. Show how to copy the key to a remote host:

```bash
ssh-copy-id -i <path>.pub user@host
```

5. Remind the user to set correct permissions:

```bash
chmod 600 <private_key_path>
chmod 644 <public_key_path>
```

## Security Notes

- **Ed25519** is recommended: fast, small keys, strong security, no known weaknesses.
- **RSA-4096** should only be used for compatibility with systems that don't support Ed25519.
- Always set a strong passphrase on private keys.
- Never share or transmit private keys. Only the `.pub` file should be distributed.
- Add keys to `ssh-agent` to avoid typing passphrases repeatedly: `ssh-add <key>`.
