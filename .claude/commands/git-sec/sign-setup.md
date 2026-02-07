# Commit Signing Setup

Set up GPG or SSH commit signing for git. Walks through key generation, git configuration, and verification testing.

## Arguments

$ARGUMENTS should include:
- `--gpg` to set up GPG-based signing
- `--ssh` to set up SSH-based signing
- Optionally a key identifier (existing GPG key ID or SSH public key path)

Examples:
- `--gpg`
- `--ssh`
- `--gpg ABCDEF1234567890`
- `--ssh ~/.ssh/id_ed25519.pub`

## Workflow

1. Parse the signing method (`--gpg` or `--ssh`) and optional key identifier from `$ARGUMENTS`.
2. If neither is specified, recommend SSH signing for simplicity (requires git 2.34+) and ask the user to choose.
3. Show the user the exact commands before executing.

### Option A: GPG Signing Setup

#### Step 1 — Check prerequisites

```bash
# Verify GPG is installed
gpg --version

# Verify git version
git --version

# List existing GPG secret keys
gpg --list-secret-keys --keyid-format=long
```

#### Step 2 — Generate a GPG key (if no key ID provided)

```bash
# Generate a new GPG key — select RSA 4096, no expiry or set expiry as needed
gpg --full-generate-key
```

When prompted:
- Key type: **(1) RSA and RSA**
- Key size: **4096**
- Expiry: **0** (no expiry) or set an appropriate expiry
- Real name: Your full name
- Email: Must match your git `user.email`

#### Step 3 — Get the key ID

```bash
# List keys — the key ID is the hex string after 'rsa4096/' on the 'sec' line
gpg --list-secret-keys --keyid-format=long

# Example output:
# sec   rsa4096/ABCDEF1234567890 2024-01-01 [SC]
#       FINGERPRINT
# uid           [ultimate] Name <email@example.com>
# The key ID is: ABCDEF1234567890
```

#### Step 4 — Configure git

```bash
git config --global user.signingkey <key_id>
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# On macOS, you may need to set the GPG program
git config --global gpg.program gpg
```

#### Step 5 — Export public key for GitHub/GitLab

```bash
gpg --armor --export <key_id>
```

Copy the output (including the `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----` lines) and add it to:
- **GitHub**: Settings > SSH and GPG keys > New GPG key
- **GitLab**: Preferences > GPG Keys

#### Step 6 — Test signing

```bash
# Create a test signed commit
git commit --allow-empty -S -m "test: verify GPG commit signing"

# Verify it worked
git verify-commit HEAD
git log --show-signature -1
```

### Option B: SSH Signing Setup

SSH signing is available in git 2.34+ and avoids the complexity of GPG key management.

#### Step 1 — Check prerequisites

```bash
# Verify git version (must be 2.34+)
git --version

# Check for existing SSH keys
ls -la ~/.ssh/id_*.pub 2>/dev/null
```

#### Step 2 — Generate an SSH key (if no key path provided)

```bash
# Generate an Ed25519 key for signing
ssh-keygen -t ed25519 -C "$(git config user.email)" -f ~/.ssh/id_ed25519_signing
```

#### Step 3 — Configure git

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

#### Step 4 — Set up the allowed signers file

The allowed signers file maps email addresses to public keys, enabling `git verify-commit` to validate signatures locally.

```bash
# Create the allowed signers directory
mkdir -p ~/.config/git

# Add your own key
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519_signing.pub)" >> ~/.config/git/allowed_signers

# Tell git where to find it
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

To verify other team members' commits, add their entries:
```bash
echo "colleague@example.com ssh-ed25519 AAAA... colleague@example.com" >> ~/.config/git/allowed_signers
```

#### Step 5 — Export public key for GitHub/GitLab

```bash
cat ~/.ssh/id_ed25519_signing.pub
```

Copy the output and add it to:
- **GitHub**: Settings > SSH and GPG keys > New SSH key > Key type: **Signing Key**
- **GitLab**: Preferences > SSH Keys (enable "signing" usage)

#### Step 6 — Test signing

```bash
# Create a test signed commit
git commit --allow-empty -S -m "test: verify SSH commit signing"

# Verify it worked
git verify-commit HEAD
git log --show-signature -1
```

### Post-Setup — Verify Configuration

```bash
echo "=== Git Signing Configuration ==="
echo "gpg.format:              $(git config --global gpg.format || echo 'gpg (default)')"
echo "user.signingkey:         $(git config --global user.signingkey || echo '(not set)')"
echo "commit.gpgsign:          $(git config --global commit.gpgsign || echo 'false')"
echo "tag.gpgsign:             $(git config --global tag.gpgsign || echo 'false')"
echo "gpg.ssh.allowedSigners:  $(git config --global gpg.ssh.allowedSignersFile || echo '(not set)')"
```

## Security Notes

- **SSH signing** is recommended for most teams — it is simpler to set up and avoids GPG keyring complexity. It requires git 2.34+.
- **GPG signing** is the established standard and is required by some compliance frameworks and legacy workflows.
- The email in your signing key **must match** your `git config user.email` for GitHub/GitLab to mark commits as "Verified".
- GPG keys should use **RSA 4096** or **Ed25519** (via `--expert` mode). Do not use RSA keys shorter than 2048 bits.
- Consider setting a key expiry on GPG keys (e.g., 1-2 years) and rotating keys periodically.
- Store GPG private keys securely. Back them up with `gpg --export-secret-keys <key_id> > backup.gpg` and keep the backup offline.
- For SSH signing keys, use a strong passphrase and add the key to `ssh-agent` to avoid repeated passphrase prompts.
- Enforce signed commits at the repository level using branch protection rules to prevent unsigned commits on protected branches.
