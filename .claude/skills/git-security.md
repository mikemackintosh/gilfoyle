---
name: Git Security
description: Git security scanning, signed commit verification, .gitignore auditing, and pre-commit hook setup for secret prevention.
instructions: |
  Use this skill when the user is working with git repository security — scanning history for
  leaked secrets, verifying or configuring signed commits, auditing .gitignore for missing
  security-relevant entries, setting up pre-commit hooks for secret detection, or detecting
  sensitive or large files in a repository. Always show commands before executing them.
---

# Git Security Skill

## Related Commands
- `/git-sec-secret-scan` — Scan git history for leaked secrets
- `/git-sec-verify-commits` — Verify GPG/SSH signed commits
- `/git-sec-sign-setup` — Set up GPG or SSH commit signing
- `/git-sec-gitignore-audit` — Audit .gitignore for missing security-relevant entries

## Scanning Git History for Secrets

Secrets committed to git remain accessible in history even after the file is deleted. Use `git log -p -S` to search the full diff history for sensitive patterns.

### Key Patterns to Search

| Category | Search Pattern | What It Catches |
|----------|---------------|-----------------|
| AWS Keys | `AKIA[0-9A-Z]{16}` | AWS access key IDs |
| Private Keys | `BEGIN.*PRIVATE KEY` | RSA, EC, PGP, SSH private keys |
| GitHub Tokens | `ghp_`, `github_pat_`, `gho_` | GitHub personal access tokens |
| Generic Passwords | `password\|passwd\|secret\|api_key` | Hardcoded credentials |
| Connection Strings | `://[^:]+:[^@]+@` | Database URIs with embedded passwords |
| Slack Tokens | `xoxb-`, `xoxp-`, `xoxa-` | Slack bot and user tokens |
| Stripe Keys | `sk_live_`, `rk_live_` | Stripe secret and restricted keys |
| JWT Tokens | `eyJ[A-Za-z0-9_-]*\.eyJ` | Hardcoded JSON Web Tokens |

### Scanning Commands

```bash
# Search all commits for AWS keys
git log -p --all -S 'AKIA' -- . ':!*.lock' ':!node_modules'

# Search all commits for private keys
git log -p --all -S 'BEGIN.*PRIVATE KEY' -- .

# Search for password assignments in config files
git log -p --all --pickaxe-regex -S '(password|secret|api_key)\s*[:=]' -- '*.env' '*.yml' '*.conf' '*.json'

# Find sensitive files that were added then removed
git log --all --diff-filter=D --name-only -- '*.env' '*.pem' '*.key' '*.p12'

# Files that should never have been committed
git log --all --name-only -- '*.pem' '*.key' '*.p12' '*.pfx' '*.env' '*.tfstate' | sort -u
```

## Signed Commit Verification

Signed commits provide cryptographic proof of authorship. Git supports both GPG and SSH signing.

### Verifying Signatures

```bash
# Show signature status for recent commits
git log --show-signature -5

# Verify a specific commit
git verify-commit <commit_hash>

# Verify a range of commits
git log --show-signature <start>..<end>

# Show signature for a tag
git verify-tag <tag_name>
```

### Signature Status Meanings

| Status | Meaning |
|--------|---------|
| `Good signature` | Valid signature from a known key |
| `BAD signature` | Signature does not match — commit may have been tampered with |
| `Can't check signature: No public key` | Signing key is not in your keyring |
| `No signature` | Commit was not signed |

## GPG Commit Signing Setup

```bash
# List existing GPG keys
gpg --list-secret-keys --keyid-format=long

# Generate a new GPG key (RSA 4096)
gpg --full-generate-key

# Export the public key (for GitHub/GitLab)
gpg --armor --export <key_id>

# Configure git to sign commits
git config --global user.signingkey <key_id>
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Test with a signed commit
git commit --allow-empty -S -m "test: verify GPG signing"
git verify-commit HEAD
```

## SSH Commit Signing Setup

Git 2.34+ supports SSH keys for commit signing, which avoids the complexity of GPG.

```bash
# Configure git for SSH signing
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Set up allowed signers file for verification
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# Test with a signed commit
git commit --allow-empty -S -m "test: verify SSH signing"
git verify-commit HEAD
```

## .gitignore Audit Patterns

These entries should be present in every repository's `.gitignore`:

```gitignore
# Private keys and certificates
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore

# Environment and credentials
.env
.env.*
*.env
credentials.json
service-account.json
**/secrets.yml
**/secrets.yaml

# Cloud and infrastructure state
*.tfstate
*.tfstate.backup
.terraform/

# IDE and editor secrets
.idea/dataSources/
.vscode/settings.json

# OS files
.DS_Store
Thumbs.db
```

### Checking for Already-Tracked Files

```bash
# Check if any sensitive files are already tracked
git ls-files | grep -iE '\.(pem|key|p12|pfx|jks|env|tfstate)$'

# Check for credential files in the tree
git ls-files | grep -iE '(credentials|secrets|service.account).*\.(json|yml|yaml)$'

# Remove a tracked file without deleting it locally
git rm --cached <file>
```

## Pre-Commit Hook Setup for Secret Scanning

### Simple regex-based hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit — block commits containing secrets

PATTERNS=(
  'AKIA[0-9A-Z]{16}'
  'BEGIN.*PRIVATE KEY'
  '(sk_live|rk_live)_[0-9a-zA-Z]+'
  '(ghp_|github_pat_|gho_)[A-Za-z0-9_]+'
  'xox[bpoas]-[0-9a-zA-Z-]+'
  'AIza[0-9A-Za-z\-_]{35}'
)

STAGED=$(git diff --cached --name-only --diff-filter=ACM)
EXIT=0

for FILE in $STAGED; do
  for PATTERN in "${PATTERNS[@]}"; do
    if git diff --cached -- "$FILE" | grep -qE "$PATTERN"; then
      echo "BLOCKED: Potential secret matching '$PATTERN' found in $FILE"
      EXIT=1
    fi
  done
done

exit $EXIT
```

### Installing the hook

```bash
# Copy hook into place
cp pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Or use a symlink for version-controlled hooks
mkdir -p .githooks
cp pre-commit .githooks/pre-commit
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

### Using third-party tools

```bash
# detect-secrets (Python-based)
pip install detect-secrets
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline

# pre-commit framework
pip install pre-commit
# Add to .pre-commit-config.yaml:
# repos:
#   - repo: https://github.com/Yelp/detect-secrets
#     rev: v1.4.0
#     hooks:
#       - id: detect-secrets
#         args: ['--baseline', '.secrets.baseline']
pre-commit install
```

## Sensitive File Detection

```bash
# Find private keys in the working tree
find . -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' 2>/dev/null

# Find environment files
find . -name '.env' -o -name '.env.*' -o -name '*.env' 2>/dev/null

# Find Terraform state files
find . -name '*.tfstate' -o -name '*.tfstate.backup' 2>/dev/null

# Find files with overly permissive permissions
find . -name '*.pem' -o -name '*.key' | xargs ls -la 2>/dev/null | grep -v '^-rw-------'
```

## Large File Detection

Large files bloat git history and cannot be removed without rewriting history.

```bash
# Find large files in the current tree
find . -type f -size +10M -not -path './.git/*' -exec ls -lh {} \;

# Find large objects in git history
git rev-list --objects --all | \
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | \
  awk '/^blob/ {print $3, $4}' | \
  sort -rn | \
  head -20

# Find files larger than a threshold across all history
git rev-list --objects --all | \
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | \
  awk '/^blob/ && $3 > 1048576 {printf "%.1fMB\t%s\n", $3/1048576, $4}' | \
  sort -rn
```

## Repository Permission Concepts

### Branch Protection

| Setting | Purpose |
|---------|---------|
| Require pull request reviews | Prevent direct pushes to protected branches |
| Require signed commits | Only allow verified commits on protected branches |
| Require status checks | Enforce CI/CD pipeline passes before merge |
| Restrict force pushes | Prevent history rewriting on shared branches |
| Require linear history | Prevent merge commits, enforce rebase workflow |

### Access Control Best Practices

- **Least privilege**: Grant the minimum access level needed (read, write, maintain, admin).
- **Review collaborators regularly**: Remove inactive or departed team members promptly.
- **Use deploy keys over personal tokens**: Deploy keys are scoped to a single repository.
- **Audit access tokens**: Regularly review and rotate personal access tokens and app tokens.
- **Enable branch protection on main/production**: Prevent accidental or malicious direct pushes.
- **Require signed commits on protected branches**: Ensures cryptographic proof of authorship.
- **Use CODEOWNERS files**: Require specific reviewers for sensitive paths (e.g., `.github/workflows/`, `terraform/`, `*.key`).

### CODEOWNERS Example

```
# .github/CODEOWNERS
# Security team must review changes to CI/CD and infrastructure
.github/workflows/    @security-team
terraform/            @security-team @infrastructure-team
*.key                 @security-team
*.pem                 @security-team
.env*                 @security-team
```
