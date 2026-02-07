# Git Secret Scan

Scan git commit history for leaked secrets such as API keys, private keys, passwords, and tokens by searching commit diffs.

## Arguments

$ARGUMENTS is optional:
- A repository path (default: current directory)
- `--type <type>` to filter: `aws`, `keys`, `passwords`, `tokens`, `all` (default)

Examples:
- (no args — scan current repo for all secret types)
- `/path/to/repo`
- `. --type aws`
- `/path/to/repo --type keys`
- `--type tokens`

## Workflow

1. Parse the path and type filter from `$ARGUMENTS`. Default path is `.`, default type is `all`.
2. Confirm we are inside a git repository by checking for a `.git` directory.
3. Show the user the exact commands before executing.

### Scan for AWS keys

```bash
echo "=== AWS Access Keys ==="
git -C <path> log -p --all -S 'AKIA' -- . ':!*.lock' ':!node_modules' ':!vendor' | head -200

echo "=== AWS Secret Keys (high-entropy base64 near AWS context) ==="
git -C <path> log -p --all --pickaxe-regex -S 'aws_secret_access_key\s*[:=]' -- . ':!*.lock' | head -100
```

### Scan for private keys

```bash
echo "=== RSA/EC/Generic Private Keys ==="
git -C <path> log -p --all -S 'BEGIN.*PRIVATE KEY' -- . | head -200

echo "=== SSH Private Keys ==="
git -C <path> log -p --all -S 'BEGIN OPENSSH PRIVATE KEY' -- . | head -100

echo "=== PGP Private Keys ==="
git -C <path> log -p --all -S 'BEGIN PGP PRIVATE KEY BLOCK' -- . | head -100
```

### Scan for passwords and credentials

```bash
echo "=== Password Assignments ==="
git -C <path> log -p --all --pickaxe-regex -S '(password|passwd|pwd|secret|api_key|apikey)\s*[:=]\s*['"'"'""][^'"'"'""]+['"'"'""]' -- '*.env' '*.yml' '*.yaml' '*.conf' '*.json' '*.py' '*.js' '*.ts' '*.rb' '*.go' '*.java' '*.cfg' '*.ini' '*.toml' | head -200

echo "=== Connection Strings ==="
git -C <path> log -p --all --pickaxe-regex -S '(mysql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@' -- . | head -100
```

### Scan for tokens

```bash
echo "=== GitHub Tokens ==="
git -C <path> log -p --all --pickaxe-regex -S '(ghp_|github_pat_|gho_|ghs_)[A-Za-z0-9_]+' -- . ':!*.lock' | head -100

echo "=== Slack Tokens ==="
git -C <path> log -p --all --pickaxe-regex -S 'xox[bpoas]-[0-9a-zA-Z-]+' -- . | head -100

echo "=== Stripe Keys ==="
git -C <path> log -p --all --pickaxe-regex -S '(sk_live|rk_live)_[0-9a-zA-Z]+' -- . | head -100

echo "=== GCP API Keys ==="
git -C <path> log -p --all -S 'AIza' -- . ':!*.lock' | head -100

echo "=== SendGrid / Twilio / Mailgun ==="
git -C <path> log -p --all --pickaxe-regex -S '(SG\.[A-Za-z0-9_-]+|SK[a-f0-9]{32}|key-[a-f0-9]{32})' -- . | head -100
```

### Check for sensitive files ever committed

```bash
echo "=== Sensitive Files in History ==="
git -C <path> log --all --name-only --format="" -- '*.pem' '*.key' '*.p12' '*.pfx' '*.env' '*.tfstate' '*.jks' '*.keystore' 'credentials.json' 'service-account.json' | sort -u

echo "=== Sensitive Files Added Then Deleted ==="
git -C <path> log --all --diff-filter=D --name-only --format="" -- '*.pem' '*.key' '*.p12' '*.pfx' '*.env' '*.tfstate' | sort -u
```

4. For each finding:
   - Show the commit hash, author, and date
   - Show the file path and matched line (redact the middle of any actual secret values)
   - Identify the secret type
   - Rate severity:
     - **CRITICAL** — live cloud keys (AWS, GCP, Stripe), private keys
     - **HIGH** — API tokens (GitHub, Slack, SendGrid), connection strings
     - **MEDIUM** — password assignments, generic credentials

5. Present a summary:
   - Total findings by type and severity
   - Files with the most findings
   - Whether the secrets still exist in the current working tree
   - Recommended remediation steps

6. If secrets are found, provide cleanup guidance:

```bash
# Rotate the secret FIRST — never rely on history cleaning alone

# Option 1: BFG Repo-Cleaner (faster, simpler)
java -jar bfg.jar --replace-text passwords.txt repo.git

# Option 2: git filter-repo
git filter-repo --replace-text expressions.txt

# After rewriting history, all collaborators must re-clone
```

## Security Notes

- **Redact secrets** when displaying results. Show enough context to identify the finding but not enough to exploit it.
- Secrets in git history remain accessible even after the file is deleted from the working tree.
- Cleaning git history requires a **force push**, which rewrites history for all collaborators.
- **Rotate the secret first**, then clean history. Old clones and GitHub/GitLab caches may still contain the secret.
- A finding is not always a real secret — hardcoded test values and examples will match. Review each finding in context.
- Scan results should not be committed to version control or shared in plaintext.
