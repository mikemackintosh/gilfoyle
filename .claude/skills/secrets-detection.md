---
name: Secrets Detection
description: Find leaked API keys, passwords, tokens, and private keys in files, directories, and git history.
instructions: |
  Use this skill when the user needs to scan codebases, files, or git repositories for leaked
  secrets, credentials, API keys, or private keys. Provide regex patterns, explain the risk of
  each finding, and recommend remediation steps. Never display or log actual secret values in
  full — redact middle characters.
---

# Secrets Detection Skill

## Common Secret Patterns

### Cloud Provider Keys

| Provider | Pattern | Example Format |
|----------|---------|----------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Access Key | `[0-9a-zA-Z/+=]{40}` | (40 char base64) |
| GCP API Key | `AIza[0-9A-Za-z\-_]{35}` | `AIzaSyD-EXAMPLE...` |
| GCP Service Account | `"type": "service_account"` | JSON key file |
| Azure Storage Key | `[A-Za-z0-9+/]{86}==` | (88 char base64) |
| Azure Client Secret | `[a-zA-Z0-9~._-]{34}` | In app registrations |
| DigitalOcean Token | `dop_v1_[a-f0-9]{64}` | Personal access token |

### SaaS & API Tokens

| Service | Pattern | Example Format |
|---------|---------|----------------|
| GitHub PAT (classic) | `ghp_[A-Za-z0-9_]{36}` | `ghp_xxxxxxxxxxxx` |
| GitHub PAT (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` | `github_pat_xxxxx` |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` | OAuth token |
| GitLab PAT | `glpat-[A-Za-z0-9\-_]{20}` | `glpat-xxxxxxxxxx` |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | `xoxb-xxx-xxx-xxx` |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` | Webhook URL |
| Stripe Secret Key | `sk_live_[0-9a-zA-Z]{24,}` | `sk_live_xxxxxxxxx` |
| Stripe Publishable | `pk_live_[0-9a-zA-Z]{24,}` | `pk_live_xxxxxxxxx` |
| SendGrid API Key | `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}` | `SG.xxxxx.xxxxx` |
| Twilio API Key | `SK[a-f0-9]{32}` | `SKxxxxxxxxxxxxxxx` |
| Mailgun API Key | `key-[a-f0-9]{32}` | `key-xxxxxxxxx` |

### Private Keys & Certificates

| Type | Pattern |
|------|---------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| Generic Private Key | `-----BEGIN PRIVATE KEY-----` |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |

### Credentials & Passwords

| Type | Pattern |
|------|---------|
| Generic password | `(password\|passwd\|pwd)\s*[:=]\s*['"][^'"]+['"]` |
| Connection string | `(mysql\|postgres\|mongodb\|redis)://[^:]+:[^@]+@` |
| Bearer token | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*` |
| Basic auth header | `Basic\s+[A-Za-z0-9+/]+=*` |
| JWT | `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` |

## Scanning Commands

### Scan files/directories

```bash
# AWS keys
grep -rn 'AKIA[0-9A-Z]\{16\}' /path/to/scan/

# Private keys
grep -rn '-----BEGIN.*PRIVATE KEY-----' /path/to/scan/

# Generic password assignments
grep -rnE '(password|passwd|pwd|secret|token|api_key)\s*[:=]\s*['"'"'""][^'"'"'""]+['"'"'""]' /path/to/scan/

# Connection strings
grep -rnE '(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@' /path/to/scan/

# High-entropy strings (possible secrets)
grep -rnE '[A-Za-z0-9+/]{40,}={0,2}' /path/to/scan/ --include='*.env' --include='*.yml' --include='*.yaml' --include='*.json' --include='*.conf'
```

### Scan git history

```bash
# Search all commits for patterns
git log -p --all -S 'AKIA' -- . ':!*.lock'
git log -p --all -S 'BEGIN.*PRIVATE KEY' -- .
git log -p --all -S 'password' -- '*.env' '*.yml' '*.conf'

# Search commit messages for sensitive terms
git log --all --grep='password\|secret\|key\|token' --oneline

# Find files that were deleted but contained secrets
git log --all --diff-filter=D --name-only -- '*.pem' '*.key' '*.env'
```

### Files to always check

```bash
# Environment files
find . -name '.env' -o -name '.env.*' -o -name '*.env' 2>/dev/null

# Config files with possible credentials
find . -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' -o -name '*.toml' 2>/dev/null

# Key files
find . -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' 2>/dev/null

# Terraform state (often contains secrets)
find . -name '*.tfstate' -o -name '*.tfstate.backup' 2>/dev/null
```

## Entropy-Based Detection

High-entropy strings are likely random (keys, tokens, passwords).

```bash
python3 -c "
import math, re, sys

def entropy(s):
    if not s: return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

threshold = 4.5  # bits per character
for line_num, line in enumerate(sys.stdin, 1):
    for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', line):
        e = entropy(token)
        if e > threshold:
            print(f'Line {line_num}: entropy={e:.2f} token={token[:20]}...{token[-4:]}')
" < /path/to/file
```

## Remediation

When a secret is found:

1. **Rotate immediately** — generate a new key/password and replace the old one
2. **Revoke the old secret** — deactivate it in the provider's console
3. **Remove from history** — use `git filter-repo` or `BFG Repo-Cleaner` (force-push required)
4. **Add to .gitignore** — prevent future commits of the file type
5. **Audit access logs** — check if the secret was used by an unauthorised party

```bash
# BFG Repo-Cleaner (remove a file from all history)
java -jar bfg.jar --delete-files '*.env' repo.git

# git filter-repo (remove a specific string)
git filter-repo --replace-text expressions.txt
```

## .gitignore Essentials

```gitignore
# Secrets and credentials
.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore
credentials.json
service-account.json
*.tfstate
*.tfstate.backup
```
