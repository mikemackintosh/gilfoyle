# Gitignore Audit

Audit the repository's `.gitignore` for missing security-relevant entries and check whether any sensitive files are already tracked.

## Arguments

$ARGUMENTS is optional:
- A repository path (default: current directory)

Examples:
- (no args — audit current repo)
- `/path/to/repo`

## Workflow

1. Parse the path from `$ARGUMENTS`. Default to `.`.
2. Confirm we are inside a git repository.
3. Show the user the exact commands before executing.

### Step 1 — Read the current .gitignore

```bash
echo "=== .gitignore Contents ==="
cat <path>/.gitignore 2>/dev/null || echo "(no .gitignore found)"

# Also check for global gitignore
echo ""
echo "=== Global Gitignore ==="
GLOBAL_IGNORE=$(git config --global core.excludesfile 2>/dev/null)
if [ -n "$GLOBAL_IGNORE" ]; then
  cat "$GLOBAL_IGNORE" 2>/dev/null || echo "(file not found: $GLOBAL_IGNORE)"
else
  echo "(not configured)"
fi

# Check for nested .gitignore files
echo ""
echo "=== Nested .gitignore Files ==="
find <path> -name '.gitignore' -not -path '*/.git/*' 2>/dev/null
```

### Step 2 — Check for missing security-relevant patterns

The following patterns should be present in `.gitignore` for security:

#### Private keys and certificates

| Pattern | Description |
|---------|-------------|
| `*.pem` | PEM-encoded keys and certificates |
| `*.key` | Private key files |
| `*.p12` | PKCS#12 bundles |
| `*.pfx` | PKCS#12 bundles (Windows) |
| `*.jks` | Java KeyStore files |
| `*.keystore` | Generic keystore files |

```bash
echo "=== Checking for Key/Cert Patterns ==="
for PATTERN in '*.pem' '*.key' '*.p12' '*.pfx' '*.jks' '*.keystore'; do
  if grep -qF "$PATTERN" <path>/.gitignore 2>/dev/null; then
    echo "PASS: $PATTERN is in .gitignore"
  else
    echo "MISSING: $PATTERN is NOT in .gitignore"
  fi
done
```

#### Environment and credentials

| Pattern | Description |
|---------|-------------|
| `.env` | Environment variable files |
| `.env.*` | Environment variant files (.env.local, .env.production) |
| `credentials.json` | Cloud provider credential files |
| `service-account.json` | GCP service account keys |

```bash
echo "=== Checking for Env/Credential Patterns ==="
for PATTERN in '.env' '.env.*' 'credentials.json' 'service-account.json'; do
  if grep -qF "$PATTERN" <path>/.gitignore 2>/dev/null; then
    echo "PASS: $PATTERN is in .gitignore"
  else
    echo "MISSING: $PATTERN is NOT in .gitignore"
  fi
done
```

#### Infrastructure and state

| Pattern | Description |
|---------|-------------|
| `*.tfstate` | Terraform state (contains secrets in plaintext) |
| `*.tfstate.backup` | Terraform state backups |
| `.terraform/` | Terraform working directory |

```bash
echo "=== Checking for Infrastructure Patterns ==="
for PATTERN in '*.tfstate' '*.tfstate.backup' '.terraform/'; do
  if grep -qF "$PATTERN" <path>/.gitignore 2>/dev/null; then
    echo "PASS: $PATTERN is in .gitignore"
  else
    echo "MISSING: $PATTERN is NOT in .gitignore"
  fi
done
```

#### Other security-relevant patterns

| Pattern | Description |
|---------|-------------|
| `*.log` | Log files may contain sensitive data |
| `.DS_Store` | macOS metadata (can leak directory structure) |
| `Thumbs.db` | Windows metadata |
| `*.swp` / `*.swo` | Vim swap files (may contain secrets being edited) |
| `*~` | Backup files |

```bash
echo "=== Checking for Other Patterns ==="
for PATTERN in '*.log' '.DS_Store' 'Thumbs.db' '*.swp' '*.swo'; do
  if grep -qF "$PATTERN" <path>/.gitignore 2>/dev/null; then
    echo "PASS: $PATTERN is in .gitignore"
  else
    echo "MISSING: $PATTERN is NOT in .gitignore"
  fi
done
```

### Step 3 — Check if sensitive files are already tracked

Even if a pattern is in `.gitignore`, files added before the rule was created remain tracked.

```bash
echo "=== Sensitive Files Currently Tracked ==="

echo "--- Private keys and certificates ---"
git -C <path> ls-files | grep -iE '\.(pem|key|p12|pfx|jks|keystore)$'

echo "--- Environment files ---"
git -C <path> ls-files | grep -iE '(^|/)\.env($|\.)'

echo "--- Credential files ---"
git -C <path> ls-files | grep -iE '(credentials|service.account|secrets)\.(json|yml|yaml)$'

echo "--- Terraform state ---"
git -C <path> ls-files | grep -iE '\.tfstate(\.backup)?$'

echo "--- Other sensitive files ---"
git -C <path> ls-files | grep -iE '(id_rsa|id_ecdsa|id_ed25519|\.htpasswd|\.netrc|\.npmrc|\.pypirc)$'
```

### Step 4 — Check for sensitive files in the working tree (untracked)

```bash
echo "=== Sensitive Untracked Files in Working Tree ==="
find <path> -not -path '*/.git/*' \( \
  -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
  -o -name '*.jks' -o -name '*.keystore' \
  -o -name '.env' -o -name '.env.*' \
  -o -name 'credentials.json' -o -name 'service-account.json' \
  -o -name '*.tfstate' -o -name '*.tfstate.backup' \
  -o -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \
  -o -name '.htpasswd' -o -name '.netrc' \
\) 2>/dev/null
```

4. Present results as a table:

| Category | Pattern | In .gitignore | Tracked Files | Action Needed |
|----------|---------|---------------|---------------|---------------|
| Keys | `*.pem` | YES | 0 | None |
| Keys | `*.key` | NO | 1 | Add to .gitignore, `git rm --cached` |
| Env | `.env` | YES | 1 | `git rm --cached .env` |

5. For any tracked sensitive files, provide the removal commands:

```bash
# Remove from tracking without deleting the local file
git rm --cached <file>

# Commit the removal
git commit -m "sec: stop tracking sensitive file <file>"
```

6. If patterns are missing from `.gitignore`, offer to add them:

```bash
# Append missing security patterns to .gitignore
cat >> <path>/.gitignore << 'EOF'

# Security - private keys and certificates
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore

# Security - environment and credentials
.env
.env.*
credentials.json
service-account.json

# Security - infrastructure state
*.tfstate
*.tfstate.backup
.terraform/
EOF
```

## Security Notes

- A `.gitignore` rule only prevents **future** commits. Files already tracked are not affected — use `git rm --cached` to stop tracking them.
- After removing a tracked sensitive file, it still exists in git history. Use `BFG Repo-Cleaner` or `git filter-repo` to purge it from all commits if it contained secrets.
- Terraform state files (`*.tfstate`) often contain secrets in plaintext (database passwords, API keys). They should **never** be committed — use remote state backends instead.
- The `.env` pattern may not catch all variants. Consider also adding `*.env`, `.env.local`, `.env.production`, etc.
- Review the global gitignore (`git config --global core.excludesfile`) — it applies to all repositories on the machine and can serve as a safety net.
- Consider using a `.gitignore` template from [github/gitignore](https://github.com/github/gitignore) as a starting point for your language/framework.
