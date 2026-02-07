# Git History Secret Scan

Scan git commit history for secrets that were previously committed (even if later deleted).

## Arguments

$ARGUMENTS is optional:
- A repository path (default: current directory)
- `--type <type>` to filter: `aws`, `keys`, `passwords`, `all` (default)

Examples:
- (no args — scan current repo)
- `/path/to/repo`
- `. --type aws`

## Workflow

1. Parse the path and type from `$ARGUMENTS`.
2. Confirm we are inside a git repository.
3. Show the user the exact commands before executing.

### Scan all history for common secrets

```bash
# AWS keys in any commit
git log -p --all -S 'AKIA' -- . ':!*.lock' ':!node_modules' | head -100

# Private keys
git log -p --all -S 'BEGIN.*PRIVATE KEY' -- . | head -100

# Password assignments
git log -p --all --pickaxe-regex -S '(password|secret|api_key)\s*[:=]' -- '*.env' '*.yml' '*.conf' '*.json' '*.py' '*.js' | head -100

# .env files that were added then removed
git log --all --diff-filter=D --name-only -- '*.env' '*.pem' '*.key'

# Files that should never have been committed
git log --all --name-only -- '*.pem' '*.key' '*.p12' '*.pfx' '*.env' '*.tfstate' | sort -u
```

### Check specific commits

```bash
# Show what was added in a specific commit
git show <commit_hash> -- '*.env' '*.key' '*.pem'
```

3. Present findings:
   - Commit hash, author, date for each finding
   - File path and the matched secret (redacted)
   - Whether the file still exists in the current tree
   - Remediation steps

4. If secrets are found in history, provide cleanup guidance:
   ```bash
   # Option 1: BFG Repo-Cleaner (faster, simpler)
   java -jar bfg.jar --replace-text passwords.txt repo.git

   # Option 2: git filter-repo
   git filter-repo --replace-text expressions.txt
   ```

## Security Notes

- Secrets in git history remain accessible even after the file is deleted — `git log -p` reveals everything.
- Cleaning git history requires a **force push**, which rewrites history for all collaborators.
- After cleaning history, all collaborators must re-clone. Old clones still contain the secret.
- **Rotate the secret first**, then clean history. Never rely on history cleaning alone.
- GitHub and GitLab may cache old commits — contact support to purge their caches.
