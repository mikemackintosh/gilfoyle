# Secret Scan

Scan files and directories for leaked secrets, API keys, passwords, and private keys.

## Arguments

$ARGUMENTS should include:
- A file or directory path to scan
- Optionally `--type <type>` to scan for a specific secret type: `aws`, `gcp`, `github`, `slack`, `stripe`, `keys`, `passwords`, `all` (default)

Examples:
- `.`
- `/path/to/project`
- `. --type aws`
- `./src --type keys`

## Workflow

1. Parse the path and type filter from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Scan for all secret types (default)

```bash
echo "=== AWS Keys ==="
grep -rnE 'AKIA[0-9A-Z]{16}' <path> --include='*.{py,js,ts,go,rb,java,yml,yaml,json,env,conf,cfg,toml,tf,sh}' 2>/dev/null

echo "=== GCP Keys ==="
grep -rnE 'AIza[0-9A-Za-z\-_]{35}' <path> 2>/dev/null

echo "=== Private Keys ==="
grep -rn 'BEGIN.*PRIVATE KEY' <path> 2>/dev/null

echo "=== GitHub Tokens ==="
grep -rnE '(ghp_|github_pat_|gho_|ghs_)[A-Za-z0-9_]+' <path> 2>/dev/null

echo "=== Slack Tokens ==="
grep -rnE 'xox[bpoas]-[0-9a-zA-Z-]+' <path> 2>/dev/null

echo "=== Stripe Keys ==="
grep -rnE '(sk_live|pk_live)_[0-9a-zA-Z]+' <path> 2>/dev/null

echo "=== Generic Passwords ==="
grep -rnEi '(password|passwd|pwd|secret|api_key|apikey|access_token)\s*[:=]\s*['"'"'""][^'"'"'""]{8,}['"'"'""]' <path> 2>/dev/null

echo "=== Connection Strings ==="
grep -rnE '(mysql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@' <path> 2>/dev/null

echo "=== JWT Tokens ==="
grep -rnE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' <path> 2>/dev/null
```

3. For each finding:
   - Show the file, line number, and the matched pattern (redact the middle of any actual secret values)
   - Identify the secret type
   - Rate severity (CRITICAL for live keys, HIGH for private keys, MEDIUM for potential passwords)

4. Present a summary:
   - Total findings by type
   - Files with the most findings
   - Recommended next steps (rotate, revoke, remove from history)

## Security Notes

- **Redact secrets** when displaying results. Show enough context to identify the finding but not enough to exploit it.
- A finding is not always a real secret — hardcoded test/example values will match. Review each finding in context.
- Scan results should not be committed to version control or shared in plaintext.
- After fixing, check git history too — the secret may still exist in previous commits.
