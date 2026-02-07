# Verify Signed Commits

Verify GPG or SSH signed commits in a git repository. Shows the signing status, key identity, and trust level for each commit.

## Arguments

$ARGUMENTS is optional:
- A commit range (e.g., `HEAD~10..HEAD`, `main..feature-branch`, a specific commit hash)
- Default: show the last 10 commits

Examples:
- (no args — verify the last 10 commits)
- `HEAD~20..HEAD`
- `main..HEAD`
- `abc1234`
- `v1.0.0..v2.0.0`

## Workflow

1. Parse the commit range from `$ARGUMENTS`. Default to `HEAD~10..HEAD` if none specified.
2. Confirm we are inside a git repository.
3. Show the user the exact commands before executing.

### Show signature status for commits in range

```bash
git log --show-signature --format='%H %G? %GS %GK %an <%ae> %s' <range>
```

Format key:
- `%G?` — Signature status: `G` (good), `B` (bad), `U` (untrusted good), `X` (expired good), `Y` (expired key good), `R` (revoked key), `E` (cannot check), `N` (no signature)
- `%GS` — Signer name
- `%GK` — Signing key ID

### Verify individual commits

```bash
# Verify each commit in the range
for COMMIT in $(git rev-list <range>); do
  echo "--- Commit: $COMMIT ---"
  git verify-commit "$COMMIT" 2>&1
  echo ""
done
```

### Check for unsigned commits

```bash
echo "=== Unsigned Commits ==="
git log --format='%H %G? %an <%ae> %s' <range> | grep ' N '
```

### Verify tags in range

```bash
echo "=== Tags in Range ==="
for TAG in $(git tag --contains $(git rev-list --reverse <range> | head -1) 2>/dev/null); do
  echo "--- Tag: $TAG ---"
  git verify-tag "$TAG" 2>&1
  echo ""
done
```

### Check signing configuration

```bash
echo "=== Current Signing Config ==="
echo "gpg.format:        $(git config gpg.format || echo 'gpg (default)')"
echo "user.signingkey:   $(git config user.signingkey || echo '(not set)')"
echo "commit.gpgsign:    $(git config commit.gpgsign || echo 'false')"
echo "tag.gpgsign:       $(git config tag.gpgsign || echo 'false')"
```

4. Present results as a table:

| Commit | Author | Status | Signer | Key ID | Subject |
|--------|--------|--------|--------|--------|---------|
| `abc1234` | Alice | GOOD | Alice <alice@example.com> | `ABCD1234` | feat: add auth |
| `def5678` | Bob | NO SIG | — | — | fix: typo |

5. Provide a summary:
   - Total commits checked
   - Signed (good) count
   - Unsigned count
   - Bad/expired/revoked signature count
   - Whether commit.gpgsign is enabled

### Signature status reference

| Code | Status | Meaning |
|------|--------|---------|
| `G` | **Good** | Valid signature from a trusted key |
| `B` | **Bad** | Signature verification failed — possible tampering |
| `U` | **Untrusted** | Valid signature but key is not in the trust database |
| `X` | **Expired Sig** | Good signature but the signature itself has expired |
| `Y` | **Expired Key** | Good signature but the signing key has expired |
| `R` | **Revoked** | Good signature but the signing key has been revoked |
| `E` | **Error** | Cannot verify (missing public key or GPG error) |
| `N` | **None** | Commit was not signed |

## Security Notes

- Unsigned commits do not prove authorship — the `author` and `committer` fields can be set to any value with `git config`.
- A `Bad` signature (`B`) is a serious finding. It means the commit content does not match its signature and may have been tampered with.
- `Untrusted` (`U`) signatures are cryptographically valid but the signing key is not in your keyring — import and verify the signer's public key to resolve.
- Enabling `commit.gpgsign = true` globally ensures all future commits are signed, but does not retroactively sign existing history.
- For teams enforcing signed commits, configure branch protection rules on GitHub/GitLab to require signature verification on protected branches.
- SSH signing (git 2.34+) is simpler than GPG for many teams. Use `/git-sec-sign-setup` to configure it.
