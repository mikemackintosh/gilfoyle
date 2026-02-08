# Git Undo

Safely undo the last git operation.

## Arguments

$ARGUMENTS describes what to undo:

Examples:
- `commit` — undo the last commit (keep changes)
- `commit --hard` — undo the last commit (discard changes)
- `merge` — undo the last merge
- `rebase` — undo the last rebase
- `push` — undo the last push (revert commit on remote)
- `stage` or `add` — unstage all staged files
- `stage <file>` — unstage a specific file
- `stash` — undo the last stash pop/apply
- (no args — detect the last operation from reflog and offer to undo it)

## Workflow

1. Parse the operation from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. **Always prefer safe, non-destructive undo methods.**

### Auto-detect mode (no arguments)

```bash
echo "=== Last 10 Operations ==="
git reflog -10 --format='%h %gd %gs'
```

Identify the most recent significant operation (commit, merge, rebase, checkout, pull) and suggest the appropriate undo.

### Undo Last Commit

```bash
# Keep changes staged (soft undo)
git reset --soft HEAD~1

# Keep changes unstaged (mixed undo)
git reset HEAD~1

# Discard changes entirely (DESTRUCTIVE)
# git reset --hard HEAD~1
```

Default to `--soft` unless the user specifies `--hard`.

### Undo Last Merge

```bash
# If the merge commit hasn't been pushed
git reset --hard ORIG_HEAD

# If it has been pushed — create a revert commit instead
git revert -m 1 HEAD
```

### Undo Last Rebase

```bash
# Find the pre-rebase position in reflog
git reflog

# Reset to the pre-rebase commit
git reset --hard <pre-rebase-hash>

# Or use ORIG_HEAD if the rebase just happened
git reset --hard ORIG_HEAD
```

### Undo Last Push

```bash
# Create a revert commit and push it (safe — preserves history)
git revert HEAD
git push

# DESTRUCTIVE alternative (only if you own the branch):
# git reset --hard HEAD~1
# git push --force-with-lease
```

Default to the revert approach. Only suggest force-push if the user explicitly wants to rewrite remote history.

### Unstage Files

```bash
# Unstage everything
git restore --staged .

# Unstage a specific file
git restore --staged <file>

# Legacy syntax (pre-Git 2.23)
git reset HEAD <file>
```

### Undo Stash Pop

```bash
# If stash pop caused conflicts and you want to back out:
git checkout -- .
git stash

# If stash pop succeeded but you want it back in stash:
git stash
```

3. After performing the undo, show the result:

```bash
git status
git log --oneline -3
```

## Security Notes

- `git reset --hard` is destructive for uncommitted changes. Always confirm with the user.
- `git push --force-with-lease` is safer than `--force` but still rewrites shared history. Use `git revert` when possible.
- The reflog keeps a 90-day safety net. Even after a `--hard` reset, commits can be recovered from `git reflog`.
- Undoing a commit that removed security-sensitive code will re-introduce that code — be aware of what you're restoring.
