# Git Cleanup

Clean up local and remote branches, stale refs, and repository bloat.

## Arguments

$ARGUMENTS is optional:
- `branches` — clean up merged branches
- `remote` — prune stale remote-tracking branches
- `gc` — garbage collect and optimize the repo
- `all` — do everything
- (no args — same as `all`)

Examples:
- (no args — full cleanup)
- `branches`
- `remote`
- `gc`

## Workflow

1. Parse the scope from `$ARGUMENTS`. Default to `all`.
2. Show the user the exact commands before executing.
3. **This command deletes branches. Always show what will be deleted and confirm.**

### Step 1 — Survey

```bash
echo "=== Repository Size ==="
du -sh .git

echo ""
echo "=== Local Branches ($(git branch | wc -l | tr -d ' ') total) ==="
git branch

echo ""
echo "=== Remote Tracking Branches ==="
git branch -r

echo ""
echo "=== Stash Entries ==="
git stash list | wc -l | tr -d ' '
```

### Step 2 — Branch cleanup

```bash
echo "=== Branches Merged into main ==="
git branch --merged main | grep -vE '^\*|main$|master$|develop$'

echo ""
echo "=== Branches NOT Merged into main ==="
git branch --no-merged main

echo ""
echo "=== Branch Last Commit Dates ==="
git for-each-ref --sort=committerdate --format='%(committerdate:short) %(refname:short)' refs/heads/
```

For branches merged into main, offer to delete them:

```bash
# Delete merged local branches (excluding protected branches)
git branch --merged main | grep -vE '^\*|main$|master$|develop$' | xargs git branch -d
```

For branches not merged into main, show their age and let the user decide:

```bash
# Show unmerged branch details
git for-each-ref --sort=committerdate --format='%(committerdate:relative) %(refname:short) %(subject)' refs/heads/ --no-merged=main
```

### Step 3 — Remote cleanup

```bash
echo "=== Pruning Stale Remote Branches ==="
git remote prune origin --dry-run
```

If stale branches are found:

```bash
git remote prune origin
```

### Step 4 — Garbage collection

```bash
echo "=== Before GC ==="
du -sh .git

git gc --auto

echo ""
echo "=== After GC ==="
du -sh .git

echo ""
echo "=== Dangling Objects ==="
git fsck --unreachable --no-reflogs 2>&1 | head -20
```

For aggressive cleanup (large repos):

```bash
git gc --aggressive --prune=now
git repack -a -d --depth=250 --window=250
```

### Step 5 — Summary

Present a table:

| Action | Items | Result |
|--------|-------|--------|
| Merged branches deleted | 3 | `feature/x`, `fix/y`, `chore/z` |
| Stale remote refs pruned | 2 | `origin/old-branch`, `origin/done` |
| Repo size | 45MB → 38MB | Saved 7MB |

## Security Notes

- `git branch -d` only deletes branches that are fully merged — it's safe. `git branch -D` force-deletes and can lose unmerged work.
- Pruning remote-tracking branches does NOT delete branches on the remote — it only removes local stale references.
- `git gc` removes unreachable objects older than the reflog expiry (default 90 days). Recent work is safe.
- Branches containing security fixes should be verified as merged before deletion.
