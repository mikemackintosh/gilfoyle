# Reflog Recovery

Recover lost commits, branches, or stashes using git's reflog.

## Arguments

$ARGUMENTS describes what to recover:

Examples:
- (no args — show reflog and guide through recovery)
- `branch <name>` — recover a deleted branch
- `commit <message-fragment>` — find and recover a lost commit by message
- `stash` — recover a dropped stash
- `reset` — undo the last reset

## Workflow

1. Parse the recovery target from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. **This command is read-only by default — it only makes changes when the user picks a recovery action.**

### Step 1 — Show the reflog

```bash
echo "=== Recent Reflog (last 30 entries) ==="
git reflog -30 --format='%h %gd %gs (%cr)'
```

If looking for a specific thing:

```bash
# Search reflog for a commit message fragment
git reflog --grep-reflog="<search-term>"

# Search reflog for a specific action
git reflog | grep "checkout\|reset\|rebase\|merge\|commit"
```

### Step 2 — Identify the target

Help the user identify which reflog entry contains what they lost:

```bash
# Show details of a specific reflog entry
git show <reflog-hash> --stat

# Show the diff
git show <reflog-hash>

# Show the log at that point in time
git log --oneline <reflog-hash> -5
```

### Step 3 — Recovery actions

**Recover a deleted branch:**

```bash
# Find when the branch was deleted
git reflog | grep "checkout.*<branch-name>"

# Recreate the branch at that commit
git branch <branch-name> <reflog-hash>
```

**Recover a lost commit (after reset):**

```bash
# Find the commit in reflog
git reflog | grep "commit:"

# Cherry-pick it back
git cherry-pick <reflog-hash>

# Or reset back to it
git reset --hard <reflog-hash>
```

**Undo a rebase:**

```bash
# Find the pre-rebase state
git reflog | grep "rebase (start)"

# The entry BEFORE "rebase (start)" is your pre-rebase state
git reset --hard <pre-rebase-hash>
```

**Recover a dropped stash:**

```bash
# Find dangling commits that look like stashes
git fsck --unreachable | grep commit

# Check each one
git show <hash> --stat

# Apply the recovered stash
git stash apply <hash>

# Or create a branch from it
git branch recovered-stash <hash>
```

### Step 4 — Verify recovery

```bash
echo "=== Recovery Result ==="
git log --oneline -5

echo ""
echo "=== Branch List ==="
git branch

echo ""
echo "=== Status ==="
git status
```

## Reflog Retention

| Setting | Default | Controls |
|---------|---------|----------|
| `gc.reflogExpire` | 90 days | How long reachable reflog entries are kept |
| `gc.reflogExpireUnreachable` | 30 days | How long unreachable reflog entries are kept |

```bash
# Check current settings
git config gc.reflogExpire
git config gc.reflogExpireUnreachable

# Extend retention if needed
git config gc.reflogExpire 180.days
git config gc.reflogExpireUnreachable 90.days
```

## Security Notes

- The reflog is local only — it is never pushed to remotes. Each clone has its own reflog.
- Recovering a commit that contained secrets will re-introduce those secrets. Be aware of what you're restoring.
- `git gc --prune=now` permanently removes unreachable objects. Avoid running it if you might need to recover something.
- Reflog entries expire based on `gc.reflogExpire` (default 90 days). After expiry, commits may be truly unrecoverable.
