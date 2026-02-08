# Branch Sync

Sync the current branch with its upstream, choosing the right strategy (rebase vs merge) based on context.

## Arguments

$ARGUMENTS is optional:
- A branch or remote to sync with (default: upstream tracking branch)
- `--rebase` to force rebase strategy
- `--merge` to force merge strategy

Examples:
- (no args — auto-detect upstream, auto-choose strategy)
- `main`
- `origin/main --rebase`
- `upstream/main --merge`

## Workflow

1. Parse the target from `$ARGUMENTS`. Default to the tracking upstream.
2. Show the user the exact commands before executing.

### Step 1 — Assess the situation

```bash
echo "=== Current Branch ==="
BRANCH=$(git branch --show-current)
echo "$BRANCH"

echo ""
echo "=== Upstream Tracking ==="
UPSTREAM=$(git rev-parse --abbrev-ref @{upstream} 2>/dev/null)
echo "${UPSTREAM:-"(none)"}"

echo ""
echo "=== Fetch Latest ==="
git fetch --all --prune

echo ""
echo "=== Divergence ==="
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{upstream} 2>/dev/null || git rev-parse origin/main 2>/dev/null)
BASE=$(git merge-base $LOCAL $REMOTE 2>/dev/null)

if [ "$LOCAL" = "$REMOTE" ]; then
  echo "Up to date."
elif [ "$LOCAL" = "$BASE" ]; then
  echo "Behind upstream — fast-forward possible."
elif [ "$REMOTE" = "$BASE" ]; then
  echo "Ahead of upstream — push needed."
else
  AHEAD=$(git rev-list --count $REMOTE..$LOCAL)
  BEHIND=$(git rev-list --count $LOCAL..$REMOTE)
  echo "Diverged: $AHEAD ahead, $BEHIND behind."
fi
```

### Step 2 — Choose strategy

Apply this decision tree:

| Condition | Strategy | Reason |
|-----------|----------|--------|
| Fast-forward possible | `git merge --ff-only` | No divergence, cleanest |
| Branch is personal/feature | `git rebase` | Clean linear history |
| Branch is shared with others | `git merge` | Don't rewrite shared history |
| Branch is `main`/`master`/`develop` | `git merge` | Never rebase shared mainline |
| User specified `--rebase` | `git rebase` | Explicit override |
| User specified `--merge` | `git merge` | Explicit override |
| Uncertain | Ask the user | Better safe |

### Step 3 — Execute sync

**Fast-forward (no divergence):**

```bash
git merge --ff-only @{upstream}
```

**Rebase (personal branch):**

```bash
git rebase origin/main
# If conflicts: resolve, git add, git rebase --continue
```

**Merge (shared branch):**

```bash
git merge origin/main
# If conflicts: resolve, git add, git commit
```

### Step 4 — Verify

```bash
echo "=== Sync Result ==="
git log --oneline --graph -10

echo ""
echo "=== Status ==="
git status
```

If the branch was rebased and has an upstream, note that a force-push may be needed:

```bash
# Only if rebased and branch was already pushed:
git push --force-with-lease origin <branch>
```

## Security Notes

- This command fetches from remotes, which is safe and read-only for the remote.
- Rebase rewrites commit hashes. If others have based work on your branch, this will cause divergence for them.
- `--force-with-lease` checks that the remote hasn't changed since your last fetch before overwriting.
- On shared branches, always merge — never rebase.
