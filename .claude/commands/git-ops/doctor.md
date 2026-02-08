# Git Doctor

Diagnose and fix common git repository issues.

## Arguments

$ARGUMENTS is optional:
- A repository path (default: current directory)
- A specific symptom (e.g., "push rejected", "detached head", "diverged branches")

Examples:
- (no args — run full diagnostic)
- `push rejected`
- `detached HEAD`
- `/path/to/repo`

## Workflow

1. Parse the path or symptom from `$ARGUMENTS`. Default to `.` with full diagnostic.
2. Show the user the exact commands before executing.

### Step 1 — Repository health check

```bash
echo "=== Git Status ==="
git status

echo ""
echo "=== Current Branch ==="
git branch --show-current 2>/dev/null || echo "(detached HEAD)"

echo ""
echo "=== Remote Configuration ==="
git remote -v

echo ""
echo "=== Upstream Tracking ==="
git for-each-ref --format='%(refname:short) -> %(upstream:short) [%(upstream:track)]' refs/heads/
```

### Step 2 — Detect common problems

Check for and report on each of these conditions:

| Condition | Detection | Severity |
|-----------|-----------|----------|
| Detached HEAD | `git symbolic-ref HEAD` fails | Warning |
| Diverged from upstream | `[ahead N, behind M]` in tracking | Action needed |
| Untracked sensitive files | `*.env`, `*.key`, `*.pem` in working tree | Security risk |
| Merge in progress | `.git/MERGE_HEAD` exists | Needs resolution |
| Rebase in progress | `.git/rebase-merge/` or `.git/rebase-apply/` exists | Needs resolution |
| Stale remote branches | Compare `git branch -r` with `git ls-remote` | Cleanup |
| Large repo / slow ops | `du -sh .git` | Info |
| Missing upstream | Branch has no tracking branch set | Config issue |

```bash
echo "=== Detecting Issues ==="

# Detached HEAD
if ! git symbolic-ref HEAD >/dev/null 2>&1; then
  echo "ISSUE: Detached HEAD at $(git rev-parse --short HEAD)"
fi

# In-progress operations
[ -f .git/MERGE_HEAD ] && echo "ISSUE: Merge in progress"
[ -d .git/rebase-merge ] && echo "ISSUE: Rebase in progress"
[ -d .git/rebase-apply ] && echo "ISSUE: Rebase/am in progress"
[ -f .git/CHERRY_PICK_HEAD ] && echo "ISSUE: Cherry-pick in progress"
[ -f .git/BISECT_LOG ] && echo "ISSUE: Bisect in progress"

# Divergence
git for-each-ref --format='%(refname:short) %(upstream:track)' refs/heads/ | grep -v '^\s*$'

# Repo size
echo ""
echo "=== Repository Size ==="
du -sh .git
```

### Step 3 — Provide targeted fixes

Based on the detected issues, provide the specific commands to resolve each one. For example:

- **Detached HEAD**: `git checkout main` or `git switch -`
- **Merge in progress**: `git merge --abort` or resolve and `git commit`
- **Rebase in progress**: `git rebase --abort` or resolve and `git rebase --continue`
- **Diverged branches**: Recommend rebase (if solo) or merge (if shared), explain the tradeoff
- **Push rejected**: `git fetch && git rebase origin/<branch>` or `git pull`
- **Missing upstream**: `git push -u origin <branch>`

4. Present results as a summary table:

| Issue | Status | Recommended Fix |
|-------|--------|----------------|
| Branch tracking | OK | — |
| Merge state | Clean | — |
| HEAD state | Detached | `git checkout main` |

5. If $ARGUMENTS contains a specific symptom, focus the diagnosis on that problem and skip unrelated checks.

## Security Notes

- This command is read-only by default. It will not modify the repository unless the user approves a fix.
- Sensitive file detection uses the same patterns as `/git-sec:gitignore-audit`.
- The `git reflog` is your best friend for recovery — almost nothing is permanently lost within 90 days.
