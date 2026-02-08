# Rebase Guide

Interactive walkthrough for rebasing a branch — squashing, reordering, rewording, and cleaning up history.

## Arguments

$ARGUMENTS describes the rebase target:

Examples:
- `main` — rebase current branch onto main
- `HEAD~5` — rebase last 5 commits interactively
- `--onto main feature-base` — transplant commits onto main from feature-base
- `--squash` — squash all branch commits into one
- (no args — detect the upstream branch and offer options)

## Workflow

1. Parse the rebase target from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. **Always check if the branch is shared before proceeding.**

### Step 1 — Pre-flight checks

```bash
echo "=== Current Branch ==="
BRANCH=$(git branch --show-current)
echo "$BRANCH"

echo ""
echo "=== Tracking ==="
git rev-parse --abbrev-ref @{upstream} 2>/dev/null || echo "(no upstream set)"

echo ""
echo "=== Commits to Rebase ==="
# Show commits that would be rebased
git log --oneline @{upstream}..HEAD 2>/dev/null || git log --oneline main..HEAD 2>/dev/null

echo ""
echo "=== Working Tree Status ==="
git status --short
```

If there are uncommitted changes, recommend stashing first:

```bash
git stash push -m "pre-rebase stash"
```

### Step 2 — Determine rebase strategy

| Goal | Command |
|------|---------|
| Update branch with latest main | `git rebase main` |
| Squash all feature commits into one | `git rebase -i main` then mark all but first as `fixup` |
| Reword a commit message | `git rebase -i HEAD~N` then mark as `reword` |
| Reorder commits | `git rebase -i HEAD~N` then rearrange lines |
| Remove a commit from history | `git rebase -i HEAD~N` then mark as `drop` |
| Split a commit | `git rebase -i HEAD~N` then mark as `edit` |
| Transplant commits | `git rebase --onto <new-base> <old-base> <branch>` |

### Step 3 — Execute the rebase

For a simple rebase onto main:

```bash
git fetch origin
git rebase origin/main
```

For an interactive rebase:

```bash
git rebase -i <target>
```

Explain the interactive editor format:
- Each line is a commit: `pick <hash> <message>`
- Change `pick` to the desired action
- Lines can be reordered
- Deleted lines drop the commit

### Step 4 — Handle conflicts

If conflicts arise during rebase:

```bash
# See what's conflicted
git status

# After resolving:
git add <resolved-files>
git rebase --continue

# To skip this commit:
git rebase --skip

# To abort and restore pre-rebase state:
git rebase --abort
```

### Step 5 — Verify and push

```bash
echo "=== Rebase Result ==="
git log --oneline -10

echo ""
echo "=== Diff from upstream ==="
git diff @{upstream}..HEAD --stat 2>/dev/null
```

If the branch was already pushed:

```bash
# Force push with lease (safe force push)
git push --force-with-lease origin <branch>
```

Warn: "This rewrites the remote branch history. Only do this on branches you own."

## Security Notes

- **Never rebase `main`, `master`, or `production`** — these are shared branches.
- `--force-with-lease` is safer than `--force` because it checks that no one else has pushed since your last fetch.
- Rebasing commits that have been signed will invalidate the signatures. Re-sign with `git rebase --gpg-sign`.
- If you're rebasing to remove a secret from history, rebase alone is not enough — the old commits still exist in reflog and pack files. Use `git filter-repo` or BFG Repo-Cleaner.
