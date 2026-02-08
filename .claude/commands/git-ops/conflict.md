# Merge Conflict Resolution

Help resolve merge conflicts during a merge, rebase, or cherry-pick.

## Arguments

$ARGUMENTS is optional:
- A specific file to focus on
- `--abort` to abort the current operation
- `--theirs` or `--ours` to pick a side for all conflicts

Examples:
- (no args — show all conflicts and guide through resolution)
- `src/main.go`
- `--abort`
- `--theirs`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Identify the conflict state

```bash
echo "=== Current State ==="
git status

echo ""
echo "=== Operation in Progress ==="
[ -f .git/MERGE_HEAD ] && echo "MERGE in progress (merging $(cat .git/MERGE_HEAD | head -c 8))"
[ -d .git/rebase-merge ] && echo "REBASE in progress (step $(cat .git/rebase-merge/msgnum)/$(cat .git/rebase-merge/end))"
[ -d .git/rebase-apply ] && echo "REBASE/AM in progress"
[ -f .git/CHERRY_PICK_HEAD ] && echo "CHERRY-PICK in progress"

echo ""
echo "=== Conflicted Files ==="
git diff --name-only --diff-filter=U
```

### Step 2 — Show conflict details

For each conflicted file (or the file specified in $ARGUMENTS):

```bash
# Show the conflict markers
git diff --check

# Show the three-way diff
git diff <file>

# Show what each side changed
git diff --ours <file>
git diff --theirs <file>
```

3. For each conflicted file, explain:
   - What **our** side changed (the branch you were on)
   - What **their** side changed (the branch being merged in)
   - Whether the changes overlap or are in different sections

### Step 3 — Resolution strategies

Present the available resolution strategies:

| Strategy | Command | When to use |
|----------|---------|------------|
| Manual edit | Edit the file, remove markers | Changes overlap and need human judgement |
| Accept ours | `git checkout --ours <file>` | Discard their changes for this file |
| Accept theirs | `git checkout --theirs <file>` | Discard our changes for this file |
| Merge tool | `git mergetool` | Complex conflicts needing visual diff |
| Abort | `git merge --abort` / `git rebase --abort` | Start over |

### Step 4 — Complete the resolution

After the user resolves conflicts:

```bash
# Stage resolved files
git add <resolved-files>

# For a merge:
git commit

# For a rebase:
git rebase --continue

# For a cherry-pick:
git cherry-pick --continue
```

4. Verify the resolution is clean:

```bash
# Confirm no remaining conflict markers
git diff --check
```

## Security Notes

- Always review the resolved content before staging — conflict resolution can accidentally remove security-relevant code (input validation, auth checks, etc.).
- If the conflict is in a CI/CD pipeline, security config, or auth module, flag it explicitly for careful review.
- The `--theirs` and `--ours` bulk options skip manual review. Only use them when you understand both sides.
