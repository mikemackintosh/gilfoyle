---
name: Git Operations
description: Git workflow troubleshooting, merge vs rebase strategy, conflict resolution, history rewriting, reflog recovery, and common git problem solving.
instructions: |
  Use this skill when the user needs help with everyday git operations — resolving merge conflicts,
  choosing between rebase and merge, fixing push/pull errors, recovering lost commits, cleaning up
  history, working with remotes, or diagnosing any git problem. Always show commands before executing
  them and explain what each command does. Prefer safe, non-destructive approaches. Warn before any
  history-rewriting operation.
---

# Git Operations Skill

## Related Commands
- `/git-ops:doctor` — Diagnose and fix common git issues
- `/git-ops:conflict` — Resolve merge conflicts
- `/git-ops:undo` — Undo the last git operation safely
- `/git-ops:rebase-guide` — Interactive rebase walkthrough
- `/git-ops:sync` — Sync a branch with upstream (rebase vs merge decision)
- `/git-ops:cleanup` — Clean up branches, stale refs, and dangling objects
- `/git-ops:reflog-recover` — Recover lost commits using reflog

## Rebase vs Merge Decision Framework

Use this decision tree when the user is unsure whether to rebase or merge:

| Situation | Recommendation | Why |
|-----------|---------------|-----|
| Feature branch behind main, not shared | **Rebase** | Clean linear history, no merge commits |
| Feature branch behind main, shared with others | **Merge** | Rebase rewrites history others depend on |
| Long-running branch with many divergent commits | **Merge** | Rebase would replay too many commits, high conflict risk |
| Unrelated histories (e.g., new repo + GitHub init) | **Rebase** or `--allow-unrelated-histories` | Need to join two root commits |
| PR ready to land, clean history desired | **Rebase + fast-forward merge** | Linear history on main |
| PR ready to land, audit trail desired | **Merge commit** (`--no-ff`) | Preserves branch topology |
| Mid-feature, pulling latest main into branch | **Rebase** (if solo) / **Merge** (if shared) | Depends on whether others have the branch |

### Golden Rules
1. **Never rebase commits that have been pushed to a shared branch** — it rewrites history others depend on.
2. **Rebase is for local cleanup** — squashing fixups, reordering, editing messages.
3. **Merge preserves context** — you can always see where a branch joined.
4. **When in doubt, merge** — it is always safe.

## Common Git Problems & Solutions

### Push Rejected (non-fast-forward)

```bash
# Cause: remote has commits your local branch doesn't
# Safe fix: rebase your local commits on top of remote
git fetch origin
git rebase origin/<branch>
git push

# If the branch is shared and you can't rebase:
git pull --no-rebase origin <branch>
git push

# Nuclear option (DESTRUCTIVE — only if you own the branch):
# git push --force-with-lease origin <branch>
```

### Unrelated Histories

```bash
# Cause: two repos with no common ancestor (e.g., GitHub init + local init)
# Fix: rebase local onto remote
git fetch origin
git rebase origin/main

# Or merge with the flag:
git pull --allow-unrelated-histories origin main
```

### Detached HEAD

```bash
# Check where you are
git log --oneline -1
git branch

# Re-attach to a branch
git checkout main

# If you made commits in detached HEAD and want to keep them:
git branch rescue-branch
git checkout main
git merge rescue-branch
```

### Accidentally Committed to Wrong Branch

```bash
# Move the last N commits to a new branch
git branch new-branch          # create branch at current position
git reset --hard HEAD~N        # move current branch back N commits
git checkout new-branch        # switch to the new branch

# Or cherry-pick specific commits to the right branch
git checkout correct-branch
git cherry-pick <commit-hash>
git checkout wrong-branch
git reset --hard HEAD~1
```

### Undo Last Commit (keep changes)

```bash
# Undo commit, keep changes staged
git reset --soft HEAD~1

# Undo commit, keep changes unstaged
git reset HEAD~1

# Undo commit, discard changes (DESTRUCTIVE)
# git reset --hard HEAD~1
```

### Recover Deleted Branch or Lost Commit

```bash
# Find the commit in reflog
git reflog

# Restore a deleted branch
git branch <branch-name> <reflog-hash>

# Cherry-pick a lost commit
git cherry-pick <reflog-hash>
```

### Merge Conflicts

```bash
# See which files have conflicts
git status

# Show the conflict markers in a file
# <<<<<<< HEAD (your changes)
# =======
# >>>>>>> branch (their changes)

# After resolving manually:
git add <resolved-files>
git commit

# Abort a merge in progress
git merge --abort

# Abort a rebase in progress
git rebase --abort

# Use a merge tool
git mergetool
```

### Stash Operations

```bash
# Save current changes
git stash
git stash push -m "description"

# Save including untracked files
git stash push -u -m "with untracked"

# List stashes
git stash list

# Apply most recent stash (keep in stash list)
git stash apply

# Apply and remove from stash list
git stash pop

# Apply a specific stash
git stash apply stash@{2}

# Show stash contents
git stash show -p stash@{0}

# Drop a stash
git stash drop stash@{0}

# Clear all stashes (DESTRUCTIVE)
# git stash clear
```

## Interactive Rebase

```bash
# Rebase last N commits interactively
git rebase -i HEAD~N

# Rebase onto a branch
git rebase -i main
```

### Rebase Commands Reference

| Command | Short | Effect |
|---------|-------|--------|
| `pick` | `p` | Keep the commit as-is |
| `reword` | `r` | Keep the commit, edit the message |
| `edit` | `e` | Pause at this commit to amend it |
| `squash` | `s` | Meld into previous commit, combine messages |
| `fixup` | `f` | Meld into previous commit, discard this message |
| `drop` | `d` | Remove the commit entirely |

### Common Rebase Workflows

```bash
# Squash all feature commits into one before merging
git rebase -i main
# Mark all but the first commit as 'squash' or 'fixup'

# Reword a commit message
git rebase -i HEAD~3
# Change 'pick' to 'reword' on the target commit

# Remove a commit from history
git rebase -i HEAD~5
# Change 'pick' to 'drop' on the target commit
```

## Remote Operations

```bash
# List remotes
git remote -v

# Add a remote
git remote add <name> <url>

# Change a remote URL
git remote set-url origin <new-url>

# Fetch all remotes
git fetch --all

# Prune stale remote-tracking branches
git fetch --prune origin

# Track a remote branch
git checkout --track origin/<branch>

# Push and set upstream
git push -u origin <branch>

# Delete a remote branch
git push origin --delete <branch>
```

## Branch Cleanup

```bash
# List branches merged into main
git branch --merged main

# Delete merged local branches (excluding main/master/develop)
git branch --merged main | grep -vE '^\*|main|master|develop' | xargs git branch -d

# List remote branches merged into main
git branch -r --merged origin/main | grep -v 'main\|master\|develop'

# Prune remote-tracking branches that no longer exist
git remote prune origin

# Find branches with no recent commits (>30 days)
git for-each-ref --sort=committerdate --format='%(committerdate:short) %(refname:short)' refs/heads/ | head -20
```

## Git Bisect (find the commit that introduced a bug)

```bash
# Start bisecting
git bisect start
git bisect bad                 # current commit is broken
git bisect good <known-good>   # this older commit was working

# Git checks out a middle commit — test it, then:
git bisect good   # if this commit works
git bisect bad    # if this commit is broken

# Repeat until git identifies the first bad commit

# Reset when done
git bisect reset

# Automate with a test script
git bisect start HEAD <known-good>
git bisect run ./test-script.sh
```

## Configuration Tips

```bash
# Set default branch name for new repos
git config --global init.defaultBranch main

# Set default pull strategy
git config --global pull.rebase true        # rebase by default
git config --global pull.rebase false       # merge by default (default)

# Enable rerere (reuse recorded resolution)
git config --global rerere.enabled true

# Better diff algorithm
git config --global diff.algorithm histogram

# Auto-correct typos (runs after 1 second delay)
git config --global help.autocorrect 10

# Show branch in prompt (add to ~/.bashrc or ~/.zshrc)
# parse_git_branch() { git branch 2>/dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/(\1)/'; }
# PS1="\w \$(parse_git_branch) $ "
```

## Safety Practices

- **Use `--force-with-lease` instead of `--force`** — it refuses to push if someone else has pushed since your last fetch.
- **Enable `rerere`** — git remembers how you resolved conflicts and auto-applies the same resolution next time.
- **Check `git reflog` before panicking** — almost nothing in git is truly lost within 90 days.
- **Use `git stash` before risky operations** — stash your work-in-progress before rebasing or resetting.
- **Prefer `git switch` and `git restore` over `git checkout`** — they have clearer semantics (Git 2.23+).
