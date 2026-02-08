# Scheduled Tasks Review

Review Windows scheduled tasks for persistence mechanisms, suspicious entries, and misconfigured permissions.

## Arguments

$ARGUMENTS is optional:
- `--non-microsoft` — show only non-Microsoft tasks
- `--system` — show tasks running as SYSTEM
- `--recent` — show tasks created in the last 30 days
- `<task-name>` — details for a specific task
- (no args — full scheduled task review)

Examples:
- (no args — full review)
- `--non-microsoft`
- `--system`
- `--recent`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Non-Microsoft tasks

```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
  Select-Object TaskName, State, TaskPath,
    @{N='RunAs';E={$_.Principal.UserId}},
    @{N='Action';E={($_.Actions | ForEach-Object { $_.Execute }).Trim() -join ', '}} |
  Format-Table
```

### Step 2 — Tasks running as SYSTEM

```powershell
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' -and $_.TaskPath -notlike '\Microsoft\*' } |
  Select-Object TaskName, State,
    @{N='Action';E={$_.Actions[0].Execute}},
    @{N='Arguments';E={$_.Actions[0].Arguments}} |
  Format-Table
```

### Step 3 — Recently created tasks

```powershell
Get-ScheduledTask | Where-Object { $_.Date -and [datetime]$_.Date -gt (Get-Date).AddDays(-30) } |
  Select-Object TaskName, Date, State,
    @{N='RunAs';E={$_.Principal.UserId}},
    @{N='Action';E={$_.Actions[0].Execute}} |
  Sort-Object Date -Descending | Format-Table
```

### Step 4 — Tasks with suspicious characteristics

```powershell
# Tasks running scripts from user-writable locations
Get-ScheduledTask | ForEach-Object {
  $task = $_
  $task.Actions | Where-Object { $_.Execute -match '\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\' } | ForEach-Object {
    [PSCustomObject]@{TaskName=$task.TaskName; Execute=$_.Execute; RunAs=$task.Principal.UserId}
  }
} | Format-Table

# Tasks running encoded PowerShell
Get-ScheduledTask | ForEach-Object {
  $task = $_
  $task.Actions | Where-Object { $_.Arguments -match '-enc|-EncodedCommand|-e ' } | ForEach-Object {
    [PSCustomObject]@{TaskName=$task.TaskName; Execute=$_.Execute; Arguments=$_.Arguments}
  }
} | Format-Table
```

3. Flag findings:
   - Tasks running as SYSTEM from user-writable paths
   - Recently created tasks with encoded commands
   - Tasks running scripts from temp/download directories
   - Tasks with hidden or elevated attributes

## Security Notes

- Scheduled tasks are one of the most common persistence mechanisms. Attackers create tasks to survive reboots.
- Tasks running as SYSTEM with binaries in user-writable paths are a privilege escalation vector.
- Encoded PowerShell (`-EncodedCommand`) in scheduled tasks is a strong indicator of malicious activity.
- Legitimate software does create scheduled tasks, but they typically run from `Program Files` — not temp directories.
