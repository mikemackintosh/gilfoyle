# Security Event Log Analysis

Analyse Windows Security event logs for authentication events, privilege escalation, persistence, and anti-forensics indicators.

## Arguments

$ARGUMENTS is optional:
- `--logons` — focus on logon/logoff events (4624, 4625, 4634)
- `--admin` — focus on admin activity (4672, 4720, 4728, 4732)
- `--persistence` — focus on service installs, scheduled tasks (4697, 7045)
- `--cleared` — check for log clearing events (1102)
- `--brute-force` — detect brute force patterns (4625 clusters)
- `--hours <N>` — look back N hours (default: 24)
- (no args — comprehensive security log review)

Examples:
- (no args — last 24h security review)
- `--logons --hours 48`
- `--brute-force`
- `--persistence`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. Requires elevated (Administrator) privileges.

### Step 1 — Failed logon attempts

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,
    @{N='TargetUser';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[19].Value}},
    @{N='LogonType';E={$_.Properties[10].Value}},
    @{N='FailReason';E={$_.Properties[7].Value}} |
  Format-Table
```

### Step 2 — Successful logons

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}},
    @{N='Process';E={$_.Properties[17].Value}} |
  Where-Object { $_.LogonType -notin @(0,5) } |
  Format-Table
```

### Step 3 — Privilege escalation indicators

```powershell
# Special privilege logons (admin sessions)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[1].Value}} |
  Group-Object User | Sort-Object Count -Descending | Format-Table Count, Name

# Account creation
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='NewUser';E={$_.Properties[0].Value}}, @{N='CreatedBy';E={$_.Properties[4].Value}} | Format-Table

# Group membership changes
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4732,4756; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, @{N='Member';E={$_.Properties[0].Value}}, @{N='Group';E={$_.Properties[2].Value}}, @{N='ChangedBy';E={$_.Properties[6].Value}} | Format-Table
```

### Step 4 — Persistence and anti-forensics

```powershell
# Service installs
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}, @{N='AccountName';E={$_.Properties[4].Value}} | Format-Table

# Log clearing
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='ClearedBy';E={$_.Properties[1].Value}} | Format-Table

# Explicit credential logons (runas, PsExec, etc.)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[1].Value}}, @{N='TargetUser';E={$_.Properties[5].Value}}, @{N='TargetServer';E={$_.Properties[8].Value}} | Format-Table
```

3. Present a timeline of significant events and flag anomalies.

## Security Notes

- **Event ID 1102** (audit log cleared) is a strong anti-forensics indicator. This should almost never happen in production.
- **Logon type 10** (RDP) from unexpected sources warrants investigation.
- **Event ID 4648** (explicit credentials) indicates lateral movement tools like PsExec, runas, or mimikatz.
- Failed logon clusters from the same source IP indicate brute force or password spraying.
- Requires `SeSecurityPrivilege` to read the Security log — run as Administrator.
