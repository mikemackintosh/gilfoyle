# User and Group Enumeration

Enumerate local users, groups, group memberships, and identify security-relevant account configurations.

## Arguments

$ARGUMENTS is optional:
- `<username>` — details for a specific user
- `--admins` — show only administrator accounts
- `--stale` — show accounts with no recent logon
- (no args — full user and group enumeration)

Examples:
- (no args — enumerate all users and groups)
- `Administrator`
- `--admins`
- `--stale`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Local users

```powershell
Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired
```

### Step 2 — Local groups and memberships

```powershell
# All groups
Get-LocalGroup | Format-Table Name, Description

# Administrators group members
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, ObjectClass, PrincipalSource

# Remote Desktop Users
Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass
```

### Step 3 — Security flags

```powershell
# Accounts with no password required
Get-LocalUser | Where-Object { -not $_.PasswordRequired -and $_.Enabled } | Format-Table Name

# Accounts with password never expires
Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled } | Format-Table Name

# Disabled accounts
Get-LocalUser | Where-Object { -not $_.Enabled } | Format-Table Name, LastLogon

# Password policy
net accounts
```

3. Present results and flag:
   - Enabled accounts with no password required
   - Accounts with password never expires
   - Unexpected members of Administrators group
   - Stale accounts (no logon in 90+ days)

## Security Notes

- The built-in Administrator account should be renamed and disabled if not needed.
- Guest account should always be disabled.
- Local admin accounts on workstations are a lateral movement risk — consider LAPS (Local Administrator Password Solution).
- Accounts with `PasswordRequired = False` can have blank passwords, which is a critical finding.
