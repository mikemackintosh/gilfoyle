# Windows Services Audit

Audit Windows services for security misconfigurations — non-default service accounts, unquoted paths, stopped auto-start services, and writable binaries.

## Arguments

$ARGUMENTS is optional:
- `--running` — show only running services
- `--vulnerable` — check for exploitable misconfigurations
- `<service-name>` — details for a specific service
- (no args — full audit)

Examples:
- (no args — full services audit)
- `--running`
- `--vulnerable`
- `wuauserv`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Service overview

```powershell
Get-Service | Group-Object Status | Format-Table Count, Name
```

### Step 2 — Security-relevant checks

```powershell
# Services running as non-default accounts
Get-WmiObject Win32_Service | Where-Object {
  $_.StartName -and $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService'
} | Format-Table Name, StartName, State, StartMode, PathName

# Unquoted service paths (privilege escalation vector)
Get-WmiObject Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.StartMode -ne 'Disabled'
} | Format-Table Name, PathName, StartName

# Auto-start services that are stopped
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
  Format-Table Name, DisplayName, Status
```

3. Flag findings:
   - Unquoted service paths with spaces = privilege escalation risk
   - Services running as domain accounts = credential exposure risk
   - Stopped auto-start services = possible tampering or failure

## Security Notes

- **Unquoted service paths** with spaces allow an attacker to place a binary earlier in the path that runs as the service account. This is a well-known privilege escalation technique.
- Services running as domain user accounts expose those credentials if the service is compromised.
- The default service accounts (LocalSystem, LocalService, NetworkService) have well-defined privilege boundaries. Custom accounts should be reviewed for least privilege.
