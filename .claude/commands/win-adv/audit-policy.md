# Audit Policy Review

Review Windows audit policy configuration, PowerShell logging settings, and compare against security baselines.

## Arguments

$ARGUMENTS is optional:
- `--baseline` — compare against recommended baseline
- `--powershell` — focus on PowerShell logging configuration
- (no args — full audit policy review)

Examples:
- (no args — full review)
- `--baseline`
- `--powershell`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. Requires elevated (Administrator) privileges.

### Step 1 — Current audit policy

```powershell
auditpol /get /category:*
```

### Step 2 — Compare against baseline

The following are recommended minimum audit settings for security monitoring:

| Category | Subcategory | Recommended | Why |
|----------|-------------|-------------|-----|
| Account Logon | Credential Validation | Success, Failure | Detect auth attacks |
| Logon/Logoff | Logon | Success, Failure | Track all logon attempts |
| Logon/Logoff | Logoff | Success | Session duration tracking |
| Logon/Logoff | Special Logon | Success | Admin session tracking |
| Account Management | User Account Management | Success, Failure | Account creation/modification |
| Account Management | Security Group Management | Success | Group membership changes |
| Detailed Tracking | Process Creation | Success | Command execution tracking |
| Policy Change | Audit Policy Change | Success, Failure | Detect audit tampering |
| Privilege Use | Sensitive Privilege Use | Success, Failure | Privilege escalation |
| Object Access | File System | Failure | Access denied tracking |
| DS Access | Directory Service Changes | Success | AD object modifications |

### Step 3 — Process creation command line logging

```powershell
# Check if command line auditing is enabled
$cmdLine = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
if ($cmdLine.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
  Write-Host "Process command line logging: ENABLED" -ForegroundColor Green
} else {
  Write-Host "Process command line logging: DISABLED" -ForegroundColor Red
}
```

### Step 4 — PowerShell logging

```powershell
# Script block logging
$sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Write-Host "Script Block Logging: $(if ($sbl.EnableScriptBlockLogging -eq 1) {'ENABLED'} else {'DISABLED'})"

# Module logging
$ml = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
Write-Host "Module Logging: $(if ($ml.EnableModuleLogging -eq 1) {'ENABLED'} else {'DISABLED'})"

# Transcription
$tr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
Write-Host "Transcription: $(if ($tr.EnableTranscripting -eq 1) {'ENABLED'} else {'DISABLED'})"
Write-Host "Transcription Directory: $($tr.OutputDirectory)"
```

### Step 5 — Sysmon check

```powershell
# Check if Sysmon is installed
$sysmon = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
if ($sysmon) {
  Write-Host "Sysmon: INSTALLED ($($sysmon.Status))" -ForegroundColor Green
  # Check Sysmon config
  $sysmonPath = (Get-WmiObject Win32_Service -Filter "Name like 'Sysmon%'").PathName
  Write-Host "Sysmon Path: $sysmonPath"
} else {
  Write-Host "Sysmon: NOT INSTALLED" -ForegroundColor Yellow
}
```

3. Present findings as a compliance table showing current vs recommended settings.

## Security Notes

- Without process creation auditing (Event ID 4688) and command line logging, you have no visibility into what commands were executed.
- PowerShell **script block logging** is essential for detecting encoded commands, obfuscated scripts, and fileless malware.
- **Sysmon** provides far more detailed logging than native Windows auditing — including process creation with parent process, network connections, file creation, and registry changes.
- Attackers can clear audit logs (Event ID 1102) or disable audit policies to cover their tracks. Monitor for audit policy changes.
- Excessive auditing can generate massive log volumes. Focus on the categories in the baseline table.
