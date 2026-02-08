# Registry Security Audit

Audit Windows registry for persistence mechanisms, security misconfigurations, and indicators of compromise.

## Arguments

$ARGUMENTS is optional:
- `--autorun` — check all autorun/persistence locations
- `--security` — check security-relevant settings (UAC, LSA, RDP)
- `--all` — full registry audit
- (no args — same as `--all`)

Examples:
- (no args — full registry audit)
- `--autorun`
- `--security`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Autorun / persistence locations

```powershell
$autorunPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
  'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
  'HKLM:\System\CurrentControlSet\Services'
)
foreach ($path in $autorunPaths) {
  if (Test-Path $path) {
    Write-Host "`n=== $path ===" -ForegroundColor Cyan
    Get-ItemProperty $path -ErrorAction SilentlyContinue | Format-List
  }
}

# Winlogon shell and userinit (hijack targets)
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell, Userinit

# Image File Execution Options (debugger hijack)
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  Where-Object { $_.GetValue('Debugger') } | ForEach-Object {
    [PSCustomObject]@{Program=$_.PSChildName; Debugger=$_.GetValue('Debugger')}
  } | Format-Table
```

### Step 2 — Security settings

```powershell
# UAC configuration
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, FilterAdministratorToken, EnableInstallerDetection

# LSA settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object RunAsPPL, LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous, LmCompatibilityLevel

# RDP settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' |
  Select-Object fDenyTSConnections, fSingleSessionPerUser
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
  Select-Object SecurityLayer, UserAuthentication, MinEncryptionLevel

# WDigest
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue

# AlwaysInstallElevated
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

3. Present findings as a table with severity ratings.

## Security Notes

- **Image File Execution Options** debugger entries redirect program execution — a common persistence technique used by malware.
- **Winlogon Shell/Userinit** modifications replace or chain onto the login process — high-severity persistence.
- **EnableLUA = 0** means UAC is fully disabled — critical finding.
- **RunAsPPL = 0** or missing means LSASS is not protected — allows credential dumping with tools like mimikatz.
- **AlwaysInstallElevated = 1** in both HKLM and HKCU allows any user to install MSI packages as SYSTEM.
