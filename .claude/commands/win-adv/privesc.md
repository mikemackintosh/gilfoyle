# Privilege Escalation Checks

Check for common Windows privilege escalation vectors — token privileges, unquoted paths, writable services, AlwaysInstallElevated, writable PATH directories, and stored credentials.

## Arguments

$ARGUMENTS is optional:
- `--services` — focus on service-based privilege escalation
- `--tokens` — focus on token privileges
- `--paths` — focus on writable PATH and DLL hijacking
- `--creds` — focus on stored credentials
- (no args — all checks)

Examples:
- (no args — comprehensive privesc check)
- `--services`
- `--tokens`
- `--creds`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Current user context

```powershell
whoami /all
```

### Step 2 — Dangerous token privileges

```powershell
# Check for exploitable privileges
$dangerous = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege')
$current = whoami /priv /fo csv | ConvertFrom-Csv
$current | Where-Object { $dangerous -contains $_.'Privilege Name' } |
  Format-Table 'Privilege Name', 'State', @{N='Risk';E={'EXPLOITABLE'}}
```

### Step 3 — Service-based vectors

```powershell
# Unquoted service paths
Get-WmiObject Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.StartMode -ne 'Disabled'
} | Select-Object Name, PathName, StartName, StartMode | Format-Table

# Writable service binaries
Get-WmiObject Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
  $path = if ($_.PathName -match '^"([^"]+)"') { $matches[1] } else { ($_.PathName -split ' ')[0] }
  if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
    $acl = Get-Acl $path -ErrorAction SilentlyContinue
    $writable = $acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.IdentityReference -match 'Users|Everyone|Authenticated' }
    if ($writable) { [PSCustomObject]@{Service=$_.Name; Path=$path; WritableBy=($writable.IdentityReference -join ', ')} }
  }
} | Format-Table

# Writable service registry keys
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
  $acl = Get-Acl $_.PSPath -ErrorAction SilentlyContinue
  $writable = $acl.Access | Where-Object { $_.RegistryRights -match 'FullControl|SetValue' -and $_.IdentityReference -match 'Users|Everyone|Authenticated' }
  if ($writable) { [PSCustomObject]@{Service=$_.PSChildName; WritableBy=($writable.IdentityReference -join ', ')} }
} | Format-Table
```

### Step 4 — AlwaysInstallElevated

```powershell
$hklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($hklm -eq 1 -and $hkcu -eq 1) {
  Write-Warning "AlwaysInstallElevated is ENABLED in both HKLM and HKCU — any user can install MSI as SYSTEM"
} else {
  Write-Host "AlwaysInstallElevated: Not exploitable" -ForegroundColor Green
}
```

### Step 5 — Writable PATH directories

```powershell
$env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
  if (Test-Path $_ -ErrorAction SilentlyContinue) {
    $acl = Get-Acl $_ -ErrorAction SilentlyContinue
    $writable = $acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.IdentityReference -match 'Users|Everyone|Authenticated' }
    if ($writable) { [PSCustomObject]@{Path=$_; WritableBy=($writable.IdentityReference -join ', ')} }
  }
} | Format-Table
```

### Step 6 — Stored credentials

```powershell
cmdkey /list
```

3. Present findings ranked by severity.

## Security Notes

- **SeImpersonatePrivilege** + **SeAssignPrimaryTokenPrivilege** allow Potato-family attacks (JuicyPotato, PrintSpoofer, GodPotato) to escalate from service accounts to SYSTEM.
- **SeDebugPrivilege** allows attaching to any process including LSASS — direct path to credential dumping.
- **Unquoted service paths** are a classic privilege escalation. If `C:\Program Files\Some App\service.exe` is unquoted, Windows tries `C:\Program.exe` first.
- **AlwaysInstallElevated** allows crafting a malicious MSI that runs as SYSTEM when installed by any user.
- **Writable PATH directories** allow DLL hijacking — placing a malicious DLL that gets loaded by a privileged process.
