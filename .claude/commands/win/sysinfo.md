# System Information

Gather Windows system information including OS version, build, architecture, uptime, and domain membership.

## Arguments

$ARGUMENTS is optional:
- `--remote <hostname>` to query a remote machine via CIM
- (no args — query the local machine)

Examples:
- (no args — local system info)
- `--remote DC01`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — OS and hardware details

```powershell
# Basic system info
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, OsArchitecture, WindowsVersion, CsDomain, CsDomainRole, OsLastBootUpTime, OsInstallDate

# Uptime
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $boot
Write-Host "Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
```

### Step 2 — Domain and role

```powershell
# Domain membership
$cs = Get-WmiObject Win32_ComputerSystem
Write-Host "Computer Name: $($cs.Name)"
Write-Host "Domain: $($cs.Domain)"
Write-Host "Domain Joined: $($cs.PartOfDomain)"
Write-Host "Role: $($cs.DomainRole)"
# Roles: 0=Standalone Workstation, 1=Member Workstation, 2=Standalone Server, 3=Member Server, 4=Backup DC, 5=Primary DC
```

### Step 3 — PowerShell and .NET versions

```powershell
$PSVersionTable
[System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
```

### Step 4 — Installed hotfixes

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn | Format-Table
```

3. Present a summary table with findings and flag anything notable (old OS, missing patches, non-domain-joined server, etc.).

## Security Notes

- OS build numbers map to specific patch levels. A significantly outdated build may be missing critical security updates.
- Domain role reveals the machine's function — domain controllers require stricter security baselines.
- PowerShell version matters for security features: v5+ supports script block logging, AMSI, and constrained language mode.
