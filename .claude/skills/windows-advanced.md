---
name: Windows Advanced
description: Active Directory enumeration, Group Policy analysis, event log forensics, registry auditing, Windows Defender config, audit policies, privilege escalation checks, and credential store inspection.
instructions: |
  Use this skill when the user needs to perform advanced Windows security assessments — Active Directory
  enumeration, GPO analysis, event log forensics, registry security auditing, Defender configuration
  review, audit policy analysis, privilege escalation checks, or credential store inspection. These
  commands require elevated privileges in most cases. Always show commands before executing, warn about
  privilege requirements, and explain security implications of findings.
---

# Windows Advanced Skill

## Related Commands
- `/win-adv:ad-enum` — Active Directory enumeration
- `/win-adv:gpo` — Group Policy analysis
- `/win-adv:eventlog` — Security event log analysis
- `/win-adv:registry` — Registry security audit
- `/win-adv:defender` — Windows Defender status and configuration
- `/win-adv:audit-policy` — Audit policy review
- `/win-adv:privesc` — Privilege escalation checks
- `/win-adv:credentials` — Credential store and LSA audit

## Active Directory Enumeration

### Domain Information

```powershell
# Domain details
Get-ADDomain | Select-Object Name, DNSRoot, DomainMode, PDCEmulator, InfrastructureMaster

# Forest details
Get-ADForest | Select-Object Name, ForestMode, Domains, GlobalCatalogs

# Domain controllers
Get-ADDomainController -Filter * | Format-Table Name, IPv4Address, Site, OperatingSystem, IsGlobalCatalog

# Trust relationships
Get-ADTrust -Filter * | Format-Table Name, Direction, TrustType, IntraForest
```

### User Enumeration

```powershell
# All domain users
Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount |
  Format-Table Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount

# Privileged accounts (AdminCount = 1)
Get-ADUser -Filter { AdminCount -eq 1 } -Properties MemberOf, LastLogonDate, PasswordLastSet |
  Format-Table Name, LastLogonDate, PasswordLastSet

# Accounts with password never expires
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } |
  Format-Table Name, SamAccountName, DistinguishedName

# Stale accounts (no logon in 90 days)
$staleDate = (Get-Date).AddDays(-90)
Get-ADUser -Filter { LastLogonDate -lt $staleDate -and Enabled -eq $true } -Properties LastLogonDate |
  Format-Table Name, LastLogonDate

# Accounts with SPN set (Kerberoastable)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName |
  Format-Table Name, ServicePrincipalName

# Users with unconstrained delegation
Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Format-Table Name, DistinguishedName

# Accounts with no pre-authentication required (AS-REP roastable)
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth |
  Format-Table Name, DistinguishedName
```

### Group Enumeration

```powershell
# Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Format-Table Name, ObjectClass, SamAccountName

# Enterprise Admins
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Format-Table Name, ObjectClass

# Schema Admins
Get-ADGroupMember -Identity "Schema Admins" -Recursive | Format-Table Name, ObjectClass

# All privileged groups membership count
@("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators") | ForEach-Object {
  [PSCustomObject]@{Group=$_; Members=(Get-ADGroupMember -Identity $_ -ErrorAction SilentlyContinue | Measure-Object).Count}
} | Format-Table
```

### Computer Enumeration

```powershell
# All domain computers
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate |
  Format-Table Name, OperatingSystem, OperatingSystemVersion, LastLogonDate

# Computers with unconstrained delegation
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Format-Table Name, DistinguishedName

# Stale computer accounts
$staleDate = (Get-Date).AddDays(-90)
Get-ADComputer -Filter { LastLogonDate -lt $staleDate } -Properties LastLogonDate |
  Format-Table Name, LastLogonDate
```

## Group Policy Analysis

```powershell
# All GPOs
Get-GPO -All | Format-Table DisplayName, GpoStatus, CreationTime, ModificationTime

# GPO details with links
Get-GPO -All | ForEach-Object {
  $gpo = $_
  $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
  [PSCustomObject]@{Name=$gpo.DisplayName; Status=$gpo.GpoStatus; Modified=$gpo.ModificationTime}
} | Format-Table

# GPOs linked to a specific OU
Get-GPInheritance -Target "OU=Servers,DC=domain,DC=com" | Select-Object -ExpandProperty GpoLinks

# Resultant Set of Policy for a user/computer
gpresult /r

# Generate HTML report
gpresult /h gpresult.html /f

# Find GPOs with specific settings (password policy)
Get-GPO -All | ForEach-Object {
  $report = Get-GPOReport -Guid $_.Id -ReportType Xml
  if ($report -match 'MinimumPasswordLength|PasswordComplexity|LockoutThreshold') {
    $_.DisplayName
  }
}
```

### GPO Security Concerns

| Setting | Risk | What to Check |
|---------|------|--------------|
| Unrestricted PowerShell execution | Code execution | `ExecutionPolicy` in GPO |
| Stored passwords in GPP | Credential exposure | `cpassword` in SYSVOL XML files |
| Disabled Windows Firewall | Lateral movement | Firewall profile settings |
| Disabled UAC | Privilege escalation | `EnableLUA` registry setting |
| AutoLogon credentials | Credential exposure | `DefaultPassword` in registry |

## Event Log Forensics

### Key Security Events

| Event ID | Description | Significance |
|----------|-------------|-------------|
| 4624 | Successful logon | Track who logged in and how |
| 4625 | Failed logon | Brute force / password spraying |
| 4648 | Explicit credential logon | Lateral movement (runas, PsExec) |
| 4672 | Special privileges assigned | Admin logon |
| 4720 | User account created | Persistence |
| 4724 | Password reset attempt | Account takeover |
| 4728/4732/4756 | Member added to security group | Privilege escalation |
| 4768 | Kerberos TGT requested | Authentication |
| 4769 | Kerberos service ticket | Kerberoasting |
| 4771 | Kerberos pre-auth failed | Password spraying |
| 1102 | Audit log cleared | Anti-forensics |
| 4688 | Process creation | Command execution tracking |
| 4697 | Service installed | Persistence |
| 7045 | New service installed | Persistence |

```powershell
# Failed logon attempts (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} |
  Select-Object TimeCreated, @{N='TargetUser';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[19].Value}}, @{N='LogonType';E={$_.Properties[10].Value}} |
  Format-Table

# Successful admin logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=(Get-Date).AddDays(-1)} |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[1].Value}} |
  Group-Object User | Sort-Object Count -Descending | Format-Table Count, Name

# Account creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 20 |
  Select-Object TimeCreated, @{N='NewUser';E={$_.Properties[0].Value}}, @{N='CreatedBy';E={$_.Properties[4].Value}} |
  Format-Table

# Audit log cleared events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 10 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{N='ClearedBy';E={$_.Properties[1].Value}} | Format-Table

# Process creation with command lines (requires audit policy)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-1)} |
  Select-Object TimeCreated, @{N='Process';E={$_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}}, @{N='User';E={$_.Properties[1].Value}} |
  Format-Table

# PowerShell script block logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 |
  Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}} | Format-List
```

## Registry Security Audit

```powershell
# AutoRun entries (persistence)
$autorunPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
foreach ($path in $autorunPaths) {
  if (Test-Path $path) {
    Write-Host "`n=== $path ===" -ForegroundColor Cyan
    Get-ItemProperty $path | Format-List
  }
}

# LSA protection settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object RunAsPPL, LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous

# UAC settings
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, FilterAdministratorToken

# RDP settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | Select-Object fDenyTSConnections, fSingleSessionPerUser
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select-Object SecurityLayer, UserAuthentication, MinEncryptionLevel

# WDigest (plaintext password storage)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue

# AlwaysInstallElevated (privilege escalation)
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

# AMSI bypass check
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\*' -ErrorAction SilentlyContinue
```

## Windows Defender Configuration

```powershell
# Overall status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, AntispywareEnabled

# Signature info
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated, AntivirusSignatureVersion, NISSignatureLastUpdated

# Exclusions (attackers add these for persistence)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess -ErrorAction SilentlyContinue
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension -ErrorAction SilentlyContinue

# Attack Surface Reduction rules
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions

# Controlled Folder Access
Get-MpPreference | Select-Object EnableControlledFolderAccess

# Recent threat detections
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 ThreatID, @{N='Threat';E={(Get-MpThreat -ThreatID $_.ThreatID).ThreatName}}, InitialDetectionTime, ProcessName, DomainUser | Format-Table

# Scan history
Get-MpComputerStatus | Select-Object QuickScanStartTime, QuickScanEndTime, FullScanStartTime, FullScanEndTime, QuickScanAge, FullScanAge
```

## Audit Policy Review

```powershell
# Current audit policy
auditpol /get /category:*

# Recommended audit settings check
$recommended = @{
  'Credential Validation' = 'Success and Failure'
  'Logon' = 'Success and Failure'
  'Logoff' = 'Success'
  'Account Lockout' = 'Failure'
  'Special Logon' = 'Success'
  'Process Creation' = 'Success'
  'Audit Policy Change' = 'Success'
  'User Account Management' = 'Success and Failure'
  'Security Group Management' = 'Success'
}

# Check if command line auditing is enabled for process creation
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue

# Check PowerShell logging
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
```

### Recommended Audit Policy

| Category | Subcategory | Recommended |
|----------|-------------|-------------|
| Account Logon | Credential Validation | Success + Failure |
| Logon/Logoff | Logon | Success + Failure |
| Logon/Logoff | Logoff | Success |
| Logon/Logoff | Special Logon | Success |
| Account Management | User Account Management | Success + Failure |
| Account Management | Security Group Management | Success |
| Detailed Tracking | Process Creation | Success |
| Policy Change | Audit Policy Change | Success + Failure |
| Privilege Use | Sensitive Privilege Use | Success + Failure |

## Privilege Escalation Checks

```powershell
# Current user privileges
whoami /priv

# Check for SeImpersonatePrivilege (Potato attacks)
whoami /priv | Select-String "SeImpersonate|SeAssignPrimary"

# Unquoted service paths
Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.StartMode -ne 'Disabled' } |
  Format-Table Name, PathName, StartName, StartMode

# Writable service binaries
Get-WmiObject Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
  $path = ($_.PathName -split '"')[1]
  if (!$path) { $path = ($_.PathName -split ' ')[0] }
  if (Test-Path $path) {
    $acl = Get-Acl $path
    $writable = $acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.IdentityReference -match 'Users|Everyone|Authenticated' }
    if ($writable) { [PSCustomObject]@{Service=$_.Name; Path=$path; WritableBy=$writable.IdentityReference} }
  }
} | Format-Table

# AlwaysInstallElevated check
$hklm = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hkcu = Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
  Write-Warning "AlwaysInstallElevated is ENABLED — any user can install MSI as SYSTEM"
}

# Writable PATH directories
$env:PATH -split ';' | ForEach-Object {
  if ($_ -and (Test-Path $_)) {
    $acl = Get-Acl $_
    $writable = $acl.Access | Where-Object { $_.FileSystemRights -match 'Write|FullControl|Modify' -and $_.IdentityReference -match 'Users|Everyone|Authenticated' }
    if ($writable) { [PSCustomObject]@{Path=$_; WritableBy=$writable.IdentityReference} }
  }
} | Format-Table

# Stored credentials
cmdkey /list

# Saved Wi-Fi passwords
netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object {
  $profile = ($_ -split ':')[1].Trim()
  netsh wlan show profile name="$profile" key=clear | Select-String 'Key Content'
}
```

## Credential Store & LSA Audit

```powershell
# Credential Manager entries
cmdkey /list

# LSA protection status
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue

# Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue |
  Select-Object SecurityServicesRunning, VirtualizationBasedSecurityStatus

# WDigest plaintext password caching
$wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -eq 1) {
  Write-Warning "WDigest is storing plaintext passwords in memory"
} else {
  Write-Host "WDigest plaintext caching is disabled (good)" -ForegroundColor Green
}

# NTLM settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object LmCompatibilityLevel, NtlmMinClientSec, NtlmMinServerSec, RestrictSendingNTLMTraffic

# Cached logon count
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -ErrorAction SilentlyContinue

# DPAPI master key info
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -ErrorAction SilentlyContinue | Format-Table Name, LastWriteTime
```

### LSA Security Recommendations

| Setting | Recommended Value | Purpose |
|---------|-------------------|---------|
| RunAsPPL | 1 | Protect LSASS from credential dumping |
| LmCompatibilityLevel | 5 | Send NTLMv2 only, refuse LM and NTLM |
| UseLogonCredential | 0 | Disable WDigest plaintext password caching |
| Credential Guard | Enabled | Virtualization-based credential isolation |
| CachedLogonsCount | 2 | Limit cached domain credentials on endpoints |
