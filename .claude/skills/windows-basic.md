---
name: Windows Basic
description: Windows system enumeration, user management, network config, services, firewall, processes, software inventory, and scheduled tasks.
instructions: |
  Use this skill when the user needs to perform basic Windows system security checks — enumerating
  users and groups, reviewing network config, auditing services, checking firewall rules, listing
  installed software, inspecting running processes, or reviewing scheduled tasks. Commands use
  PowerShell and built-in Windows tools. Always show commands before executing and explain findings.
---

# Windows Basic Skill

## Related Commands
- `/win:sysinfo` — System information and OS details
- `/win:users` — User and group enumeration
- `/win:network` — Network configuration and connections
- `/win:services` — Windows services audit
- `/win:firewall` — Windows Firewall status and rules
- `/win:software` — Installed software inventory
- `/win:processes` — Running processes analysis
- `/win:tasks` — Scheduled tasks review

## System Information

```powershell
# OS version and build
systeminfo | Select-String "OS Name|OS Version|System Type|Hotfix"

# PowerShell version
$PSVersionTable

# Environment details
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsBuildNumber, OsArchitecture, WindowsVersion, OsLastBootUpTime

# Uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Check if domain-joined
(Get-WmiObject Win32_ComputerSystem).PartOfDomain
```

## User & Group Enumeration

```powershell
# Local users
Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires

# Local groups
Get-LocalGroup | Format-Table Name, Description

# Members of Administrators group
Get-LocalGroupMember -Group "Administrators"

# Users who have logged in recently
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20 |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}

# Accounts with no password expiry
Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled }

# Users with blank passwords (check policy)
net accounts
```

### Logon Types Reference

| Type | Name | Meaning |
|------|------|---------|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, net use, etc. |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain credentials |

## Network Configuration

```powershell
# IP configuration
Get-NetIPConfiguration | Format-Table InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer

# All adapters with details
Get-NetAdapter | Format-Table Name, Status, MacAddress, LinkSpeed

# DNS client settings
Get-DnsClientServerAddress | Format-Table InterfaceAlias, ServerAddresses

# Routing table
Get-NetRoute | Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# Active connections
Get-NetTCPConnection -State Established | Sort-Object RemotePort |
  Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Listening ports
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
  Format-Table LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess).ProcessName}}

# Hosts file
Get-Content C:\Windows\System32\drivers\etc\hosts | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' }
```

## Windows Services

```powershell
# Running services
Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object DisplayName |
  Format-Table Status, Name, DisplayName

# Services running as non-default accounts
Get-WmiObject Win32_Service | Where-Object { $_.StartName -ne 'LocalSystem' -and $_.StartName -ne 'NT AUTHORITY\LocalService' -and $_.StartName -ne 'NT AUTHORITY\NetworkService' } |
  Format-Table Name, StartName, State, StartMode

# Auto-start services that are stopped
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
  Format-Table Name, DisplayName, Status

# Services with unquoted paths (potential privilege escalation)
Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '\s' } |
  Format-Table Name, PathName, StartName
```

## Windows Firewall

```powershell
# Firewall profile status
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Inbound allow rules
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Format-Table DisplayName, Profile, @{N='LocalPort';E={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}}

# Rules allowing any remote address
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Where-Object { (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress -eq 'Any' }

# Firewall log location
Get-NetFirewallProfile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
```

## Running Processes

```powershell
# Processes with resource usage
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, Id, CPU, WorkingSet, Path

# Processes with network connections
Get-NetTCPConnection -State Established |
  Select-Object @{N='Process';E={(Get-Process -Id $_.OwningProcess).ProcessName}}, RemoteAddress, RemotePort, OwningProcess |
  Sort-Object Process | Format-Table

# Unsigned processes (potential malware indicator)
Get-Process | Where-Object { $_.Path } | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.Path
  if ($sig.Status -ne 'Valid') { [PSCustomObject]@{Name=$_.Name; PID=$_.Id; Path=$_.Path; SigStatus=$sig.Status} }
} | Format-Table

# Processes running from temp directories
Get-Process | Where-Object { $_.Path -match '\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp' } |
  Format-Table Name, Id, Path
```

## Installed Software

```powershell
# Installed programs (64-bit)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName | Format-Table

# Installed programs (32-bit on 64-bit OS)
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName | Format-Table

# Installed Windows features
Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | Format-Table FeatureName

# Recent Windows updates
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn
```

## Scheduled Tasks

```powershell
# All non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
  Format-Table TaskName, State, TaskPath

# Tasks with their actions (what they run)
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  $task = $_
  $task.Actions | ForEach-Object {
    [PSCustomObject]@{Name=$task.TaskName; Execute=$_.Execute; Arguments=$_.Arguments; RunAs=$task.Principal.UserId}
  }
} | Format-Table

# Tasks running as SYSTEM
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' -and $_.TaskPath -notlike '\Microsoft\*' } |
  Format-Table TaskName, TaskPath, State

# Tasks created in the last 30 days
Get-ScheduledTask | Where-Object { $_.Date -and [datetime]$_.Date -gt (Get-Date).AddDays(-30) } |
  Format-Table TaskName, Date, State
```

## Security Quick Checks

```powershell
# Password policy
net accounts

# Audit policy
auditpol /get /category:*

# Check if RDP is enabled
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections

# Check Windows Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated

# Check for pending reboot
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
```
