# Active Directory Enumeration

Enumerate Active Directory objects — domain info, users, groups, computers, trusts, and delegation settings.

## Arguments

$ARGUMENTS is optional:
- `--users` — focus on user enumeration
- `--groups` — focus on privileged group enumeration
- `--computers` — focus on computer accounts
- `--kerberoast` — find Kerberoastable accounts (users with SPNs)
- `--asrep` — find AS-REP roastable accounts
- `--delegation` — find unconstrained/constrained delegation
- `--stale` — find stale accounts (90+ days inactive)
- (no args — full AD enumeration)

Examples:
- (no args — full enumeration)
- `--kerberoast`
- `--stale`
- `--delegation`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Confirm the ActiveDirectory PowerShell module is available.
3. Show the user the exact commands before executing.

### Step 1 — Domain overview

```powershell
Import-Module ActiveDirectory
Get-ADDomain | Select-Object Name, DNSRoot, NetBIOSName, DomainMode, PDCEmulator, InfrastructureMaster
Get-ADForest | Select-Object Name, ForestMode, Domains, GlobalCatalogs
```

### Step 2 — User enumeration

```powershell
# Privileged accounts
Get-ADUser -Filter { AdminCount -eq 1 } -Properties MemberOf, LastLogonDate, PasswordLastSet, PasswordNeverExpires, ServicePrincipalName |
  Format-Table Name, LastLogonDate, PasswordLastSet, PasswordNeverExpires

# Kerberoastable accounts (users with SPNs)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName, AdminCount, PasswordLastSet |
  Select-Object Name, AdminCount, PasswordLastSet, @{N='SPNs';E={$_.ServicePrincipalName -join ', '}} |
  Format-Table

# AS-REP roastable accounts
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth |
  Format-Table Name, DistinguishedName

# Accounts with password never expires
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordLastSet |
  Format-Table Name, PasswordLastSet
```

### Step 3 — Group enumeration

```powershell
@("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","DnsAdmins","Group Policy Creator Owners") | ForEach-Object {
  $members = Get-ADGroupMember -Identity $_ -Recursive -ErrorAction SilentlyContinue
  [PSCustomObject]@{Group=$_; Count=$members.Count; Members=($members.Name -join ', ')}
} | Format-Table Group, Count, Members -Wrap
```

### Step 4 — Delegation

```powershell
# Unconstrained delegation (computers)
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Format-Table Name, DistinguishedName

# Unconstrained delegation (users)
Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
  Format-Table Name, DistinguishedName

# Constrained delegation
Get-ADObject -Filter { msDS-AllowedToDelegateTo -ne "$null" } -Properties msDS-AllowedToDelegateTo |
  Select-Object Name, ObjectClass, @{N='DelegateTo';E={$_.'msDS-AllowedToDelegateTo' -join ', '}} |
  Format-Table
```

### Step 5 — Trusts

```powershell
Get-ADTrust -Filter * | Format-Table Name, Direction, TrustType, IntraForest, TGTDelegation
```

3. Present findings in a risk-prioritised summary.

## Security Notes

- **Kerberoastable accounts** with SPNs set on user accounts (not computer accounts) can have their service tickets cracked offline to reveal the account password. Prioritise accounts with `AdminCount=1`.
- **AS-REP roastable accounts** do not require Kerberos pre-authentication, allowing offline cracking of their AS-REP.
- **Unconstrained delegation** allows a compromised host to impersonate any user who authenticates to it — this is a high-severity finding on non-DC machines.
- **DnsAdmins** group members can escalate to Domain Admin by loading a malicious DLL into the DNS service.
- Requires the `ActiveDirectory` PowerShell module (RSAT or Domain Controller).
