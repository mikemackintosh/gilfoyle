# Group Policy Analysis

Analyse Group Policy Objects for security-relevant settings, misconfigurations, and policy coverage.

## Arguments

$ARGUMENTS is optional:
- `<GPO-name>` — analyse a specific GPO
- `--password` — check password policy GPOs
- `--audit` — check audit policy GPOs
- `--all` — list all GPOs with details
- (no args — security-focused GPO review)

Examples:
- (no args — security GPO review)
- `Default Domain Policy`
- `--password`
- `--audit`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Confirm the GroupPolicy module is available.
3. Show the user the exact commands before executing.

### Step 1 — GPO inventory

```powershell
Import-Module GroupPolicy
Get-GPO -All | Sort-Object ModificationTime -Descending |
  Format-Table DisplayName, GpoStatus, CreationTime, ModificationTime
```

### Step 2 — Security-focused GPO analysis

```powershell
# Password policy (from Default Domain Policy)
Get-ADDefaultDomainPasswordPolicy | Format-List ComplexityEnabled, MinPasswordLength, MinPasswordAge, MaxPasswordAge, PasswordHistoryCount, LockoutThreshold, LockoutDuration, LockoutObservationWindow

# Generate resultant set of policy
gpresult /r

# Check for GPP passwords (cpassword in SYSVOL)
# This checks for the MS14-025 vulnerability
Get-ChildItem "\\$((Get-ADDomain).DNSRoot)\SYSVOL" -Recurse -Include '*.xml' -ErrorAction SilentlyContinue |
  Select-String 'cpassword' | Select-Object Path, Line
```

### Step 3 — GPO HTML report

```powershell
# Generate HTML report for a specific GPO
Get-GPOReport -Name "<GPO-Name>" -ReportType Html -Path "gpo-report.html"

# Generate all GPO reports
Get-GPO -All | ForEach-Object {
  Get-GPOReport -Guid $_.Id -ReportType Html -Path "gpo-$($_.DisplayName -replace '\s','_').html"
}
```

3. Analyse GPO settings and flag:
   - Weak password policy (MinLength < 14, no complexity)
   - Missing account lockout
   - Disabled audit policies
   - GPP stored passwords (MS14-025)
   - Unrestricted PowerShell execution policy
   - Disabled Defender or firewall via GPO

## Security Notes

- **GPP passwords** (Group Policy Preferences with `cpassword`) are trivially decryptable — the AES key is publicly known (MS14-025). This is a critical finding.
- Password policy only applies from GPOs linked at the domain level. OU-linked password GPOs are ignored (use Fine-Grained Password Policies instead).
- The `GpoStatus` field shows if a GPO is fully enabled, partially disabled, or fully disabled.
- Requires the `GroupPolicy` and `ActiveDirectory` PowerShell modules.
