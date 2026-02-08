# Installed Software Inventory

List installed software, Windows features, and recent updates to identify outdated or vulnerable applications.

## Arguments

$ARGUMENTS is optional:
- `--updates` — focus on Windows updates / hotfixes
- `--features` — show enabled Windows features
- `<search-term>` — search installed software by name
- (no args — full software inventory)

Examples:
- (no args — full inventory)
- `--updates`
- `--features`
- `Java`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Installed programs

```powershell
# 64-bit programs
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName | Format-Table

# 32-bit programs (on 64-bit OS)
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName | Format-Table
```

### Step 2 — Windows updates

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn, InstalledBy
```

### Step 3 — Enabled features

```powershell
Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } |
  Sort-Object FeatureName | Format-Table FeatureName
```

3. Flag findings:
   - Known vulnerable software versions
   - No updates installed recently (stale patching)
   - Risky features enabled (SMBv1, Telnet, TFTP)

## Security Notes

- **SMBv1** should always be disabled — it is vulnerable to EternalBlue (MS17-010).
- **Telnet Client/Server** enabled is a red flag — it transmits credentials in plaintext.
- Software without recent updates may have known CVEs. Cross-reference versions against vulnerability databases.
- Last hotfix date indicates patching cadence — anything beyond 30 days is concerning in production.
