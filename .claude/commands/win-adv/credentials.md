# Credential Store and LSA Audit

Audit credential storage, LSA protection settings, NTLM configuration, Credential Guard, and cached credentials.

## Arguments

$ARGUMENTS is optional:
- `--lsa` — focus on LSA protection settings
- `--ntlm` — focus on NTLM configuration
- `--cached` — check cached credential settings
- `--guard` — check Credential Guard status
- (no args — full credential audit)

Examples:
- (no args — full audit)
- `--lsa`
- `--ntlm`
- `--guard`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. Requires elevated (Administrator) privileges for most checks.

### Step 1 — Credential Manager

```powershell
cmdkey /list
```

### Step 2 — LSA protection

```powershell
# RunAsPPL (protected process light for LSASS)
$ppl = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
if ($ppl.RunAsPPL -eq 1) {
  Write-Host "LSA Protection (RunAsPPL): ENABLED" -ForegroundColor Green
} else {
  Write-Host "LSA Protection (RunAsPPL): DISABLED — LSASS is vulnerable to credential dumping" -ForegroundColor Red
}

# Other LSA settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous, ForceGuest, DisableDomainCreds |
  Format-List
```

### Step 3 — WDigest (plaintext password caching)

```powershell
$wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -eq 1) {
  Write-Warning "WDigest UseLogonCredential = 1 — PLAINTEXT PASSWORDS stored in LSASS memory"
} elseif ($null -eq $wdigest.UseLogonCredential) {
  # On Win 2012 R2+ / Win 8.1+, default is disabled
  Write-Host "WDigest: Default (disabled on modern OS)" -ForegroundColor Green
} else {
  Write-Host "WDigest: Explicitly disabled" -ForegroundColor Green
}
```

### Step 4 — Credential Guard

```powershell
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
  $vbsStatus = switch ($dg.VirtualizationBasedSecurityStatus) { 0 {'Not running'} 1 {'Configured but not running'} 2 {'Running'} }
  $services = $dg.SecurityServicesRunning | ForEach-Object { switch ($_) { 0 {'None'} 1 {'Credential Guard'} 2 {'HVCI'} 3 {'System Guard'} } }
  Write-Host "VBS Status: $vbsStatus"
  Write-Host "Security Services: $($services -join ', ')"
} else {
  Write-Host "Device Guard: Not available (may require Hyper-V)"
}
```

### Step 5 — NTLM configuration

```powershell
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$level = switch ($lsa.LmCompatibilityLevel) {
  0 {'Send LM & NTLM'}
  1 {'Send LM & NTLM, use NTLMv2 if negotiated'}
  2 {'Send NTLM only'}
  3 {'Send NTLMv2 only'}
  4 {'Send NTLMv2 only, refuse LM'}
  5 {'Send NTLMv2 only, refuse LM & NTLM'}
  default {'Not configured (default: 3)'}
}
Write-Host "LM Compatibility Level: $($lsa.LmCompatibilityLevel) — $level"

# NTLM audit settings
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue |
  Select-Object RestrictSendingNTLMTraffic, AuditReceivingNTLMTraffic, RestrictReceivingNTLMTraffic |
  Format-List
```

### Step 6 — Cached domain logons

```powershell
$cached = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -ErrorAction SilentlyContinue
Write-Host "Cached Logons Count: $($cached.CachedLogonsCount) (default: 10, recommended: 2)"
```

3. Present a findings table with severity ratings and remediation steps.

## Security Notes

- **RunAsPPL disabled** is a critical finding — it allows tools like mimikatz to dump credentials from LSASS memory.
- **WDigest enabled** stores plaintext passwords in memory — this was the default on older Windows versions and is the primary target for credential dumping.
- **Credential Guard** uses hardware virtualisation to isolate credentials from the OS. When running, even SYSTEM-level access cannot dump credentials.
- **LmCompatibilityLevel < 3** means legacy LM or NTLM hashes may be sent over the network — these are trivially crackable.
- **CachedLogonsCount** controls how many domain credentials are cached locally. High values increase risk on stolen laptops.
- **NTLM auditing** should be enabled as a first step before restricting NTLM. Many legacy applications depend on NTLM.
