# Windows Defender Status and Configuration

Review Windows Defender configuration, exclusions, ASR rules, threat detections, and scan history.

## Arguments

$ARGUMENTS is optional:
- `--exclusions` — focus on Defender exclusions (attacker persistence vector)
- `--threats` — show recent threat detections
- `--asr` — show Attack Surface Reduction rule status
- (no args — comprehensive Defender review)

Examples:
- (no args — full Defender review)
- `--exclusions`
- `--threats`
- `--asr`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Protection status

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled
```

### Step 2 — Signature and scan status

```powershell
Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion, AntispywareSignatureLastUpdated, QuickScanAge, FullScanAge, QuickScanStartTime, FullScanStartTime
```

### Step 3 — Exclusions (attacker favourite)

```powershell
$prefs = Get-MpPreference
Write-Host "`n=== Path Exclusions ===" -ForegroundColor Cyan
$prefs.ExclusionPath
Write-Host "`n=== Process Exclusions ===" -ForegroundColor Cyan
$prefs.ExclusionProcess
Write-Host "`n=== Extension Exclusions ===" -ForegroundColor Cyan
$prefs.ExclusionExtension
Write-Host "`n=== IP Exclusions ===" -ForegroundColor Cyan
$prefs.ExclusionIpAddress
```

### Step 4 — Attack Surface Reduction rules

```powershell
$asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
$asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
if ($asrRules) {
  for ($i=0; $i -lt $asrRules.Count; $i++) {
    $action = switch ($asrActions[$i]) { 0 {'Disabled'} 1 {'Block'} 2 {'Audit'} 6 {'Warn'} }
    [PSCustomObject]@{RuleID=$asrRules[$i]; Action=$action}
  }
} else {
  Write-Host "No ASR rules configured"
}
```

### Step 5 — Recent detections

```powershell
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID, InitialDetectionTime, ProcessName, DomainUser, @{N='Action';E={$_.ActionSuccess}} | Format-Table
```

3. Flag findings:
   - Any protection feature disabled
   - Signatures older than 7 days
   - Exclusions on broad paths (`C:\`, `C:\Users`, `%TEMP%`)
   - No ASR rules configured
   - Recent unresolved threats

## Security Notes

- **Defender exclusions** are a favourite persistence technique — attackers add exclusions for their malware directories. Review all exclusions carefully.
- Broad path exclusions (`C:\Users\*`, `C:\Temp`) effectively disable Defender for common malware drop locations.
- **ASR rules** provide defence against Office macro abuse, credential theft, script-based attacks, and more. Not having ASR configured is a missed security opportunity.
- Signatures older than 7 days indicate update failures — Defender should update daily.
- **Tamper Protection** prevents unauthorised changes to Defender settings. Verify it is enabled.
