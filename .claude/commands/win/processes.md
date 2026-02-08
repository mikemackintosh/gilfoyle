# Running Processes Analysis

Analyse running processes for suspicious activity — unsigned binaries, processes in temp directories, unusual network connections, and high resource consumers.

## Arguments

$ARGUMENTS is optional:
- `--unsigned` — show only unsigned / invalid signature processes
- `--network` — show processes with active network connections
- `--suspicious` — run all suspicion checks
- `<process-name>` — details for a specific process
- (no args — overview and suspicious process scan)

Examples:
- (no args — full process analysis)
- `--unsigned`
- `--network`
- `svchost`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Process overview

```powershell
Get-Process | Sort-Object CPU -Descending |
  Select-Object -First 25 Name, Id, CPU, @{N='MemMB';E={[math]::Round($_.WorkingSet/1MB,1)}}, Path |
  Format-Table
```

### Step 2 — Suspicious indicators

```powershell
# Unsigned processes
Get-Process | Where-Object { $_.Path } | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
  if ($sig.Status -ne 'Valid') {
    [PSCustomObject]@{Name=$_.Name; PID=$_.Id; Path=$_.Path; SigStatus=$sig.Status}
  }
} | Format-Table

# Processes in temp/user directories
Get-Process | Where-Object { $_.Path -match '\\Temp\\|\\tmp\\|\\Downloads\\|\\AppData\\' } |
  Select-Object Name, Id, Path | Format-Table

# Processes with network connections
Get-NetTCPConnection -State Established | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [PSCustomObject]@{Process=$proc.Name; PID=$_.OwningProcess; Remote="$($_.RemoteAddress):$($_.RemotePort)"; Path=$proc.Path}
} | Sort-Object Process | Format-Table
```

3. Flag findings:
   - Unsigned executables running
   - Processes executing from temp/download directories
   - Unexpected outbound connections
   - Processes masquerading as system binaries (wrong path for the name)

## Security Notes

- Legitimate Windows system processes run from `C:\Windows\System32\`. The same process name from another path is suspicious (e.g., `svchost.exe` from `C:\Users\`).
- Unsigned processes aren't always malicious but warrant investigation, especially if running as SYSTEM.
- Processes in temp directories are a common indicator of malware execution — malware often drops to `%TEMP%` and runs from there.
