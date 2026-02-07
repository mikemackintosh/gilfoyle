# String Extraction

Extract and analyse strings from a suspicious file to identify indicators of compromise, embedded URLs, command-and-control infrastructure, and other forensic artefacts.

## Arguments

$ARGUMENTS should be a path to the suspicious file.

Examples:
- `/tmp/suspicious.bin`
- `~/Downloads/malware_sample`
- `/var/tmp/unknown_binary`

## Workflow

1. Parse the file path from `$ARGUMENTS`.
2. Verify the file exists and show the user the exact commands before executing.
3. **Remind the user:** This is read-only static analysis. Do not execute the file.

### Extract ASCII strings

```bash
strings <file> | head -200
```

### Extract longer strings (reduces noise)

```bash
strings -n 10 <file>
```

### Extract Unicode (UTF-16LE) strings

Common in Windows binaries:

```bash
strings -e l <file> | head -100
```

### Search for URLs and domains

```bash
strings <file> | grep -oE 'https?://[^ "]+'
strings <file> | grep -oE '[a-zA-Z0-9.-]+\.(com|net|org|io|ru|cn|tk|xyz|top|pw|cc|info|biz)'
```

### Search for IP addresses

```bash
strings <file> | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u
```

Filter out common non-routable addresses and report only potentially interesting IPs.

### Search for email addresses

```bash
strings <file> | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u
```

### Search for file paths

```bash
# Windows paths
strings <file> | grep -iE '[A-Z]:\\[^ "]+' | sort -u

# Unix paths
strings <file> | grep -E '^/(tmp|var|etc|home|usr|bin|dev|proc|sys)/[^ ]+' | sort -u
```

### Search for Windows registry keys

```bash
strings <file> | grep -iE '(HKEY_|HKLM\\|HKCU\\|SOFTWARE\\|CurrentVersion\\Run|CurrentVersion\\Explorer)' | sort -u
```

Registry persistence keys are a strong indicator of malware intent.

### Search for Base64-encoded blobs

```bash
strings <file> | grep -oE '[A-Za-z0-9+/]{40,}={0,2}'
```

Large Base64 strings may contain encoded payloads, scripts, or configuration data. Decode with:

```bash
echo "<base64_string>" | base64 -d
```

### Search for suspicious API names

```bash
strings <file> | grep -iE '(VirtualAlloc|VirtualProtect|CreateRemoteThread|WriteProcessMemory|NtUnmapViewOfSection|LoadLibraryA?|GetProcAddress|WinExec|ShellExecuteA?|URLDownloadToFile|InternetOpenA?|HttpSendRequest|CreateServiceA?|RegSetValueExA?|CreateProcessA?|OpenProcess|ReadProcessMemory|SetWindowsHookEx|CreateToolhelp32Snapshot|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)' | sort -u
```

Flag these categories:
- **Process injection:** VirtualAlloc, CreateRemoteThread, WriteProcessMemory, NtUnmapViewOfSection
- **Dynamic loading:** LoadLibrary, GetProcAddress (minimal imports + these = likely packed)
- **Execution:** WinExec, ShellExecute, CreateProcess
- **Network:** URLDownloadToFile, InternetOpen, HttpSendRequest
- **Persistence:** CreateService, RegSetValue
- **Anti-debug:** IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess

### Search for shell commands and scripting indicators

```bash
strings <file> | grep -iE '(powershell|cmd\.exe|/bin/sh|/bin/bash|wget |curl |chmod |eval\(|exec\(|subprocess|os\.system|base64 -d|python -c)' | sort -u
```

4. Summarise findings:
   - Total number of strings extracted
   - Notable URLs, IPs, and domains (potential C2 infrastructure)
   - Suspicious API calls and their likely purpose
   - File paths and registry keys (potential persistence mechanisms)
   - Base64 blobs (decode and report contents if safe)
   - Shell commands or scripting indicators
   - Overall assessment and recommended next steps

## Security Notes

- **String extraction is read-only** and does not execute any code within the file.
- Not all strings found are meaningful — binary data often produces false-positive matches. Use context and frequency to prioritise.
- Packed or encrypted malware will yield very few useful strings. If string output is sparse relative to file size, the binary is likely packed — see `/mal-static-analysis` for packer detection.
- For obfuscated strings (stack strings, XOR-encoded), consider using FLOSS (Mandiant FLARE Obfuscated String Solver) if available.
- Extracted IOCs (IPs, domains, hashes) should be checked against threat intelligence feeds before drawing conclusions.
