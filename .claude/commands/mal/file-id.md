# File Identification

Identify a suspicious file's true type, metadata, and characteristics. Uses magic byte analysis rather than trusting the file extension.

## Arguments

$ARGUMENTS should be a path to the suspicious file.

Examples:
- `/tmp/suspicious.bin`
- `~/Downloads/invoice.pdf.exe`
- `/var/tmp/unknown_sample`

## Workflow

1. Parse the file path from `$ARGUMENTS`.
2. Verify the file exists and show the user the exact commands before executing.
3. **Remind the user:** Do not execute the file. This is static analysis only.

### File type identification

```bash
file <file>
```

This reads magic bytes to determine the true file type regardless of extension.

### Magic byte inspection

```bash
xxd <file> | head -4
```

Compare the first bytes against known signatures:
- `4D 5A` — PE executable (Windows EXE/DLL)
- `7F 45 4C 46` — ELF binary (Linux)
- `CF FA ED FE` / `CE FA ED FE` — Mach-O binary (macOS)
- `50 4B 03 04` — ZIP archive (also DOCX, XLSX, JAR, APK)
- `25 50 44 46` — PDF document
- `D0 CF 11 E0` — OLE2 compound document (DOC, XLS, PPT)
- `23 21` — Script with shebang (`#!`)

### File metadata

```bash
stat <file>                  # macOS
stat -c '%s %U %G %y %n' <file>   # Linux
ls -la <file>
```

Key details to report:
- File size (flag unusually small executables < 10 KB or very large files > 100 MB)
- Ownership and permissions (flag world-writable or SUID/SGID)
- Timestamps (creation, modification, access)

### Double extension check

```bash
basename <file> | grep -E '\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$'
```

Flag files with double extensions such as `report.pdf.exe`, `invoice.doc.scr`, or `image.jpg.js` — these are a common social engineering technique.

### Unicode control character check

```bash
echo -n "$(basename <file>)" | xxd | grep -E '(e2 80 ae|e2 80 ab|e2 80 8f)'
```

Right-to-Left Override (U+202E) characters can make `reportexe.pdf` appear as `reportfdp.exe` in file browsers.

### Hash computation

```bash
md5 <file> 2>/dev/null || md5sum <file>
shasum -a 1 <file>
shasum -a 256 <file>
```

Record hashes for threat intelligence lookups (VirusTotal, MISP, OTX).

4. Summarise findings:
   - True file type (from magic bytes, not extension)
   - Whether the extension matches the actual type (flag mismatches)
   - File size and metadata
   - Any suspicious characteristics (double extensions, unusual permissions, timestamps)
   - SHA-256 hash for reputation lookup
   - Recommended next steps (string extraction, static analysis, sandbox)

## Security Notes

- **Never execute the file** during identification. All operations here are read-only.
- A mismatch between the file extension and actual type is a strong indicator of social engineering.
- Files with double extensions are almost always malicious when received from untrusted sources.
- Compute hashes before any other tool processes the file to establish a baseline.
- If the file is on a production system, consider copying it to an isolated analysis workstation first.
