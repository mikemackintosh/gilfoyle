# YARA Rule Test

Write or test YARA rules against files and directories. Generate starter templates for common detection scenarios.

## Arguments

$ARGUMENTS should include:
- A YARA rule file and a target file or directory to scan
- Or `--template <type>` to generate a starter rule: `malware`, `packer`, `webshell`, `exploit`, `document`, `generic`

Examples:
- `my_rule.yar /path/to/suspect_file`
- `rules/ /path/to/directory/`
- `--template malware`
- `--template webshell`

## Workflow

1. Parse the arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Test a YARA rule against a file or directory

```bash
yara <rule_file> <target_file_or_directory>
```

With additional context:

```bash
# Show matching strings
yara -s <rule_file> <target>

# Show matching string offsets
yara -s -e <rule_file> <target>

# Scan recursively
yara -r <rule_file> <target_directory>

# Set a timeout (seconds)
yara -a 60 <rule_file> <target>

# Show rules that did NOT match (negated)
yara -n <rule_file> <target>

# Show metadata for matching rules
yara -m <rule_file> <target>

# Use multiple rule files
yara <rule1.yar> <rule2.yar> <target>

# Compile rules for faster repeated scanning
yarac <rule_file> compiled.yarc
yara compiled.yarc <target>
```

### Generate a starter rule template

#### Malware template

```yara
rule Malware_FamilyName {
    meta:
        author = "analyst"
        description = "Detects FamilyName malware"
        date = "2025-01-01"
        hash = ""
        reference = ""
        severity = "high"
        tlp = "white"

    strings:
        $s1 = "suspicious_string" ascii wide
        $s2 = "another_indicator" nocase
        $hex1 = { 4D 5A 90 00 03 00 00 00 }
        $url = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,6}\/[a-z0-9]+/ nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        2 of ($s*) and
        $hex1
}
```

#### Packer / obfuscation template

```yara
rule Packed_Suspicious {
    meta:
        author = "analyst"
        description = "Detects packed or obfuscated executable"
        date = "2025-01-01"
        severity = "medium"

    strings:
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $themida = ".themida" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            any of them or
            math.entropy(0, filesize) > 7.0
        )
}
```

#### Web shell template

```yara
rule Webshell_Generic {
    meta:
        author = "analyst"
        description = "Detects generic web shell indicators"
        date = "2025-01-01"
        severity = "critical"

    strings:
        $php1 = "eval($_" ascii nocase
        $php2 = "base64_decode($_" ascii nocase
        $php3 = "system($_" ascii nocase
        $php4 = "passthru(" ascii nocase
        $php5 = "shell_exec(" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii

    condition:
        filesize < 500KB and
        any of them
}
```

#### Exploit / shellcode template

```yara
rule Exploit_Shellcode {
    meta:
        author = "analyst"
        description = "Detects common shellcode patterns"
        date = "2025-01-01"
        severity = "high"

    strings:
        // NOP sled
        $nop = { 90 90 90 90 90 90 90 90 }
        // Common x86 shellcode prologue
        $shellcode1 = { 31 C0 50 68 }
        $shellcode2 = { EB ?? 5? 31 }
        // WinExec call pattern
        $winexec = { FF 15 ?? ?? ?? ?? 31 C0 50 }

    condition:
        any of them
}
```

#### Suspicious document template

```yara
rule Suspicious_Document {
    meta:
        author = "analyst"
        description = "Detects suspicious document with macros or embedded objects"
        date = "2025-01-01"
        severity = "medium"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $macro1 = "AutoOpen" ascii
        $macro2 = "AutoExec" ascii
        $macro3 = "Document_Open" ascii
        $vba1 = "Shell(" ascii nocase
        $vba2 = "WScript.Shell" ascii nocase
        $vba3 = "Powershell" ascii nocase
        $vba4 = "CreateObject" ascii nocase

    condition:
        $ole at 0 and
        any of ($macro*) and
        any of ($vba*)
}
```

3. If testing a rule, present results clearly:
   - Matching rule name(s)
   - Matched file(s)
   - Matched strings and their offsets (if `-s` flag used)
   - Total files scanned vs. matched
4. If generating a template, write the rule to a file or display it, and explain each section.

### Verify YARA is installed

```bash
yara --version 2>/dev/null || echo "YARA is not installed. Install with: brew install yara (macOS) or apt install yara (Debian/Ubuntu)"
```

## Security Notes

- YARA scans are read-only and safe to run against any file or directory.
- Be cautious scanning very large directories — set a timeout with `-a` to avoid long-running scans.
- When writing rules, aim for specificity to reduce false positives — combine multiple strings with file type checks and size constraints.
- Test new rules against known-clean files and known-malicious samples before deploying to production.
- YARA rules may contain indicators that are themselves sensitive (e.g., C2 domains, hashes). Handle rule files according to your TLP marking.
- Use `import "pe"`, `import "math"`, or other modules for richer detection logic when scanning PE files.
