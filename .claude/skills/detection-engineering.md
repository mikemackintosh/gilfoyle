---
name: Detection Engineering
description: Writing, testing, and tuning detection rules — YARA, Sigma, Snort/Suricata — and related concepts like IOC formats and detection-as-code.
instructions: |
  Use this skill when the user is writing, reviewing, testing, or debugging detection rules such
  as YARA, Sigma, or Snort/Suricata signatures. Also applies to building regex patterns for WAF
  rules, working with IOC formats (STIX, OpenIOC), or discussing detection engineering practices
  like false positive tuning and detection-as-code. Provide syntax guidance, explain detection
  logic, and note effectiveness and coverage implications.
---

# Detection Engineering Skill

## Related Commands
- `/detect-yara` — Write or test YARA rules against files
- `/detect-sigma` — Create or validate Sigma detection rules
- `/detect-snort` — Create or explain Snort/Suricata signatures
- `/detect-regex` — Build and test regex patterns for detection rules

## YARA Rule Syntax

### Basic Structure

```yara
rule RuleName {
    meta:
        author = "analyst"
        description = "What this rule detects"
        date = "2025-01-01"
        reference = "https://example.com/report"
        severity = "high"

    strings:
        $text1 = "suspicious string"
        $hex1 = { 4D 5A 90 00 }
        $regex1 = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/

    condition:
        $text1 or $hex1 or $regex1
}
```

### String Types

| Type | Syntax | Example | Notes |
|------|--------|---------|-------|
| Text | `"string"` | `$s = "cmd.exe"` | Case-sensitive by default |
| Text (nocase) | `"string" nocase` | `$s = "cmd.exe" nocase` | Case-insensitive |
| Text (wide) | `"string" wide` | `$s = "cmd" wide` | UTF-16LE encoding |
| Text (ascii wide) | `"string" ascii wide` | `$s = "cmd" ascii wide` | Match both encodings |
| Text (fullword) | `"string" fullword` | `$s = "evil" fullword` | Must be delimited by non-alphanumeric chars |
| Hex | `{ AB CD }` | `$h = { 4D 5A }` | Raw byte patterns |
| Hex (wildcard) | `{ AB ?? CD }` | `$h = { 4D ?? 90 }` | `??` matches any byte |
| Hex (jump) | `{ AB [2-4] CD }` | `$h = { 4D [0-100] 90 }` | Variable-length gap |
| Hex (alternative) | `{ (AB | CD) }` | `$h = { (4D | 5A) 90 }` | Byte alternatives |
| Regex | `/pattern/` | `$r = /[a-z]{8}\.exe/` | Perl-compatible regex |
| Regex (nocase) | `/pattern/ nocase` | `$r = /cmd/ nocase` | Case-insensitive regex |

### Condition Operators

```yara
condition:
    // Boolean
    $a and $b
    $a or $b
    not $a

    // Counting
    #a > 3                        // string $a appears more than 3 times
    2 of ($s1, $s2, $s3)          // at least 2 of the listed strings
    any of ($s*)                  // any string starting with $s
    all of them                   // all defined strings
    3 of them                     // at least 3 of all defined strings

    // File size
    filesize < 500KB
    filesize > 1MB

    // Offset / position
    $a at 0                       // $a at file offset 0
    $a in (0..100)                // $a within first 100 bytes

    // Entry point (PE files)
    $a at entrypoint

    // Modules (pe, elf, math, etc.)
    pe.imports("kernel32.dll", "CreateRemoteThread")
    pe.number_of_sections > 5
    math.entropy(0, filesize) > 7.0
```

### Common YARA Modules

| Module | Use Case | Example |
|--------|----------|---------|
| `pe` | PE file analysis | `pe.imports("ws2_32.dll", "connect")` |
| `elf` | ELF file analysis | `elf.number_of_sections > 4` |
| `math` | Entropy, statistics | `math.entropy(0, filesize) > 7.0` |
| `hash` | Hash matching | `hash.sha256(0, filesize) == "abc..."` |
| `dotnet` | .NET assembly analysis | `dotnet.assembly.name == "Payload"` |
| `cuckoo` | Sandbox results | `cuckoo.network.http_request(/evil/)` |

## Sigma Rule Format

### Basic Structure

```yaml
title: Suspicious Process Creation
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: test
level: high
description: Detects suspicious process execution patterns
author: analyst
date: 2025/01/01
references:
    - https://example.com/report
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'encodedcommand'
            - '-enc '
            - 'downloadstring'
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative scripts
    - Software installers
fields:
    - Image
    - CommandLine
    - ParentImage
    - User
```

### Logsource Types

| Category | Product | Example |
|----------|---------|---------|
| `process_creation` | `windows` | Process execution events |
| `file_event` | `windows` | File creation, modification |
| `registry_event` | `windows` | Registry key changes |
| `network_connection` | `windows` | Outbound connections |
| `dns_query` | `windows` | DNS resolution |
| `image_load` | `windows` | DLL/module loading |
| `firewall` | (any) | Firewall logs |
| `proxy` | (any) | Web proxy logs |
| `webserver` | (any) | Web server access logs |
| `antivirus` | (any) | AV detection logs |

### Detection Modifiers

| Modifier | Meaning | Example |
|----------|---------|---------|
| `|contains` | Substring match | `CommandLine|contains: '-enc'` |
| `|endswith` | Ends with | `Image|endswith: '\cmd.exe'` |
| `|startswith` | Starts with | `Image|startswith: 'C:\Users'` |
| `|re` | Regex match | `CommandLine|re: '.*-e(nc)?.*'` |
| `|base64` | Base64-encoded value | `CommandLine|base64: 'Invoke-'` |
| `|base64offset` | Base64 with offset | `CommandLine|base64offset: 'http'` |
| `|cidr` | CIDR notation match | `DestinationIp|cidr: '10.0.0.0/8'` |
| `|all` | All values must match | `CommandLine|all|contains: ['-a', '-b']` |

### Level and Status

| Level | Use |
|-------|-----|
| `informational` | Baseline, enrichment |
| `low` | Noteworthy but common |
| `medium` | Should be reviewed |
| `high` | Likely malicious activity |
| `critical` | Almost certain compromise |

| Status | Meaning |
|--------|---------|
| `stable` | Production-ready |
| `test` | Needs validation |
| `experimental` | New, unvalidated |
| `deprecated` | No longer maintained |
| `unsupported` | Not supported by backends |

### Sigma to SIEM Conversion

Sigma rules are backend-agnostic. Use `sigma-cli` or `pySigma` to convert to specific SIEMs:

```bash
# Install sigma-cli
pip install sigma-cli

# List available backends
sigma list backends

# Convert to Splunk
sigma convert -t splunk -p sysmon rule.yml

# Convert to Elastic/EQL
sigma convert -t elasticsearch -p ecs_windows rule.yml

# Convert to Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender rule.yml

# Convert to QRadar AQL
sigma convert -t qradar rule.yml
```

## Snort/Suricata Rule Syntax

### Rule Structure

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

### Components

| Component | Values | Example |
|-----------|--------|---------|
| **Action** | `alert`, `log`, `pass`, `drop`, `reject` | `alert` |
| **Protocol** | `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `tls` | `tcp` |
| **Source IP** | IP, CIDR, variable, `any` | `$HOME_NET`, `any` |
| **Source Port** | Port, range, variable, `any` | `any`, `1024:` |
| **Direction** | `->` (unidirectional), `<>` (bidirectional) | `->` |
| **Dest IP** | IP, CIDR, variable, `any` | `$EXTERNAL_NET` |
| **Dest Port** | Port, range, variable, `any` | `443`, `$HTTP_PORTS` |

### Common Options

```
# Content matching
content:"GET"; http_method;
content:"/evil.php"; http_uri;
content:"User-Agent: BadBot"; http_header;
content:|4D 5A|; offset:0; depth:2;

# PCRE (regex)
pcre:"/\/[a-z]{8}\.php/Ui";

# Flow control
flow:to_server,established;
flow:to_client,established;

# Metadata
msg:"ET MALWARE Possible C2 Beacon";
sid:1000001;
rev:1;
classtype:trojan-activity;
priority:1;

# Thresholding
threshold:type both, track by_src, count 5, seconds 60;

# Reference
reference:url,example.com/ioc;
reference:cve,2024-12345;

# Byte matching
byte_test:4,>,1000,0,relative;
byte_jump:4,0,relative;

# Payload size
dsize:>500;

# Flow bits (stateful detection)
flowbits:set,malware.stage1;
flowbits:isset,malware.stage1;
```

### Example Rules

```
# Detect HTTP request to known C2 domain
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Beacon to evil.com"; flow:to_server,established; content:"Host"; http_header; content:"evil.com"; http_header; sid:1000001; rev:1; classtype:trojan-activity;)

# Detect DNS query for suspicious TLD
alert dns $HOME_NET any -> any any (msg:"DNS query for .xyz TLD"; dns.query; content:".xyz"; endswith; sid:1000002; rev:1;)

# Detect outbound SSH to non-standard port
alert tcp $HOME_NET any -> $EXTERNAL_NET !22 (msg:"SSH on non-standard port"; flow:to_server,established; content:"SSH-"; depth:4; sid:1000003; rev:1;)
```

## Regex Patterns for WAF Rules

### Common Detection Patterns

| Attack | Pattern | Notes |
|--------|---------|-------|
| SQL Injection | `(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table)` | Common SQLi payloads |
| XSS | `(?i)(<script|javascript:|on\w+\s*=|<img[^>]+onerror)` | Script injection |
| Path Traversal | `(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)` | Directory traversal |
| Command Injection | `(\||;|&&|\$\(|` `` ` `` `|%0a|%0d)` | Shell metacharacters |
| SSRF | `(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.\d+\.\d+|::1)` | Internal addresses |
| Log4Shell | `(\$\{jndi:|%24%7bjndi:)` | JNDI lookup |

## IOC Formats

### STIX (Structured Threat Information eXpression)

STIX 2.1 uses JSON and defines objects for threat intelligence sharing:

| Object | Purpose |
|--------|---------|
| `indicator` | Observable pattern with detection context |
| `malware` | Malware description |
| `attack-pattern` | TTP (maps to MITRE ATT&CK) |
| `threat-actor` | Attribution |
| `campaign` | Related activity grouping |
| `observed-data` | Raw observations |
| `relationship` | Links between objects |

STIX pattern examples:
```
[file:hashes.'SHA-256' = 'abc123...']
[ipv4-addr:value = '198.51.100.1']
[domain-name:value = 'evil.example.com']
[email-message:from_ref.value = 'attacker@evil.com']
```

### OpenIOC

XML-based format from Mandiant/FireEye:
```xml
<ioc>
  <short_description>Malware Indicators</short_description>
  <definition>
    <Indicator operator="OR">
      <IndicatorItem condition="is">
        <Context document="FileItem" search="FileItem/Md5sum"/>
        <Content type="md5">abc123...</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>
```

## Detection Rule Testing Methodology

1. **True positive validation** — Run the rule against known-malicious samples to confirm it fires
2. **True negative validation** — Run against known-clean samples to confirm it does not fire
3. **False positive assessment** — Run against production-like data to measure noise
4. **Performance testing** — Measure CPU/memory impact and scan throughput
5. **Evasion testing** — Attempt common bypasses (encoding, obfuscation, case variation)
6. **Coverage mapping** — Map rules to MITRE ATT&CK techniques

## False Positive Tuning

- **Whitelist known-good** — Exclude specific paths, users, processes, or IPs
- **Add context conditions** — Require multiple indicators instead of a single string match
- **Increase specificity** — Use tighter regex, more content matches, byte offsets
- **Use threshold/aggregation** — Alert only when count exceeds a baseline
- **Tune logsource** — Filter by event IDs, log channels, or severity before rule evaluation
- **Track FP rate** — Measure and record false positive ratio per rule over time

## Detection-as-Code

### Principles

- **Version control** — Store all rules in Git with meaningful commit messages
- **CI/CD testing** — Validate syntax, run against test data, and check for regressions on every PR
- **Peer review** — Require review before merging new or modified rules
- **Automated deployment** — Push validated rules to SIEM/IDS/EDR via pipeline
- **Documentation** — Each rule should have a description, author, MITRE mapping, and runbook link
- **Metrics** — Track true positive rate, false positive rate, mean time to detect, and rule coverage

### Directory Structure Example

```
detection-rules/
  sigma/
    windows/
      process_creation/
      file_events/
    linux/
    network/
  yara/
    malware/
    packers/
    exploits/
  snort/
    malware/
    policy/
  tests/
    sigma/
    yara/
  .github/
    workflows/
      validate.yml
```
