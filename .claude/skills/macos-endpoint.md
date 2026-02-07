---
name: macOS Endpoint Security
description: macOS security assessment — MDM enrollment, configuration profiles, code signing, notarization, quarantine flags, TCC privacy permissions, system extensions, Gatekeeper, SIP, FileVault, launchd services, firewall, Keychain, and macOS unified logging.
instructions: |
  Use this skill when the user is assessing macOS endpoint security posture, investigating MDM
  configuration, verifying code signing or notarization, auditing privacy permissions (TCC),
  inspecting quarantine flags, checking Gatekeeper or SIP status, managing FileVault encryption,
  auditing launchd services, reviewing macOS firewall rules, working with Keychain, or querying
  the macOS unified log system. Always show commands before executing them, explain security
  implications, and note when elevated privileges (sudo) are required.
---

# macOS Endpoint Security Skill

## Related Commands
- `/macos-mdm-status` — Check MDM enrollment and configuration profiles
- `/macos-codesign` — Verify code signing and notarization of applications
- `/macos-privacy` — Audit TCC/privacy permission grants
- `/macos-quarantine` — Inspect quarantine extended attributes on files

## MDM Enrollment Status

### Check Enrollment

```bash
# MDM enrollment status
profiles status -type enrollment

# List all installed configuration profiles
profiles list

# Show detailed profile information
profiles show
```

### Key Things to Check
- **DEP/ADE enrolled** — Was the device enrolled via Automated Device Enrollment?
- **User-approved MDM** — Was enrollment user-approved (required for kernel extension management)?
- **MDM server URL** — Which MDM server is managing the device?
- **Profile payloads** — What restrictions, certificates, and Wi-Fi configs are pushed?

## Configuration Profiles

```bash
# List profiles for current user
profiles list -output stdout

# List profiles for all users (requires root)
sudo profiles list -all

# Show profile details in XML format
sudo profiles show -type configuration

# Export a specific profile
sudo profiles show -type configuration -output /tmp/profiles_export.xml
```

### Profile Payload Types to Note
| Payload | Purpose | Security Relevance |
|---------|---------|-------------------|
| `com.apple.security.firewall` | Firewall configuration | Network security |
| `com.apple.screensaver` | Screen lock settings | Physical security |
| `com.apple.MCX` | Managed preferences | Policy enforcement |
| `com.apple.security.certificatetransparency` | CT enforcement | TLS security |
| `com.apple.syspolicy.kernel-extension-policy` | Kernel extension whitelist | Endpoint integrity |
| `com.apple.TCC.configuration-profile-policy` | Privacy permission control | Data access control |

## Code Signing Verification

### Verify an Application or Binary

```bash
# Display code signing information (verbose)
codesign -dvvv /path/to/app

# Verify code signature is valid
codesign --verify --verbose=4 /path/to/app

# Deep verify (checks all nested code in bundles)
codesign --verify --deep --verbose=4 /path/to/App.app

# Check strict validation
codesign --verify --deep --strict /path/to/App.app
```

### Check Entitlements

```bash
# Display entitlements
codesign -d --entitlements - /path/to/app

# XML format for detailed parsing
codesign -d --entitlements :- /path/to/app
```

### Dangerous Entitlements to Flag
- `com.apple.security.cs.disable-library-validation` — Allows loading unsigned libraries
- `com.apple.security.cs.allow-unsigned-executable-memory` — JIT, can be abused
- `com.apple.security.cs.debugger` — Allows debugging other processes
- `com.apple.security.get-task-allow` — Allows task_for_pid (should not be in production builds)
- `com.apple.private.tcc.allow` — Grants TCC access without user consent

## Notarization Checking

```bash
# Check Gatekeeper assessment (includes notarization)
spctl -a -v /path/to/app

# Check a disk image
spctl -a -v --type install /path/to/file.dmg

# Check notarization ticket stapled to app
stapler validate /path/to/App.app

# Check notarization status via Apple (requires internet)
xcrun notarytool info <submission-id> --apple-id <email> --team-id <team>
```

### Assessment Results
- **accepted / source=Notarized Developer ID** — Properly signed and notarized
- **accepted / source=Developer ID** — Signed but not notarized (older apps)
- **rejected** — Failed Gatekeeper check; may be unsigned, revoked, or tampered

## Quarantine Flag Inspection

```bash
# Check extended attributes on a file
xattr -l /path/to/file

# Check specifically for quarantine flag
xattr -p com.apple.quarantine /path/to/file 2>/dev/null

# List all quarantine flags recursively in a directory
find /path/to/dir -xattr -print0 | xargs -0 xattr -l 2>/dev/null | grep -A1 'com.apple.quarantine'

# Remove quarantine flag (use with caution)
xattr -d com.apple.quarantine /path/to/file

# Remove all quarantine flags recursively
xattr -dr com.apple.quarantine /path/to/dir
```

### Quarantine Flag Format

The quarantine attribute value has the format: `flag;timestamp;agent_name;UUID`

| Field | Description |
|-------|-------------|
| `flag` | Hex flags (e.g., `0083` = downloaded, needs Gatekeeper check) |
| `timestamp` | Hex-encoded timestamp (seconds since 2001-01-01) |
| `agent_name` | Application that downloaded the file (e.g., `Safari`, `curl`) |
| `UUID` | Unique identifier for the download event |

## TCC Database and Privacy Permissions

### Understanding TCC

TCC (Transparency, Consent, and Control) manages access to sensitive resources. Permissions are stored in SQLite databases:

- **User-level:** `~/Library/Application Support/com.apple.TCC/TCC.db`
- **System-level:** `/Library/Application Support/com.apple.TCC/TCC.db` (requires FDA or SIP disable to read)

### Query TCC Databases

```bash
# User-level TCC grants (current user)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, auth_reason FROM access ORDER BY service;"

# System-level TCC grants (requires Full Disk Access)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client, auth_value, auth_reason FROM access ORDER BY service;"
```

### Key TCC Service Names

| Service | Protects |
|---------|----------|
| `kTCCServiceAccessibility` | Accessibility API access |
| `kTCCServiceScreenCapture` | Screen recording |
| `kTCCServiceMicrophone` | Microphone access |
| `kTCCServiceCamera` | Camera access |
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access |
| `kTCCServiceAppleEvents` | Automation / Apple Events |
| `kTCCServiceSystemPolicySysAdminFiles` | Administer Files |
| `kTCCServiceListenEvent` | Input Monitoring |
| `kTCCServicePostEvent` | Posting HID events |

### Auth Values
- `0` — Denied
- `1` — Unknown
- `2` — Allowed
- `3` — Limited

### Alternative: System Profiler

```bash
# Privacy settings overview
system_profiler SPConfigurationProfileDataType

# Installed applications (useful for cross-referencing TCC clients)
system_profiler SPApplicationsDataType
```

### Reset TCC Permissions

```bash
# Reset all TCC permissions for a specific app
tccutil reset All com.example.appbundleid

# Reset a specific service for all apps
tccutil reset Camera
tccutil reset Microphone
tccutil reset ScreenCapture
tccutil reset Accessibility
```

## Kernel Extensions vs System Extensions

### Kernel Extensions (Legacy)

```bash
# List loaded kernel extensions
kextstat

# Filter for third-party kexts (exclude Apple)
kextstat | grep -v com.apple

# Check if a specific kext is loaded
kextstat | grep -i <vendor_name>

# Show kext details
kextfind -b <bundle_id> -print-info
```

### System Extensions (Modern)

```bash
# List system extensions
systemextensionsctl list

# Show active system extensions
systemextensionsctl list | grep -E 'activated|enabled'
```

> **Note:** Starting with macOS 11 (Big Sur), Apple deprecated kernel extensions in favour of system extensions (Endpoint Security, Network Extension, DriverKit). Third-party kexts require user approval and MDM whitelisting.

## Gatekeeper Deep Dive

```bash
# Check Gatekeeper status
spctl --status

# Assess an app
spctl -a -v /path/to/App.app

# Assess an installer package
spctl -a -v --type install /path/to/package.pkg

# List the Gatekeeper policy database rules
sudo spctl --list

# Check Gatekeeper assessment for a downloaded disk image
spctl -a -v --type open /path/to/file.dmg
```

### Gatekeeper Enforcement Levels
- **App Store** — Only apps from the Mac App Store
- **App Store and identified developers** — Notarized or Developer ID signed (default)
- **Anywhere** — No restrictions (not available in modern macOS GUI, only via `spctl --master-disable`)

## SIP (System Integrity Protection) Status

```bash
# Check SIP status
csrutil status

# Detailed SIP configuration
csrutil status --verbose 2>/dev/null || csrutil status
```

### SIP-Protected Areas
- `/System` — Core system files
- `/usr` (except `/usr/local`) — System binaries
- `/bin`, `/sbin` — System commands
- Pre-installed Apple apps

> **Warning:** SIP can only be modified from Recovery Mode (`csrutil disable`/`csrutil enable`). A disabled SIP is a significant security concern and should always be flagged.

## FileVault Management

```bash
# Check FileVault status
fdesetup status

# Check if institutional recovery key exists
fdesetup hasinstitutionalrecoverykey

# Check if personal recovery key exists
fdesetup haspersonalrecoverykey

# List FileVault-enabled users
fdesetup list

# Validate recovery key (prompts for key)
sudo fdesetup validaterecovery
```

### FileVault Assessment
- **Enabled** with recovery key escrowed to MDM: Ideal enterprise configuration
- **Enabled** with personal recovery key only: Acceptable for personal use
- **Disabled**: Flag as a security finding; disk data is unencrypted

## Launchd Service Audit

```bash
# List all loaded launch jobs (user context)
launchctl list

# List all loaded launch jobs (system context)
sudo launchctl list

# Show details for a specific job
launchctl print system/<label>
launchctl print gui/$(id -u)/<label>

# Check user Launch Agents
ls -la ~/Library/LaunchAgents/

# Check system-wide Launch Agents and Daemons
ls -la /Library/LaunchAgents/
ls -la /Library/LaunchDaemons/

# Check Apple Launch Daemons
ls -la /System/Library/LaunchDaemons/

# Find recently modified plists
find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name '*.plist' -mtime -30 2>/dev/null

# Dump a plist for inspection
plutil -p /Library/LaunchDaemons/<label>.plist
```

### Suspicious Indicators
- Plists with `ProgramArguments` pointing to `/tmp`, `/var/tmp`, or hidden directories
- `RunAtLoad` set to `true` with unfamiliar binaries
- `StartInterval` or `WatchPaths` triggering unknown scripts
- Plists created or modified recently that do not match known software installs

## macOS Firewall

### Application Firewall

```bash
# Status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

# Block all incoming connections
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall

# List allowed/blocked apps
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# Logging mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode
```

### pf (Packet Filter)

```bash
# Show pf status
sudo pfctl -si

# Show active rules
sudo pfctl -sr

# Show loaded anchors
sudo pfctl -sA

# Show NAT rules
sudo pfctl -sn

# Show state table
sudo pfctl -ss

# Test a rule file without loading
sudo pfctl -n -f /etc/pf.conf
```

## Keychain Operations

```bash
# List keychains in search path
security list-keychains

# Show default keychain
security default-keychain

# Dump all keychain metadata (no secrets)
security dump-keychain

# Find a specific certificate
security find-certificate -a -c "<common_name>" /Library/Keychains/System.keychain

# Find an identity (cert + private key)
security find-identity -v -p codesigning

# Show trust settings for certificates
security dump-trust-settings

# Verify a certificate in the keychain
security verify-cert -c /path/to/cert.pem

# Check keychain lock status
security show-keychain-info ~/Library/Keychains/login.keychain-db
```

## macOS Log System (Unified Logging)

```bash
# Show recent logs
log show --last 1h

# Filter by process
log show --predicate 'process == "sshd"' --last 24h

# Filter by subsystem
log show --predicate 'subsystem == "com.apple.securityd"' --last 1h

# Authentication events
log show --predicate 'process == "loginwindow" OR process == "authd"' --last 24h

# Gatekeeper events
log show --predicate 'subsystem == "com.apple.syspolicy"' --last 24h

# TCC access events
log show --predicate 'subsystem == "com.apple.TCC"' --last 24h

# Kernel extension events
log show --predicate 'process == "kernelmanagerd"' --last 24h

# Firewall events
log show --predicate 'process == "socketfilterfw"' --last 24h

# Stream logs in real time
log stream --predicate 'subsystem == "com.apple.securityd"'

# Collect a log archive for offline analysis
sudo log collect --output /tmp/system_logs.logarchive
```

### Useful Log Predicates for Security

| Predicate | Purpose |
|-----------|---------|
| `process == "sudo"` | Privilege escalation |
| `process == "sshd"` | Remote access |
| `process == "loginwindow"` | User logins |
| `subsystem == "com.apple.syspolicy"` | Gatekeeper decisions |
| `subsystem == "com.apple.TCC"` | Privacy permission checks |
| `process == "kernel"` | Kernel messages |
| `subsystem == "com.apple.securityd"` | Security daemon activity |
| `process == "socketfilterfw"` | Application firewall |
| `process == "XProtect"` | Malware detection (XProtect) |
