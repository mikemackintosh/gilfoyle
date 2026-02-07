# MDM Status

Check MDM enrollment status and installed configuration profiles on macOS.

## Arguments

$ARGUMENTS is not required. This command takes no arguments.

Examples:
- (no args — check MDM enrollment and profiles on the local host)

## Workflow

1. Show the user the exact commands that will run before executing them.
2. Run the following inspection commands:

### Check MDM enrollment status

```bash
profiles status -type enrollment
```

This reveals:
- Whether the device is enrolled in MDM
- Whether enrollment is DEP/ADE (Automated Device Enrollment)
- Whether the MDM enrollment is user-approved
- The MDM server URL

### List installed configuration profiles

```bash
profiles list
```

Key fields to highlight:
- **Profile name** — Human-readable name assigned by the administrator
- **Organisation** — Who deployed the profile
- **Verification state** — Whether the profile is verified
- **Payload types** — What restrictions and configurations are applied (Wi-Fi, VPN, certificates, passcode policy, etc.)

### Show detailed profile information

```bash
profiles show
```

This provides detailed payload contents including:
- Certificate payloads (root CAs pushed by MDM)
- Restriction payloads (e.g., disabling AirDrop, enforcing passwords)
- VPN and Wi-Fi configuration payloads
- Privacy Preferences Policy Control (TCC) payloads

3. Summarise findings:
   - MDM enrollment status (enrolled / not enrolled)
   - Enrollment type (DEP, user-approved, or manual)
   - MDM server identity (if enrolled)
   - Number of installed profiles
   - Key payloads and restrictions in effect
   - Any profiles that appear unusual or unexpected

## Security Notes

- A device not enrolled in MDM cannot be remotely managed, locked, or wiped by the organisation.
- User-approved MDM enrollment is required for managing kernel extensions and Privacy Preferences on macOS 10.14+.
- Configuration profiles can push trusted root CA certificates — verify that only expected CAs are present, as rogue CAs enable MITM attacks.
- Profiles installed manually (not via MDM) may indicate social engineering or a user bypassing policy.
- DEP/ADE enrollment provides the strongest management guarantee because it survives OS reinstallation.
