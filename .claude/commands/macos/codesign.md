# Code Signing Verify

Verify the code signing status, notarization, and entitlements of a macOS application or binary.

## Arguments

$ARGUMENTS should be the path to an application bundle (.app) or binary to verify.

Examples:
- `/Applications/Safari.app`
- `/usr/bin/ssh`
- `/Applications/Slack.app`
- `~/Downloads/SomeApp.app`

## Workflow

1. Parse the target path from `$ARGUMENTS`.
2. Show the user the exact commands that will run before executing them.
3. Run the following verification commands:

### Display code signing information

```bash
codesign -dvvv <path>
```

Key fields to highlight:
- **Authority** — The signing certificate chain (should trace back to Apple Root CA)
- **TeamIdentifier** — The developer's Apple team ID
- **Identifier** — The bundle or binary identifier
- **Format** — App bundle, Mach-O binary, disk image, etc.
- **Timestamp** — When the code was signed
- **Runtime version** — Hardened Runtime version (required for notarization)

### Verify the code signature

```bash
codesign --verify --deep --strict --verbose=4 <path>
```

This checks:
- Signature validity (has the code been modified since signing?)
- Certificate chain validity
- Deep verification of nested code (frameworks, plugins within .app bundles)
- Strict validation rules

### Check Gatekeeper assessment and notarization

```bash
spctl -a -v <path>
```

Assessment results:
- **accepted / source=Notarized Developer ID** — Properly signed and notarized
- **accepted / source=Developer ID** — Signed but not notarized
- **accepted / source=Apple System** — Apple system binary
- **rejected** — Failed Gatekeeper check

### Check entitlements

```bash
codesign -d --entitlements - <path>
```

Flag any dangerous entitlements:
- `com.apple.security.cs.disable-library-validation` — Allows loading unsigned libraries
- `com.apple.security.cs.allow-unsigned-executable-memory` — Allows JIT, can be abused
- `com.apple.security.cs.debugger` — Allows debugging other processes
- `com.apple.security.get-task-allow` — Allows task_for_pid (should not be in production builds)
- `com.apple.private.tcc.allow` — Grants TCC access without user consent
- `com.apple.security.cs.allow-dyld-environment-variables` — Allows DYLD_* injection

4. Summarise findings:
   - Signing status (signed / unsigned / invalid)
   - Signing authority and team identifier
   - Notarization status
   - Hardened Runtime enabled (yes / no)
   - Entitlements summary with any dangerous entitlements flagged
   - Overall trust assessment

## Security Notes

- Unsigned or ad-hoc signed binaries should be treated with suspicion, especially if downloaded from the internet.
- The `get-task-allow` entitlement is normal in development builds but should never appear in production/distribution builds.
- Hardened Runtime is required for notarization and provides important exploit mitigations (library validation, memory protections).
- A valid code signature does not guarantee the software is safe — it only confirms the identity of the signer and that the code has not been tampered with since signing.
- If `spctl` rejects an app, it will be blocked by Gatekeeper on first launch unless the user explicitly overrides it.
- Notarization means Apple has scanned the software for known malicious content, but it is not a full security audit.
