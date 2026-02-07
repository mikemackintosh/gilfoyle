# SSH Server Hardening Audit

Audit the SSH server (sshd) configuration for security weaknesses.

## Arguments

$ARGUMENTS is optional:
- A path to an `sshd_config` file (default: `/etc/ssh/sshd_config`)
- Or `--remote user@host` to audit a remote host

Examples:
- (no args — audit local `/etc/ssh/sshd_config`)
- `/path/to/sshd_config`
- `--remote admin@server.example.com`

## Workflow

1. Parse the config path or remote target from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Read the sshd config

```bash
sudo cat /etc/ssh/sshd_config
```

Or for remote:

```bash
ssh <user@host> 'sudo cat /etc/ssh/sshd_config'
```

### Also check for override files

```bash
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
sudo cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

3. Audit each setting against the hardening checklist:

| Setting | Secure Value | Risk if Insecure |
|---------|-------------|------------------|
| `PermitRootLogin` | `no` | Direct root access |
| `PasswordAuthentication` | `no` | Brute-force attacks |
| `ChallengeResponseAuthentication` | `no` | Bypass key-only auth |
| `PermitEmptyPasswords` | `no` | No-password login |
| `MaxAuthTries` | `3` | Slow brute-force |
| `X11Forwarding` | `no` | Attack surface |
| `AllowTcpForwarding` | `no` (unless needed) | Tunnel abuse |
| `AllowAgentForwarding` | `no` (unless needed) | Agent hijacking |
| `LoginGraceTime` | `30` | Resource exhaustion |
| `ClientAliveInterval` | `300` | Idle session risk |
| `LogLevel` | `VERBOSE` | Insufficient audit trail |
| `AllowUsers` / `AllowGroups` | Set | Unrestricted access |

### Check cipher and key exchange strength

Look for weak algorithms:
- KEX: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
- Ciphers: `3des-cbc`, `arcfour`, `blowfish-cbc`, any `-cbc` mode
- MACs: `hmac-md5`, `hmac-sha1` (non-ETM)

4. Present a summary table:
   - Setting | Current Value | Recommended | Status (PASS/FAIL/WARN)

5. If issues are found, provide the corrective `sshd_config` lines and the reload command:

```bash
sudo sshd -t && sudo systemctl reload sshd
```

## Security Notes

- Always validate config with `sshd -t` before reloading — a syntax error will prevent sshd from restarting.
- Keep an existing SSH session open while testing changes, so you don't lock yourself out.
- `sshd_config.d/*.conf` files can override the main config — always check both.
- On macOS, sshd is managed via `launchctl`, not `systemctl`.
