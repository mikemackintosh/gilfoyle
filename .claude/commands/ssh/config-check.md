# SSH Config Check

Review the SSH client configuration for a host and check for common issues.

## Arguments

$ARGUMENTS should be a hostname or Host alias from `~/.ssh/config`.

Examples:
- `myserver`
- `bastion`
- `github.com`
- (no args — review the entire `~/.ssh/config`)

## Workflow

1. Parse the hostname from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### If a host is specified, show resolved config

```bash
ssh -G <host>
```

This expands all `~/.ssh/config` matching (wildcards, includes) and shows the effective configuration.

### Show the raw config file

```bash
cat ~/.ssh/config
```

### Check file permissions

```bash
ls -la ~/.ssh/config
ls -la ~/.ssh/
```

3. Audit the configuration for:

| Check | Expected | Issue if wrong |
|-------|----------|----------------|
| `~/.ssh/config` permissions | `600` | SSH may refuse to use it |
| `~/.ssh/` permissions | `700` | SSH may refuse to use directory |
| Private key permissions | `600` | SSH will reject the key |
| `IdentitiesOnly` | `yes` (recommended) | Agent may try too many keys |
| `ServerAliveInterval` | Set (e.g., `60`) | Connections may drop on idle |
| `ForwardAgent` | `no` (unless needed) | Security risk if enabled broadly |
| `StrictHostKeyChecking` | `ask` or `yes` | `no` disables MITM protection |

4. Present findings:
   - Effective config for the target host
   - Any permission issues
   - Security recommendations
   - Missing recommended settings

## Security Notes

- `ForwardAgent yes` on untrusted hosts allows root on that host to use your SSH keys. Prefer `ProxyJump`.
- `StrictHostKeyChecking no` disables host key verification — never use in production.
- `ControlMaster` multiplexing reuses connections, which is convenient but means all sessions share one TCP connection.
- Include files (`Include ~/.ssh/config.d/*`) can override settings — check for unexpected includes.
