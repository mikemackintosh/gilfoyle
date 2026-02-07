# SSH Debug

Debug an SSH connection to diagnose authentication or connectivity issues.

## Arguments

$ARGUMENTS should be a user@host connection string, optionally with a port.

Examples:
- `user@host`
- `user@host -p 2222`
- `host` (uses current user)

## Workflow

1. Parse the connection target from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Verbose connection test

```bash
ssh -vvv <user@host> exit 2>&1
```

3. Parse the verbose output and identify:

### Key diagnostics to extract

- **Connection phase:** Did TCP connect succeed?
- **Host key:** Was the server's host key accepted/known?
- **Authentication methods offered:** What does the server support? (`publickey`, `password`, `keyboard-interactive`)
- **Keys tried:** Which identity files were offered?
- **Key accepted/rejected:** Was a key accepted?
- **Final result:** Did authentication succeed?

### Additional checks

If the connection fails, run these follow-up diagnostics:

```bash
# Test TCP connectivity
nc -zv -w 5 <host> <port>

# Scan the server's host key
ssh-keyscan -t ed25519,rsa <host>

# Check local SSH config for this host
ssh -G <host>
```

4. Present a clear diagnosis:
   - What failed (DNS, TCP, host key, auth)
   - The likely cause
   - Specific fix (with commands)

### Common SSH Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `Connection refused` | sshd not running or port blocked | Check service status, firewall |
| `Connection timed out` | Network/firewall blocking | Check routing, security groups |
| `Permission denied (publickey)` | Key not accepted | Verify key path, permissions, `authorized_keys` |
| `Host key verification failed` | Host key changed | Verify legitimacy, `ssh-keygen -R <host>` |
| `Too many authentication failures` | Agent offering too many keys | Use `IdentitiesOnly yes` in config |

## Security Notes

- The `-vvv` output may reveal local file paths and usernames. Be careful sharing it publicly.
- A changed host key (`REMOTE HOST IDENTIFICATION HAS CHANGED`) could indicate a MITM attack. Always verify before removing the old key.
- If `IdentitiesOnly yes` is not set, `ssh-agent` may try all loaded keys, causing `Too many authentication failures`.
