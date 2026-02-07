# SSH Server Audit

Audit an SSH server's configuration, algorithms, and authentication settings for security weaknesses.

## Arguments

$ARGUMENTS should include:
- A hostname or IP (to audit a remote SSH server's offered algorithms)
- Or a path to `sshd_config` (to audit a local config file)

Examples:
- `example.com`
- `10.0.0.1`
- `/etc/ssh/sshd_config`

## Workflow

1. Parse the target from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Remote audit — scan offered algorithms

```bash
# Scan host key types
ssh-keyscan -t ed25519,rsa,ecdsa <host> 2>&1

# Check offered key exchange, ciphers, and MACs
ssh -v -o BatchMode=yes <host> exit 2>&1 | grep -E 'kex_algorithms|server_host_key|encryption|mac'

# Test if password auth is offered
ssh -v -o PreferredAuthentications=password -o BatchMode=yes <host> exit 2>&1 | grep 'Authentications that can continue'
```

### Local config audit

```bash
sudo cat /etc/ssh/sshd_config
sudo cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

3. Check each algorithm and setting against the hardening baseline:

### Weak algorithms to flag

| Type | Weak (flag these) | Strong (recommended) |
|------|-------------------|---------------------|
| KEX | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1` | `curve25519-sha256` |
| Host Key | `ssh-dss` | `ssh-ed25519`, `rsa-sha2-512` |
| Ciphers | `3des-cbc`, `arcfour*`, `blowfish-cbc`, `*-cbc` | `chacha20-poly1305`, `aes256-gcm` |
| MACs | `hmac-md5*`, `hmac-sha1` (non-ETM) | `hmac-sha2-256-etm`, `hmac-sha2-512-etm` |

### Configuration checks

| Setting | Expected | Risk |
|---------|----------|------|
| Password auth | Disabled | Brute-force |
| Root login | Disabled | Privilege escalation |
| Empty passwords | Disabled | Unauthenticated access |
| X11 forwarding | Disabled | Attack surface |

4. Present results as a table:
   - Check | Status (PASS/FAIL/WARN) | Detail

## Security Notes

- Remote algorithm scanning only shows what the server offers — it doesn't reveal the full `sshd_config`.
- If `ssh-audit` (the third-party tool) is installed, it provides a more comprehensive analysis: `ssh-audit <host>`.
- Always keep an existing SSH session open when making sshd changes, to avoid lockout.
- Test config changes with `sshd -t` before reloading.
