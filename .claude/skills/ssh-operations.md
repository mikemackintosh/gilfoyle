---
name: SSH Operations
description: SSH configuration, key management, tunneling, troubleshooting, and secure file transfer.
instructions: |
  Use this skill when the user needs help with SSH key generation, config management, tunneling,
  agent forwarding, sshd hardening, debugging connection issues, or secure file transfers.
  Always show commands before executing them and explain security implications.
---

# SSH Operations Skill

## SSH Key Generation & Management

### Generate Keys

```bash
# Ed25519 (recommended — fast, small, secure)
ssh-keygen -t ed25519 -C "user@host"

# Ed25519 with custom path
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_work -C "user@work"

# RSA-4096 (wider compatibility)
ssh-keygen -t rsa -b 4096 -C "user@host"

# ECDSA P-256
ssh-keygen -t ecdsa -b 256 -C "user@host"
```

> **Recommendation:** Use Ed25519 for new keys. Use RSA-4096 only when Ed25519 is not supported by the remote host.

### Key Management

```bash
# List keys in ~/.ssh/
ls -la ~/.ssh/

# Show public key fingerprint
ssh-keygen -lf ~/.ssh/id_ed25519.pub

# Show fingerprint in different formats
ssh-keygen -lf ~/.ssh/id_ed25519.pub -E md5
ssh-keygen -lf ~/.ssh/id_ed25519.pub -E sha256

# Change passphrase on an existing key
ssh-keygen -p -f ~/.ssh/id_ed25519

# Extract public key from private key
ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub

# Convert OpenSSH key to PEM format
ssh-keygen -e -m PEM -f ~/.ssh/id_ed25519 > key.pem

# Remove a host from known_hosts
ssh-keygen -R hostname
ssh-keygen -R [hostname]:port

# Show known_hosts entries for a host
ssh-keygen -F hostname
```

### Authorised Keys

```bash
# Copy public key to remote host
ssh-copy-id user@host
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host

# Manual method
cat ~/.ssh/id_ed25519.pub | ssh user@host 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'

# Correct permissions (on remote host)
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/id_*.pub
chmod 644 ~/.ssh/config
```

## SSH Config Patterns (`~/.ssh/config`)

### Basic Host Entry

```ssh-config
Host myserver
    HostName 10.0.1.50
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_work
```

### Jump Host / Bastion

```ssh-config
# Modern syntax (OpenSSH 7.3+)
Host internal-server
    HostName 10.0.1.50
    User admin
    ProxyJump bastion

Host bastion
    HostName bastion.example.com
    User jumpuser
    IdentityFile ~/.ssh/id_ed25519

# Legacy ProxyCommand syntax
Host internal-server-legacy
    HostName 10.0.1.50
    User admin
    ProxyCommand ssh -W %h:%p bastion
```

### Connection Multiplexing

```ssh-config
Host *
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h-%p
    ControlPersist 600
```

```bash
# Create the sockets directory
mkdir -p ~/.ssh/sockets
```

### Wildcard and Pattern Matching

```ssh-config
# Apply settings to all hosts in a domain
Host *.example.com
    User admin
    IdentityFile ~/.ssh/id_ed25519_work

# Apply settings to all hosts
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    AddKeysToAgent yes
    IdentitiesOnly yes
```

### GitHub / GitLab with Separate Keys

```ssh-config
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_github
    IdentitiesOnly yes

Host gitlab.com
    HostName gitlab.com
    User git
    IdentityFile ~/.ssh/id_ed25519_gitlab
    IdentitiesOnly yes
```

## SSH Tunneling

### Local Port Forward (access remote service locally)

```bash
# Forward local:8080 → remote-db:5432 through ssh-host
ssh -L 8080:remote-db:5432 user@ssh-host

# Bind to all interfaces (not just localhost)
ssh -L 0.0.0.0:8080:remote-db:5432 user@ssh-host

# Run in background
ssh -fNL 8080:remote-db:5432 user@ssh-host
```

Use case: Access a database or internal web app that's only reachable from the SSH host.

### Remote Port Forward (expose local service to remote)

```bash
# Make local:3000 available as remote:9090
ssh -R 9090:localhost:3000 user@remote-host

# Run in background
ssh -fNR 9090:localhost:3000 user@remote-host
```

Use case: Expose a local dev server to a remote machine (e.g., for webhooks).

### Dynamic Port Forward (SOCKS proxy)

```bash
# Create SOCKS5 proxy on local:1080
ssh -D 1080 user@ssh-host

# Run in background
ssh -fND 1080 user@ssh-host

# Use with curl
curl --socks5 localhost:1080 https://example.com

# Use with browser (configure SOCKS5 proxy to localhost:1080)
```

Use case: Route traffic through a remote host (e.g., access geo-restricted content or internal networks).

### Tunnel Management

```bash
# List active tunnels (find background SSH processes)
ps aux | grep 'ssh -[fNL]\|ssh -[fNR]\|ssh -[fND]'

# Kill a specific tunnel
kill <pid>
```

## SSH Agent

```bash
# Start the agent
eval "$(ssh-agent -s)"

# Add a key
ssh-add ~/.ssh/id_ed25519

# Add with macOS Keychain integration
ssh-add --apple-use-keychain ~/.ssh/id_ed25519

# List loaded keys
ssh-add -l

# Remove all keys from agent
ssh-add -D

# Remove a specific key
ssh-add -d ~/.ssh/id_ed25519
```

### Agent Forwarding

```bash
# Enable for a single connection
ssh -A user@host

# In config
# Host bastion
#     ForwardAgent yes
```

> **Security warning:** Agent forwarding exposes your keys to the remote host's root user. Only forward to hosts you trust. Prefer `ProxyJump` over agent forwarding when possible.

## SSHD Hardening

### Recommended `/etc/ssh/sshd_config` Settings

```sshd_config
# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no

# Disable root login
PermitRootLogin no

# Use only protocol 2
Protocol 2

# Restrict to specific users/groups
AllowUsers deploy admin
# AllowGroups ssh-users

# Key exchange, ciphers, and MACs (modern)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Disable unused features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Logging
LogLevel VERBOSE

# Session limits
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30

# Client alive (disconnect idle sessions)
ClientAliveInterval 300
ClientAliveCountMax 2

# Use only host keys with strong algorithms
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
```

```bash
# Validate config syntax before reloading
sudo sshd -t

# Reload sshd (does not drop existing connections)
sudo systemctl reload sshd      # systemd
sudo launchctl kickstart -k system/com.openssh.sshd   # macOS
```

## Debugging SSH Connections

```bash
# Verbose output (increasing verbosity)
ssh -v user@host
ssh -vv user@host
ssh -vvv user@host

# Test authentication without opening a shell
ssh -o BatchMode=yes user@host exit

# Check what key the server expects
ssh -v user@host 2>&1 | grep "Offering"
ssh -v user@host 2>&1 | grep "Accepted"

# Check server's host key
ssh-keyscan host
ssh-keyscan -t ed25519 host
```

### Common SSH Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Permission denied (publickey)` | Key not accepted | Check key path, permissions, `authorized_keys` |
| `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` | Host key changed | Verify legitimacy, then `ssh-keygen -R host` |
| `Connection refused` | sshd not running or port blocked | Check service status and firewall |
| `Connection timed out` | Network/firewall blocking | Check routing, firewall, security groups |
| `Too many authentication failures` | Agent offering too many keys | Use `IdentitiesOnly yes` in config |
| `Bad owner or permissions on ~/.ssh/config` | Wrong file permissions | `chmod 600 ~/.ssh/config` |

### Permission Requirements

```
~/.ssh/                 700  (drwx------)
~/.ssh/authorized_keys  600  (-rw-------)
~/.ssh/id_*             600  (-rw-------)
~/.ssh/id_*.pub         644  (-rw-r--r--)
~/.ssh/config           600  (-rw-------)
~/.ssh/known_hosts      644  (-rw-r--r--)
```

## Secure File Transfer

### SCP

```bash
# Copy file to remote
scp file.txt user@host:/path/to/destination/

# Copy file from remote
scp user@host:/path/to/file.txt ./

# Copy directory recursively
scp -r ./local-dir user@host:/path/to/destination/

# Use a specific port
scp -P 2222 file.txt user@host:/path/
```

### SFTP

```bash
# Interactive session
sftp user@host

# SFTP commands
# ls, cd, pwd, get, put, mkdir, rm, bye

# Non-interactive: download a file
sftp user@host:/path/to/file.txt ./
```

### rsync (preferred for large transfers)

```bash
# Sync local → remote
rsync -avz --progress ./local-dir/ user@host:/path/to/remote-dir/

# Sync remote → local
rsync -avz --progress user@host:/path/to/remote-dir/ ./local-dir/

# Dry run (preview changes)
rsync -avzn ./local-dir/ user@host:/path/to/remote-dir/

# Delete files on destination that don't exist on source
rsync -avz --delete ./local-dir/ user@host:/path/to/remote-dir/

# Use a specific SSH port
rsync -avz -e 'ssh -p 2222' ./local-dir/ user@host:/path/

# Exclude patterns
rsync -avz --exclude='*.log' --exclude='.git' ./src/ user@host:/path/
```
