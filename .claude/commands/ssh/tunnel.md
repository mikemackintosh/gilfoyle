# SSH Tunnel

Create an SSH tunnel (local forward, remote forward, or SOCKS proxy).

## Arguments

$ARGUMENTS should include:
- Tunnel type: `local` (default), `remote`, or `socks`
- For local/remote: `<local_port>:<remote_host>:<remote_port> <ssh_host>`
- For socks: `<port> <ssh_host>`

Examples:
- `local 8080:db.internal:5432 bastion.example.com`
- `remote 9090:localhost:3000 remote.example.com`
- `socks 1080 bastion.example.com`
- `8080:localhost:8080 user@host` (local forward shorthand)

## Workflow

1. Parse the tunnel type, port mapping, and SSH host from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Local port forward

Access a remote service through a local port.

```bash
ssh -fNL <local_port>:<remote_host>:<remote_port> <user@ssh_host>
```

Use case: Access `db.internal:5432` at `localhost:8080` through a bastion host.

### Remote port forward

Expose a local service on a remote host.

```bash
ssh -fNR <remote_port>:localhost:<local_port> <user@ssh_host>
```

Use case: Make your local dev server (port 3000) accessible on the remote host at port 9090.

### Dynamic port forward (SOCKS proxy)

```bash
ssh -fND <port> <user@ssh_host>
```

Use case: Route all traffic through the SSH host. Configure your browser to use `localhost:<port>` as a SOCKS5 proxy.

3. After starting the tunnel, show:
   - What the tunnel does in plain English
   - How to test it (e.g., `curl localhost:<port>`)
   - How to find and kill the tunnel later: `ps aux | grep 'ssh -fN'`

## Security Notes

- Tunnels run in the background with `-fN`. Use `ps` to find them and `kill <pid>` to stop them.
- Remote port forwarding exposes a local service — make sure this is intentional.
- Prefer `ProxyJump` over agent forwarding when accessing internal hosts through a bastion.
- SOCKS proxies route all traffic through the SSH host — be aware of what data traverses the tunnel.
