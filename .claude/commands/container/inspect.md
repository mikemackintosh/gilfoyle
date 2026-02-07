# Container Inspect

Inspect a running container's security posture — processes, network configuration, mounts, environment variables, capabilities, and security options.

## Arguments

$ARGUMENTS should be a container ID or container name.

Examples:
- `my-web-app`
- `a1b2c3d4e5f6`
- `redis-cache`

## Workflow

1. Parse the container ID or name from `$ARGUMENTS`.
2. Show the user the exact commands before executing them.
3. Verify the container is running:

```bash
docker inspect --format '{{.State.Status}}' <container>
```

### Processes running inside the container

```bash
docker top <container> -eo pid,user,comm,args
```

Flag any processes running as root (UID 0) or unexpected processes (shells, package managers, debugging tools).

### Container user configuration

```bash
docker inspect --format 'User: {{.Config.User}} | Privileged: {{.HostConfig.Privileged}}' <container>
```

Flag if `Privileged` is `true` (**CRITICAL** — full host access) or if `User` is empty/root.

### Network configuration

```bash
docker inspect --format '{{json .NetworkSettings.Networks}}' <container>
```

```bash
docker inspect --format 'NetworkMode: {{.HostConfig.NetworkMode}}' <container>
```

```bash
docker port <container>
```

Flag if `NetworkMode` is `host` (**WARNING** — no network isolation).

### Mounted volumes and bind mounts

```bash
docker inspect --format '{{json .Mounts}}' <container>
```

Flag:
- Docker socket mounted (`/var/run/docker.sock`) — **CRITICAL**: grants root-equivalent host access
- Host filesystem mounts (`/`, `/etc`, `/var`) — **CRITICAL**: host filesystem exposure
- Writable mounts to sensitive paths — **WARNING**

### Environment variables (redact potential secrets)

```bash
docker inspect --format '{{json .Config.Env}}' <container>
```

Redact values of any variables whose names contain: `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `API_KEY`, `PRIVATE`, `CREDENTIAL`, `AUTH`, `PASS`. Show the variable name and only the first two and last two characters of the value (e.g., `DB_PASSWORD=hu****r2`).

### Capabilities

```bash
docker inspect --format 'CapAdd: {{json .HostConfig.CapAdd}} | CapDrop: {{json .HostConfig.CapDrop}}' <container>
```

Flag dangerous added capabilities:
- `SYS_ADMIN` — **CRITICAL**: near-root, can mount filesystems and escape containers
- `SYS_PTRACE` — **WARNING**: can debug/inject into other processes
- `NET_ADMIN` — **WARNING**: full network control
- `SYS_MODULE` — **CRITICAL**: can load kernel modules
- `SYS_RAWIO` — **CRITICAL**: direct I/O access

Commend if `ALL` capabilities are dropped and only specific ones are added.

### Security options (AppArmor, seccomp)

```bash
docker inspect --format '{{json .HostConfig.SecurityOpt}}' <container>
```

Flag if seccomp is set to `unconfined` (**WARNING** — no syscall filtering). Note if AppArmor profile is applied.

### Read-only root filesystem

```bash
docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' <container>
```

Flag if `false` — the container filesystem is writable, allowing an attacker to write to disk.

### PID and IPC namespace sharing

```bash
docker inspect --format 'PidMode: {{.HostConfig.PidMode}} | IpcMode: {{.HostConfig.IpcMode}}' <container>
```

Flag if `PidMode` is `host` (**WARNING** — container can see host processes) or `IpcMode` is `host`.

### Resource limits

```bash
docker inspect --format 'Memory: {{.HostConfig.Memory}} | CPUs: {{.HostConfig.NanoCpus}} | PidsLimit: {{.HostConfig.PidsLimit}}' <container>
```

Flag if memory or CPU limits are 0 (unlimited) — allows resource exhaustion DoS.

4. Present a summary report:

| Check | Result | Severity |
|-------|--------|----------|
| Privileged | true / false | CRITICAL / OK |
| User | root / non-root | CRITICAL / OK |
| Network Mode | bridge / host / none | OK / WARNING |
| Docker Socket Mount | yes / no | CRITICAL / OK |
| Sensitive Host Mounts | list | CRITICAL / OK |
| Added Capabilities | list | varies |
| Dropped Capabilities | list | OK / INFO |
| Seccomp Profile | applied / unconfined | OK / WARNING |
| Read-only Root FS | true / false | OK / WARNING |
| Resource Limits | set / unlimited | OK / WARNING |
| Secret Env Vars | found / none | WARNING / OK |

5. Provide actionable hardening recommendations for any findings.

## Security Notes

- A privileged container has **full access to the host** — it can load kernel modules, access all devices, and escape trivially. Never run privileged containers in production.
- Mounting the Docker socket into a container is equivalent to giving that container root access to the host. An attacker inside the container can create new privileged containers, access host filesystems, and compromise the entire host.
- Containers without resource limits can exhaust host CPU, memory, or PIDs, causing denial of service to other containers and the host itself.
- Environment variables are visible to anyone who can `docker inspect` the container. For sensitive values, use Docker secrets, mounted files, or a secrets manager.
- The `--read-only` flag prevents filesystem writes inside the container, limiting an attacker's ability to drop tools or establish persistence.
