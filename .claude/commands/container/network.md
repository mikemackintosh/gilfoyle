# Container Network Inspect

Inspect Docker container networking — networks, port mappings, inter-container connectivity, and network isolation.

## Arguments

$ARGUMENTS is optional:
- A container name/ID to inspect that specific container's networking
- A Docker network name to inspect that specific network
- (no args — show all networks and their connected containers)

Examples:
- (no args — list all networks)
- `my-web-app`
- `bridge`
- `my-custom-network`

## Workflow

1. Parse the target from `$ARGUMENTS`.
2. Show the user the exact commands before executing them.

### List all Docker networks

```bash
docker network ls --format "table {{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}"
```

### Inspect a specific network

```bash
docker network inspect <network> --format '{{json .}}' 2>/dev/null
```

Key fields to extract:
- Driver (bridge, host, overlay, macvlan)
- Subnet and gateway
- Connected containers (name, IP, MAC)
- Internal flag (no external access)
- Enable ICC (inter-container communication)

### Inspect a specific container's networking

```bash
docker inspect --format '{{json .NetworkSettings}}' <container>
```

Key fields to extract:
- Network mode
- IP address(es)
- MAC address
- Connected networks
- Port mappings (HostPort -> ContainerPort)

### Show port mappings for a container

```bash
docker port <container>
```

Flag ports bound to `0.0.0.0` (**WARNING** — accessible from all interfaces). Recommend binding to `127.0.0.1` for services that should only be accessed locally.

### Check for host network mode

```bash
docker inspect --format '{{.HostConfig.NetworkMode}}' <container>
```

Flag if `host` — **WARNING**: the container shares the host's network namespace, bypassing all Docker network isolation.

### List all containers and their network connections

```bash
docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Ports}}"
```

### Check inter-container connectivity on a network

```bash
docker network inspect <network> --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
```

### Check for containers with no network

```bash
docker ps --filter "network=none" --format "table {{.ID}}\t{{.Names}}"
```

### Check for published ports across all containers

```bash
docker ps --format '{{.Names}}: {{.Ports}}' | grep '0.0.0.0'
```

Flag any ports published on `0.0.0.0` that are sensitive services:
- 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB) — database ports should not be exposed externally
- 2375/2376 (Docker API) — **CRITICAL**: unauthenticated Docker API access
- 9200/9300 (Elasticsearch) — often misconfigured without authentication

### Check Docker daemon API exposure

```bash
# Check if Docker daemon is listening on TCP
docker info --format '{{json .}}' 2>/dev/null | grep -o '"Host":"[^"]*"'
```

```bash
# Check for exposed Docker API port
ss -tlnp 2>/dev/null | grep -E ':(2375|2376)\s' || lsof -i -P -n | grep -E ':(2375|2376)\s.*LISTEN'
```

Flag if port 2375 is open (**CRITICAL** — unauthenticated Docker API). Port 2376 with TLS is acceptable but should be verified.

3. Present a summary:

| Check | Result | Severity |
|-------|--------|----------|
| Total Networks | count | INFO |
| Host-mode Containers | list | WARNING / OK |
| Ports on 0.0.0.0 | list | WARNING / OK |
| Sensitive Ports Exposed | list | CRITICAL / OK |
| Docker API Exposed | yes / no | CRITICAL / OK |
| Containers without Network | list | INFO |
| ICC Enabled | per network | INFO |

4. Provide a network topology summary showing which containers can communicate with each other based on shared networks.

5. Provide actionable recommendations for any findings.

## Security Notes

- Containers on the same Docker bridge network can communicate freely by default. Use user-defined bridge networks with `--internal` to restrict external access and separate application tiers.
- Publishing ports on `0.0.0.0` makes them accessible from any network interface, including public-facing ones. Always bind to `127.0.0.1` unless external access is intended.
- The Docker API (port 2375 without TLS) provides unauthenticated root-level access to the host. If this port is exposed to the network, any attacker can create privileged containers and compromise the host.
- Host network mode (`--network=host`) removes all network isolation. The container can bind to any port, see all host traffic, and access services on `localhost`.
- Database ports (MySQL, PostgreSQL, Redis, MongoDB) should never be directly exposed. Use Docker networks for container-to-container communication and expose only the application frontend.
- Docker's default bridge network does not provide automatic DNS resolution between containers. Use user-defined networks where containers can reach each other by name.
