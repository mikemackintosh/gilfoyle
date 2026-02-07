---
name: Container Security
description: Docker and container security auditing — image analysis, runtime inspection, Dockerfile best practices, and container hardening.
instructions: |
  Use this skill when the user needs to audit Docker images, inspect running containers, review
  Dockerfiles for security best practices, assess container networking, or harden container
  deployments. Always show commands before executing them and explain the security implications
  of each finding. Never expose secrets found in environment variables or build arguments —
  redact middle characters.
---

# Container Security Skill

## Related Commands
- `/container-image-audit` — Audit a Docker image for security issues
- `/container-inspect` — Inspect a running container's security posture
- `/container-dockerfile-check` — Check a Dockerfile for security best practices
- `/container-network` — Inspect container networking configuration

## Docker Image Security

### Image Audit Checklist

| Check | Risk | Command |
|-------|------|---------|
| Running as root | Container escape, host compromise | `docker inspect --format '{{.Config.User}}' <image>` |
| Exposed ports | Unnecessary attack surface | `docker inspect --format '{{json .Config.ExposedPorts}}' <image>` |
| Environment secrets | Credential leakage | `docker inspect --format '{{json .Config.Env}}' <image>` |
| Layer count | Build hygiene, bloat | `docker history <image>` |
| Image size | Attack surface (more packages = more vulns) | `docker images <image>` |
| No HEALTHCHECK | No liveness monitoring | `docker inspect --format '{{json .Config.Healthcheck}}' <image>` |
| Writable filesystem | Persistence by attacker | `docker inspect --format '{{json .Config.Volumes}}' <image>` |

### Base Image Selection

| Base Image | Size | Use Case | Security Notes |
|------------|------|----------|----------------|
| `scratch` | 0 MB | Static Go/Rust binaries | Smallest attack surface possible |
| `distroless` | ~2-20 MB | Most compiled languages | No shell, no package manager |
| `alpine` | ~5 MB | When shell is needed | Minimal but includes musl libc |
| `slim` variants | ~30-80 MB | When debian packages needed | Reduced Debian/Ubuntu |
| Full `ubuntu`/`debian` | ~75-130 MB | Development/debugging | Largest attack surface |

### Image Vulnerability Scanning

```bash
# Docker Scout (built-in)
docker scout cves <image>
docker scout quickview <image>

# Trivy (if installed)
trivy image <image>

# Grype (if installed)
grype <image>

# Snyk (if installed)
snyk container test <image>
```

## Dockerfile Best Practices

### Security-Critical Rules

| Rule | Bad | Good |
|------|-----|------|
| Non-root user | No `USER` instruction | `RUN useradd -r appuser && USER appuser` |
| Pinned versions | `FROM node:latest` | `FROM node:20.11.0-alpine@sha256:abc...` |
| No ADD for URLs | `ADD https://example.com/file.tar.gz /` | `RUN curl -sSL https://example.com/file.tar.gz \| tar xz` |
| No secrets in ENV/ARG | `ENV DB_PASSWORD=hunter2` | Use Docker secrets or mount at runtime |
| HEALTHCHECK present | No HEALTHCHECK | `HEALTHCHECK CMD curl -f http://localhost/ \|\| exit 1` |
| Multi-stage build | Single stage with build tools | Separate build and runtime stages |
| Minimal base | `FROM ubuntu:latest` | `FROM alpine:3.19` or `FROM gcr.io/distroless/static` |
| COPY over ADD | `ADD . /app` | `COPY . /app` |
| .dockerignore | Missing | Include `.git`, `.env`, `node_modules`, `*.key` |

### Multi-Stage Build Example

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server

# Runtime stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/server /server
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/server", "-healthcheck"]
ENTRYPOINT ["/server"]
```

## Running Container Security

### Runtime Inspection

```bash
# Processes inside container
docker top <container>

# Real-time resource usage
docker stats <container> --no-stream

# Full container configuration
docker inspect <container>

# Network configuration
docker inspect --format '{{json .NetworkSettings}}' <container>

# Mounted volumes
docker inspect --format '{{json .Mounts}}' <container>

# Security options (AppArmor, seccomp, capabilities)
docker inspect --format '{{json .HostConfig.SecurityOpt}}' <container>
docker inspect --format '{{json .HostConfig.CapAdd}}' <container>
docker inspect --format '{{json .HostConfig.CapDrop}}' <container>

# Privileged mode (CRITICAL — should be false)
docker inspect --format '{{.HostConfig.Privileged}}' <container>

# PID namespace sharing
docker inspect --format '{{.HostConfig.PidMode}}' <container>
```

### Capabilities Reference

Default Docker capabilities that are granted:

| Capability | Purpose | Risk if abused |
|------------|---------|----------------|
| `CAP_CHOWN` | Change file ownership | Modify file permissions |
| `CAP_DAC_OVERRIDE` | Bypass file permissions | Read/write any file |
| `CAP_FSETID` | Set SUID/SGID bits | Privilege escalation |
| `CAP_KILL` | Send signals to processes | DoS |
| `CAP_NET_BIND_SERVICE` | Bind to low ports (<1024) | Usually needed |
| `CAP_NET_RAW` | Raw sockets | Network sniffing, spoofing |
| `CAP_SETGID` / `CAP_SETUID` | Change process UID/GID | Privilege escalation |
| `CAP_SYS_CHROOT` | Use chroot | Escape container |

Dangerous capabilities to flag when added:

| Capability | Risk |
|------------|------|
| `CAP_SYS_ADMIN` | Near-root — can mount filesystems, escape containers |
| `CAP_SYS_PTRACE` | Debug/inject into other processes |
| `CAP_NET_ADMIN` | Full network control |
| `CAP_SYS_MODULE` | Load kernel modules |
| `CAP_SYS_RAWIO` | Direct I/O access |

### Recommended: Drop All, Add Only What's Needed

```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE <image>
```

## Docker Socket Security

The Docker socket (`/var/run/docker.sock`) provides **full root access** to the host.

```bash
# Check if Docker socket is mounted into a container
docker inspect --format '{{json .Mounts}}' <container> | grep docker.sock

# Check permissions on Docker socket
ls -la /var/run/docker.sock

# Check who is in the docker group (all members have root-equivalent access)
getent group docker
```

**Rules:**
- Never mount the Docker socket into a container unless absolutely required
- If mounted, treat that container as having **root access to the host**
- Use TCP with TLS mutual authentication if remote Docker API access is needed
- Consider rootless Docker or Podman for reduced attack surface

## Container Networking

### Network Modes

| Mode | Isolation | Use Case |
|------|-----------|----------|
| `bridge` (default) | Separate network namespace | Standard containers |
| `host` | **No isolation** — shares host network | Performance (avoid if possible) |
| `none` | No networking at all | Maximum isolation |
| Custom bridge | Isolated user-defined network | Multi-container apps |
| `overlay` | Cross-host networking | Docker Swarm / multi-node |
| `macvlan` | Direct physical network access | Legacy app compatibility |

```bash
# List networks
docker network ls

# Inspect a network
docker network inspect <network>

# Find which containers are on a network
docker network inspect <network> --format '{{range .Containers}}{{.Name}} {{end}}'

# Check port mappings for a container
docker port <container>
```

### Network Security Best Practices

- Use **user-defined bridge networks** instead of the default bridge
- Containers on different networks cannot communicate (network segmentation)
- Avoid `--network=host` — it defeats network isolation
- Limit published ports: use `-p 127.0.0.1:8080:8080` instead of `-p 8080:8080` (binds to all interfaces)
- Use `--internal` flag for networks that should not have external access

## Registry Security

```bash
# Check image provenance
docker trust inspect <image>

# View image signatures (Docker Content Trust / Notary)
DOCKER_CONTENT_TRUST=1 docker pull <image>

# Check image digest (verify integrity)
docker inspect --format '{{index .RepoDigests 0}}' <image>

# Scan a private registry image
docker scout cves registry.example.com/app:latest
```

### Registry Hardening

- Enable Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) to require signed images
- Use image digests (`image@sha256:...`) instead of tags for immutable references
- Restrict who can push to your registry
- Scan images in CI/CD before pushing to registry
- Implement an image admission policy in Kubernetes (OPA/Gatekeeper, Kyverno)

## Kubernetes Pod Security Basics

### Pod Security Standards (PSS)

| Level | Description | Key Restrictions |
|-------|-------------|------------------|
| `Privileged` | Unrestricted | None |
| `Baseline` | Minimally restrictive | No privileged, no hostNetwork, no hostPID |
| `Restricted` | Heavily restricted | Must run as non-root, drop ALL capabilities, read-only rootfs |

### Security Context Fields

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:1.0@sha256:abc...
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "500m"
        memory: "128Mi"
```

### Pod Security Checklist

| Check | Expected | Risk if misconfigured |
|-------|----------|-----------------------|
| `runAsNonRoot: true` | Set | Container runs as root |
| `allowPrivilegeEscalation: false` | Set | SUID binaries can escalate |
| `readOnlyRootFilesystem: true` | Set | Attacker can write to filesystem |
| `capabilities.drop: ["ALL"]` | Set | Unnecessary kernel capabilities |
| `hostNetwork: false` | Default | Pod shares host network stack |
| `hostPID: false` | Default | Pod can see host processes |
| `hostIPC: false` | Default | Pod can access host IPC |
| `seccompProfile: RuntimeDefault` | Set | No syscall filtering |
| Resource limits | Set | DoS via resource exhaustion |
| Image pull policy `Always` | Set | Stale/tampered cached images |
