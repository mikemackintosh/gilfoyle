# Container Image Audit

Audit a Docker image for security issues — inspect layers, user configuration, exposed ports, environment variables, HEALTHCHECK, and image size.

## Arguments

$ARGUMENTS should be a Docker image name (with optional tag or digest).

Examples:
- `nginx:latest`
- `myapp:1.2.3`
- `registry.example.com/app:prod`
- `python:3.12-slim`

## Workflow

1. Parse the image name from `$ARGUMENTS`.
2. Show the user the exact commands before executing them.
3. Run the following audit checks:

### Pull the image (if not already present)

```bash
docker image inspect <image> >/dev/null 2>&1 || docker pull <image>
```

### Image metadata overview

```bash
docker images <image> --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"
```

### Check user configuration (root vs non-root)

```bash
docker inspect --format '{{.Config.User}}' <image>
```

If the output is empty or `root` or `0`, flag as **WARNING** — the container runs as root by default.

### Check exposed ports

```bash
docker inspect --format '{{json .Config.ExposedPorts}}' <image>
```

Flag any unexpected or high-risk ports (e.g., 22/SSH, 3306/MySQL, 5432/PostgreSQL exposed without clear reason).

### Check environment variables for secrets

```bash
docker inspect --format '{{json .Config.Env}}' <image>
```

Flag any environment variables whose names contain: `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `API_KEY`, `PRIVATE`, `CREDENTIAL`, `AUTH`. Redact the values — show only the variable name and first/last two characters of the value.

### Check HEALTHCHECK

```bash
docker inspect --format '{{json .Config.Healthcheck}}' <image>
```

If empty or null, flag as **WARNING** — no health check configured.

### Inspect image layers

```bash
docker history --no-trunc <image>
```

Review layers for:
- Secrets or credentials passed via `RUN` commands (e.g., `curl -u user:pass`, `echo password`)
- `ADD` instructions fetching remote URLs (should use `COPY` or `RUN curl`)
- Unnecessary package installations (build tools left in final image)
- Large layers that indicate bloat

### Check layer count

```bash
docker history <image> --format '{{.CreatedBy}}' | wc -l
```

Flag if the image has an unusually high number of layers (>30) — indicates poor layer consolidation.

### Check image digest (integrity verification)

```bash
docker inspect --format '{{index .RepoDigests 0}}' <image> 2>/dev/null
```

### Check for known vulnerabilities (if scanner available)

```bash
# Docker Scout (if available)
docker scout quickview <image> 2>/dev/null

# Trivy (if available)
trivy image --severity HIGH,CRITICAL <image> 2>/dev/null
```

4. Present a summary report:

| Check | Result | Severity |
|-------|--------|----------|
| User | root / non-root | CRITICAL / OK |
| Exposed Ports | list | INFO |
| Env Secrets | found / none | CRITICAL / OK |
| HEALTHCHECK | present / missing | WARNING / OK |
| Image Size | value | INFO |
| Layer Count | value | INFO / WARNING |
| Vulnerability Scan | summary | varies |

5. Provide actionable recommendations for any findings.

## Security Notes

- Running containers as root is the most common container security misconfiguration. If the image does not set a `USER`, the container process runs as UID 0 inside the container, which maps to root on the host if the container escapes.
- Environment variables baked into images are visible to anyone who can pull the image. Use Docker secrets, mounted config files, or runtime environment variables instead.
- A missing HEALTHCHECK means the orchestrator cannot detect if the application inside the container has crashed or become unresponsive.
- Image layers are immutable — even if a secret is deleted in a later layer, it remains in the image history. Use multi-stage builds to avoid leaking secrets.
- Always verify image integrity using digests (`image@sha256:...`) rather than mutable tags.
