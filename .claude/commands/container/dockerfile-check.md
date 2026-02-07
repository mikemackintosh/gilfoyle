# Dockerfile Check

Check a Dockerfile for security best practices — user configuration, pinned versions, secrets exposure, HEALTHCHECK, base image selection, and multi-stage build usage.

## Arguments

$ARGUMENTS should be a path to a Dockerfile.

Examples:
- `Dockerfile`
- `./docker/Dockerfile.prod`
- `/home/user/project/Dockerfile`

## Workflow

1. Parse the Dockerfile path from `$ARGUMENTS`.
2. Show the user the exact commands before executing them.
3. Read the Dockerfile and perform the following checks:

### Check for USER instruction (non-root)

```bash
grep -n '^USER ' <dockerfile>
```

If no `USER` instruction is found, or if `USER root` is set without switching to a non-root user later, flag as **WARNING** — the container will run as root.

### Check base image version pinning

```bash
grep -n '^FROM ' <dockerfile>
```

Flag as **WARNING** if any `FROM` instruction uses:
- `:latest` tag (e.g., `FROM node:latest`)
- No tag at all (e.g., `FROM node`)
- An unpinned tag without a digest (e.g., `FROM node:20` without `@sha256:...`)

Recommend pinning to a specific version and digest: `FROM node:20.11.0-alpine@sha256:abc...`

### Check for ADD with remote URLs

```bash
grep -n '^ADD ' <dockerfile>
```

Flag as **WARNING** if `ADD` is used with a URL (e.g., `ADD https://example.com/file.tar.gz /app/`). `ADD` with remote URLs does not verify checksums and can introduce supply chain risks. Recommend using `COPY` for local files or `RUN curl`/`RUN wget` with checksum verification for remote files.

### Check for secrets in ENV and ARG instructions

```bash
grep -n '^\(ENV\|ARG\) ' <dockerfile>
```

Flag as **CRITICAL** if any `ENV` or `ARG` instruction contains variable names matching: `PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `API_KEY`, `PRIVATE`, `CREDENTIAL`, `AUTH`, `PASS`. Secrets in `ENV` persist in the image metadata. Secrets in `ARG` are visible in `docker history`.

### Check for HEALTHCHECK instruction

```bash
grep -n '^HEALTHCHECK ' <dockerfile>
```

If no `HEALTHCHECK` instruction is found, flag as **WARNING** — the orchestrator cannot monitor application health.

### Check base image choice

```bash
head -1 <dockerfile> | grep '^FROM'
```

Flag as **INFO** if using a full OS image (`ubuntu`, `debian`, `centos`, `fedora`) without a `slim` or `alpine` variant. Recommend minimal base images to reduce attack surface:
- `alpine` variants for shell-based workflows
- `distroless` for compiled languages
- `scratch` for static binaries

### Check for multi-stage build

```bash
grep -c '^FROM ' <dockerfile>
```

If only one `FROM` instruction exists and the image installs build tools (compilers, `build-essential`, `gcc`, `make`, `npm install`, `go build`), flag as **WARNING** — build tools should not be in the final image. Recommend a multi-stage build.

### Check for .dockerignore reference

```bash
ls -la "$(dirname <dockerfile>)/.dockerignore" 2>/dev/null
```

If no `.dockerignore` exists alongside the Dockerfile, flag as **WARNING** — the build context may include `.git`, `.env`, `node_modules`, private keys, and other sensitive files.

### Check COPY vs ADD usage

```bash
grep -n '^\(COPY\|ADD\) ' <dockerfile>
```

Flag `ADD` instructions that do not involve tar extraction. `COPY` is preferred because it is more explicit and does not auto-extract archives or fetch URLs.

### Check for package cache cleanup

```bash
grep -n 'apt-get install\|apk add\|yum install\|dnf install' <dockerfile>
```

Flag as **INFO** if package install commands do not clean up caches in the same `RUN` layer:
- Debian/Ubuntu: `rm -rf /var/lib/apt/lists/*`
- Alpine: `--no-cache` flag or `rm -rf /var/cache/apk/*`
- RHEL/CentOS: `yum clean all` or `dnf clean all`

### Check for shell form vs exec form in ENTRYPOINT/CMD

```bash
grep -n '^\(ENTRYPOINT\|CMD\) ' <dockerfile>
```

Flag as **INFO** if shell form is used (e.g., `CMD command arg1 arg2`) instead of exec form (e.g., `CMD ["command", "arg1", "arg2"]`). Shell form runs under `/bin/sh -c`, which does not receive signals properly and adds an unnecessary shell process.

4. Present a summary report:

| Check | Result | Severity |
|-------|--------|----------|
| Non-root USER | present / missing | WARNING / OK |
| Pinned base image | pinned / unpinned | WARNING / OK |
| ADD remote URLs | found / none | WARNING / OK |
| Secrets in ENV/ARG | found / none | CRITICAL / OK |
| HEALTHCHECK | present / missing | WARNING / OK |
| Minimal base image | yes / no | INFO / OK |
| Multi-stage build | yes / no | WARNING / OK |
| .dockerignore | present / missing | WARNING / OK |
| Package cache cleanup | yes / no | INFO / OK |
| Exec form CMD/ENTRYPOINT | yes / no | INFO / OK |

5. Provide specific fix recommendations with code examples for each finding.

## Security Notes

- Secrets baked into image layers via `ENV`, `ARG`, or `RUN` commands persist in the image even if overwritten or deleted in later layers. Use Docker build secrets (`--mount=type=secret`) or runtime injection instead.
- Running as root inside a container is dangerous because user namespaces are not enabled by default — UID 0 inside the container is UID 0 on the host. A container escape vulnerability grants immediate root access.
- Unpinned base images can change without notice. A `docker build` today may produce a different image than tomorrow if the tag is updated. Pin versions and digests for reproducible, auditable builds.
- `ADD` with remote URLs does not verify TLS certificates or file integrity by default. Use `RUN curl` with `--fail` and verify checksums.
- A `.dockerignore` file is critical for preventing secrets (`.env`, `*.key`, `.git/`) from being copied into the build context and potentially into the final image.
