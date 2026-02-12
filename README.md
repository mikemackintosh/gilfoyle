# SecEng 101

A security engineering toolkit built on [Claude Code](https://docs.anthropic.com/en/docs/claude-code). It packages roughly 100 slash commands and 30 skills into a single assistant that handles the stuff security engineers actually do day-to-day -- TLS debugging, log analysis, incident response, hardening audits, and everything in between.

Instead of memorizing `openssl` flags or grepping through man pages, you type a slash command and get the answer (plus an explanation of what just happened and why it matters).

## Getting started

1. Install [Claude Code](https://docs.anthropic.com/en/docs/claude-code) if you haven't already.
2. Clone this repo and `cd` into it.
3. Run `claude` to start a session. The commands and skills load automatically from the `.claude/` directory.

That's it. No build step, no dependencies, no config files to edit. The whole thing is just markdown files that Claude Code reads at startup.

## What's in the box

Commands are organized by domain. Each one is a focused workflow you invoke with a slash command.

### TLS and certificates

Inspect live connections, decode certificate files, verify chains, scan cipher suites. If something is wrong with TLS, start here.

```
/tls:inspect example.com
/tls:cert-info ./server.pem
/tls:cert-chain-verify ./cert.pem ./ca-bundle.pem
/tls:cipher-scan example.com
```

### Key management and PKI

Generate key pairs, create CSRs, build self-signed certs, work with PKCS#12 bundles, set up a certificate authority. Defaults to strong algorithms (RSA-4096, P-256, Ed25519) unless you say otherwise.

```
/key:gen ed25519
/key:gen-csr ./server.key "/CN=myapp.example.com"
/key:gen-selfsigned ./ca.key "/CN=My CA" 3650
/pki:ca-setup
```

### Network diagnostics

DNS lookups, ping, port scanning, traceroute, packet capture, whois. The usual suspects, but with context about what the results mean.

```
/net:dig example.com MX
/net:portscan 192.168.1.1 --service
/net:traceroute example.com --mtr
/net:tcpdump "port 443" --count 100
```

### SSH operations

Generate keys, set up tunnels, debug connection problems, review client config, audit server hardening.

```
/ssh:keygen ed25519
/ssh:tunnel local 8080:db.internal:5432 bastion.example.com
/ssh:harden /etc/ssh/sshd_config
```

### Log analysis

Parse auth failures, detect brute-force attempts, analyze web server errors, search across system logs with time filtering.

```
/log:auth-failures /var/log/auth.log --last 24h
/log:brute-force /var/log/auth.log --threshold 5
/log:web-errors /var/log/nginx/access.log --scanners
```

### Incident response

Initial triage, network connection auditing, persistence mechanism checks, and evidence collection. Designed for the first 30 minutes of an incident.

```
/ir:triage --save ./evidence
/ir:connections --suspicious
/ir:persistence --full
/ir:collect-evidence ./case-2024-001
```

### Security hardening

SSH audits, firewall checks, SUID/SGID binary scanning, CIS benchmark spot checks. Quick wins for tightening a system.

```
/harden:ssh-audit example.com
/harden:firewall-status --detailed
/harden:suid-audit /usr
/harden:cis-check linux
```

### Web application security

HTTP security headers, CORS misconfiguration testing, cookie flags, Content Security Policy analysis, and detailed request inspection.

```
/web:headers https://example.com
/web:cors https://api.example.com https://evil.com
/web:cookies https://example.com
/web:csp https://example.com
```

### Email security

SPF, DKIM, and DMARC record analysis. Or run a full domain audit that checks all of them plus MX, CAA, and MTA-STS in one pass. The macro checker parses and test-expands SPF macros -- the `%{i}`, `%{ir}`, `exists:` patterns that are powerful but nearly impossible to read without help.

```
/email:domain-audit example.com
/email:spf-check example.com
/email:spf-macro example.com
/email:spf-macro example.com --test --ip 203.0.113.10 --sender user@example.com
/email:dmarc-check example.com
```

### JWT and token analysis

Decode tokens, verify signatures against secrets or JWKS endpoints, and run security checks for common JWT vulnerabilities.

```
/jwt:decode eyJhbGciOi...
/jwt:verify eyJhbGciOi... --jwks https://auth.example.com/.well-known/jwks.json
/jwt:inspect eyJhbGciOi...
```

### Secrets detection

Scan files, directories, and git history for accidentally committed secrets. Includes an entropy scanner for catching things that don't match known patterns.

```
/secrets:scan ./src
/secrets:git-history
/secrets:entropy ./config
```

### Git security

Audit your `.gitignore`, set up commit signing, verify signed commits, scan for secrets in the repo.

```
/git-sec:gitignore-audit
/git-sec:sign-setup
/git-sec:secret-scan
```

### Git operations

Day-to-day git troubleshooting. Fix detached HEAD, resolve conflicts, undo mistakes, clean up stale branches, recover lost commits from reflog.

```
/git-ops:doctor
/git-ops:undo commit
/git-ops:conflict --theirs
/git-ops:reflog-recover stash
```

### Container security

Audit images for vulnerabilities, inspect running containers, check network configuration, and lint Dockerfiles.

```
/container:image-audit myapp:latest
/container:dockerfile-check ./Dockerfile
/container:inspect <container_id>
```

### Cloud security (AWS)

Audit security groups, S3 bucket permissions, and IAM configurations.

```
/cloud:aws-sg
/cloud:aws-s3
/cloud:aws-iam
```

### Linux administration

Disk management, package operations, user/group management, systemd services, process management, file permissions, performance tuning, and boot configuration.

```
/linux:disk --usage
/linux:users audit
/linux:systemd failed
/linux:performance --memory
```

### Web server administration

nginx and Apache configuration, reverse proxy setup, SSL certificate deployment with certbot, and troubleshooting common errors (502s, 504s, permission issues).

```
/webserver:nginx status
/webserver:ssl-deploy certbot example.com
/webserver:troubleshoot 502
```

### Database administration

PostgreSQL and MySQL/MariaDB monitoring, backup and restore, query performance analysis, and user/privilege management.

```
/db:postgres connections
/db:backup postgres dump mydb
/db:performance slow
/db:users audit
```

### Windows security

System enumeration, user and group auditing, network analysis, service auditing, firewall review, process analysis, and scheduled task review. Plus advanced commands for Active Directory, Group Policy, event log forensics, registry auditing, Defender configuration, privilege escalation checks, and credential store analysis.

```
/win:sysinfo
/win:services --vulnerable
/win-adv:ad-enum --kerberoast
/win-adv:eventlog --brute-force
```

### Other tools

There are also commands for OSINT/reconnaissance, API security testing, VPN/WireGuard configuration, password generation and policy checking, malware triage (string extraction, file identification), YARA rule testing, macOS endpoint checks, and cryptographic encoding/hashing.

Browse the full list by looking at the `.claude/commands/` directory, or just ask the assistant what it can do.

## How it works

The project is a collection of markdown files in `.claude/`:

- **`commands/`** -- Slash command definitions. Each `.md` file describes a single workflow: what arguments it takes, what commands it runs, and how to interpret the output. Claude Code loads these automatically and makes them available as `/category:command`.

- **`skills/`** -- Background knowledge that gets activated contextually. These contain reference tables, best practices, troubleshooting steps, and security guidance. When you ask about TLS, the transport security skill kicks in. When you're doing incident response, that skill loads instead.

The assistant (named Gilfoyle, because of course it is) uses `openssl`, `nmap`, `dig`, `curl`, and other standard tools under the hood. It shows you every command before running it and explains the security implications of what it finds.

## Design principles

- **Show your work.** Every command is displayed before execution. No black boxes.
- **Safe defaults.** Strong algorithms, secure configurations, conservative recommendations.
- **Explain the "why."** Don't just run the command -- explain what the output means and what to do about it.
- **Stay local.** Private keys and sensitive data never leave the machine.
- **Use standard tools.** OpenSSL, nmap, dig, curl, systemctl -- stuff that's already on the box or one package install away.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (the CLI)
- Standard system tools: `openssl`, `curl`, `dig`, `nmap`, etc. (the assistant will tell you if something is missing)
- For Windows commands: a Windows machine or PowerShell remoting
- For cloud commands: appropriate CLI tools (`aws`) and credentials configured

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
