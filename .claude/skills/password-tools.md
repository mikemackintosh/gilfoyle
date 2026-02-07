---
name: Password & Credential Tools
description: Secure password generation, hash type identification, password policy checking, and credential format utilities.
instructions: |
  Use this skill when the user needs to generate secure passwords, identify hash types, check
  passwords against policies, generate htpasswd entries, or decode credential formats. Always
  use cryptographically secure random sources and explain password strength.
---

# Password & Credential Tools Skill

## Password Generation

### Using openssl

```bash
# Random base64 password (32 chars)
openssl rand -base64 24

# Random hex password
openssl rand -hex 16

# Alphanumeric password (no special chars)
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 24

# Password with special characters
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+-=' | head -c 24

# Passphrase (word-based)
python3 -c "
import secrets, string
words = ['correct','horse','battery','staple','orange','purple','basket','window','garden','silver','rocket','planet','forest','ocean','castle','bridge','dragon','falcon','marble','sunset']
print('-'.join(secrets.choice(words) for _ in range(5)))
"
```

### Password Strength Reference

| Type | Length | Entropy (approx.) | Example |
|------|--------|-------------------|---------|
| Numeric PIN | 4 digits | ~13 bits | `7294` |
| Numeric PIN | 6 digits | ~20 bits | `729413` |
| Alpha lowercase | 8 chars | ~38 bits | `kxmpqbvz` |
| Alphanumeric | 12 chars | ~71 bits | `aB3kX9mP2wQ7` |
| Full ASCII | 16 chars | ~105 bits | `aB3!kX9@mP2#wQ7$` |
| Passphrase (5 words) | ~25 chars | ~65 bits | `correct-horse-battery-staple-orange` |
| Random base64 | 32 chars | ~192 bits | `K7x2mP9Q...` |

**Minimum recommendations:**
- User passwords: 14+ characters, or 4+ word passphrase
- API keys: 32+ random bytes (256 bits)
- Encryption keys: 32 random bytes (256 bits) minimum

## Hash Type Identification

### Common Hash Formats

| Hash Type | Length | Prefix/Pattern | Example |
|-----------|--------|----------------|---------|
| MD5 | 32 hex | None | `5d41402abc4b2a76b9719d911017c592` |
| SHA-1 | 40 hex | None | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| SHA-256 | 64 hex | None | `2cf24dba5fb0a30e...` |
| SHA-512 | 128 hex | None | `9b71d224bd62f378...` |
| bcrypt | 60 chars | `$2b$` or `$2a$` | `$2b$12$LJ3m4ys...` |
| scrypt | Variable | `$scrypt$` | `$scrypt$ln=15,r=8,p=1$...` |
| Argon2 | Variable | `$argon2id$` | `$argon2id$v=19$m=65536,t=3,p=4$...` |
| NTLM | 32 hex | None | `a4f49c406510bdca...` |
| MySQL 4.1+ | 40 hex | `*` | `*2470C0C06DEE42FD...` |
| Linux shadow (SHA-512) | Variable | `$6$` | `$6$rounds=5000$salt$hash` |
| Linux shadow (SHA-256) | Variable | `$5$` | `$5$rounds=5000$salt$hash` |
| Apache MD5 | Variable | `$apr1$` | `$apr1$salt$hash` |

### Linux Shadow File Prefixes

| Prefix | Algorithm |
|--------|-----------|
| `$1$` | MD5 (deprecated) |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 (recommended) |
| `$y$` | yescrypt (modern Linux default) |
| `$2b$` | bcrypt |

## htpasswd Generation

```bash
# Apache htpasswd — bcrypt (most secure)
htpasswd -nbBC 12 username password

# Without htpasswd — using openssl
openssl passwd -apr1 password

# Using python3 bcrypt
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt(rounds=12)).decode())"
```

## Credential Format Utilities

### Decode Basic Auth Header

```bash
# Basic auth is base64(username:password)
echo "dXNlcm5hbWU6cGFzc3dvcmQ=" | base64 -d
# Output: username:password

# Encode Basic auth
echo -n "username:password" | base64
```

### Decode Bearer Token

If the Bearer token is a JWT, use `/jwt:decode`.

### Parse Connection Strings

```bash
# PostgreSQL: postgres://user:pass@host:port/db
# MySQL:      mysql://user:pass@host:port/db
# MongoDB:    mongodb://user:pass@host:port/db
# Redis:      redis://:pass@host:port/db

python3 -c "
from urllib.parse import urlparse
import sys
r = urlparse(sys.argv[1])
print(f'Scheme:   {r.scheme}')
print(f'User:     {r.username}')
print(f'Password: {\"*\" * len(r.password) if r.password else \"(none)\"}')
print(f'Host:     {r.hostname}')
print(f'Port:     {r.port}')
print(f'Database: {r.path.lstrip(\"/\")}')
" "postgres://user:pass@host:5432/mydb"
```
