# Hash Identification

Identify the type of a hash based on its format, length, and prefix.

## Arguments

$ARGUMENTS should be a hash string.

Examples:
- `5d41402abc4b2a76b9719d911017c592`
- `$2b$12$LJ3m4ysLk0RVe7V5HxPJUOq1Kz3hFNOkz1z8R0q.X2GkPZ8LZ8K6i`
- `$6$rounds=5000$saltsalt$hashhashhash...`
- `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19`

## Workflow

1. Parse the hash from `$ARGUMENTS`.
2. Analyse the hash format.

```bash
python3 -c "
import re, sys

h = sys.argv[1].strip()
matches = []

# By prefix
if h.startswith('\$2b\$') or h.startswith('\$2a\$') or h.startswith('\$2y\$'):
    matches.append(('bcrypt', 'Secure, widely used for passwords. Cost factor in prefix.'))
elif h.startswith('\$argon2id\$') or h.startswith('\$argon2i\$'):
    matches.append(('Argon2', 'Modern, memory-hard. Recommended for new applications.'))
elif h.startswith('\$scrypt\$'):
    matches.append(('scrypt', 'Memory-hard KDF. Used in some crypto applications.'))
elif h.startswith('\$6\$'):
    matches.append(('SHA-512 crypt (Linux shadow)', 'Standard Linux password hash.'))
elif h.startswith('\$5\$'):
    matches.append(('SHA-256 crypt (Linux shadow)', 'Linux password hash.'))
elif h.startswith('\$1\$'):
    matches.append(('MD5 crypt (Linux shadow)', 'DEPRECATED. Upgrade to SHA-512 or bcrypt.'))
elif h.startswith('\$y\$'):
    matches.append(('yescrypt (Linux shadow)', 'Modern Linux default. Memory-hard.'))
elif h.startswith('\$apr1\$'):
    matches.append(('Apache MD5', 'Apache htpasswd MD5 format.'))
elif h.startswith('*') and len(h) == 41:
    matches.append(('MySQL 4.1+', 'MySQL password hash (SHA-1 based).'))
elif h.startswith('{SSHA}'):
    matches.append(('SSHA (LDAP)', 'Salted SHA-1 for LDAP/OpenLDAP.'))

# By length (hex only)
if re.match(r'^[a-fA-F0-9]+\$', h):
    length = len(h)
    if length == 32:
        matches.append(('MD5', '128-bit. BROKEN for security. Also matches NTLM.'))
    elif length == 40:
        matches.append(('SHA-1', '160-bit. DEPRECATED for security.'))
    elif length == 56:
        matches.append(('SHA-224', '224-bit. Uncommon.'))
    elif length == 64:
        matches.append(('SHA-256', '256-bit. Widely used, secure.'))
    elif length == 96:
        matches.append(('SHA-384', '384-bit.'))
    elif length == 128:
        matches.append(('SHA-512', '512-bit. Secure.'))

if not matches:
    matches.append(('Unknown', 'Could not identify hash type from format.'))

print(f'Hash:   {h[:40]}...' if len(h) > 40 else f'Hash:   {h}')
print(f'Length: {len(h)} characters')
print()
for name, desc in matches:
    print(f'  -> {name}: {desc}')
" "<hash>"
```

3. Present:
   - Identified hash type(s) (may have multiple candidates for hex hashes)
   - Hash length
   - Security assessment (secure / deprecated / broken)
   - If deprecated, recommend the modern alternative

## Security Notes

- MD5 and SHA-1 are **broken** for password hashing — they can be cracked quickly with GPU hardware.
- Plain hex hashes (MD5, SHA-*) without a salt are vulnerable to rainbow table attacks.
- bcrypt, scrypt, and Argon2 are the recommended password hashing algorithms — they include salt and are intentionally slow.
- Hash length alone is not definitive — MD5 and NTLM are both 32 hex chars. Context matters.
