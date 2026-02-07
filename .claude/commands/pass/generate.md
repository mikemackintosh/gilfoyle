# Password Generate

Generate a cryptographically secure random password.

## Arguments

$ARGUMENTS is optional:
- A length (default: 24)
- `--type <type>`: `full` (default), `alpha`, `alphanum`, `hex`, `base64`, `pin`, `passphrase`
- `--count <n>`: generate multiple passwords (default: 1)

Examples:
- (no args — 24-char full ASCII password)
- `32`
- `16 --type alphanum`
- `6 --type pin`
- `--type passphrase`
- `24 --count 5`

## Workflow

1. Parse length, type, and count from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Full ASCII (default)

```bash
openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*()_+-=' | head -c <length>
```

### Alphanumeric only

```bash
openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c <length>
```

### Hex

```bash
openssl rand -hex <length/2>
```

### Base64

```bash
openssl rand -base64 <length>
```

### PIN

```bash
python3 -c "import secrets; print(''.join(str(secrets.randbelow(10)) for _ in range(<length>)))"
```

### Passphrase

```bash
python3 -c "
import secrets
words = ['correct','horse','battery','staple','orange','purple','basket','window','garden','silver','rocket','planet','forest','ocean','castle','bridge','dragon','falcon','marble','sunset','crimson','emerald','thunder','crystal','phantom','voyage','summit','anchor','beacon','cipher']
print('-'.join(secrets.choice(words) for _ in range(5)))
"
```

3. Display the password(s) and estimated entropy.

## Security Notes

- All generation uses `openssl rand` or Python's `secrets` module, which use cryptographically secure random sources.
- Never use `random.random()` or `$RANDOM` for password generation — these are not cryptographically secure.
- Longer passwords are always stronger. 16+ characters for most use cases, 24+ for high-security contexts.
- Passphrases (5+ random words) are easier to remember and type than random character strings, with comparable security.
