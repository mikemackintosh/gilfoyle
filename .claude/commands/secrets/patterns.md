# Secret Patterns Library

Display or test regex patterns for detecting specific types of secrets.

## Arguments

$ARGUMENTS is optional:
- A secret type to show patterns for: `aws`, `gcp`, `azure`, `github`, `gitlab`, `slack`, `stripe`, `keys`, `passwords`, `connections`, `jwt`, `all` (default)
- Or `--test <string>` to test a string against all patterns

Examples:
- (no args — show all patterns)
- `aws`
- `github`
- `--test "AKIAIOSFODNN7EXAMPLE"`

## Workflow

1. Parse the type or test string from `$ARGUMENTS`.

### Display patterns

Show the regex pattern, description, and an example match for the requested type(s).

### Test a string

```bash
python3 -c "
import re, sys

test_string = sys.argv[1]

patterns = [
    ('AWS Access Key ID',     r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret Key',        r'[0-9a-zA-Z/+=]{40}'),
    ('GCP API Key',           r'AIza[0-9A-Za-z\-_]{35}'),
    ('GitHub PAT (classic)',  r'ghp_[A-Za-z0-9_]{36}'),
    ('GitHub PAT (fine)',     r'github_pat_[A-Za-z0-9_]{82}'),
    ('GitLab PAT',            r'glpat-[A-Za-z0-9\-_]{20}'),
    ('Slack Bot Token',       r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+'),
    ('Slack Webhook',         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'),
    ('Stripe Secret Key',    r'sk_live_[0-9a-zA-Z]{24,}'),
    ('SendGrid API Key',     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
    ('Twilio API Key',       r'SK[a-f0-9]{32}'),
    ('Private Key',          r'-----BEGIN.*PRIVATE KEY-----'),
    ('JWT',                  r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    ('Connection String',    r'(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@'),
    ('Bearer Token',         r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*'),
    ('Basic Auth',           r'Basic\s+[A-Za-z0-9+/]+=*'),
]

matched = False
for name, pattern in patterns:
    if re.search(pattern, test_string):
        print(f'MATCH: {name} ({pattern})')
        matched = True

if not matched:
    print('No known secret pattern matched.')
" "<string>"
```

2. Present patterns in a clear table with regex, description, and example.

## Security Notes

- These patterns catch common formats but are not exhaustive — custom API keys or internal tokens may not match.
- False positives are expected — example values, test keys, and documentation will match. Always review in context.
- Combine pattern matching with entropy analysis for better detection accuracy.
- For production secret scanning, consider dedicated tools like `trufflehog`, `gitleaks`, or `detect-secrets`.
