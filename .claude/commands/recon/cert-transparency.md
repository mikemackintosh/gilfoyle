# Certificate Transparency Search

Search Certificate Transparency logs for certificates issued to a domain. Reveals subdomains, certificate authorities, issuance dates, and historical certificate data.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `corp.example.com`

## Workflow

1. Parse the target domain from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Query crt.sh for all certificates

```bash
DOMAIN=<domain>

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | python3 -m json.tool
```

### Extract unique subdomains

```bash
DOMAIN=<domain>

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry['name_value'].split('\n'):
            name = name.strip().lower()
            if name:
                names.add(name)
    print('=== Unique Subdomains ===')
    for name in sorted(names):
        print(name)
    print(f'\nTotal unique names: {len(names)}')
except Exception as e:
    print(f'Error parsing CT data: {e}', file=sys.stderr)
"
```

### Extract certificate issuers

```bash
DOMAIN=<domain>

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "
import sys, json
from collections import Counter
try:
    data = json.load(sys.stdin)
    issuers = Counter()
    for entry in data:
        issuer = entry.get('issuer_name', 'Unknown')
        issuers[issuer] += 1
    print('=== Certificate Issuers ===')
    for issuer, count in issuers.most_common():
        print(f'  {count:4d}x  {issuer}')
except Exception as e:
    print(f'Error parsing CT data: {e}', file=sys.stderr)
"
```

### Extract certificate dates and details

```bash
DOMAIN=<domain>

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('=== Recent Certificates ===')
    # Sort by not_before descending (most recent first)
    sorted_data = sorted(data, key=lambda x: x.get('not_before', ''), reverse=True)
    for entry in sorted_data[:20]:
        print(f\"  ID: {entry.get('id', 'N/A')}\")
        print(f\"  Name(s): {entry.get('name_value', 'N/A')}\")
        print(f\"  Issuer: {entry.get('issuer_name', 'N/A')}\")
        print(f\"  Not Before: {entry.get('not_before', 'N/A')}\")
        print(f\"  Not After: {entry.get('not_after', 'N/A')}\")
        print(f\"  Serial: {entry.get('serial_number', 'N/A')}\")
        print()
except Exception as e:
    print(f'Error parsing CT data: {e}', file=sys.stderr)
"
```

### Search for wildcard certificates

```bash
DOMAIN=<domain>

curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    wildcards = set()
    for entry in data:
        for name in entry['name_value'].split('\n'):
            name = name.strip()
            if '*' in name:
                wildcards.add(name)
    if wildcards:
        print('=== Wildcard Certificates ===')
        for name in sorted(wildcards):
            print(f'  {name}')
    else:
        print('No wildcard certificates found.')
except Exception as e:
    print(f'Error parsing CT data: {e}', file=sys.stderr)
"
```

3. Present a consolidated summary:
   - Total certificates found
   - Unique subdomains discovered
   - Certificate authorities in use (with counts)
   - Wildcard certificates
   - Most recent and oldest certificates (date range)
   - Any expired certificates still in logs

4. Flag noteworthy findings:
   - Subdomains that may indicate internal/development infrastructure
   - Multiple CAs in use (potential supply chain consideration)
   - Very recently issued certificates (may indicate infrastructure changes)
   - Certificates with unusually long validity periods

## Security Notes

- Certificate Transparency queries are fully passive — they search public logs and do not interact with the target infrastructure.
- CT logs are append-only and publicly accessible by design (RFC 6962). Searching them is not adversarial.
- Certificates in CT logs may reference subdomains that are no longer active or were pre-provisioned before deployment.
- The presence of a certificate does not confirm a service is running — always verify with DNS resolution.
- CT data may reveal internal naming conventions, staging environments, or acquisition history that inform further assessment.
