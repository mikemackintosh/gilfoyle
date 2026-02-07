# Subdomain Enumeration

Enumerate subdomains for a target domain using multiple methods: DNS brute-force with a common wordlist, Certificate Transparency log searches, and DNS zone transfer attempts.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `corp.example.com`

## Workflow

1. Parse the target domain from `$ARGUMENTS`.
2. Remind the user that subdomain enumeration should only be performed against domains they own or have explicit written authorisation to test.
3. Show the user the exact commands before executing.

### Method 1: DNS brute-force with common wordlist

Test common subdomain names using `dig`:

```bash
DOMAIN=<domain>

for sub in www mail ftp vpn api dev staging test admin portal blog shop app cdn ns1 ns2 mx smtp imap pop3 webmail owa remote gateway sso login dashboard monitor status docs wiki git jenkins ci cd jira confluence grafana kibana elastic prometheus nagios zabbix backup db database sql mysql postgres redis mongo cache proxy lb load edge static media assets images files upload download support help desk ticket crm erp hr finance billing pay payments checkout cart store inventory warehouse staging uat qa sandbox demo preview beta alpha internal intranet corp office vpn2 vpn1 relay autodiscover autoconfig cpanel plesk whm wss ws socket realtime live stream video; do
  result=$(dig +short "$sub.$DOMAIN" 2>/dev/null)
  if [ -n "$result" ]; then
    echo "$sub.$DOMAIN -> $result"
  fi
done
```

### Method 2: Certificate Transparency via crt.sh

Query public CT logs for certificates issued to the domain:

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
            if name and name.endswith('.$DOMAIN'.lower()):
                names.add(name)
    for name in sorted(names):
        print(name)
except Exception as e:
    print(f'Error parsing CT data: {e}', file=sys.stderr)
"
```

### Method 3: DNS zone transfer attempt

Attempt a zone transfer against each authoritative nameserver:

```bash
DOMAIN=<domain>

# Get authoritative nameservers
NAMESERVERS=$(dig +short NS "$DOMAIN")

for ns in $NAMESERVERS; do
  echo "=== Attempting zone transfer from $ns ==="
  dig axfr "$DOMAIN" "@$ns"
done
```

4. Consolidate results from all methods into a deduplicated list.
5. For each discovered subdomain, resolve its IP address and note the record type (A, AAAA, CNAME).
6. Present a summary table:

| Subdomain | Record Type | Value | Discovery Method |
|-----------|-------------|-------|------------------|
| `www.example.com` | A | 93.184.216.34 | DNS brute-force |
| `mail.example.com` | CNAME | mail.provider.com | Certificate Transparency |

7. Report totals: unique subdomains found, methods that yielded results, whether zone transfer succeeded.

## Security Notes

- **Only enumerate subdomains on domains you own or have explicit written authorisation to test.** Unauthorised reconnaissance may violate laws and acceptable use policies.
- DNS brute-force generates many DNS queries which may be logged by the target's DNS provider.
- Certificate Transparency is a fully passive method — it queries public logs, not the target infrastructure.
- A successful DNS zone transfer is a significant misconfiguration finding. Zone transfers should be restricted to authorised secondary nameservers.
- Discovered subdomains may reveal internal services, development environments, or shadow IT that increase the attack surface.
