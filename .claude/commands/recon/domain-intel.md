# Domain Intelligence

Gather comprehensive intelligence about a domain by combining whois registration data, DNS records, mail configuration, nameserver analysis, IP geolocation, ASN lookup, domain age, and registrar information.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `corp.example.com`

## Workflow

1. Parse the target domain from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Whois registration data

```bash
DOMAIN=<domain>

echo "=== WHOIS Registration ==="
whois "$DOMAIN"
```

### DNS record enumeration

```bash
DOMAIN=<domain>

echo "=== A Records ==="
dig +short "$DOMAIN" A

echo ""
echo "=== AAAA Records ==="
dig +short "$DOMAIN" AAAA

echo ""
echo "=== MX Records ==="
dig +short "$DOMAIN" MX

echo ""
echo "=== NS Records ==="
dig +short "$DOMAIN" NS

echo ""
echo "=== TXT Records ==="
dig +short "$DOMAIN" TXT

echo ""
echo "=== SOA Record ==="
dig +short "$DOMAIN" SOA

echo ""
echo "=== CAA Records ==="
dig +short "$DOMAIN" CAA

echo ""
echo "=== CNAME Record ==="
dig +short "$DOMAIN" CNAME
```

### IP geolocation and ASN lookup

For each IP address discovered from A records:

```bash
IP=<resolved_ip>

echo "=== IP Intelligence ==="
curl -s "https://ipinfo.io/$IP/json"
```

### ASN details

```bash
ASN=<asn_number>

echo "=== ASN Details ==="
whois -h whois.radb.net "$ASN"
```

### Reverse DNS for discovered IPs

```bash
IP=<resolved_ip>

echo "=== Reverse DNS ==="
dig +short -x "$IP"
```

### Check for DNSSEC

```bash
DOMAIN=<domain>

echo "=== DNSSEC Check ==="
dig +dnssec +short "$DOMAIN" DNSKEY
if [ $? -eq 0 ] && dig +short "$DOMAIN" DNSKEY 2>/dev/null | grep -q .; then
  echo "DNSSEC: ENABLED"
else
  echo "DNSSEC: NOT DETECTED"
fi
```

### Mail infrastructure analysis

```bash
DOMAIN=<domain>

echo "=== Mail Infrastructure ==="
echo "--- MX Records ---"
dig +short "$DOMAIN" MX

echo ""
echo "--- SPF Record ---"
dig +short "$DOMAIN" TXT | grep -i 'v=spf'

echo ""
echo "--- DMARC Record ---"
dig +short "_dmarc.$DOMAIN" TXT

echo ""
echo "--- DKIM Selector Test (common selectors) ---"
for selector in default google dkim s1 s2 selector1 selector2 k1 mail; do
  result=$(dig +short "$selector._domainkey.$DOMAIN" TXT 2>/dev/null)
  if [ -n "$result" ]; then
    echo "  $selector: $result"
  fi
done
```

3. Extract and summarise key intelligence from whois:
   - **Registrar:** Who manages the domain registration
   - **Creation Date:** When the domain was first registered (domain age)
   - **Expiry Date:** When the registration expires
   - **Updated Date:** Last modification to registration
   - **Nameservers:** Authoritative DNS servers
   - **Registrant:** Owner information (may be privacy-protected)
   - **DNSSEC:** Whether DNSSEC is enabled

4. Present a consolidated intelligence report:

| Category | Detail |
|----------|--------|
| Domain | example.com |
| Registrar | Example Registrar Inc. |
| Created | 2010-01-15 |
| Expires | 2026-01-15 |
| Domain Age | ~16 years |
| Nameservers | ns1.example.com, ns2.example.com |
| IP Address | 93.184.216.34 |
| ASN | AS12345 (Example Hosting) |
| Location | US, California |
| Mail Provider | Google Workspace (MX: aspmx.l.google.com) |
| SPF | Present |
| DMARC | Present |
| DNSSEC | Enabled |

5. Flag noteworthy findings:
   - Domain expiring soon (within 90 days)
   - Missing email security records (SPF, DMARC)
   - DNSSEC not enabled
   - Privacy/proxy registration (not necessarily suspicious but worth noting)
   - Hosting provider and CDN identification
   - Multiple IPs suggesting load balancing or CDN

## Security Notes

- Whois data may be redacted due to GDPR or privacy protection services — this is normal and does not indicate suspicious activity.
- Domain age is a useful indicator: very new domains may be associated with phishing or fraud, while old domains are generally more established.
- Domains approaching expiry are at risk of hijacking if not renewed. Monitor critical domain expiry dates.
- Missing SPF, DKIM, or DMARC records leave a domain vulnerable to email spoofing.
- DNSSEC protects against DNS spoofing attacks but is not universally deployed. Its absence is worth noting but common.
- ASN and IP range data helps identify the hosting provider, which is useful for abuse reporting and understanding infrastructure.
