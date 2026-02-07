# Whois Lookup

Look up registration and ownership information for a domain or IP address.

## Arguments

$ARGUMENTS should be a domain name or IP address.

Examples:
- `example.com`
- `93.184.216.34`

## Workflow

1. Parse the target from `$ARGUMENTS`.
2. Determine if the input is a domain or IP address.
3. Show the user the exact commands before executing.

### Domain whois

```bash
whois <domain>
```

### IP whois

```bash
whois <ip>
```

### IP geolocation and ASN info

```bash
curl -s https://ipinfo.io/<ip>/json
```

4. Summarise key details:
   - **For domains:** Registrar, creation/expiry dates, nameservers, registrant info (if available), DNSSEC status
   - **For IPs:** Network range (CIDR), organisation, ASN, country, abuse contact

## Security Notes

- Whois data may be redacted due to GDPR or privacy services — this is normal for many domains.
- Domain expiry dates are important to monitor — expired domains can be hijacked.
- IP ownership information helps identify the hosting provider for abuse reports.
- Use whois data to verify legitimacy during phishing investigations.
