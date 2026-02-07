---
name: OSINT & Reconnaissance
description: Subdomain enumeration, certificate transparency log searches, domain intelligence gathering, and technology fingerprinting for authorised security assessments.
instructions: |
  Use this skill when the user needs to perform reconnaissance or OSINT (Open Source Intelligence)
  activities such as subdomain enumeration, certificate transparency searches, domain registration
  intelligence, technology fingerprinting, or general attack surface discovery. Recon should only
  be performed on assets the user owns or has explicit written authorisation to test. Always show
  commands before executing them and explain security implications.
---

# OSINT & Reconnaissance Skill

## Related Commands
- `/recon-subdomains` — Enumerate subdomains for a domain
- `/recon-cert-transparency` — Search Certificate Transparency logs
- `/recon-tech-fingerprint` — Identify technologies used by a web application
- `/recon-domain-intel` — Gather intelligence about a domain

## Subdomain Enumeration Methods

### DNS Brute-Force

Test common subdomain names against a target domain using DNS lookups:

```bash
# Brute-force with a wordlist using dig
for sub in www mail ftp vpn api dev staging test admin portal blog shop app cdn ns1 ns2 mx smtp imap pop3 webmail owa remote gateway sso login dashboard monitor status docs wiki git jenkins ci cd jira confluence grafana kibana elastic; do
  result=$(dig +short "$sub.example.com" 2>/dev/null)
  if [ -n "$result" ]; then
    echo "$sub.example.com -> $result"
  fi
done
```

### Certificate Transparency

Query public CT logs for certificates issued to the target domain:

```bash
# Query crt.sh for all certificates issued to a domain (including subdomains)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import sys,json; [print(d['name_value']) for d in json.load(sys.stdin)]" | \
  sort -u
```

### Search Engine Techniques

Google dorking patterns for subdomain discovery:
- `site:example.com -www` — Find indexed subdomains
- `site:*.example.com` — Wildcard subdomain search
- `inurl:example.com` — URLs containing the domain

### DNS Zone Transfer

Attempt a zone transfer (misconfigured servers will return all records):

```bash
# Get nameservers first
dig +short NS example.com

# Attempt zone transfer against each nameserver
dig axfr example.com @ns1.example.com
```

> **Note:** Zone transfers should rarely succeed on properly configured servers. A successful transfer is a finding worth reporting.

## Certificate Transparency Logs

Certificate Transparency (CT) is a public framework for monitoring and auditing SSL/TLS certificates. All publicly trusted CAs must log certificates to CT logs.

### crt.sh Queries

```bash
# Find all certificates for a domain
curl -s "https://crt.sh/?q=%25.example.com&output=json" | python3 -m json.tool

# Extract unique subdomains
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import sys,json; names=set(); [names.update(d['name_value'].split('\n')) for d in json.load(sys.stdin)]; [print(n) for n in sorted(names)]"

# Find certificates for exact domain only
curl -s "https://crt.sh/?q=example.com&output=json" | python3 -m json.tool

# Search for wildcard certificates
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import sys,json; [print(d['name_value']) for d in json.load(sys.stdin) if '*' in d['name_value']]" | sort -u
```

### Key CT Fields

| Field | Description |
|-------|-------------|
| `issuer_name` | Certificate Authority that issued the cert |
| `name_value` | Domain name(s) in the certificate |
| `not_before` | Certificate validity start date |
| `not_after` | Certificate expiry date |
| `serial_number` | Unique certificate serial |

### Why CT Matters for Recon

- Reveals subdomains that may not be in DNS (pre-provisioned certs)
- Shows which CAs are in use (useful for supply chain awareness)
- Historical certs may reveal old subdomains or infrastructure
- Wildcard certs indicate infrastructure patterns

## Domain Registration Intelligence

### whois

```bash
# Domain registration information
whois example.com

# Key fields to extract:
# - Registrar
# - Creation Date / Registration Date
# - Expiry Date
# - Updated Date
# - Nameservers
# - Registrant (may be privacy-protected)
# - DNSSEC status
```

### Domain Age and History

- **Creation Date:** Older domains are generally more trustworthy; very new domains may indicate phishing.
- **Expiry Date:** Domains near expiry may be vulnerable to hijacking.
- **Registrar changes:** Frequent registrar transfers can be suspicious.

### DNS Record Intelligence

```bash
# All common record types
dig +short example.com A
dig +short example.com AAAA
dig +short example.com MX
dig +short example.com NS
dig +short example.com TXT
dig +short example.com SOA
dig +short example.com CNAME
dig +short example.com CAA

# Reverse DNS for discovered IPs
dig -x <ip>
```

## Technology Fingerprinting

### Response Header Analysis

```bash
# Check Server and technology headers
curl -sI https://example.com | grep -iE '(^server:|x-powered-by|x-aspnet|x-generator|x-drupal|x-varnish|x-cache|via|x-amz|x-cdn)'
```

### Common Technology Indicators

| Indicator | Technology |
|-----------|-----------|
| `Server: nginx` | Nginx web server |
| `Server: Apache` | Apache HTTP Server |
| `Server: Microsoft-IIS` | IIS web server |
| `Server: cloudflare` | Cloudflare CDN/proxy |
| `X-Powered-By: PHP` | PHP application |
| `X-Powered-By: Express` | Node.js Express framework |
| `X-Powered-By: ASP.NET` | .NET application |
| `X-Drupal-Cache` | Drupal CMS |
| `X-Generator: WordPress` | WordPress CMS |
| `X-Varnish` | Varnish cache |

### Cookie-Based Fingerprinting

| Cookie Name | Technology |
|-------------|-----------|
| `PHPSESSID` | PHP |
| `JSESSIONID` | Java (Tomcat/Spring) |
| `ASP.NET_SessionId` | ASP.NET |
| `connect.sid` | Node.js Express |
| `_rails_session` | Ruby on Rails |
| `laravel_session` | Laravel (PHP) |
| `CFID` / `CFTOKEN` | ColdFusion |
| `wp-settings-*` | WordPress |

### HTML Pattern Analysis

```bash
# Check meta generators and framework indicators
curl -s https://example.com | grep -iE '(meta.*generator|wp-content|wp-includes|drupal|joomla|django|rails|laravel|next|nuxt|gatsby)'

# Check JavaScript libraries
curl -s https://example.com | grep -ioE '(jquery|react|angular|vue|bootstrap|tailwind|lodash|moment|axios)[^"'"'"']*\.js'

# Check common framework paths
for path in /wp-login.php /wp-admin /administrator /user/login /admin /xmlrpc.php /api /graphql /.well-known/security.txt /robots.txt /sitemap.xml; do
  code=$(curl -o /dev/null -s -w "%{http_code}" "https://example.com$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "$code $path"
  fi
done
```

## Google Dorking for Security Research

### Useful Dork Patterns

| Dork | Purpose |
|------|---------|
| `site:example.com filetype:pdf` | Find PDF documents |
| `site:example.com filetype:xls OR filetype:xlsx` | Find spreadsheets |
| `site:example.com filetype:doc OR filetype:docx` | Find Word documents |
| `site:example.com inurl:admin` | Find admin pages |
| `site:example.com inurl:login` | Find login pages |
| `site:example.com intitle:"index of"` | Find directory listings |
| `site:example.com ext:sql OR ext:bak OR ext:log` | Find backup/log files |
| `site:example.com ext:env OR ext:yml OR ext:conf` | Find configuration files |
| `site:example.com "error" OR "warning" OR "fatal"` | Find error messages |
| `site:example.com inurl:api` | Find API endpoints |
| `"example.com" filetype:xml` | Find XML files mentioning the domain |

> **Note:** Google dorking should only target domains you are authorised to assess. Accessing exposed sensitive data without authorisation may violate laws.

## IP Range Discovery

```bash
# Find the IP of the target
dig +short example.com

# Look up the network/ASN for that IP
whois <ip>
curl -s https://ipinfo.io/<ip>/json

# Query the ASN for all prefixes
whois -h whois.radb.net AS<number>

# Reverse DNS sweep of a subnet (small ranges only)
for i in $(seq 1 254); do
  result=$(dig +short -x 192.168.1.$i 2>/dev/null)
  if [ -n "$result" ]; then
    echo "192.168.1.$i -> $result"
  fi
done
```

## Email Harvesting Concepts

> **Important:** Email harvesting should only be performed on domains you own or have explicit authorisation to test. This data is useful for social engineering assessments and phishing simulations.

Common sources of email addresses (for authorised testing):
- Public web pages (contact, about, team pages)
- WHOIS registrant contacts
- DNS SOA records (admin email)
- Google dorking: `site:example.com "@example.com"`
- Certificate Transparency logs (email fields)
- Public code repositories (git commit metadata)
- Job postings and press releases

```bash
# Extract email from SOA record
dig SOA example.com +short

# Search for email patterns on a website
curl -s https://example.com/about | grep -ioE '[a-zA-Z0-9._%+-]+@example\.com'
```

## OSINT Workflow Methodology

### Phase 1: Passive Reconnaissance

Gather information without directly interacting with the target infrastructure:

1. **Domain registration:** `whois` for registrar, dates, nameservers
2. **Certificate Transparency:** Query crt.sh for subdomains and CA usage
3. **DNS records:** Enumerate A, AAAA, MX, NS, TXT, CAA records
4. **Search engine recon:** Google dorks for exposed content
5. **Public data sources:** Code repos, job postings, social media

### Phase 2: Semi-Passive Reconnaissance

Interact with the target but only through normal expected traffic:

1. **HTTP header analysis:** Technology fingerprinting via response headers
2. **HTML analysis:** Meta tags, JavaScript libraries, framework indicators
3. **Cookie inspection:** Session technology identification
4. **robots.txt / sitemap.xml:** Discover paths and structure
5. **security.txt:** Check for vulnerability disclosure policy

### Phase 3: Active Reconnaissance

Direct interaction that may be logged or detected:

1. **Subdomain brute-force:** DNS resolution of common names
2. **Port scanning:** Identify open services (requires authorisation)
3. **Zone transfer attempts:** Test DNS misconfiguration
4. **Path enumeration:** Probe for common application paths
5. **Service version detection:** Banner grabbing

### Reporting

Consolidate findings into categories:
- **Attack surface:** Discovered hosts, IPs, open ports, services
- **Technology stack:** Web servers, frameworks, languages, CDNs
- **Potential issues:** Exposed admin panels, directory listings, version disclosure
- **Recommendations:** Reduce attack surface, fix misconfigurations, harden DNS
