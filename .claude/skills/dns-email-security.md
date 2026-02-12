---
name: DNS & Email Security
description: DNS record management, SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, and DANE for email and domain security.
instructions: |
  Use this skill when the user needs to inspect, configure, or troubleshoot DNS-based security
  records (SPF, DKIM, DMARC, CAA, DNSSEC) or email authentication. Always show commands before
  executing them and explain the security implications of record configurations.
---

# DNS & Email Security Skill

## DNS Record Types Reference

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | `93.184.216.34` |
| AAAA | IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | Canonical name (alias) | `www.example.com → example.com` |
| MX | Mail exchange | `10 mail.example.com` |
| TXT | Text records (SPF, DKIM, DMARC, etc.) | `v=spf1 include:_spf.google.com ~all` |
| NS | Nameservers | `ns1.example.com` |
| SOA | Start of authority | Zone metadata |
| SRV | Service location | `_sip._tcp.example.com` |
| CAA | Certificate authority authorisation | `0 issue "letsencrypt.org"` |
| PTR | Reverse DNS | `34.216.184.93.in-addr.arpa → example.com` |
| TLSA | DANE TLS association | Certificate constraints for SMTP |

### DNS Lookup Commands

```bash
# Query specific record types
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com TXT
dig example.com NS
dig example.com CAA

# Short output
dig +short example.com MX

# Query a specific nameserver
dig @8.8.8.8 example.com TXT

# Trace delegation path
dig +trace example.com

# Reverse lookup
dig -x 93.184.216.34

# Check all records
dig example.com ANY
```

## SPF (Sender Policy Framework)

SPF specifies which mail servers are authorised to send email for a domain.

### SPF Syntax

| Mechanism | Meaning | Example |
|-----------|---------|---------|
| `ip4:` | Allow IPv4 address/range | `ip4:203.0.113.0/24` |
| `ip6:` | Allow IPv6 address/range | `ip6:2001:db8::/32` |
| `a` | Allow domain's A record IPs | `a` or `a:mail.example.com` |
| `mx` | Allow domain's MX IPs | `mx` |
| `include:` | Include another domain's SPF | `include:_spf.google.com` |
| `redirect=` | Use another domain's SPF entirely | `redirect=_spf.example.com` |
| `all` | Match everything (used at end) | `-all` (fail), `~all` (softfail) |

### SPF Qualifiers

| Qualifier | Meaning | Result |
|-----------|---------|--------|
| `+` (default) | Pass | Allow |
| `-` | Fail (hard) | Reject |
| `~` | SoftFail | Accept but mark |
| `?` | Neutral | No policy |

### SPF Lookup and Validation

```bash
# Look up SPF record
dig +short TXT example.com | grep "v=spf1"

# Verify SPF for a specific sender IP
# (requires a tool like pyspf or online checkers)

# Count DNS lookups in an SPF record (max 10 allowed)
# Each include:, a, mx, redirect counts as a lookup
dig +short TXT example.com | grep spf
# Then check each include: recursively
dig +short TXT _spf.google.com
```

### SPF Examples

```dns
; Simple — only this server sends mail
v=spf1 ip4:203.0.113.10 -all

; Google Workspace
v=spf1 include:_spf.google.com -all

; Microsoft 365
v=spf1 include:spf.protection.outlook.com -all

; Multiple providers
v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 -all

; No mail sent from this domain
v=spf1 -all
```

> **Limit:** SPF records must not exceed 10 DNS lookups (include, a, mx, redirect each count). Exceeding this causes a `permerror`.

### SPF Macros (RFC 7208 Section 7)

SPF macros allow dynamic construction of DNS names during evaluation. They appear as `%{x}` sequences inside mechanisms and modifiers.

#### Macro Letters

| Letter | Name | Description | Example Value |
|--------|------|-------------|---------------|
| `s` | sender | Full envelope-from address | `user@example.com` |
| `l` | local-part | Local-part of envelope-from | `user` |
| `o` | domain | Domain part of envelope-from | `example.com` |
| `d` | current domain | Domain currently being evaluated (follows `include:`/`redirect=`) | `example.com` |
| `i` | IP | Connecting client IP | `203.0.113.10` or `2001:db8::1` |
| `p` | PTR domain | Validated reverse DNS of client IP | `mail.example.com` |
| `v` | IP version string | `in-addr` for IPv4, `ip6` for IPv6 | `in-addr` |
| `h` | HELO/EHLO | HELO domain from SMTP session | `mail.example.com` |
| `c` | SMTP client IP | Same as `i` (only in `exp=` strings) | `203.0.113.10` |
| `r` | receiving host | Receiving MTA domain (only in `exp=` strings) | `mx.receiver.com` |
| `t` | timestamp | Unix timestamp (only in `exp=` strings) | `1700000000` |

#### Transformers

Transformers modify the macro output. They appear between the letter and the closing brace.

| Transformer | Syntax | Effect | Example |
|-------------|--------|--------|---------|
| Reverse | `r` | Reverse dot-separated parts | `%{ir}` on `203.0.113.10` → `10.113.0.203` |
| Truncate | *N* (digits) | Keep rightmost N parts | `%{i2}` on `203.0.113.10` → `113.10` |
| Reverse + truncate | *N*`r` | Reverse, then keep rightmost N | `%{ir2}` on `203.0.113.10` → `0.203` |
| Delimiter | char after all else | Split on this instead of `.` | `%{l-}` splits local-part on `-` |

Full syntax: `%{` *letter* [*digits*] [`r`] [*delimiters*] `}`

#### Common Macro Patterns

```dns
; Per-IP allowlist via exists (counts as 1 DNS lookup regardless of IP count)
v=spf1 exists:%{i}._spf.example.com -all
; → Looks up A record for 203.0.113.10._spf.example.com

; DNSBL-style reverse-IP lookup
v=spf1 include:%{ir}.%{v}._spf.example.com -all
; → Evaluates SPF at 10.113.0.203.in-addr._spf.example.com

; Per-user SPF policy
v=spf1 exists:%{l}._spf.%{d} -all
; → Looks up A record for user._spf.example.com

; Centralised SPF via redirect
v=spf1 redirect=%{d}._spf.hosting.com
; → Redirects evaluation to example.com._spf.hosting.com

; Custom rejection message with macros in exp=
v=spf1 ... -all exp=explain.%{d}
; TXT at explain.example.com might contain:
; "Mail from %{d} is not allowed from %{i}. See https://example.com/spf"
```

#### Macro Warnings

- **`%{p}` is discouraged.** RFC 7208 says `SHOULD NOT` use it. It forces a PTR lookup on every SPF check — slow, unreliable, and the result is controlled by whoever owns the IP's reverse zone.
- **`%{c}`, `%{r}`, `%{t}` are `exp=` only.** Using them in mechanisms is invalid.
- **Sender-controlled input.** Macros like `%{s}`, `%{l}`, and `%{h}` expand values the sender controls. This means the sender can trigger DNS lookups to arbitrary names. This is by design, but be aware of information leakage via DNS.
- **`exists:` with macros** sidesteps the 10-lookup limit (one `exists:` = one lookup). This is the main reason macros exist in large-scale SPF deployments. The trade-off is readability and debuggability.

## DKIM (DomainKeys Identified Mail)

DKIM adds a digital signature to outgoing email, verified via a DNS public key.

### DKIM Record Lookup

```bash
# DKIM records are stored at: <selector>._domainkey.<domain>
# Common selectors: google, default, selector1, selector2, k1, s1

# Google Workspace
dig +short TXT google._domainkey.example.com

# Microsoft 365
dig +short TXT selector1._domainkey.example.com
dig +short TXT selector2._domainkey.example.com

# Generic
dig +short TXT default._domainkey.example.com
```

### DKIM Record Format

```dns
; Example DKIM record
google._domainkey.example.com. IN TXT (
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhki..."
)
```

| Tag | Meaning | Values |
|-----|---------|--------|
| `v=` | Version | `DKIM1` |
| `k=` | Key type | `rsa` (default), `ed25519` |
| `p=` | Public key (base64) | The actual key data |
| `t=` | Flags | `y` (testing), `s` (strict) |
| `h=` | Hash algorithms | `sha256` |

### Verify DKIM Signature

```bash
# Check raw email headers for DKIM-Signature header
# Look for: d= (domain), s= (selector), b= (signature)

# Then verify the public key exists
dig +short TXT <selector>._domainkey.<domain>

# Use opendkim-testkey (if installed)
opendkim-testkey -d example.com -s google -vvv
```

## DMARC (Domain-based Message Authentication, Reporting & Conformance)

DMARC ties SPF and DKIM together with a policy and reporting mechanism.

### DMARC Record Lookup

```bash
# DMARC records are at _dmarc.<domain>
dig +short TXT _dmarc.example.com
```

### DMARC Tags

| Tag | Meaning | Values |
|-----|---------|--------|
| `v=` | Version | `DMARC1` (required) |
| `p=` | Policy | `none`, `quarantine`, `reject` |
| `sp=` | Subdomain policy | `none`, `quarantine`, `reject` |
| `rua=` | Aggregate report URI | `mailto:dmarc-reports@example.com` |
| `ruf=` | Forensic report URI | `mailto:dmarc-forensic@example.com` |
| `pct=` | Percentage of messages to apply policy | `0`–`100` (default: 100) |
| `adkim=` | DKIM alignment | `r` (relaxed), `s` (strict) |
| `aspf=` | SPF alignment | `r` (relaxed), `s` (strict) |
| `fo=` | Forensic report options | `0`, `1`, `d`, `s` |

### DMARC Examples

```dns
; Monitor only (start here)
_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

; Quarantine (move to spam)
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100"

; Reject (block delivery)
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc-forensic@example.com"

; Domain that sends no email
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"
```

### DMARC Deployment Path

1. **Start with `p=none`** — monitor without affecting delivery
2. **Analyse aggregate reports** — identify legitimate senders
3. **Ensure SPF and DKIM pass** for all legitimate sources
4. **Move to `p=quarantine`** with `pct=10`, gradually increase
5. **Move to `p=reject`** once confident

### DMARC Report Interpretation

Aggregate reports (RUA) are XML files. Key fields:

```bash
# Download and extract a DMARC report
gunzip report.xml.gz

# Parse with xmllint or xq
xmllint --xpath '//record' report.xml
cat report.xml | python3 -c "
import xml.etree.ElementTree as ET, sys
tree = ET.parse(sys.stdin)
for rec in tree.findall('.//record'):
    ip = rec.find('.//source_ip').text
    count = rec.find('.//count').text
    spf = rec.find('.//policy_evaluated/spf').text
    dkim = rec.find('.//policy_evaluated/dkim').text
    print(f'{ip:20s} count={count:>5s} spf={spf:5s} dkim={dkim}')
"
```

## DNSSEC Validation

DNSSEC adds cryptographic signatures to DNS responses to prevent spoofing.

### Check DNSSEC

```bash
# Check if a domain is DNSSEC-signed
dig +dnssec example.com

# Look for RRSIG records in the response (indicates DNSSEC)
dig +dnssec +short example.com

# Check the DNSKEY record
dig DNSKEY example.com

# Check DS record (at parent zone)
dig DS example.com

# Full DNSSEC validation with delv
delv example.com
delv @8.8.8.8 example.com

# Check the chain of trust
dig +sigchase +trusted-key=/etc/trusted-key.key example.com

# Verify DNSSEC with drill (if available)
drill -DT example.com
```

### DNSSEC Record Types

| Type | Purpose |
|------|---------|
| RRSIG | Signature over a record set |
| DNSKEY | Zone signing key (ZSK) and key signing key (KSK) |
| DS | Delegation signer (hash of child's KSK, stored at parent) |
| NSEC/NSEC3 | Authenticated denial of existence |

## CAA Records

CAA (Certificate Authority Authorisation) records specify which CAs are allowed to issue certificates for a domain.

### CAA Lookup

```bash
dig CAA example.com
dig +short CAA example.com
```

### CAA Record Format

```dns
; Only Let's Encrypt can issue certificates
example.com. IN CAA 0 issue "letsencrypt.org"

; Allow Let's Encrypt and DigiCert
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issue "digicert.com"

; Wildcard certificates only from specific CA
example.com. IN CAA 0 issuewild "letsencrypt.org"

; Deny all certificate issuance
example.com. IN CAA 0 issue ";"

; Report violations
example.com. IN CAA 0 iodef "mailto:security@example.com"
```

### CAA Tags

| Tag | Purpose |
|-----|---------|
| `issue` | Authorise a CA for non-wildcard certs |
| `issuewild` | Authorise a CA for wildcard certs |
| `iodef` | Report policy violations (email or URL) |

> **Best practice:** Always set CAA records. If no CAA record exists, any CA can issue certificates for your domain.

## MTA-STS (Mail Transfer Agent Strict Transport Security)

MTA-STS enforces TLS for incoming SMTP connections, preventing downgrade attacks.

### Check MTA-STS

```bash
# Check for MTA-STS DNS record
dig +short TXT _mta-sts.example.com
# Expected: v=STSv1; id=20240101

# Fetch the MTA-STS policy file
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
```

### MTA-STS Policy File

Host at `https://mta-sts.<domain>/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 604800
```

| Mode | Behaviour |
|------|-----------|
| `none` | No MTA-STS enforcement |
| `testing` | Send reports but don't enforce |
| `enforce` | Require TLS, reject on failure |

### SMTP TLS Reporting (TLSRPT)

```bash
# Check for TLS reporting record
dig +short TXT _smtp._tls.example.com
# Expected: v=TLSRPTv1; rua=mailto:tlsrpt@example.com
```

## DANE (DNS-based Authentication of Named Entities)

DANE uses DNSSEC to bind TLS certificates to DNS names via TLSA records.

### Check DANE / TLSA Records

```bash
# TLSA record for SMTP (port 25)
dig TLSA _25._tcp.mail.example.com

# TLSA record for HTTPS (port 443)
dig TLSA _443._tcp.example.com

# Verify with openssl
openssl s_client -connect mail.example.com:25 -starttls smtp -dane_tlsa_domain mail.example.com
```

### TLSA Record Format

```
_25._tcp.mail.example.com. IN TLSA <usage> <selector> <matching-type> <hash>
```

| Usage | Meaning |
|-------|---------|
| 0 | CA constraint (PKIX-TA) |
| 1 | Service cert constraint (PKIX-EE) |
| 2 | Trust anchor assertion (DANE-TA) |
| 3 | Domain-issued cert (DANE-EE) — most common for SMTP |

| Selector | Meaning |
|----------|---------|
| 0 | Full certificate |
| 1 | SubjectPublicKeyInfo (SPKI) |

| Matching Type | Meaning |
|---------------|---------|
| 0 | Exact match |
| 1 | SHA-256 hash |
| 2 | SHA-512 hash |

### Generate TLSA Record

```bash
# Generate TLSA hash from certificate (usage=3, selector=1, matching=1)
openssl x509 -in cert.pem -noout -pubkey | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p -c 64

# Result is used as: 3 1 1 <hash>
```

## Common Email Security Misconfigurations

| Issue | Symptom | Fix |
|-------|---------|-----|
| No SPF record | Mail spoofing possible | Add `v=spf1 ... -all` TXT record |
| SPF with `+all` | Everyone is authorised (useless) | Change to `-all` or `~all` |
| SPF > 10 lookups | SPF `permerror`, treated as no SPF | Flatten includes or use fewer |
| No DKIM | Messages can't be cryptographically verified | Configure DKIM signing + publish key |
| DMARC `p=none` forever | No enforcement, spoofing still possible | Progress to `quarantine` then `reject` |
| No DMARC record | No policy, no reporting | Add `_dmarc` TXT record |
| Missing CAA | Any CA can issue certs | Add CAA records |
| No reverse DNS (PTR) | Mail rejected by many providers | Configure PTR for mail server IPs |
| MX pointing to CNAME | RFC violation | MX should point to an A/AAAA record |

### Quick Domain Email Security Audit

```bash
DOMAIN="example.com"

echo "=== SPF ==="
dig +short TXT "$DOMAIN" | grep "v=spf1"

echo "=== DMARC ==="
dig +short TXT "_dmarc.$DOMAIN"

echo "=== DKIM (common selectors) ==="
for sel in google default selector1 selector2 k1 s1 dkim; do
  result=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>/dev/null)
  [ -n "$result" ] && echo "  $sel: $result"
done

echo "=== MX ==="
dig +short MX "$DOMAIN"

echo "=== CAA ==="
dig +short CAA "$DOMAIN"

echo "=== MTA-STS ==="
dig +short TXT "_mta-sts.$DOMAIN"

echo "=== TLSRPT ==="
dig +short TXT "_smtp._tls.$DOMAIN"
```
