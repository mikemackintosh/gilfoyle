# Domain Email Security Audit

Perform a comprehensive email security audit for a domain — checking SPF, DKIM, DMARC, MX, CAA, MTA-STS, and TLSRPT.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `google.com`

## Workflow

1. Parse the domain from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Run all checks

```bash
DOMAIN="<domain>"

echo "=== MX Records ==="
dig +short MX "$DOMAIN"

echo ""
echo "=== SPF ==="
dig +short TXT "$DOMAIN" | grep "v=spf1"

echo ""
echo "=== DMARC ==="
dig +short TXT "_dmarc.$DOMAIN"

echo ""
echo "=== DKIM (common selectors) ==="
for sel in google default selector1 selector2 k1 k2 s1 s2 dkim mail protonmail; do
  result=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>/dev/null)
  [ -n "$result" ] && echo "  ${sel}: $result"
done

echo ""
echo "=== CAA ==="
dig +short CAA "$DOMAIN"

echo ""
echo "=== MTA-STS ==="
dig +short TXT "_mta-sts.$DOMAIN"

echo ""
echo "=== TLSRPT ==="
dig +short TXT "_smtp._tls.$DOMAIN"

echo ""
echo "=== DNSSEC ==="
dig +short DNSKEY "$DOMAIN" | head -5

echo ""
echo "=== Reverse DNS for MX ==="
for mx in $(dig +short MX "$DOMAIN" | awk '{print $2}'); do
  ip=$(dig +short A "$mx")
  ptr=$(dig +short -x "$ip" 2>/dev/null)
  echo "  $mx ($ip) -> PTR: $ptr"
done
```

3. For each check, assess and rate:

| Check | Status | Detail |
|-------|--------|--------|
| MX | PASS/FAIL | Records found / missing |
| SPF | PASS/WARN/FAIL | `-all` / `~all` / missing |
| DKIM | PASS/WARN/FAIL | Key found / testing / missing |
| DMARC | PASS/WARN/FAIL | `reject` / `quarantine` / `none` / missing |
| CAA | PASS/WARN | Records set / missing |
| MTA-STS | PASS/WARN | Policy published / missing |
| TLSRPT | PASS/WARN | Reporting configured / missing |
| DNSSEC | PASS/WARN | Signed / unsigned |
| Reverse DNS | PASS/FAIL | PTR matches MX / missing |

4. Present:
   - Summary scorecard table
   - Detailed findings for each check
   - Overall rating (Strong / Moderate / Weak / Critical)
   - Prioritised recommendations

## Security Notes

- A domain with no SPF, DKIM, or DMARC can be trivially spoofed for phishing attacks.
- CAA records prevent unauthorised certificate issuance — they should be set even for non-mail domains.
- MTA-STS prevents TLS downgrade attacks on incoming mail — important for domains receiving sensitive email.
- Reverse DNS (PTR) records are required by many mail providers — missing PTR causes delivery failures.
- Domains that do not send email should still have `v=spf1 -all` and `v=DMARC1; p=reject` to prevent abuse.
