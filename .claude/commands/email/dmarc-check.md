# DMARC Check

Look up and analyse the DMARC (Domain-based Message Authentication, Reporting & Conformance) policy for a domain.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `google.com`

## Workflow

1. Parse the domain from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Look up the DMARC record

```bash
dig +short TXT _dmarc.<domain>
```

### Also check SPF and DKIM (DMARC depends on both)

```bash
# SPF
dig +short TXT <domain> | grep "v=spf1"

# DKIM (try common selectors)
for sel in google default selector1 selector2; do
  result=$(dig +short TXT "${sel}._domainkey.<domain>" 2>/dev/null)
  [ -n "$result" ] && echo "$sel: found"
done
```

3. Parse and explain each DMARC tag:

| Tag | Value | Meaning |
|-----|-------|---------|
| `v=` | `DMARC1` | Version (required) |
| `p=` | `none` / `quarantine` / `reject` | Policy for the domain |
| `sp=` | `none` / `quarantine` / `reject` | Policy for subdomains |
| `rua=` | `mailto:...` | Aggregate report destination |
| `ruf=` | `mailto:...` | Forensic report destination |
| `pct=` | `0`–`100` | Percentage of messages to apply policy |
| `adkim=` | `r` / `s` | DKIM alignment (relaxed/strict) |
| `aspf=` | `r` / `s` | SPF alignment (relaxed/strict) |

4. Assess the configuration:

| Rating | Criteria |
|--------|----------|
| **Strong** | `p=reject`, SPF with `-all`, DKIM configured, `rua=` set |
| **Moderate** | `p=quarantine`, SPF present, DKIM present |
| **Weak** | `p=none` (monitor only) |
| **Missing** | No DMARC record |

5. Present findings:
   - DMARC policy and all tags explained
   - SPF status
   - DKIM selectors found
   - Overall email authentication rating
   - Recommendations for improvement

## Security Notes

- `p=none` provides visibility (reports) but does not protect against spoofing. It should be a temporary state during deployment.
- Without DMARC, there is no mechanism to enforce SPF and DKIM failures — spoofed emails may still be delivered.
- The `rua=` address receives aggregate reports (XML) showing who is sending email as your domain — essential for identifying legitimate senders before enforcing.
- Subdomains inherit the parent's DMARC policy unless `sp=` is set or the subdomain has its own `_dmarc` record.
- The recommended deployment path: `p=none` (monitor) → `p=quarantine` (gradual) → `p=reject` (enforce).
