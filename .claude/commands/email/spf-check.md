# SPF Check

Look up and analyse the SPF (Sender Policy Framework) record for a domain.

## Arguments

$ARGUMENTS should be a domain name.

Examples:
- `example.com`
- `google.com`

## Workflow

1. Parse the domain from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Look up the SPF record

```bash
dig +short TXT <domain> | grep "v=spf1"
```

### Count DNS lookups (SPF has a 10-lookup limit)

For each `include:`, `a`, `mx`, and `redirect=` in the SPF record, recursively resolve:

```bash
# Check each include
dig +short TXT <included_domain>
```

3. Parse and explain the SPF record:
   - List each mechanism (`ip4:`, `ip6:`, `include:`, `a`, `mx`)
   - Explain the qualifier (`+` pass, `-` fail, `~` softfail, `?` neutral)
   - Explain the `all` directive
   - Count total DNS lookups and warn if approaching or exceeding 10

4. Present results:

| Component | Value | Meaning |
|-----------|-------|---------|
| `include:_spf.google.com` | Resolved IPs | Google Workspace mail servers |
| `ip4:203.0.113.0/24` | Direct | Mail server range |
| `-all` | Hard fail | Reject mail from unlisted sources |

- **DNS lookups used:** X / 10
- **Verdict:** PASS (well-configured) / WARN (softfail or approaching lookup limit) / FAIL (missing, +all, or >10 lookups)

## Security Notes

- `+all` or `?all` effectively disables SPF — anyone can send mail as this domain. This should always be `-all` or `~all`.
- Exceeding 10 DNS lookups causes a `permerror`, and SPF is treated as if it doesn't exist.
- `~all` (softfail) is less strict than `-all` (hard fail). Use `-all` in production once all legitimate senders are listed.
- A missing SPF record means no sender validation — the domain can be freely spoofed.
- SPF alone is not sufficient — it should be paired with DKIM and DMARC.
