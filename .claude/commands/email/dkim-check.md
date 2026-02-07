# DKIM Check

Look up and verify DKIM (DomainKeys Identified Mail) records for a domain.

## Arguments

$ARGUMENTS should include:
- A domain name
- Optionally a DKIM selector (e.g., `google`, `selector1`, `default`)

If no selector is provided, common selectors will be tried automatically.

Examples:
- `example.com`
- `example.com google`
- `example.com selector1`

## Workflow

1. Parse the domain and optional selector from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### If a selector is provided

```bash
dig +short TXT <selector>._domainkey.<domain>
```

### If no selector — try common selectors

```bash
for sel in google default selector1 selector2 k1 k2 s1 s2 dkim mail protonmail everlytickey1 mandrill; do
  result=$(dig +short TXT "${sel}._domainkey.<domain>" 2>/dev/null)
  if [ -n "$result" ]; then
    echo "Selector: $sel"
    echo "$result"
    echo "---"
  fi
done
```

3. For each DKIM record found, parse and explain:

| Tag | Value | Meaning |
|-----|-------|---------|
| `v=` | `DKIM1` | Version |
| `k=` | `rsa` / `ed25519` | Key type |
| `p=` | (base64 data) | Public key |
| `t=` | `y` / `s` | Testing / strict mode |
| `h=` | `sha256` | Hash algorithm |

4. Validate:
   - Is the `p=` field present and non-empty? (empty = key revoked)
   - Is the key type strong? (RSA >= 1024 bits, Ed25519 preferred)
   - Is `t=y` set? (testing mode — signatures are not enforced)

5. Present findings:
   - Selectors found
   - Key type and strength
   - Any issues (revoked key, testing mode, missing records)

## Security Notes

- DKIM selectors are not discoverable via DNS zone transfers — you need to know or guess the selector name.
- An empty `p=` tag means the key has been revoked — emails signed with that selector will fail DKIM verification.
- `t=y` (testing mode) means receiving servers may not enforce DKIM failures.
- RSA DKIM keys shorter than 1024 bits can be factored and should be rotated immediately.
- DKIM verifies the message was not altered in transit, but does not prove the sender is legitimate — that's DMARC's job.
