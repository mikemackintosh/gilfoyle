# DNS Lookup

Perform DNS lookups for a domain or IP address using `dig`.

## Arguments

$ARGUMENTS should include:
- A domain name or IP address (for reverse lookup)
- Optionally a record type: `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CNAME`, `CAA`, `PTR`, `ANY`
- Optionally a nameserver prefixed with `@`: `@8.8.8.8`

Examples:
- `example.com`
- `example.com MX`
- `example.com TXT @8.8.8.8`
- `93.184.216.34` (reverse lookup)

## Workflow

1. Parse the domain, optional record type (default `A`), and optional nameserver from `$ARGUMENTS`.
2. If the input looks like an IP address, perform a reverse lookup instead.
3. Show the user the exact command before executing.

### Standard lookup

```bash
dig <@nameserver> <domain> <record_type>
```

### Reverse lookup

```bash
dig -x <ip_address>
```

### Additional context

After the primary lookup, run a short output for quick reference:

```bash
dig +short <@nameserver> <domain> <record_type>
```

4. Present results clearly:
   - Query performed
   - Answer section (records returned)
   - TTL values
   - Authority and nameserver info if relevant

## Security Notes

- When investigating DNS, query multiple resolvers (`8.8.8.8`, `1.1.1.1`, authoritative NS) to detect discrepancies or poisoning.
- DNS responses are unauthenticated unless DNSSEC is in use — results can be spoofed.
- Use `dig +trace` to follow the full delegation path when investigating DNS issues.
