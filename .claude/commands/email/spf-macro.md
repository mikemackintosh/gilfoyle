# SPF Macro Check

Parse, explain, and test-expand SPF macros in a record. SPF macros (RFC 7208 Section 7) let records dynamically reference the sender IP, envelope-from, HELO domain, and more — but they are notoriously hard to read and easy to get wrong. This command breaks them down.

## Arguments

$ARGUMENTS should be one of:

- A domain name — fetch its SPF record and analyse any macros found
- A raw SPF string — parse the macros directly (wrap in quotes if it contains spaces)
- A domain or SPF string followed by `--test` and test parameters to expand macros with real values

Examples:
- `example.com`
- `"v=spf1 exists:%{i}._spf.%{d} -all"`
- `example.com --test --ip 203.0.113.10 --sender user@example.com --helo mail.example.com`

## Workflow

### Step 1 — Obtain the SPF record

If $ARGUMENTS is a domain name, fetch the SPF record:

```bash
dig +short TXT <domain> | grep "v=spf1"
```

If $ARGUMENTS is a quoted SPF string, use it directly.

If no macros are found in the record (no `%{` sequences), report that the record uses no macros and give a brief summary of the record instead. No further steps needed.

### Step 2 — Identify all macros

Scan the SPF record for all `%{...}` sequences. For each one, extract:

- The **macro letter** (the variable being referenced)
- Any **transformers** (digit truncation, `r` for reverse)
- Any **delimiter** override (default is `.`)

### Step 3 — Explain each macro

Present a table of every macro found in the record, with its meaning and behaviour:

| Macro in Record | Variable | Meaning | Transformers | Notes |
|-----------------|----------|---------|--------------|-------|
| `%{i}` | `i` | Connecting client IP address | none | IPv4 dotted or IPv6 colon notation |
| `%{ir.}` | `i` | Connecting client IP, reversed | `r` = reverse, `.` delimiter | Used for DNSBL-style lookups |
| ... | ... | ... | ... | ... |

Use this reference for explanations:

#### Macro letters

| Letter | Variable | Description | Example value |
|--------|----------|-------------|---------------|
| `s` | sender | Envelope-from (full address) | `user@example.com` |
| `l` | local-part | Local-part of envelope-from | `user` |
| `o` | domain | Domain of envelope-from | `example.com` |
| `d` | current domain | Domain currently being evaluated (changes with include/redirect) | `example.com` |
| `i` | IP | Connecting client IP address | `203.0.113.10` or `2001:db8::1` |
| `p` | validated domain | Validated reverse DNS name of the client IP | `mail.example.com` (requires PTR lookup; RFC says "SHOULD NOT" be used — slow and unreliable) |
| `v` | IP version | `in-addr` for IPv4, `ip6` for IPv6 | `in-addr` |
| `h` | HELO/EHLO | HELO or EHLO domain presented by the client | `mail.example.com` |
| `c` | SMTP client IP | Same as `i` (only valid in `exp=` text) | `203.0.113.10` |
| `r` | receiving host | Domain of the receiving MTA (only valid in `exp=` text) | `mx.receiver.com` |
| `t` | timestamp | Current Unix timestamp (only valid in `exp=` text) | `1700000000` |

#### Transformers

| Transformer | Syntax | Description | Example |
|-------------|--------|-------------|---------|
| Reverse | `r` after the letter | Reverse the dot-separated parts | `%{ir}` on `203.0.113.10` yields `10.113.0.203` |
| Truncate | digit(s) before `r` | Keep only the rightmost N parts | `%{i2}` on `203.0.113.10` yields `113.10` |
| Truncate + reverse | digit(s) then `r` | Reverse first, then keep rightmost N | `%{ir2}` on `203.0.113.10` yields `0.203` |
| Delimiter | character(s) after all else | Split on this instead of `.` | `%{l-}` splits local-part on `-` instead of `.` |

### Step 4 — Analyse the context

For each mechanism or modifier that contains a macro, explain what it is actually doing in context:

- **`exists:%{i}._spf.%{d}`** — "This does a DNS A lookup for `<client-IP>._spf.<domain>`. If the record exists, the mechanism matches. This is a per-IP allowlist pattern: you add A records for each authorised sender IP under `_spf.<domain>`."

- **`include:%{ir}.%{v}._spf.%{d}`** — "This reverses the client IP and constructs a DNS name like `10.113.0.203.in-addr._spf.<domain>`, then evaluates the SPF record there. This is a DNSBL-style lookup pattern."

- **`redirect=%{d}._spf.example.com`** — "This redirects SPF evaluation to `<current-domain>._spf.example.com`, allowing centralised SPF management for multiple domains."

- **`exp=explain.%{d}`** — "On SPF failure, the receiving server looks up the TXT record at `explain.<domain>` to get a human-readable rejection reason. Macros in that TXT record will also be expanded."

Flag any issues:
- Use of `%{p}` — the RFC discourages it (`SHOULD NOT`) because it requires a PTR lookup which is slow, unreliable, and can cause DNS timeouts
- Macros in mechanisms that could create excessive DNS lookups
- `%{c}`, `%{r}`, or `%{t}` used outside of `exp=` (they are only valid in explanation strings)
- Malformed macro syntax (missing closing brace, invalid letter, etc.)

### Step 5 — Test expansion (if `--test` is provided)

If the user passed `--test`, expand every macro in the record using the provided values:

| Parameter | Flag | Default if not provided |
|-----------|------|------------------------|
| Client IP | `--ip` | `203.0.113.10` |
| Envelope-from | `--sender` | `user@example.com` |
| HELO domain | `--helo` | `mail.example.com` |
| Current domain | (always the SPF record's domain) | (from the record) |

Show the expansion step by step:

```
Original:   exists:%{i}._spf.%{d}
Expanded:   exists:203.0.113.10._spf.example.com
            → dig +short A 203.0.113.10._spf.example.com
```

```
Original:   include:%{ir}.%{v}._spf.%{d}
Expanded:   include:10.113.0.203.in-addr._spf.example.com
            → dig +short TXT 10.113.0.203.in-addr._spf.example.com
```

If the expanded result is a DNS name, actually run the lookup and show whether a record exists:

```bash
dig +short A <expanded-name>
# or
dig +short TXT <expanded-name>
```

Report what the result means:
- Record exists → mechanism would **match**
- NXDOMAIN → mechanism would **not match**
- SERVFAIL/timeout → mechanism would produce a **temperror**

### Step 6 — Summary

Present a final summary:

- Number of macros found and their types
- Any warnings (deprecated macros, RFC violations, DNS performance concerns)
- If test expansion was run: which mechanisms matched, which didn't, and the final SPF result for that test case
- Recommendations if applicable (e.g., "consider replacing `%{p}` with `%{i}` to avoid PTR lookup delays")

## Security Notes

- SPF macros can construct arbitrary DNS names from sender-controlled input (`%{s}`, `%{l}`, `%{h}`). An attacker can trigger DNS lookups to domains they control by crafting envelope-from addresses. This is by design, but be aware that macro-heavy records can leak information via DNS queries.
- `%{p}` forces a reverse DNS lookup on every SPF check. This is slow, can time out, and the result is attacker-influenceable (whoever controls the IP's PTR record). The RFC explicitly says `SHOULD NOT` be used.
- Macros in `exists:` mechanisms are a common pattern for large-scale SPF (it avoids the 10-lookup limit since `exists:` counts as only one lookup regardless of how many IPs you have). But the trade-off is that debugging becomes harder — you need to know the exact DNS namespace layout.
- Complex macro expressions can make SPF records effectively unreadable. If you find yourself needing macros, document the DNS namespace layout separately.
