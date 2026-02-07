# Log Search

Search across system and application logs for a pattern, keyword, or time range.

## Arguments

$ARGUMENTS should include:
- A search pattern (string or regex)
- Optionally a log file or directory (default: common system log locations)
- Optionally `--time <range>` for time-based filtering

Examples:
- `"error" /var/log/syslog`
- `"connection refused"`
- `"10.0.0.50" /var/log/`
- `"segfault" --time "1 hour ago"`
- `"Failed password" /var/log/auth.log`

## Workflow

1. Parse the search pattern, log target, and time range from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Search a specific log file

```bash
grep -n '<pattern>' <logfile>
```

### Search a directory of logs (including rotated)

```bash
grep -rn '<pattern>' <directory>
```

### Search compressed/rotated logs

```bash
zgrep '<pattern>' <logfile>.*.gz
```

### journalctl search (systemd)

```bash
journalctl --since "<time_range>" | grep '<pattern>'
```

Or with built-in grep:

```bash
journalctl -g '<pattern>' --since "<time_range>"
```

### macOS unified log search

```bash
log show --predicate 'eventMessage CONTAINS "<pattern>"' --last <duration>
```

### Context and counting

```bash
# Show lines around matches
grep -n -C 3 '<pattern>' <logfile>

# Count matches
grep -c '<pattern>' <logfile>

# Count matches per file
grep -rc '<pattern>' <directory> | sort -t: -k2 -rn
```

3. Present results:
   - Matching lines with context
   - Match count
   - If searching across files, which files had matches
   - Timestamp range of matches

## Security Notes

- Log files may contain sensitive information (passwords in failed login attempts, session tokens, PII). Handle search results carefully.
- Rotated logs (`.gz` files) often contain historical evidence — always include them in investigations.
- Absence of log entries can be significant — check for log tampering or gaps in timestamps.
- On busy systems, broad searches may be slow. Use specific file paths and patterns when possible.
