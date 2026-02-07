# Encode / Decode

Perform Base64 and hex encoding/decoding operations.

## Arguments

$ARGUMENTS should include:
- Operation: `base64-encode`, `base64-decode`, `hex-encode`, `hex-decode`
- Target: a file path or `--string "text"`

Examples:
- `base64-encode myfile.bin`
- `base64-decode encoded.txt`
- `hex-encode --string "hello"`
- `hex-decode --string "68656c6c6f"`
- `base64-encode --string "user:password"`

## Workflow

1. Parse the operation and target from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Base64 encode

```bash
# File
base64 < <file>
# or
openssl base64 -in <file>

# String
echo -n "<string>" | base64
```

### Base64 decode

```bash
# File
base64 -d < <file>
# or (macOS)
base64 -D < <file>

# String
echo -n "<encoded>" | base64 -d
# or (macOS)
echo -n "<encoded>" | base64 -D
```

### Hex encode

```bash
# File
xxd -p < <file>
# or
od -A n -t x1 < <file> | tr -d ' \n'
# or
openssl hex -in <file>

# String
echo -n "<string>" | xxd -p
```

### Hex decode

```bash
# String to binary
echo -n "<hex>" | xxd -r -p

# Hex file to binary
xxd -r -p < <hexfile> > <output>
```

### URL-safe Base64

```bash
# Encode (replace +/ with -_ and strip =)
echo -n "<string>" | base64 | tr '+/' '-_' | tr -d '='

# Decode
echo -n "<urlsafe>" | tr '-_' '+/' | base64 -d
```

3. Display the result:
   - Operation performed
   - Input summary (filename or first N chars of string)
   - Output (or first N lines if very large, with full output written to file)

## Notes

- `echo -n` is critical to avoid trailing newline changing the output.
- On macOS, `base64 -D` is decode (capital D). On Linux, `base64 -d` (lowercase).
- For large files, write output to a file rather than displaying in terminal.
- Base64 increases size by ~33%. Hex encoding doubles the size.
- URL-safe Base64 (RFC 4648 §5) replaces `+` with `-`, `/` with `_`, and strips padding `=`.
