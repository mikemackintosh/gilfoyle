# Hash

Compute cryptographic hash digests of files or strings.

## Arguments

$ARGUMENTS should include:
- Hash algorithm: `sha256`, `sha512`, `sha384`, `sha1`, `md5`
- Target: a file path or a quoted string (prefix with `--string` for inline text)

Examples:
- `sha256 myfile.bin`
- `sha512 /path/to/document.pdf`
- `md5 --string "hello world"`
- `sha256 --string "test data"`
- `sha1 *.pem` (hash multiple files)

## Workflow

1. Parse the algorithm and target from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Hash a file

```bash
openssl dgst -<algorithm> <file>
```

Or using system utilities:

```bash
shasum -a 256 <file>     # SHA-256
shasum -a 512 <file>     # SHA-512
shasum -a 1 <file>       # SHA-1
md5 <file>               # MD5 (macOS)
md5sum <file>            # MD5 (Linux)
```

### Hash a string

```bash
echo -n "<string>" | openssl dgst -<algorithm>
```

Note: `echo -n` is critical — without it, a trailing newline changes the hash.

### Hash multiple files

```bash
openssl dgst -<algorithm> file1 file2 file3
```

Or:

```bash
shasum -a 256 file1 file2 file3
```

### HMAC (if a key is provided)

```bash
echo -n "<string>" | openssl dgst -<algorithm> -hmac "<key>"
```

3. Display the result clearly:
   - Algorithm used
   - Input (file path or "[string]")
   - Digest value (hex)

## Security Notes

- **MD5** is cryptographically broken. Do not use for security purposes. Only use for legacy checksum compatibility.
- **SHA-1** is deprecated for certificates and signatures (collision attacks demonstrated). Use only for git commit hashes or legacy systems.
- **SHA-256** is the recommended default for most purposes.
- **SHA-512** provides a wider output and is faster on 64-bit systems.
- When verifying file integrity, always compare hashes received over a separate trusted channel.
