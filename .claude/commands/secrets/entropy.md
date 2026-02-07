# Entropy Scanner

Detect high-entropy strings in files that may be secrets, tokens, or keys using Shannon entropy analysis.

## Arguments

$ARGUMENTS should include:
- A file or directory path
- Optionally `--threshold <float>` (default: 4.5 bits per character)

Examples:
- `config.yml`
- `./src`
- `.env --threshold 4.0`

## Workflow

1. Parse the path and threshold from `$ARGUMENTS`.
2. Show the user the exact command before executing.

### Scan a file

```bash
python3 -c "
import math, re, sys, os

threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 4.5

def entropy(s):
    if not s: return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', line):
                    e = entropy(token)
                    if e > threshold:
                        display = token[:16] + '...' + token[-4:] if len(token) > 24 else token
                        findings.append((filepath, line_num, e, display))
    except (IOError, UnicodeDecodeError):
        pass
    return findings

path = sys.argv[1]
results = []

if os.path.isfile(path):
    results = scan_file(path)
elif os.path.isdir(path):
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'vendor', 'dist', 'build'}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            if f.endswith(('.env', '.yml', '.yaml', '.json', '.conf', '.cfg', '.toml', '.tf', '.py', '.js', '.ts', '.go', '.rb', '.java', '.sh', '.xml', '.properties')):
                results.extend(scan_file(os.path.join(root, f)))

results.sort(key=lambda x: -x[2])
for filepath, line_num, e, display in results[:50]:
    print(f'{e:.2f}  {filepath}:{line_num}  {display}')

print(f'\nTotal: {len(results)} high-entropy strings found (threshold: {threshold})')
" "<path>" "<threshold>"
```

3. Present results:
   - Sorted by entropy (highest first)
   - File path, line number, entropy score, redacted token
   - Context about what entropy means and what scores indicate

### Entropy Reference

| Entropy | Likely Content |
|---------|---------------|
| < 3.0 | Natural language, repetitive strings |
| 3.0–4.0 | Code identifiers, short words |
| 4.0–4.5 | Mixed content, possible encoded data |
| 4.5–5.5 | Likely random: API keys, tokens, hashes |
| > 5.5 | Almost certainly random: cryptographic keys, passwords |

## Security Notes

- High entropy alone does not confirm a secret — base64-encoded data, UUIDs, and hashes are also high-entropy.
- Low entropy does not mean safe — dictionary passwords like `correcthorsebatterystaple` have low entropy but are still secrets.
- Best results come from combining entropy scanning with pattern matching (`/secrets:scan`).
- Skip binary files and lock files to reduce false positives.
