# Password Policy Check

Check a password against a configurable security policy.

## Arguments

$ARGUMENTS should include:
- A password to check (will be processed locally, never transmitted)
- Optionally `--policy <level>`: `basic`, `standard` (default), `strict`

Examples:
- `MyP@ssw0rd123`
- `correcthorsebatterystaple --policy strict`

## Workflow

1. Parse the password and policy level from `$ARGUMENTS`.
2. **Note to user:** The password is processed locally and never stored or transmitted.

```bash
python3 -c "
import re, math, sys

password = sys.argv[1]
policy = sys.argv[2] if len(sys.argv) > 2 else 'standard'

policies = {
    'basic':    {'min_len': 8,  'upper': False, 'lower': False, 'digit': False, 'special': False},
    'standard': {'min_len': 12, 'upper': True,  'lower': True,  'digit': True,  'special': False},
    'strict':   {'min_len': 16, 'upper': True,  'lower': True,  'digit': True,  'special': True},
}

p = policies.get(policy, policies['standard'])

results = []
results.append(('Length >= ' + str(p['min_len']), len(password) >= p['min_len']))
results.append(('Has uppercase', bool(re.search(r'[A-Z]', password)) if p['upper'] else True))
results.append(('Has lowercase', bool(re.search(r'[a-z]', password)) if p['lower'] else True))
results.append(('Has digit', bool(re.search(r'[0-9]', password)) if p['digit'] else True))
results.append(('Has special char', bool(re.search(r'[^A-Za-z0-9]', password)) if p['special'] else True))
results.append(('No common patterns', not bool(re.search(r'(password|123456|qwerty|admin|letmein|welcome)', password.lower()))))
results.append(('No repeated chars (3+)', not bool(re.search(r'(.)\1{2,}', password))))

# Entropy estimate
charset = 0
if re.search(r'[a-z]', password): charset += 26
if re.search(r'[A-Z]', password): charset += 26
if re.search(r'[0-9]', password): charset += 10
if re.search(r'[^A-Za-z0-9]', password): charset += 32
entropy = len(password) * math.log2(charset) if charset > 0 else 0

print(f'Password:  {\"*\" * len(password)} ({len(password)} chars)')
print(f'Policy:    {policy}')
print(f'Entropy:   ~{entropy:.0f} bits')
print()

all_pass = True
for check, passed in results:
    status = 'PASS' if passed else 'FAIL'
    if not passed: all_pass = False
    print(f'  [{status}] {check}')

print()
if all_pass:
    print('Result: PASS')
else:
    print('Result: FAIL')

if entropy < 40: print('Strength: WEAK')
elif entropy < 60: print('Strength: FAIR')
elif entropy < 80: print('Strength: GOOD')
else: print('Strength: STRONG')
" "<password>" "<policy>"
```

3. Present:
   - Policy checks (pass/fail for each rule)
   - Entropy estimate
   - Strength rating
   - Suggestions for improvement if any checks fail

## Security Notes

- This is a local policy check, not a breach database check. For breach checking, use the Have I Been Pwned API (k-anonymity model).
- Entropy is an estimate based on character set and length — it doesn't account for dictionary words or patterns.
- Long passphrases (5+ random words) are often stronger than short complex passwords.
- The strongest passwords are randomly generated, not human-chosen.
