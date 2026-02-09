# User and Group Management

Manage Linux users, groups, sudoers, password policies, and account security.

## Arguments

$ARGUMENTS is optional:
- `list` — list all users and groups
- `add <username>` — create a new user
- `lock <username>` — lock an account
- `sudoers` — review sudoers configuration
- `audit` — audit accounts for security issues
- `<username>` — show details for a specific user
- (no args — user audit overview)

Examples:
- (no args — audit overview)
- `list`
- `audit`
- `sudoers`
- `deploy`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — User overview

```bash
echo "=== System Users (UID < 1000) ==="
awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {print $1, $3, $7}' /etc/passwd

echo ""
echo "=== Regular Users (UID >= 1000) ==="
awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd

echo ""
echo "=== Users with Login Shells ==="
awk -F: '$7 !~ /nologin|false|sync|shutdown|halt/ {print $1, $7}' /etc/passwd
```

### Step 2 — Sudoers review

```bash
echo "=== /etc/sudoers ==="
sudo cat /etc/sudoers | grep -v '^#' | grep -v '^$'

echo ""
echo "=== /etc/sudoers.d/ ==="
sudo ls -la /etc/sudoers.d/
for f in /etc/sudoers.d/*; do
  echo "--- $f ---"
  sudo cat "$f" | grep -v '^#' | grep -v '^$'
done

echo ""
echo "=== Users in sudo/wheel group ==="
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null
```

### Step 3 — Security audit

```bash
echo "=== Accounts with Empty Passwords ==="
sudo awk -F: '($2 == "" || $2 == "!") && $3 >= 1000 {print $1}' /etc/shadow

echo ""
echo "=== Accounts with UID 0 (root equivalent) ==="
awk -F: '$3 == 0 {print $1}' /etc/passwd

echo ""
echo "=== Password Aging ==="
for user in $(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd); do
  chage -l "$user" 2>/dev/null | head -4
  echo ""
done

echo ""
echo "=== NOPASSWD Sudo Rules ==="
sudo grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

3. Flag findings:
   - Accounts with empty passwords
   - Multiple UID 0 accounts
   - NOPASSWD sudo rules
   - Users with login shells that shouldn't have them
   - Accounts with no password expiry set

## Security Notes

- Only root should have UID 0. Additional UID 0 accounts are a red flag.
- `NOPASSWD` sudo rules should be limited to specific commands, never `ALL`.
- Service accounts should use `/usr/sbin/nologin` or `/bin/false` as their shell.
- Password aging should be configured: `chage -M 90 -m 7 -W 14 <user>`.
- Always use `visudo` to edit sudoers — it validates syntax before saving.
