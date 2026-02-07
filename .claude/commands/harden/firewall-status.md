# Firewall Status

Check the current firewall status, rules, and configuration on the local system.

## Arguments

$ARGUMENTS is optional:
- `--detailed` — show verbose rule output with packet counts

Examples:
- (no args — auto-detect firewall and show status)
- `--detailed`

## Workflow

1. Detect the operating system and active firewall.
2. Show the user the exact commands before executing.

### macOS — pf + Application Firewall

```bash
# Application firewall status
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode

# Block all incoming
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall

# Allowed apps
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# pf rules
sudo pfctl -sr 2>/dev/null

# pf status
sudo pfctl -si 2>/dev/null
```

### Linux — ufw

```bash
sudo ufw status verbose
```

### Linux — iptables

```bash
sudo iptables -L -n -v --line-numbers
sudo iptables -t nat -L -n -v 2>/dev/null
```

### Linux — nftables

```bash
sudo nft list ruleset 2>/dev/null
```

### Linux — firewalld

```bash
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

3. Check for common issues:
   - Is the firewall actually enabled?
   - Are there overly permissive rules (e.g., allow all from `0.0.0.0/0`)?
   - Is SSH access restricted to specific source IPs?
   - Are there any DROP/REJECT rules?
   - Are unused ports open?

4. Summarise:
   - Firewall type and status (enabled/disabled)
   - Number of rules
   - Open inbound ports
   - Key findings (wide-open rules, missing default deny, etc.)
   - Recommendations

## Security Notes

- A firewall that is installed but disabled provides no protection.
- Default policy should be DROP/DENY for inbound traffic, with explicit ALLOW rules.
- SSH (port 22) should be restricted to trusted source IPs where possible.
- On macOS, the Application Firewall and `pf` are separate systems — both should be checked.
- Firewall rules are evaluated in order — a broad ALLOW early in the chain can negate later restrictions.
