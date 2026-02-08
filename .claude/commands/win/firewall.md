# Windows Firewall Status

Check Windows Firewall profile status, inbound/outbound rules, and identify overly permissive configurations.

## Arguments

$ARGUMENTS is optional:
- `--rules` — list all enabled inbound allow rules
- `--permissive` — show only overly permissive rules (any source, any port)
- `--profile <Domain|Private|Public>` — focus on a specific profile
- (no args — overview of all profiles and notable rules)

Examples:
- (no args — firewall overview)
- `--rules`
- `--permissive`
- `--profile Public`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Profile status

```powershell
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName, LogAllowed, LogBlocked
```

### Step 2 — Inbound allow rules

```powershell
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
  Select-Object DisplayName, Profile,
    @{N='LocalPort';E={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort}},
    @{N='RemoteAddress';E={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}},
    @{N='Program';E={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Program}} |
  Format-Table
```

### Step 3 — Overly permissive rules

```powershell
# Rules allowing any source to any port
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Where-Object {
  $addr = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress
  $port = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_).LocalPort
  $addr -eq 'Any' -and $port -eq 'Any'
} | Select-Object DisplayName, Profile | Format-Table
```

3. Present results and flag:
   - Any disabled firewall profile (especially Public)
   - Rules allowing any source to any port
   - Default outbound action set to Allow (should be reviewed)
   - Firewall logging disabled

## Security Notes

- All three profiles (Domain, Private, Public) should be enabled. A disabled Public profile is a critical finding.
- Default inbound action should be Block. Default outbound as Allow is typical but permissive.
- Rules with `RemoteAddress = Any` and `LocalPort = Any` effectively disable the firewall for that traffic.
- Firewall logging should be enabled for both allowed and blocked connections for forensic purposes.
