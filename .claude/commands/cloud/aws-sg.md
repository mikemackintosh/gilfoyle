# AWS Security Group Audit

Review AWS EC2 security groups for overly permissive ingress rules, wide port ranges, and unused groups.

## Arguments

$ARGUMENTS is optional:
- `--vpc <vpc-id>` to audit security groups in a specific VPC
- `--group-id <sg-id>` to audit a specific security group
- `--profile <name>` to use a specific AWS CLI profile

Examples:
- (no args — audit all security groups in the default region)
- `--vpc vpc-0abc123def456`
- `--group-id sg-0abc123def456`
- `--vpc vpc-0abc123def456 --profile production`

## Workflow

1. Parse `$ARGUMENTS` for optional `--vpc`, `--group-id`, and `--profile` flags.
2. Show the user the exact commands before executing.

### Step 1: List security groups

If `--group-id` is provided, describe that group only. If `--vpc` is provided, filter by VPC. Otherwise, list all.

```bash
# All security groups
aws ec2 describe-security-groups \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,VPC:VpcId,Description:Description}' \
  --output table

# Filter by VPC
aws ec2 describe-security-groups \
  --filters Name=vpc-id,Values=<vpc-id> \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,Description:Description}' \
  --output table

# Specific group
aws ec2 describe-security-groups \
  --group-ids <sg-id>
```

### Step 2: Find security groups with 0.0.0.0/0 ingress

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,VPC:VpcId}' \
  --output table
```

### Step 3: Find security groups with ::/0 ingress (IPv6)

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.ipv6-cidr,Values='::/0' \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,VPC:VpcId}' \
  --output table
```

### Step 4: Detail risky ingress rules

```bash
for sg in $(aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].GroupId' --output text); do

  echo "=== $sg ==="
  aws ec2 describe-security-groups --group-ids "$sg" \
    --query 'SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)].{Proto:IpProtocol,FromPort:FromPort,ToPort:ToPort,CIDR:IpRanges[].CidrIp}' \
    --output table
  echo ""
done
```

Flag these patterns:
- **Critical:** `0.0.0.0/0` or `::/0` on port 22 (SSH)
- **Critical:** `0.0.0.0/0` or `::/0` on port 3389 (RDP)
- **Critical:** `0.0.0.0/0` or `::/0` on all ports (protocol `-1` or from 0 to 65535)
- **High:** `0.0.0.0/0` on database ports (3306, 5432, 1433, 27017, 6379)
- **Medium:** Wide port ranges (span > 100 ports) open to any source
- **Low:** `0.0.0.0/0` on port 80/443 (may be intentional for web servers)

### Step 5: Find wide port ranges

```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[].IpPermissions[?((ToPort - FromPort) > `100`)].{SG:join(``, []),Proto:IpProtocol,FromPort:FromPort,ToPort:ToPort}' \
  --output table
```

### Step 6: Find unused security groups

```bash
# Get all security groups
ALL_SGS=$(aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --output text)

# Get security groups attached to network interfaces (in use)
USED_SGS=$(aws ec2 describe-network-interfaces \
  --query 'NetworkInterfaces[].Groups[].GroupId' --output text)

# Find unused (excluding default groups)
echo "Unused security groups:"
for sg in $ALL_SGS; do
  if ! echo "$USED_SGS" | grep -qw "$sg"; then
    name=$(aws ec2 describe-security-groups --group-ids "$sg" \
      --query 'SecurityGroups[0].GroupName' --output text)
    if [ "$name" != "default" ]; then
      echo "  $sg ($name)"
    fi
  fi
done
```

4. Present findings as a summary table:

| SG ID | Name | VPC | Issue | Severity | Detail |
|-------|------|-----|-------|----------|--------|
| sg-xxx | web-sg | vpc-xxx | Open SSH | Critical | 0.0.0.0/0 on port 22 |
| sg-xxx | db-sg | vpc-xxx | Open DB port | High | 0.0.0.0/0 on port 5432 |
| sg-xxx | old-sg | vpc-xxx | Unused | Low | Not attached to any ENI |

5. Provide overall counts:
   - Total security groups audited
   - Critical findings
   - High findings
   - Medium/Low findings
   - Unused groups

6. For each finding, provide the specific remediation command.

### Remediation Commands

```bash
# Remove a specific ingress rule
aws ec2 revoke-security-group-ingress --group-id <sg-id> \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Replace with a restricted CIDR
aws ec2 authorize-security-group-ingress --group-id <sg-id> \
  --protocol tcp --port 22 --cidr <your-ip>/32

# Delete an unused security group
aws ec2 delete-security-group --group-id <sg-id>
```

## Security Notes

- Security groups with `0.0.0.0/0` ingress on SSH (22) or RDP (3389) are consistently flagged by every cloud security benchmark (CIS, SOC 2, PCI-DSS). These should be restricted to specific IP ranges or accessed via a bastion host or VPN.
- A security group with protocol `-1` (all traffic) open to `0.0.0.0/0` effectively disables the firewall for that resource.
- Default security groups should have all rules removed. AWS creates them with a permissive self-referencing rule that allows all traffic between members.
- Unused security groups should be cleaned up to reduce configuration drift and audit noise.
- Security groups are stateful — if ingress is allowed, the return traffic is automatically allowed regardless of egress rules.
- This audit requires `ec2:DescribeSecurityGroups` and `ec2:DescribeNetworkInterfaces` permissions.
