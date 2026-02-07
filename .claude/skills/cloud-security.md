---
name: Cloud Security
description: AWS, GCP, and Azure security auditing — IAM, storage, networking, audit logs, and CIS cloud benchmarks.
instructions: |
  Use this skill when the user needs to audit, review, or harden cloud infrastructure security across
  AWS, GCP, or Azure. Cover IAM configuration, public resource detection, credential rotation, audit
  logging, and compliance benchmarks. Always show commands before executing them and explain the
  security implications of each finding.
---

# Cloud Security Skill

## Related Commands
- `/cloud-aws-iam` — Audit AWS IAM users, policies, access keys, and MFA
- `/cloud-aws-s3` — Audit S3 bucket permissions, encryption, and public access
- `/cloud-aws-sg` — Review AWS security groups for overly permissive rules
- `/cloud-gcp-iam` — Audit GCP IAM roles, service accounts, and keys

## AWS IAM Security

### Key Audit Areas

| Area | Risk | Check |
|------|------|-------|
| Users without MFA | Account takeover | `aws iam list-mfa-devices --user-name <user>` |
| Old access keys (>90 days) | Credential compromise | `aws iam list-access-keys --user-name <user>` |
| Unused credentials | Unnecessary attack surface | `aws iam get-credential-report` |
| Overly permissive policies | Privilege escalation | `aws iam list-attached-user-policies` |
| Root account usage | Full account compromise | Check CloudTrail for root events |
| Inline policies | Shadow permissions | `aws iam list-user-policies` |

### Common Dangerous IAM Policies

| Policy / Pattern | Risk |
|-----------------|------|
| `Action: "*", Resource: "*"` | Full administrative access |
| `iam:PassRole` + `ec2:RunInstances` | Privilege escalation via role assumption |
| `iam:CreatePolicyVersion` | Self-escalation by writing new policy versions |
| `iam:AttachUserPolicy` | Self-escalation by attaching admin policies |
| `sts:AssumeRole` with broad Resource | Lateral movement across roles |
| `lambda:CreateFunction` + `iam:PassRole` | Escalation via Lambda execution role |

### AWS Access Key Rotation

```bash
# List access keys and their age
aws iam list-access-keys --user-name <user> \
  --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Created:CreateDate,Status:Status}'

# Create new access key
aws iam create-access-key --user-name <user>

# Deactivate old key (test first, then delete)
aws iam update-access-key --user-name <user> --access-key-id <old-key-id> --status Inactive

# Delete old key after confirming new key works
aws iam delete-access-key --user-name <user> --access-key-id <old-key-id>
```

## AWS S3 Security

### Bucket Security Checklist

| Setting | Recommended | Command |
|---------|------------|---------|
| Public Access Block | All four settings enabled | `aws s3api get-public-access-block --bucket <name>` |
| Bucket Policy | No `Principal: "*"` | `aws s3api get-bucket-policy --bucket <name>` |
| ACL | Private (no public grants) | `aws s3api get-bucket-acl --bucket <name>` |
| Encryption | SSE-S3 or SSE-KMS enabled | `aws s3api get-bucket-encryption --bucket <name>` |
| Versioning | Enabled (data protection) | `aws s3api get-bucket-versioning --bucket <name>` |
| Logging | Enabled (audit trail) | `aws s3api get-bucket-logging --bucket <name>` |
| Object Lock | Consider for compliance data | `aws s3api get-object-lock-configuration --bucket <name>` |

### Dangerous S3 Bucket Policy Patterns

```json
// PUBLIC READ — anyone on the internet can read objects
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bucket-name/*"
}

// PUBLIC WRITE — anyone can upload objects (critical risk)
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::bucket-name/*"
}
```

## AWS Security Groups

### Rules to Flag

| Pattern | Risk | Severity |
|---------|------|----------|
| `0.0.0.0/0` ingress on port 22 | SSH open to internet | Critical |
| `0.0.0.0/0` ingress on port 3389 | RDP open to internet | Critical |
| `0.0.0.0/0` ingress on all ports | Fully open to internet | Critical |
| `::/0` ingress | IPv6 open to internet | Critical |
| Wide port ranges (e.g. 0-65535) | Excessive access | High |
| Unused security groups | Stale configuration | Low |
| Self-referencing rules on all ports | Overly broad internal access | Medium |

### Security Group Audit Commands

```bash
# List all security groups
aws ec2 describe-security-groups --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,VPC:VpcId}'

# Find groups with 0.0.0.0/0 ingress
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}'

# Find groups open on SSH
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values='22' Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}'
```

## GCP IAM Security

### Key Audit Areas

| Area | Risk | Check |
|------|------|-------|
| Overly permissive roles (Owner, Editor) | Full project access | `gcloud projects get-iam-policy <project>` |
| User-managed service account keys | Key leakage, no rotation | `gcloud iam service-accounts keys list` |
| Default service accounts with roles | Unintended privilege | Check for `*-compute@developer.gserviceaccount.com` |
| Domain-wide delegation | G Workspace impersonation | Check service account settings |
| Primitive roles on production | Excessive permissions | Filter for `roles/owner`, `roles/editor` |

### GCP Predefined Roles — Risk Levels

| Role | Risk | Notes |
|------|------|-------|
| `roles/owner` | Critical | Full control including IAM changes and billing |
| `roles/editor` | High | Full control minus IAM changes |
| `roles/viewer` | Low | Read-only access |
| `roles/iam.serviceAccountTokenCreator` | High | Can impersonate any SA in the project |
| `roles/iam.serviceAccountKeyAdmin` | High | Can create SA keys (credential leak risk) |
| `roles/resourcemanager.projectIamAdmin` | Critical | Can modify all IAM policies |

### GCP Service Account Key Rotation

```bash
# List keys for a service account
gcloud iam service-accounts keys list \
  --iam-account=<sa-email> \
  --format="table(name.basename(), validAfterTime, validBeforeTime, keyType)"

# Create a new key
gcloud iam service-accounts keys create new-key.json \
  --iam-account=<sa-email>

# Delete old key
gcloud iam service-accounts keys delete <key-id> \
  --iam-account=<sa-email>
```

> **Best practice:** Prefer Workload Identity Federation over service account keys. Keys are long-lived credentials that can leak.

## Azure AD / Entra ID & RBAC

### Key Audit Areas

| Area | Risk | Check |
|------|------|-------|
| Global Administrator accounts | Full tenant control | `az role assignment list --role "Global Administrator"` |
| Users without MFA | Account takeover | Check Conditional Access policies |
| Service principals with broad roles | Privilege escalation | `az role assignment list --assignee <sp-id>` |
| Guest users with roles | External access risk | `az ad user list --filter "userType eq 'Guest'"` |
| Subscription-level Owner | Full resource control | `az role assignment list --role "Owner" --scope /subscriptions/<id>` |

### Azure Dangerous Roles

| Role | Risk | Scope |
|------|------|-------|
| Global Administrator | Critical | Tenant-wide |
| Owner | Critical | Subscription/resource group |
| Contributor | High | Can create and manage all resources |
| User Access Administrator | High | Can manage access to resources |
| Key Vault Administrator | High | Full access to secrets, keys, certs |

### Azure Audit Commands

```bash
# List role assignments at subscription level
az role assignment list --scope /subscriptions/<sub-id> \
  --query "[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}" -o table

# List service principals
az ad sp list --all --query "[].{Name:displayName,AppId:appId,Type:servicePrincipalType}" -o table

# Check storage account public access
az storage account list \
  --query "[].{Name:name,PublicAccess:allowBlobPublicAccess,HttpsOnly:enableHttpsTrafficOnly}" -o table
```

## Cloud Credential Rotation Best Practices

| Provider | Credential Type | Max Age | Rotation Method |
|----------|----------------|---------|-----------------|
| AWS | Access keys | 90 days | Create new, test, deactivate old, delete |
| AWS | Console password | 90 days | IAM password policy enforcement |
| GCP | Service account keys | 90 days | Create new key, update consumers, delete old |
| GCP | API keys | 90 days | Regenerate in console, update consumers |
| Azure | Client secrets | 90 days | Add new secret, update consumers, remove old |
| Azure | Storage keys | 90 days | Rotate via `az storage account keys renew` |
| All | Root / break-glass | Never share | MFA-protected, stored in secure vault |

### Rotation Workflow

1. **Create** a new credential
2. **Deploy** the new credential to all consumers
3. **Verify** all consumers are using the new credential
4. **Deactivate** the old credential (monitoring period)
5. **Delete** the old credential after confirming no usage

## Public Resource Detection

### AWS — Find Public Resources

```bash
# Public S3 buckets (via access block check)
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  result=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "NO PUBLIC ACCESS BLOCK: $bucket"
  fi
done

# Public EC2 instances
aws ec2 describe-instances \
  --filters Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'Reservations[].Instances[].{ID:InstanceId,PublicIP:PublicIpAddress}'

# Public RDS instances
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].{ID:DBInstanceIdentifier,Engine:Engine}'

# Public ELBs
aws elbv2 describe-load-balancers \
  --query 'LoadBalancers[?Scheme==`internet-facing`].{Name:LoadBalancerName,DNS:DNSName}'
```

### GCP — Find Public Resources

```bash
# Public GCS buckets
gsutil iam get gs://<bucket> | grep -i allUsers

# Public Compute instances with external IP
gcloud compute instances list \
  --format="table(name, networkInterfaces[0].accessConfigs[0].natIP)" \
  --filter="networkInterfaces[0].accessConfigs[0].natIP:*"

# Public Cloud SQL instances
gcloud sql instances list \
  --format="table(name, ipAddresses[].ipAddress, settings.ipConfiguration.authorizedNetworks)"
```

## CloudTrail / Audit Log Basics

### AWS CloudTrail

```bash
# Check if CloudTrail is enabled
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,Bucket:S3BucketName,IsMultiRegion:IsMultiRegionTrail}'

# Check trail status
aws cloudtrail get-trail-status --name <trail-name>

# Look up recent events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --max-items 10

# Check for root account usage
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --max-items 10
```

### GCP Audit Logs

```bash
# View admin activity logs
gcloud logging read 'logName="projects/<project>/logs/cloudaudit.googleapis.com%2Factivity"' \
  --limit=20 --format=json

# Check for IAM changes
gcloud logging read 'protoPayload.methodName="SetIamPolicy"' \
  --limit=20 --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, resource.type)"

# Check for service account key creation
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --limit=20
```

### Azure Activity Log

```bash
# View recent activity log
az monitor activity-log list --max-events 20 \
  --query "[].{Time:eventTimestamp,Operation:operationName.value,Caller:caller,Status:status.value}" -o table

# Filter for role assignments
az monitor activity-log list \
  --query "[?contains(operationName.value, 'roleAssignments')]" -o table
```

## Multi-Cloud Security Comparison

| Concern | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Identity | IAM Users + Roles | IAM + Service Accounts | Entra ID + RBAC |
| MFA | Per-user IAM setting | Google account 2SV | Conditional Access |
| Audit Logs | CloudTrail | Cloud Audit Logs | Activity Log |
| Secrets | Secrets Manager, SSM | Secret Manager | Key Vault |
| Encryption at rest | KMS (default SSE-S3) | Cloud KMS (default Google-managed) | Key Vault + CMK |
| Network | VPC + Security Groups | VPC + Firewall Rules | VNet + NSG |
| Public storage | S3 bucket policies + Block Public Access | GCS IAM + uniform access | Storage account public access setting |
| Compliance | AWS Config, Security Hub | Security Command Center | Defender for Cloud |
| Benchmark tool | AWS Security Hub (CIS) | SCC + Forseti | Defender for Cloud (CIS) |

## CIS Cloud Benchmarks Overview

The Center for Internet Security (CIS) publishes benchmarks for each major cloud provider. Key sections:

### CIS AWS Foundations Benchmark — Key Controls

| # | Control | Category |
|---|---------|----------|
| 1.1 | Avoid root account usage | IAM |
| 1.4 | Ensure no root access keys exist | IAM |
| 1.5 | MFA enabled for root | IAM |
| 1.10 | MFA enabled for all IAM users with console access | IAM |
| 1.14 | Access keys rotated every 90 days | IAM |
| 2.1 | CloudTrail enabled in all regions | Logging |
| 2.6 | S3 bucket access logging on CloudTrail bucket | Logging |
| 3.1 | Log metric filter for unauthorized API calls | Monitoring |
| 4.1 | No security groups allow ingress 0.0.0.0/0 to port 22 | Networking |
| 4.2 | No security groups allow ingress 0.0.0.0/0 to port 3389 | Networking |

### CIS GCP Foundations Benchmark — Key Controls

| # | Control | Category |
|---|---------|----------|
| 1.1 | Corporate login credentials used (not Gmail) | IAM |
| 1.4 | No service account keys for default SAs | IAM |
| 1.5 | No user-managed SA keys where avoidable | IAM |
| 1.6 | SA not assigned Owner or Editor role | IAM |
| 2.1 | Cloud Audit Logging enabled for all services | Logging |
| 3.6 | SSH access not open from 0.0.0.0/0 | Networking |
| 5.1 | Default encryption enabled on GCS buckets | Storage |

### CIS Azure Foundations Benchmark — Key Controls

| # | Control | Category |
|---|---------|----------|
| 1.1 | MFA enabled for all privileged users | IAM |
| 1.3 | Guest users reviewed regularly | IAM |
| 2.1 | Defender for Cloud enabled | Security Centre |
| 3.1 | Storage account requires secure transfer (HTTPS) | Storage |
| 3.7 | Public access disabled on storage accounts | Storage |
| 5.1 | Diagnostic logs enabled | Logging |
| 6.1 | RDP access restricted from internet | Networking |
| 6.2 | SSH access restricted from internet | Networking |

> **Note:** CIS benchmarks are updated regularly. Always reference the latest version from [cisecurity.org](https://www.cisecurity.org/benchmark). For automated compliance scanning, use provider-native tools (AWS Security Hub, GCP SCC, Azure Defender) or third-party tools (Prowler, ScoutSuite, Steampipe).
