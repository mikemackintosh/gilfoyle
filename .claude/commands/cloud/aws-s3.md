# AWS S3 Audit

Audit S3 bucket security configuration — public access settings, bucket policies, ACLs, encryption, versioning, and logging.

## Arguments

$ARGUMENTS is optional:
- A specific bucket name to audit
- `--all` to audit all buckets in the account
- `--profile <name>` to use a specific AWS CLI profile

Examples:
- `my-bucket-name`
- `--all`
- `my-bucket-name --profile production`
- `--all --profile staging`

## Workflow

1. Parse `$ARGUMENTS` for an optional bucket name, `--all` flag, and `--profile` flag.
2. If no bucket is specified and `--all` is not set, list all buckets and ask the user which to audit.
3. Show the user the exact commands before executing.

### Step 1: List buckets (if --all or no bucket specified)

```bash
aws s3api list-buckets --query 'Buckets[].{Name:Name,Created:CreationDate}' --output table
```

### Step 2: Check Public Access Block settings

```bash
aws s3api get-public-access-block --bucket <bucket-name>
```

All four settings should be `true`:
- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

If the command returns a `NoSuchPublicAccessBlockConfiguration` error, the bucket has **no public access block** — flag as critical.

### Step 3: Check bucket policy

```bash
aws s3api get-bucket-policy --bucket <bucket-name> --output text 2>/dev/null | python3 -m json.tool
```

Flag dangerous patterns:
- `"Principal": "*"` — public access
- `"Principal": {"AWS": "*"}` — public access
- `"Effect": "Allow"` with `"Action": "s3:*"` — overly permissive
- Missing `Condition` blocks on Allow statements for `"Principal": "*"`

### Step 4: Check bucket ACL

```bash
aws s3api get-bucket-acl --bucket <bucket-name>
```

Flag these grantees:
- `http://acs.amazonaws.com/groups/global/AllUsers` — public access (critical)
- `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` — any AWS account (high risk)

### Step 5: Check encryption configuration

```bash
aws s3api get-bucket-encryption --bucket <bucket-name>
```

- **PASS:** SSE-S3 (`AES256`) or SSE-KMS (`aws:kms`) configured
- **FAIL:** `ServerSideEncryptionConfigurationNotFoundError` — no default encryption

### Step 6: Check versioning

```bash
aws s3api get-bucket-versioning --bucket <bucket-name>
```

- **PASS:** `Status: Enabled`
- **WARN:** `Status: Suspended` — was enabled, now suspended
- **WARN:** No output — versioning never enabled

### Step 7: Check logging

```bash
aws s3api get-bucket-logging --bucket <bucket-name>
```

- **PASS:** `LoggingEnabled` with a target bucket and prefix
- **WARN:** Empty response — access logging not configured

### Step 8: (If --all) Scan all buckets

```bash
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="

  echo "Public Access Block:"
  aws s3api get-public-access-block --bucket "$bucket" 2>&1

  echo "ACL:"
  aws s3api get-bucket-acl --bucket "$bucket" \
    --query 'Grants[?Grantee.URI!=`null`].{Grantee:Grantee.URI,Permission:Permission}' --output table 2>&1

  echo "Encryption:"
  aws s3api get-bucket-encryption --bucket "$bucket" 2>&1 | head -5

  echo "Versioning:"
  aws s3api get-bucket-versioning --bucket "$bucket" 2>&1

  echo ""
done
```

4. Present findings as a summary table:

| Bucket | Public Block | Policy | ACL | Encryption | Versioning | Logging |
|--------|-------------|--------|-----|------------|------------|---------|
| name | PASS/FAIL | PASS/FAIL | PASS/FAIL | PASS/FAIL | PASS/WARN | PASS/WARN |

5. For each FAIL, provide the specific remediation command.

### Remediation Commands

```bash
# Enable public access block (recommended for all buckets)
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable default encryption (SSE-S3)
aws s3api put-bucket-encryption --bucket <bucket-name> \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Enable versioning
aws s3api put-bucket-versioning --bucket <bucket-name> \
  --versioning-configuration Status=Enabled

# Enable access logging
aws s3api put-bucket-logging --bucket <bucket-name> \
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>","TargetPrefix":"<bucket-name>/"}}'
```

## Security Notes

- Public S3 buckets are one of the most common sources of cloud data breaches. Always enable the account-level S3 Block Public Access setting in addition to per-bucket settings.
- Even with `BlockPublicAcls` enabled, pre-existing public ACLs may still grant access unless `IgnorePublicAcls` is also enabled.
- SSE-S3 encryption protects data at rest but does not prevent access by anyone with S3 read permissions. Use SSE-KMS with key policies for stricter control.
- Versioning protects against accidental deletion but increases storage costs. Consider lifecycle rules to expire old versions.
- Bucket policies with `"Principal": "*"` and no `Condition` are effectively public, even if the intent is IP-restricted access — always verify Condition blocks.
- This audit requires `s3:GetBucket*`, `s3:ListBucket`, and `s3:ListAllMyBuckets` permissions.
