# AWS IAM Audit

Audit AWS IAM configuration for security weaknesses — users without MFA, old access keys, unused credentials, and overly permissive policies.

## Arguments

$ARGUMENTS is optional:
- `--profile <name>` to use a specific AWS CLI profile

Examples:
- (no args — uses default profile)
- `--profile production`
- `--profile staging`

## Workflow

1. Parse `$ARGUMENTS` for an optional `--profile` flag. If provided, append `--profile <name>` to all AWS CLI commands.
2. Show the user the exact commands before executing.
3. Run the following audit steps:

### Step 1: List all IAM users

```bash
aws iam list-users \
  --query 'Users[].{UserName:UserName,Created:CreateDate,PasswordLastUsed:PasswordLastUsed}' \
  --output table
```

### Step 2: Generate and retrieve the credential report

```bash
aws iam generate-credential-report
sleep 3
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

The credential report reveals:
- **Password enabled** — whether the user has console access
- **Password last used** — flag if never used or not used in >90 days
- **MFA active** — flag any user with console access but no MFA
- **Access key 1/2 active** — flag if active
- **Access key 1/2 last used** — flag if never used or not used in >90 days
- **Access key 1/2 last rotated** — flag if >90 days old

### Step 3: Check MFA for each user

```bash
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices[].SerialNumber' --output text)
  if [ -z "$mfa" ]; then
    echo "NO MFA: $user"
  else
    echo "MFA OK: $user ($mfa)"
  fi
done
```

### Step 4: Check access key age

```bash
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$user" \
    --query "AccessKeyMetadata[].{User:'$user',KeyId:AccessKeyId,Created:CreateDate,Status:Status}" \
    --output table
done
```

Flag any access key where the creation date is more than 90 days ago.

### Step 5: List attached policies per user

```bash
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  echo "=== $user ==="
  echo "Attached policies:"
  aws iam list-attached-user-policies --user-name "$user" \
    --query 'AttachedPolicies[].PolicyName' --output text
  echo "Inline policies:"
  aws iam list-user-policies --user-name "$user" \
    --query 'PolicyNames' --output text
  echo "Groups:"
  aws iam list-groups-for-user --user-name "$user" \
    --query 'Groups[].GroupName' --output text
  echo ""
done
```

Flag these dangerous policies:
- `AdministratorAccess`
- `IAMFullAccess`
- `PowerUserAccess`
- Any policy with `Action: "*"` and `Resource: "*"`

### Step 6: Check for root account access keys

```bash
aws iam get-account-summary \
  --query '{RootMFA:SummaryMap.AccountMFAEnabled,RootAccessKeys:SummaryMap.AccountAccessKeysPresent}'
```

Flag if root has access keys or if root MFA is not enabled.

4. Present findings as a summary table:

| # | Check | Status | Detail |
|---|-------|--------|--------|
| 1 | Users without MFA | PASS/FAIL | List of users |
| 2 | Access keys >90 days old | PASS/FAIL | List of keys |
| 3 | Unused credentials | PASS/WARN | Users with unused passwords or keys |
| 4 | Overly permissive policies | PASS/FAIL | Users with admin-level policies |
| 5 | Root access keys | PASS/FAIL | Keys present or not |
| 6 | Root MFA | PASS/FAIL | Enabled or not |

5. For each FAIL, provide the specific remediation command.

## Security Notes

- Users without MFA are vulnerable to credential theft and phishing attacks. MFA should be enforced for all users, especially those with console access.
- Access keys older than 90 days should be rotated. Deactivate the old key before deleting to test that nothing breaks.
- The credential report is the single most useful artefact for IAM auditing — review it regularly.
- Inline policies are harder to audit than managed policies. Prefer attaching managed policies to groups rather than individual users.
- Root account access keys should **never** exist. Use IAM users or roles instead.
- This audit requires `iam:List*`, `iam:Get*`, and `iam:GenerateCredentialReport` permissions.
