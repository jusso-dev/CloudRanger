# AWS onboarding (read-only)

CloudRanger's agent needs a working `aws` CLI with **read-only** access.

## Recommended: IAM Identity Center (SSO) with a read-only permission set

Attach the AWS-managed **`SecurityAudit`** policy (optionally plus
`ViewOnlyAccess`) to a permission set, then:

```bash
aws configure sso        # once
aws sso login --profile security-audit
export AWS_PROFILE=security-audit
aws sts get-caller-identity   # note the Account — this is your scan scopeId
```

## Alternative: read-only role assumption

Create a role with `SecurityAudit` trusted by your identity, and use a
profile with `role_arn`/`source_profile`.

## Permissions used by the seed catalog

`iam:Get*`, `iam:List*`, `s3:ListAllMyBuckets`, `s3:GetBucket*`,
`s3:GetPublicAccessBlock` (implicitly via s3api), `ec2:Describe*`,
`ec2:GetEbsEncryptionByDefault`, `cloudtrail:DescribeTrails`,
`cloudtrail:GetTrailStatus`, `rds:Describe*`, `kms:ListKeys`,
`kms:GetKeyRotationStatus`, `guardduty:ListDetectors`,
`config:DescribeConfigurationRecorderStatus` — all inside `SecurityAudit`.

Missing permissions are not fatal: submit the AccessDenied error as
evidence and the affected controls report `error`, never `pass`.

## Scan

Ask your agent: _"Run a CloudRanger scan of AWS account `<id>` in regions
`ap-southeast-2, us-east-1`."_ Keep the region list to regions you actually
use — every regional collector multiplies commands.
