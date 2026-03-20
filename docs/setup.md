# Setup guide

This document covers the one-time AWS and GitHub configuration needed before
the compliance workflow can run.

---

## 1. Create the AWS IAM role

The workflow assumes a dedicated read-only role via OIDC — no long-lived
access keys are stored anywhere.

### 1a. Create the role in AWS

Go to **IAM → Roles → Create role** and choose **Web identity** as the
trusted entity type.

- Identity provider: `token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

Then attach the policy from `iam_policy_collector_role.json` in this repo.

Name the role `ComplianceCollectorRole`.

### 1b. Set the trust policy

Replace the default trust policy with the following. Substitute your GitHub
org/user and repo name.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<YOUR_ORG>/<YOUR_REPO>:*"
        }
      }
    }
  ]
}
```

### 1c. Add the OIDC provider (if not already present)

In **IAM → Identity providers → Add provider**:

- Provider type: OpenID Connect
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

This only needs to be done once per AWS account.

---

## 2. Configure GitHub repository secrets and variables

Go to **Settings → Secrets and variables → Actions**.

### Secret (sensitive — stored encrypted)

| Name | Value |
|---|---|
| `AWS_ROLE_ARN` | `arn:aws:iam::<ACCOUNT_ID>:role/ComplianceCollectorRole` |

### Variable (non-sensitive — visible in logs)

| Name | Value |
|---|---|
| `AWS_REGION` | `us-east-1` (or your primary region) |

---

## 3. Create the issue labels

The workflow tags issues with `compliance`, `automated`, and a per-source
label. Create these in **Issues → Labels**:

| Label | Suggested colour |
|---|---|
| `compliance` | `#0075ca` |
| `automated` | `#e4e669` |
| `aws-cloudtrail-logs` | `#d93f0b` |
| `aws-config-rules` | `#d93f0b` |
| `aws-iam-posture` | `#d93f0b` |
| `aws-securityhub-findings` | `#d93f0b` |

---

## 4. Add evidence/ and reports/ to .gitignore or keep them

The workflow commits evidence and reports directly to the repo. If you prefer
to keep them out of version control and use GitHub Artifacts instead, change
the **Commit evidence and reports** step to use `actions/upload-artifact`
and remove the `git push`.

For most GRC use cases, keeping them in the repo is better — you get a full
audit trail via git history with timestamps and run IDs in every commit message.

---

## 5. Run it manually the first time

Go to **Actions → Compliance — collect and report → Run workflow**.

Check the job summary tab after it completes to see fail counts, and look at
**Issues** to see any automatically opened gaps.
