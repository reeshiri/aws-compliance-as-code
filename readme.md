# AWS Compliance as Code

Automated evidence collection and gap reporting for AWS environments across
PCI-DSS, SOC 2, ISO 27001, and ISO 42001 — powered by Python, GitHub Actions,
and the AWS SDK.

---

## What this project does

Most compliance programmes are manual: spreadsheets, screenshots, and
quarterly scrambles before an audit. This project treats compliance the same
way good engineering teams treat infrastructure — as code that runs
automatically, produces consistent outputs, and lives in version control.

Every week, a GitHub Actions workflow:

1. Connects to AWS using short-lived OIDC credentials (no stored access keys)
2. Collects evidence from four AWS services — CloudTrail, Config, IAM, and Security Hub
3. Maps that evidence to control IDs across all four frameworks simultaneously
4. Generates three CSV reports covering signal health, control coverage, and individual findings
5. Commits everything to this repository, creating a timestamped audit trail in git history
6. Opens a GitHub Issue for every failing control, with affected resources and remediation guidance

The result is a continuously maintained compliance posture that any auditor,
engineer, or stakeholder can inspect at any time — no manual effort required
between runs.

---

## Why compliance as code matters

Traditional GRC work has a few persistent problems:

**Evidence goes stale.** A screenshot taken six months ago doesn't prove
anything is true today. Git-committed JSON artifacts with timestamps do.

**Coverage is inconsistent.** When evidence collection is manual, things get
missed. Automated collectors run the same checks every time without exception.

**Frameworks overlap massively.** PCI-DSS, SOC 2, ISO 27001, and ISO 42001
share a large number of underlying controls. A single piece of AWS evidence —
say, an IAM credential report — satisfies controls across all four frameworks
at once. The `controls.yaml` mapping file in this repo makes that overlap
explicit, so compliance work isn't duplicated across frameworks.

**Audits are expensive surprises.** When evidence is collected continuously
and gaps are surfaced as GitHub Issues the moment they appear, there are no
surprises when an auditor arrives. The repo history is the audit trail.

---

## Architecture

```
AWS account
  ├── CloudTrail      ─┐
  ├── AWS Config      ─┼──▶  boto3 collectors  ──▶  evidence/  ──▶  controls.yaml
  ├── IAM             ─┤         (Python)            (JSON)          (mapping file)
  └── Security Hub   ─┘
                                                                           │
                                                                           ▼
                                                                   generate_report.py
                                                                           │
                                                              ┌────────────┼────────────┐
                                                              ▼            ▼            ▼
                                                        01_summary   02_coverage   03_findings
                                                           .csv          .csv          .csv
```

All code, evidence, and reports live in this repository. The GitHub Actions
workflow runs every Monday at 06:00 UTC and can also be triggered manually
from the Actions tab.

---

## Frameworks covered

| Framework | Focus |
|---|---|
| **PCI-DSS v4** | Payment card data security |
| **SOC 2 Type II** | Security, availability, and confidentiality trust principles |
| **ISO 27001:2022** | Information security management system |
| **ISO 42001:2023** | AI management system — governance of AI systems and models |

---

## Evidence sources

| Collector | What it captures | IAM permissions needed |
|---|---|---|
| `collect_cloudtrail.py` | Trail configuration, log validation, write event count, compliance signals | `cloudtrail:DescribeTrails`, `GetTrailStatus`, `LookupEvents` |
| `collect_config.py` | Config rule compliance status, non-compliant resources, high-value rule failures | `config:DescribeConfigRules`, `DescribeComplianceByConfigRule`, `GetComplianceDetailsByConfigRule` |
| `collect_iam.py` | Password policy, root account MFA, user MFA status, stale access keys, credential report | `iam:GetAccountPasswordPolicy`, `GenerateCredentialReport`, `GetCredentialReport`, `ListUsers` |
| `collect_securityhub.py` | Hub status, enabled standards, active findings by severity, critical/high finding details | `securityhub:DescribeHub`, `GetEnabledStandards`, `GetFindings` |

Each collector saves its output to `evidence/<evidence_id>/latest.json` and a
dated snapshot to `evidence/<evidence_id>/YYYYMMDD_HHMMSS.json`. The dated
snapshots are the audit trail — they are never overwritten.

---

## Reports

Three CSV files are generated into `reports/` on every run.

### `01_summary.csv` — signal health

One row per compliance signal. Shows whether each check passed or failed, and
which control IDs across all four frameworks it satisfies.

| Column | Description |
|---|---|
| `evidence_id` | The collector that produced this signal |
| `signal` | The specific check (e.g. `root_mfa_enabled`) |
| `description` | Human-readable description of the check |
| `status` | `PASS`, `FAIL`, or `ERROR` |
| `collected_at` | ISO 8601 timestamp of when evidence was collected |
| `aws_account` | AWS account ID |
| `PCI-DSS` | Semicolon-separated PCI-DSS control IDs satisfied by this signal |
| `SOC 2` | SOC 2 criteria satisfied |
| `ISO 27001` | ISO 27001 Annex A controls satisfied |
| `ISO 42001` | ISO 42001 controls satisfied |

### `02_control_coverage.csv` — framework control mapping

One row per framework control ID. Shows whether the control is covered by
evidence and its current pass/fail status. This is the view an auditor asks
for — "show me your evidence for PCI-DSS 8.4.2."

| Column | Description |
|---|---|
| `framework` | Framework name |
| `control_id` | Control identifier (e.g. `8.4.2`) |
| `overall_status` | `PASS` if all signals pass, `FAIL` if any fail |
| `evidence_count` | Number of signals covering this control |
| `passing_signals` | Count of passing signals |
| `failing_signals` | Count of failing signals |
| `evidence_ids` | Which collectors cover this control |
| `signal_descriptions` | What each signal checks |

### `03_findings_detail.csv` — individual findings

One row per individual finding. This is the remediation worklist — specific
users without MFA, specific stale access keys with age in days, specific
Config rule failures by resource ID, and Security Hub critical/high findings.

| Column | Description |
|---|---|
| `evidence_id` | Source collector |
| `finding_type` | Category of finding |
| `severity` | `CRITICAL`, `HIGH`, or `MEDIUM` |
| `resource` | Affected resource (username, resource ID, ARN) |
| `detail` | Additional context (key age, resource type, annotation) |
| `remediation` | Recommended fix |
| `collected_at` | When the finding was observed |
| `aws_account` | AWS account ID |

---

## Repository structure

```
├── .github/
│   └── workflows/
│       └── compliance.yml        # weekly automation
├── collectors/
│   ├── base.py                   # shared output format
│   ├── collect_cloudtrail.py
│   ├── collect_config.py
│   ├── collect_iam.py
│   ├── collect_securityhub.py
│   └── run_all.py                # runs all four collectors
├── docs/
│   └── setup.md                  # full setup instructions
├── evidence/                     # auto-committed JSON artifacts
├── reports/                      # auto-committed CSV reports
├── controls.yaml                 # evidence → framework control ID mapping
├── generate_report.py            # reads evidence + controls.yaml → CSVs
├── iam_policy_collector_role.json # least-privilege AWS policy for the collector role
└── requirements.txt
```

---

## Authentication

The workflow uses **OpenID Connect (OIDC)** to assume an AWS IAM role — no
long-lived access keys are stored anywhere in GitHub. The `ComplianceCollectorRole`
in AWS is scoped specifically to this repository, and the attached policy is
strictly read-only. This means:

- No credentials to rotate
- No credentials to leak
- The role cannot be assumed by any other repository or principal
- Every session is short-lived and tied to a specific workflow run

This approach satisfies several IAM-related controls in the frameworks this
project targets, including PCI-DSS 8.2.1, SOC 2 CC6.1, and ISO 27001 A.5.16.

---

## Running locally

```bash
# activate venv and install dependencies
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt pyyaml

# configure AWS credentials
aws configure

# collect evidence
cd collectors
python run_all.py --region us-east-1

# generate reports
cd ..
python generate_report.py --evidence-dir evidence --controls controls.yaml --output-dir reports
```

---

## Setup

See [docs/setup.md](docs/setup.md) for full instructions covering AWS
configuration, OIDC role creation, and GitHub secrets setup.
