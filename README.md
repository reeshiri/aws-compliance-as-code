# AWS Compliance as Code

Automated compliance evidence collection for AWS, mapped to four frameworks
simultaneously: PCI-DSS v4, SOC 2 Type II, ISO 27001:2022, and ISO 42001:2023.

Instead of collecting evidence manually before an audit, this runs every week
on a schedule. It queries your AWS environment, evaluates each control, commits
the results to git as a timestamped audit trail, and opens a GitHub Issue for
every failing control with the affected resource and a remediation step.

The output is three CSV reports, a stakeholder-ready HTML dashboard, and a
formatted Word audit report -- all generated automatically from the same
evidence collection run.

A second workflow runs every Monday and checks the official source for each framework for version changes, using RSS monitoring for PCI-DSS and NIST CSF and hash-based fingerprinting for ISO 27001, SOC 2, and ISO 42001. When a change is detected it opens a GitHub Issue with a review checklist. Every run is saved to `evidence/framework_versions/` as a timestamped artifact. See [docs/Framework_Version_Governance_Procedure.docx](docs/Framework_Version_Governance_Procedure.docx) for the full procedure.


## Sample outputs

![Compliance Dashboard](docs/screenshots/dashboard.png)
![Compliance Dashboard](docs/screenshots/compliance_dashboard_sample.pdf)
![Audit Report](docs/screenshots/audit_report_sample.pdf)


## Compliance documents

| Document | Description |
|---|---|
| [NIST CSF 2.0 Crosswalk](docs/NIST_CSF2_Crosswalk_GCP.docx) | Maps all evidence signals to NIST CSF 2.0 subcategories |
