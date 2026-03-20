"""
collect_securityhub.py — Security Hub findings evidence collector

Evidence ID : aws_securityhub_findings
IAM needed  : securityhub:GetFindings, securityhub:DescribeHub,
              securityhub:GetEnabledStandards

Controls satisfied:
  PCI-DSS   6.3.3, 11.3.x  (vulnerability management / pen test)
  SOC 2     CC7.1, CC7.2   (threat detection / anomaly monitoring)
  ISO 27001 A.8.8           (management of technical vulnerabilities)
  ISO 42001 6.6.2           (AI system threat monitoring)
"""

import boto3
from collections import defaultdict
from base import BaseCollector


# Severity levels in descending order
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

# Standards we care about — used to confirm they're enabled
EXPECTED_STANDARDS = {
    "pci-dss":    "standards/pci-dss",
    "cis":        "standards/cis-aws-foundations-benchmark",
    "aws-fsbp":   "standards/aws-foundational-security-best-practices",
}


class SecurityHubCollector(BaseCollector):

    def collect(self) -> dict:
        hub = self.session.client("securityhub")

        # --- Hub enabled check ---
        try:
            hub.describe_hub()
            hub_enabled = True
        except hub.exceptions.InvalidAccessException:
            hub_enabled = False
            return {
                "hub_enabled": False,
                "compliance_signals": {
                    "security_hub_enabled": False,
                    "no_critical_findings": False,
                    "no_high_findings": False,
                },
            }

        # --- Enabled standards ---
        standards_resp = hub.get_enabled_standards()
        enabled_standards = []
        for std in standards_resp.get("StandardsSubscriptions", []):
            arn = std.get("StandardsArn", "")
            enabled_standards.append({
                "arn": arn,
                "status": std.get("StandardsStatus"),
                "name": arn.split("/")[-2] if "/" in arn else arn,
            })

        enabled_arns = " ".join(s["arn"] for s in enabled_standards).lower()
        standards_signals = {
            key: (slug in enabled_arns)
            for key, slug in EXPECTED_STANDARDS.items()
        }

        # --- Active findings (non-archived, non-suppressed) ---
        paginator = hub.get_paginator("get_findings")
        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW", "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
        }

        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        critical_sample = []
        high_sample = []
        total_findings = 0

        for page in paginator.paginate(
            Filters=filters,
            PaginationConfig={"MaxItems": 2000},
        ):
            for finding in page.get("Findings", []):
                total_findings += 1
                severity = (
                    finding.get("Severity", {}).get("Label", "UNKNOWN").upper()
                )
                severity_counts[severity] += 1

                # Type bucketing (first type label only)
                types = finding.get("Types", ["Unknown"])
                type_counts[types[0]] += 1

                # Keep a small sample of critical and high for the artifact
                summary = {
                    "id": finding.get("Id"),
                    "title": finding.get("Title"),
                    "severity": severity,
                    "product": finding.get("ProductName"),
                    "resource_type": (
                        finding.get("Resources", [{}])[0].get("Type")
                        if finding.get("Resources") else None
                    ),
                    "resource_id": (
                        finding.get("Resources", [{}])[0].get("Id")
                        if finding.get("Resources") else None
                    ),
                    "updated_at": finding.get("UpdatedAt"),
                    "remediation": (
                        finding.get("Remediation", {})
                        .get("Recommendation", {})
                        .get("Text")
                    ),
                }
                if severity == "CRITICAL" and len(critical_sample) < 10:
                    critical_sample.append(summary)
                elif severity == "HIGH" and len(high_sample) < 10:
                    high_sample.append(summary)

        return {
            "hub_enabled": hub_enabled,
            "enabled_standards": enabled_standards,
            "total_active_findings": total_findings,
            "findings_by_severity": dict(severity_counts),
            "top_finding_types": sorted(
                type_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "critical_findings_sample": critical_sample,
            "high_findings_sample": high_sample,
            "compliance_signals": {
                "security_hub_enabled": hub_enabled,
                "pci_dss_standard_enabled": standards_signals.get("pci-dss", False),
                "cis_standard_enabled": standards_signals.get("cis", False),
                "aws_fsbp_standard_enabled": standards_signals.get("aws-fsbp", False),
                "no_critical_findings": severity_counts.get("CRITICAL", 0) == 0,
                "no_high_findings": severity_counts.get("HIGH", 0) == 0,
                "critical_finding_count": severity_counts.get("CRITICAL", 0),
                "high_finding_count": severity_counts.get("HIGH", 0),
            },
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect Security Hub evidence")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result = SecurityHubCollector("aws_securityhub_findings", session).run()

    signals = result.get("data", {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, (list, int)) or isinstance(v, int):
            print(f"  ℹ  {k}: {v}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
