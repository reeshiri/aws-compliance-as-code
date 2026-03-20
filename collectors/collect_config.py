"""
collect_config.py — AWS Config rules compliance evidence collector

Evidence ID : aws_config_rules
IAM needed  : config:DescribeConfigRules,
              config:DescribeComplianceByConfigRule,
              config:GetComplianceDetailsByConfigRule

Controls satisfied:
  PCI-DSS   2.2.1, 6.3.3  (system hardening / known vuln)
  SOC 2     CC6.6, CC7.1  (vulnerability / configuration management)
  ISO 27001 A.8.9          (configuration management)
  ISO 42001 6.6.1          (AI infrastructure configuration)
"""

import boto3
from base import BaseCollector


# Config rules that carry the most compliance weight — used to flag
# specifically non-compliant rules in the summary signals block.
HIGH_VALUE_RULES = {
    "restricted-ssh",
    "restricted-common-ports",
    "s3-bucket-public-read-prohibited",
    "s3-bucket-public-write-prohibited",
    "s3-bucket-ssl-requests-only",
    "root-account-mfa-enabled",
    "iam-password-policy",
    "iam-user-mfa-enabled",
    "cloud-trail-enabled",
    "cloudtrail-s3-dataevents-enabled",
    "guardduty-enabled-centralized",
    "securityhub-enabled",
    "vpc-flow-logs-enabled",
    "encrypted-volumes",
    "rds-storage-encrypted",
    "kms-cmk-not-scheduled-for-deletion",
    "access-keys-rotated",
    "iam-root-access-key-check",
}


class ConfigCollector(BaseCollector):

    def collect(self) -> dict:
        cfg = self.session.client("config")
        paginator = cfg.get_paginator("describe_config_rules")

        rules = []
        compliant_count = 0
        non_compliant_count = 0
        not_applicable_count = 0
        high_value_failures = []

        for page in paginator.paginate():
            for rule in page.get("ConfigRules", []):
                rule_name = rule["ConfigRuleName"]
                rule_arn = rule.get("ConfigRuleArn", "")

                # Get compliance status for this rule
                comp = cfg.describe_compliance_by_config_rule(
                    ConfigRuleNames=[rule_name]
                )
                compliance_items = comp.get("ComplianceByConfigRules", [])
                compliance_type = (
                    compliance_items[0].get("Compliance", {}).get("ComplianceType", "UNKNOWN")
                    if compliance_items else "UNKNOWN"
                )

                # For non-compliant rules, fetch failing resource details (up to 10)
                failing_resources = []
                if compliance_type == "NON_COMPLIANT":
                    non_compliant_count += 1
                    detail_paginator = cfg.get_paginator(
                        "get_compliance_details_by_config_rule"
                    )
                    for dp in detail_paginator.paginate(
                        ConfigRuleName=rule_name,
                        ComplianceTypes=["NON_COMPLIANT"],
                        PaginationConfig={"MaxItems": 10},
                    ):
                        for res in dp.get("EvaluationResults", []):
                            qual = res.get("EvaluationResultIdentifier", {})
                            rid = qual.get("EvaluationResultQualifier", {})
                            failing_resources.append({
                                "resource_type": rid.get("ResourceType"),
                                "resource_id": rid.get("ResourceId"),
                                "annotation": res.get("Annotation"),
                            })

                    # Track high-value rule failures separately
                    if rule_name.lower() in HIGH_VALUE_RULES or any(
                        hvr in rule_name.lower() for hvr in HIGH_VALUE_RULES
                    ):
                        high_value_failures.append(rule_name)

                elif compliance_type == "COMPLIANT":
                    compliant_count += 1
                elif compliance_type == "NOT_APPLICABLE":
                    not_applicable_count += 1

                rules.append({
                    "rule_name": rule_name,
                    "rule_arn": rule_arn,
                    "source": rule.get("Source", {}).get("Owner"),
                    "compliance_type": compliance_type,
                    "failing_resources": failing_resources,
                })

        total_evaluated = compliant_count + non_compliant_count
        compliance_pct = (
            round(compliant_count / total_evaluated * 100, 1)
            if total_evaluated > 0 else 0
        )

        return {
            "rule_count": len(rules),
            "compliant": compliant_count,
            "non_compliant": non_compliant_count,
            "not_applicable": not_applicable_count,
            "compliance_percentage": compliance_pct,
            "rules": rules,
            "compliance_signals": {
                "all_rules_compliant": non_compliant_count == 0,
                "compliance_rate_above_90pct": compliance_pct >= 90,
                "no_high_value_rule_failures": len(high_value_failures) == 0,
                "high_value_failures": high_value_failures,
                "rules_evaluated_count": total_evaluated,
            },
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect AWS Config evidence")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result = ConfigCollector("aws_config_rules", session).run()

    signals = result.get("data", {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            print(f"  ℹ  {k}: {v if v else '(none)'}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
