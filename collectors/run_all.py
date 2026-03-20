"""
run_all.py — run every collector and print a summary

Usage:
    python run_all.py [--profile PROFILE] [--region REGION]

The EVIDENCE_DIR environment variable controls where artifacts are written.
Defaults to ./evidence relative to the working directory.
"""

import argparse
import sys
import boto3

from collect_cloudtrail import CloudTrailCollector
from collect_config import ConfigCollector
from collect_iam import IAMCollector
from collect_securityhub import SecurityHubCollector

COLLECTORS = [
    ("aws_cloudtrail_logs",      CloudTrailCollector),
    ("aws_config_rules",         ConfigCollector),
    ("aws_iam_posture",          IAMCollector),
    ("aws_securityhub_findings", SecurityHubCollector),
]


def main():
    parser = argparse.ArgumentParser(description="Run all compliance collectors")
    parser.add_argument("--profile", default=None, help="AWS named profile")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    print(f"\n{'='*56}")
    print(f"  AWS Compliance Collectors")
    print(f"  account : {session.client('sts').get_caller_identity()['Account']}")
    print(f"  region  : {args.region}")
    print(f"{'='*56}\n")

    results = {}
    errors = []

    for evidence_id, CollectorClass in COLLECTORS:
        print(f"── {evidence_id}")
        try:
            artifact = CollectorClass(evidence_id, session).run()
            results[evidence_id] = artifact

            signals = (artifact.get("data") or {}).get("compliance_signals", {})
            for k, v in signals.items():
                if isinstance(v, list):
                    tag = "ℹ" if not v else "⚠"
                    label = "(none)" if not v else ", ".join(str(x) for x in v[:3])
                    print(f"     {tag}  {k}: {label}")
                elif isinstance(v, int):
                    print(f"     ℹ  {k}: {v}")
                else:
                    icon = "✓" if v else "✗"
                    print(f"     {icon}  {k}")

            if artifact["status"] == "error":
                errors.append(evidence_id)
        except Exception as exc:
            print(f"     ✗  COLLECTOR CRASHED: {exc}")
            errors.append(evidence_id)

        print()

    # Summary
    total = len(COLLECTORS)
    ok = total - len(errors)
    print(f"{'='*56}")
    print(f"  {ok}/{total} collectors succeeded")
    if errors:
        print(f"  Failed: {', '.join(errors)}")
    print(f"  Evidence written to: ./evidence/")
    print(f"{'='*56}\n")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
