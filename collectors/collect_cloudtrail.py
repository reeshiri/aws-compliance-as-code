"""
collect_cloudtrail.py — CloudTrail audit log evidence collector

Evidence ID : aws_cloudtrail_logs
IAM needed  : cloudtrail:LookupEvents, cloudtrail:DescribeTrails,
              cloudtrail:GetTrailStatus

Controls satisfied:
  PCI-DSS   10.2.1, 10.2.2, 10.3.x, 10.7.1  (audit trail requirements)
  SOC 2     CC7.2                              (anomaly / event monitoring)
  ISO 27001 A.8.15                             (logging)
  ISO 42001 6.5.1                              (AI system activity logs)
"""

import boto3
from datetime import datetime, timezone, timedelta
from base import BaseCollector


LOOKBACK_DAYS = int(90)  # PCI-DSS requires 90-day log retention proof


class CloudTrailCollector(BaseCollector):

    def collect(self) -> dict:
        ct = self.session.client("cloudtrail")

        # 1. Trail configuration — proves trails exist and are enabled
        trails_raw = ct.describe_trails(includeShadowTrails=False)["trailList"]
        trails = []
        for trail in trails_raw:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            trails.append({
                "name": trail.get("Name"),
                "arn": trail.get("TrailARN"),
                "s3_bucket": trail.get("S3BucketName"),
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
                "log_file_validation": trail.get("LogFileValidationEnabled", False),
                "is_logging": status.get("IsLogging", False),
                "latest_delivery_time": status.get("LatestDeliveryTime"),
            })

        # 2. Sample of recent management events — proves logging is active
        #    (we pull metadata only, not full event payloads, to keep artifact small)
        start = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
        paginator = ct.get_paginator("lookup_events")

        event_summary: dict[str, int] = {}  # event_name → count
        total_events = 0
        sample_events = []

        for page in paginator.paginate(
            StartTime=start,
            LookupAttributes=[
                {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
            ],
            PaginationConfig={"MaxItems": 1000},
        ):
            for ev in page.get("Events", []):
                name = ev.get("EventName", "unknown")
                event_summary[name] = event_summary.get(name, 0) + 1
                total_events += 1
                if len(sample_events) < 10:
                    sample_events.append({
                        "event_id": ev.get("EventId"),
                        "event_name": name,
                        "event_time": ev.get("EventTime"),
                        "username": ev.get("Username"),
                        "source_ip": ev.get("CloudTrailEvent", "{}"),
                    })

        return {
            "lookback_days": LOOKBACK_DAYS,
            "trail_count": len(trails),
            "trails": trails,
            "write_event_count_sampled": total_events,
            "top_event_types": sorted(
                event_summary.items(), key=lambda x: x[1], reverse=True
            )[:20],
            "sample_recent_events": sample_events,
            "compliance_signals": {
                "trails_enabled": all(t["is_logging"] for t in trails),
                "multi_region_coverage": any(t["is_multi_region"] for t in trails),
                "log_validation_enabled": all(t["log_file_validation"] for t in trails),
                "active_logging_confirmed": total_events > 0,
            },
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect CloudTrail evidence")
    parser.add_argument("--profile", default=None, help="AWS profile name")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result = CloudTrailCollector("aws_cloudtrail_logs", session).run()

    signals = result.get("data", {}).get("compliance_signals", {})
    for k, v in signals.items():
        icon = "✓" if v else "✗"
        print(f"  {icon}  {k}")
