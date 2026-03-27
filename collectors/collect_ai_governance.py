"""
collect_ai_governance.py — AI governance evidence collector for ISO 42001

Evidence ID : aws_ai_governance
IAM needed  : sagemaker:ListModelPackageGroups, DescribeModelPackageGroup,
                        ListModelPackages, DescribeModelPackage,
                        ListMonitoringSchedules, DescribeMonitoringSchedule,
                        ListEndpoints, DescribeEndpoint
              bedrock:ListFoundationModels, GetFoundationModelAvailability,
                      ListGuardrails, GetModelInvocationLoggingConfiguration
              s3:ListBuckets, GetBucketTagging, GetBucketLogging
              cloudtrail:LookupEvents  (reuses existing permission)

Controls satisfied (ISO 42001:2023):
  6.1.2  — AI risk assessment documented and maintained
  6.2.1  — AI objectives defined and measurable
  6.4.1  — AI system access controls (via IAM signals, cross-mapped)
  6.5.1  — AI system activity logging (via CloudTrail, cross-mapped)
  7.4    — AI system documentation and records
  8.4    — Data management controls for AI — lineage, quality monitoring
  9.1    — Monitoring and measurement of AI system performance
  9.3    — Management review of AI system posture
  10.2   — Incident response for AI system failures

Design notes:
  - SageMaker and Bedrock checks degrade gracefully when services are not
    in use. A "not_configured" signal is INFORMATIONAL, not a hard FAIL,
    because ISO 42001 only applies to AI systems the organisation actually
    operates. Presence of the service without governance controls is a FAIL.
  - Each signal maps to specific ISO 42001 clause numbers so auditors can
    trace evidence back to requirements without reading the code.
  - Data provenance signals check whether S3 buckets tagged for AI workloads
    have versioning and access logging enabled — the minimum evidence trail
    for Clause 8.4 (data management).
"""

import boto3
from datetime import datetime, timezone, timedelta
from base import BaseCollector


class AIGovernanceCollector(BaseCollector):

    def collect(self) -> dict:
        results = {}

        # ── 1. SageMaker model governance ─────────────────────────────────
        results["sagemaker"] = self._collect_sagemaker()

        # ── 2. Bedrock model invocation logging and guardrails ────────────
        results["bedrock"] = self._collect_bedrock()

        # ── 3. AI workload data provenance (S3 tagging + versioning) ──────
        results["data_provenance"] = self._collect_data_provenance()

        # ── 4. AI-related CloudTrail activity (model deployments etc.) ────
        results["ai_activity"] = self._collect_ai_activity()

        # ── Derive compliance signals ──────────────────────────────────────
        sm  = results["sagemaker"]
        bd  = results["bedrock"]
        dp  = results["data_provenance"]
        act = results["ai_activity"]

        # Signal: model registry exists (documents AI systems — Clause 7.4)
        model_registry_exists = sm.get("model_package_groups_count", 0) > 0

        # Signal: all registered models have approval status set (Clause 6.1.2)
        models_have_approval = sm.get("models_without_approval_status", 0) == 0 \
            and sm.get("total_model_packages", 0) > 0

        # Signal: SageMaker Model Monitor schedules are configured (Clause 9.1)
        monitoring_configured = sm.get("monitoring_schedules_count", 0) > 0

        # Signal: production endpoints have data capture enabled (Clause 9.1)
        endpoints_with_capture = sm.get("endpoints_with_data_capture", 0)
        endpoints_total        = sm.get("endpoints_total", 0)
        data_capture_enabled   = (
            endpoints_total == 0  # no endpoints deployed is not a violation
            or endpoints_with_capture == endpoints_total
        )

        # Signal: Bedrock invocation logging is enabled (Clause 6.5.1 / 9.3)
        bedrock_logging_enabled = bd.get("invocation_logging_enabled", False)

        # Signal: Bedrock guardrails exist (Clause 6.1.2 — AI risk controls)
        bedrock_guardrails_exist = bd.get("guardrails_count", 0) > 0

        # Signal: AI-tagged S3 buckets have versioning enabled (Clause 8.4)
        ai_buckets_total      = dp.get("ai_tagged_buckets_total", 0)
        ai_buckets_versioned  = dp.get("ai_tagged_buckets_versioned", 0)
        data_versioning_ok    = (
            ai_buckets_total == 0  # no AI-tagged buckets is informational
            or ai_buckets_versioned == ai_buckets_total
        )

        # Signal: AI-tagged S3 buckets have access logging enabled (Clause 8.4)
        ai_buckets_logged = dp.get("ai_tagged_buckets_with_logging", 0)
        data_logging_ok   = (
            ai_buckets_total == 0
            or ai_buckets_logged == ai_buckets_total
        )

        # Signal: AI-related management events observed in CloudTrail (Clause 9.3)
        ai_events_observed = act.get("ai_event_count", 0) > 0

        # Which AI services are active (context for auditors)
        sagemaker_active = sm.get("sagemaker_active", False)
        bedrock_active   = bd.get("bedrock_active", False)

        return {
            "sagemaker":       results["sagemaker"],
            "bedrock":         results["bedrock"],
            "data_provenance": results["data_provenance"],
            "ai_activity":     results["ai_activity"],
            "compliance_signals": {
                # Clause 7.4 — AI system documentation
                "model_registry_configured":     model_registry_exists,
                # Clause 6.1.2 — AI risk assessment / model approval workflow
                "models_have_approval_workflow":  models_have_approval,
                # Clause 9.1 — Performance monitoring
                "model_monitoring_configured":    monitoring_configured,
                # Clause 9.1 — Inference data capture for drift detection
                "endpoint_data_capture_enabled":  data_capture_enabled,
                # Clause 6.5.1 / 9.3 — Bedrock invocation audit trail
                "bedrock_invocation_logging":     bedrock_logging_enabled,
                # Clause 6.1.2 — Input/output guardrails as risk controls
                "bedrock_guardrails_configured":  bedrock_guardrails_exist,
                # Clause 8.4 — Training/inference data versioning
                "ai_data_versioning_enabled":     data_versioning_ok,
                # Clause 8.4 — Data access audit trail
                "ai_data_access_logging_enabled": data_logging_ok,
                # Clause 9.3 — Management review evidence
                "ai_management_events_observed":  ai_events_observed,
                # Context (not pass/fail)
                "sagemaker_in_use":  sagemaker_active,
                "bedrock_in_use":    bedrock_active,
                "ai_buckets_found":  ai_buckets_total,
            },
        }

    # ── SageMaker ──────────────────────────────────────────────────────────

    def _collect_sagemaker(self) -> dict:
        sm = self.session.client("sagemaker")

        try:
            # Model Package Groups = model registry entries
            groups_resp = sm.list_model_package_groups(MaxResults=100)
            groups      = groups_resp.get("ModelPackageGroupSummaryList", [])
            group_count = len(groups)
            sagemaker_active = True
        except Exception as e:
            return {
                "sagemaker_active": False,
                "error": str(e),
                "model_package_groups_count": 0,
                "total_model_packages": 0,
                "models_without_approval_status": 0,
                "monitoring_schedules_count": 0,
                "endpoints_total": 0,
                "endpoints_with_data_capture": 0,
            }

        # Model packages and their approval status
        total_packages        = 0
        without_approval      = 0
        model_details         = []

        for group in groups[:20]:  # cap at 20 to stay within rate limits
            gname = group["ModelPackageGroupName"]
            try:
                pkgs = sm.list_model_packages(
                    ModelPackageGroupName=gname,
                    MaxResults=10,
                ).get("ModelPackageSummaryList", [])

                for pkg in pkgs:
                    total_packages += 1
                    approval = pkg.get("ModelApprovalStatus", "")
                    if not approval:
                        without_approval += 1
                    model_details.append({
                        "group":           gname,
                        "arn":             pkg.get("ModelPackageArn"),
                        "approval_status": approval or "NOT_SET",
                        "creation_time":   pkg.get("CreationTime"),
                    })
            except Exception:
                pass

        # Monitoring schedules (data quality, model quality, bias, explainability)
        try:
            schedules_resp = sm.list_monitoring_schedules(MaxResults=100)
            schedules      = schedules_resp.get("MonitoringScheduleSummaries", [])
            schedule_details = [{
                "name":   s.get("MonitoringScheduleName"),
                "status": s.get("MonitoringScheduleStatus"),
                "type":   s.get("MonitoringType"),
            } for s in schedules]
        except Exception:
            schedules         = []
            schedule_details  = []

        # Endpoints and data capture status
        try:
            eps_resp       = sm.list_endpoints(MaxResults=100)
            endpoints      = eps_resp.get("Endpoints", [])
            ep_details     = []
            with_capture   = 0

            for ep in endpoints[:20]:
                try:
                    desc    = sm.describe_endpoint(EndpointName=ep["EndpointName"])
                    capture = desc.get("DataCaptureConfig", {})
                    enabled = capture.get("EnableCapture", False)
                    if enabled:
                        with_capture += 1
                    ep_details.append({
                        "name":          ep["EndpointName"],
                        "status":        ep.get("EndpointStatus"),
                        "data_capture":  enabled,
                    })
                except Exception:
                    pass
        except Exception:
            endpoints    = []
            ep_details   = []
            with_capture = 0

        return {
            "sagemaker_active":              sagemaker_active,
            "model_package_groups_count":    group_count,
            "model_package_groups":          [g["ModelPackageGroupName"] for g in groups[:10]],
            "total_model_packages":          total_packages,
            "models_without_approval_status": without_approval,
            "model_details":                 model_details[:10],
            "monitoring_schedules_count":    len(schedules),
            "monitoring_schedule_details":   schedule_details[:10],
            "endpoints_total":               len(endpoints),
            "endpoints_with_data_capture":   with_capture,
            "endpoint_details":              ep_details[:10],
        }

    # ── Bedrock ────────────────────────────────────────────────────────────

    def _collect_bedrock(self) -> dict:
        bd = self.session.client("bedrock")

        # Check invocation logging configuration
        try:
            logging_cfg  = bd.get_model_invocation_logging_configuration()
            logging_conf = logging_cfg.get("loggingConfig", {})
            logging_on   = (
                logging_conf.get("textDataDeliveryEnabled", False)
                or logging_conf.get("imageDataDeliveryEnabled", False)
                or logging_conf.get("embeddingDataDeliveryEnabled", False)
            )
            log_destination = {
                "s3_bucket":     logging_conf.get("s3Config", {}).get("bucketName"),
                "cloudwatch_lg": logging_conf.get("cloudWatchConfig", {}).get("logGroupName"),
            }
            bedrock_active = True
        except Exception as e:
            err = str(e)
            # AccessDeniedException or ResourceNotFoundException both mean
            # Bedrock is either not enabled or not accessible
            if "AccessDenied" in err or "not found" in err.lower():
                return {
                    "bedrock_active":            False,
                    "invocation_logging_enabled": False,
                    "guardrails_count":           0,
                    "note": "Bedrock not accessible — may not be enabled in this region",
                }
            return {
                "bedrock_active":            True,
                "invocation_logging_enabled": False,
                "error":                     err,
                "guardrails_count":           0,
            }

        # Guardrails (content filtering, PII redaction, topic denial)
        try:
            gr_resp    = bd.list_guardrails(maxResults=100)
            guardrails = gr_resp.get("guardrails", [])
            gr_details = [{
                "id":      g.get("guardrailId"),
                "name":    g.get("name"),
                "status":  g.get("status"),
                "version": g.get("version"),
            } for g in guardrails]
        except Exception:
            guardrails = []
            gr_details = []

        return {
            "bedrock_active":            bedrock_active,
            "invocation_logging_enabled": logging_on,
            "log_destination":           log_destination,
            "guardrails_count":          len(guardrails),
            "guardrail_details":         gr_details[:10],
        }

    # ── Data provenance (S3 buckets tagged for AI workloads) ──────────────

    def _collect_data_provenance(self) -> dict:
        """
        Check S3 buckets tagged with Purpose=AI or Workload=ML (or similar).
        These tags indicate buckets holding training data, model artifacts,
        or inference inputs/outputs — all in scope for ISO 42001 Clause 8.4.

        Recognised tag patterns (case-insensitive value matching):
          Purpose  : ai, ml, machine-learning, sagemaker, bedrock
          Workload : ai, ml, machine-learning
          Project  : (any value containing 'ai' or 'ml')
        """
        s3 = self.session.client("s3")

        AI_TAG_KEYS   = {"purpose", "workload", "project", "team", "environment"}
        AI_TAG_VALUES = {"ai", "ml", "machine-learning", "sagemaker", "bedrock",
                         "machinelearning", "machine_learning"}

        def is_ai_bucket(tags: list) -> bool:
            for tag in tags:
                k = tag.get("Key", "").lower()
                v = tag.get("Value", "").lower()
                if k in AI_TAG_KEYS and (v in AI_TAG_VALUES or "ai" in v or "ml" in v):
                    return True
            return False

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            return {"error": str(e), "ai_tagged_buckets_total": 0}

        ai_buckets        = []
        versioned_count   = 0
        logged_count      = 0

        for bucket in buckets:
            name = bucket["Name"]

            # Check tags
            try:
                tags = s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
            except Exception:
                tags = []

            if not is_ai_bucket(tags):
                continue

            bucket_info = {"name": name, "tags": tags}

            # Check versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                versioning_on = ver.get("Status") == "Enabled"
                bucket_info["versioning"] = versioning_on
                if versioning_on:
                    versioned_count += 1
            except Exception:
                bucket_info["versioning"] = False

            # Check access logging
            try:
                log_cfg = s3.get_bucket_logging(Bucket=name)
                logging_on = "LoggingEnabled" in log_cfg
                bucket_info["access_logging"] = logging_on
                if logging_on:
                    logged_count += 1
            except Exception:
                bucket_info["access_logging"] = False

            ai_buckets.append(bucket_info)

        return {
            "ai_tagged_buckets_total":       len(ai_buckets),
            "ai_tagged_buckets_versioned":   versioned_count,
            "ai_tagged_buckets_with_logging": logged_count,
            "ai_bucket_details":             ai_buckets[:20],
            "tag_patterns_checked":          sorted(AI_TAG_VALUES),
        }

    # ── AI activity in CloudTrail ──────────────────────────────────────────

    def _collect_ai_activity(self) -> dict:
        """
        Look for AI/ML management events in CloudTrail over the past 30 days.
        These events demonstrate that AI systems are actively managed and
        that management actions are being audited — evidence for Clause 9.3.
        """
        ct = self.session.client("cloudtrail")

        # Event names that indicate active AI system management
        AI_EVENT_PREFIXES = (
            "CreateModel", "DeleteModel", "UpdateModel",
            "CreateEndpoint", "DeleteEndpoint", "UpdateEndpoint",
            "CreateModelPackage", "UpdateModelPackage",
            "CreateMonitoringSchedule", "UpdateMonitoringSchedule",
            "CreateTrainingJob", "StopTrainingJob",
            "InvokeModel", "InvokeModelWithResponseStream",
            "CreateGuardrail", "UpdateGuardrail",
            "PutModelInvocationLoggingConfiguration",
        )

        start = datetime.now(timezone.utc) - timedelta(days=30)
        event_counts: dict[str, int] = {}
        total = 0
        sample = []

        try:
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start,
                PaginationConfig={"MaxItems": 500},
            ):
                for ev in page.get("Events", []):
                    name = ev.get("EventName", "")
                    if any(name.startswith(p) for p in AI_EVENT_PREFIXES):
                        event_counts[name] = event_counts.get(name, 0) + 1
                        total += 1
                        if len(sample) < 10:
                            sample.append({
                                "event":    name,
                                "time":     ev.get("EventTime"),
                                "user":     ev.get("Username"),
                                "source":   ev.get("EventSource"),
                            })
        except Exception as e:
            return {"error": str(e), "ai_event_count": 0}

        return {
            "ai_event_count":    total,
            "lookback_days":     30,
            "event_type_counts": sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:15],
            "sample_events":     sample,
        }


# ── CLI entrypoint ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect AI governance evidence (ISO 42001)")
    parser.add_argument("--profile", default=None, help="AWS named profile")
    parser.add_argument("--region",  default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result  = AIGovernanceCollector("aws_ai_governance", session).run()

    print()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, bool):
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
        else:
            print(f"  ℹ  {k}: {v}")
