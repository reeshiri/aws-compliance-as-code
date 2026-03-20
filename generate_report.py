"""
generate_report.py — compliance gap report generator

Reads evidence/*/latest.json and controls.yaml, then writes three CSVs:

  reports/
  ├── 01_summary.csv          — one row per signal, pass/fail, per framework
  ├── 02_control_coverage.csv — one row per framework control, evidence status
  └── 03_findings_detail.csv  — raw findings (users without MFA, stale keys, etc.)

Usage:
    python generate_report.py [--evidence-dir EVIDENCE_DIR] [--controls CONTROLS_YAML]
"""

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml


FRAMEWORKS = ["pci_dss", "soc2", "iso_27001", "iso_42001"]
FRAMEWORK_LABELS = {
    "pci_dss":   "PCI-DSS",
    "soc2":      "SOC 2",
    "iso_27001": "ISO 27001",
    "iso_42001": "ISO 42001",
}

# Signals that carry list values (used for detail rows)
DETAIL_SIGNALS = {
    "mfa_disabled_users": {
        "title": "IAM user with console access but no MFA",
        "evidence_id": "aws_iam_posture",
        "severity": "HIGH",
        "remediation": "Enable MFA for the user in IAM > Users > Security credentials.",
    },
    "stale_keys": {
        "title": "Active access key older than 90 days",
        "evidence_id": "aws_iam_posture",
        "severity": "HIGH",
        "remediation": "Rotate or deactivate the key in IAM > Users > Security credentials.",
    },
    "high_value_failures": {
        "title": "High-value AWS Config rule failure",
        "evidence_id": "aws_config_rules",
        "severity": "HIGH",
        "remediation": "Remediate the failing resources shown in AWS Config console.",
    },
}


def load_evidence(evidence_dir: Path) -> dict:
    """Load all latest.json artifacts keyed by evidence_id."""
    evidence = {}
    for latest in evidence_dir.glob("*/latest.json"):
        evidence_id = latest.parent.name
        try:
            artifact = json.loads(latest.read_text())
            evidence[evidence_id] = artifact
        except json.JSONDecodeError as exc:
            print(f"  [WARN] Could not parse {latest}: {exc}")
    return evidence


def load_controls(controls_path: Path) -> list[dict]:
    with open(controls_path) as f:
        return yaml.safe_load(f)["controls"]


def get_signal_value(artifact: dict, signal: str):
    """Return the value of a compliance_signal from an artifact."""
    if artifact.get("status") == "error":
        return None
    return (artifact.get("data") or {}).get("compliance_signals", {}).get(signal)


def signal_status(value) -> str:
    """Convert a signal value to PASS / FAIL / ERROR."""
    if value is None:
        return "ERROR"
    if isinstance(value, bool):
        return "PASS" if value else "FAIL"
    if isinstance(value, list):
        return "PASS" if len(value) == 0 else "FAIL"
    if isinstance(value, int):
        return "PASS" if value == 0 else "INFO"
    return "UNKNOWN"


def write_summary(controls: list, evidence: dict, out_path: Path, run_at: str):
    """
    01_summary.csv
    One row per control entry. Columns: signal details + pass/fail per framework.
    """
    fieldnames = [
        "evidence_id",
        "signal",
        "description",
        "status",
        "collected_at",
        "aws_account",
    ] + [FRAMEWORK_LABELS[f] for f in FRAMEWORKS]

    rows = []
    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        row = {
            "evidence_id": eid,
            "signal": signal,
            "description": ctrl["description"],
            "status": status,
            "collected_at": artifact.get("collected_at", "N/A"),
            "aws_account": artifact.get("aws_account", "N/A"),
        }

        for fw in FRAMEWORKS:
            control_ids = ctrl.get("frameworks", {}).get(fw, [])
            row[FRAMEWORK_LABELS[fw]] = "; ".join(control_ids) if control_ids else ""

        rows.append(row)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  ✓  {out_path}  ({len(rows)} rows)")


def write_control_coverage(controls: list, evidence: dict, out_path: Path, run_at: str):
    """
    02_control_coverage.csv
    One row per (framework, control_id). Shows which evidence covers it and status.
    """
    # Build a map: (framework, control_id) → list of (signal, status, description)
    coverage: dict[tuple, list] = {}

    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        for fw in FRAMEWORKS:
            for ctrl_id in ctrl.get("frameworks", {}).get(fw, []):
                key = (FRAMEWORK_LABELS[fw], ctrl_id)
                coverage.setdefault(key, [])
                coverage[key].append({
                    "signal": signal,
                    "status": status,
                    "description": ctrl["description"],
                    "evidence_id": eid,
                })

    fieldnames = [
        "framework",
        "control_id",
        "overall_status",
        "evidence_count",
        "passing_signals",
        "failing_signals",
        "evidence_ids",
        "signal_descriptions",
    ]

    rows = []
    for (framework, ctrl_id), entries in sorted(coverage.items()):
        passing = [e for e in entries if e["status"] == "PASS"]
        failing = [e for e in entries if e["status"] in ("FAIL", "ERROR")]

        if failing:
            overall = "FAIL"
        elif passing:
            overall = "PASS"
        else:
            overall = "UNKNOWN"

        rows.append({
            "framework": framework,
            "control_id": ctrl_id,
            "overall_status": overall,
            "evidence_count": len(entries),
            "passing_signals": len(passing),
            "failing_signals": len(failing),
            "evidence_ids": "; ".join(sorted({e["evidence_id"] for e in entries})),
            "signal_descriptions": " | ".join(e["description"] for e in entries),
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    pass_count = sum(1 for r in rows if r["overall_status"] == "PASS")
    fail_count = sum(1 for r in rows if r["overall_status"] == "FAIL")
    print(f"  ✓  {out_path}  ({len(rows)} controls: {pass_count} pass, {fail_count} fail)")


def write_findings_detail(evidence: dict, out_path: Path, run_at: str):
    """
    03_findings_detail.csv
    One row per individual finding — users without MFA, stale keys, Config failures, etc.
    """
    fieldnames = [
        "evidence_id",
        "finding_type",
        "severity",
        "resource",
        "detail",
        "remediation",
        "collected_at",
        "aws_account",
    ]

    rows = []

    for signal_key, meta in DETAIL_SIGNALS.items():
        eid = meta["evidence_id"]
        artifact = evidence.get(eid, {})
        if not artifact or artifact.get("status") == "error":
            continue

        collected_at = artifact.get("collected_at", "N/A")
        aws_account = artifact.get("aws_account", "N/A")
        signals = (artifact.get("data") or {}).get("compliance_signals", {})
        items = signals.get(signal_key, [])

        for item in items:
            if isinstance(item, dict):
                # stale_keys is a list of {"user": ..., "age_days": ...}
                resource = item.get("user") or item.get("resource_id") or str(item)
                detail = "; ".join(f"{k}={v}" for k, v in item.items() if k != "user")
            else:
                resource = str(item)
                detail = ""

            rows.append({
                "evidence_id": eid,
                "finding_type": meta["title"],
                "severity": meta["severity"],
                "resource": resource,
                "detail": detail,
                "remediation": meta["remediation"],
                "collected_at": collected_at,
                "aws_account": aws_account,
            })

    # Also pull Security Hub critical/high findings
    hub_artifact = evidence.get("aws_securityhub_findings", {})
    if hub_artifact and hub_artifact.get("status") != "error":
        hub_data = hub_artifact.get("data") or {}
        collected_at = hub_artifact.get("collected_at", "N/A")
        aws_account = hub_artifact.get("aws_account", "N/A")

        for sev_key in ("critical_findings_sample", "high_findings_sample"):
            for finding in hub_data.get(sev_key, []):
                rows.append({
                    "evidence_id": "aws_securityhub_findings",
                    "finding_type": f"Security Hub {finding.get('severity', '')} finding",
                    "severity": finding.get("severity", "UNKNOWN"),
                    "resource": finding.get("resource_id", "N/A"),
                    "detail": finding.get("title", ""),
                    "remediation": finding.get("remediation") or "See Security Hub console for remediation guidance.",
                    "collected_at": collected_at,
                    "aws_account": aws_account,
                })

        # Config non-compliant resource details
    config_artifact = evidence.get("aws_config_rules", {})
    if config_artifact and config_artifact.get("status") != "error":
        config_data = config_artifact.get("data") or {}
        collected_at = config_artifact.get("collected_at", "N/A")
        aws_account = config_artifact.get("aws_account", "N/A")

        for rule in config_data.get("rules", []):
            if rule.get("compliance_type") != "NON_COMPLIANT":
                continue
            for res in rule.get("failing_resources", []):
                rows.append({
                    "evidence_id": "aws_config_rules",
                    "finding_type": f"Config rule failure: {rule['rule_name']}",
                    "severity": "HIGH" if rule["rule_name"].lower() in
                        {"restricted-ssh", "root-account-mfa-enabled",
                         "s3-bucket-public-read-prohibited", "iam-root-access-key-check"}
                        else "MEDIUM",
                    "resource": res.get("resource_id", "N/A"),
                    "detail": f"type={res.get('resource_type')}; {res.get('annotation') or ''}",
                    "remediation": "Remediate in AWS Config console or correct via IaC.",
                    "collected_at": collected_at,
                    "aws_account": aws_account,
                })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    high = sum(1 for r in rows if r["severity"] in ("CRITICAL", "HIGH"))
    print(f"  ✓  {out_path}  ({len(rows)} findings, {high} high/critical)")


def main():
    parser = argparse.ArgumentParser(description="Generate compliance CSV reports")
    parser.add_argument("--evidence-dir", default="evidence", help="Path to evidence/ folder")
    parser.add_argument("--controls", default="controls.yaml", help="Path to controls.yaml")
    parser.add_argument("--output-dir", default="reports", help="Where to write CSVs")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    controls_path = Path(args.controls)
    output_dir = Path(args.output_dir)
    run_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*56}")
    print(f"  Compliance Report Generator")
    print(f"  run at  : {run_at}")
    print(f"  evidence: {evidence_dir}")
    print(f"  controls: {controls_path}")
    print(f"{'='*56}\n")

    if not evidence_dir.exists():
        print(f"[ERROR] Evidence directory not found: {evidence_dir}")
        print("  Run collectors/run_all.py first.")
        raise SystemExit(1)

    if not controls_path.exists():
        print(f"[ERROR] controls.yaml not found: {controls_path}")
        raise SystemExit(1)

    evidence = load_evidence(evidence_dir)
    controls = load_controls(controls_path)

    print(f"  Loaded {len(evidence)} evidence artifact(s)")
    print(f"  Loaded {len(controls)} control mapping(s)\n")

    write_summary(
        controls, evidence,
        output_dir / "01_summary.csv",
        run_at,
    )
    write_control_coverage(
        controls, evidence,
        output_dir / "02_control_coverage.csv",
        run_at,
    )
    write_findings_detail(
        evidence,
        output_dir / "03_findings_detail.csv",
        run_at,
    )

    print(f"\n  Reports written to {output_dir}/")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
