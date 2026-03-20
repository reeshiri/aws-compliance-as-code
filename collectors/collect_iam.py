"""
collect_iam.py — IAM posture evidence collector

Evidence ID : aws_iam_posture
IAM needed  : iam:GetAccountPasswordPolicy, iam:GetAccountSummary,
              iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys,
              iam:ListRoles, iam:ListPolicies, iam:GenerateCredentialReport,
              iam:GetCredentialReport

Controls satisfied:
  PCI-DSS   7.1–7.3  (least privilege / access control)
             8.2–8.6  (user ID / password / MFA requirements)
  SOC 2     CC6.1, CC6.2  (logical access / provisioning)
  ISO 27001 A.5.15, A.5.18  (access control / access rights review)
  ISO 42001 6.4.1           (AI system access controls)
"""

import boto3
import csv
import io
import time
from base import BaseCollector


class IAMCollector(BaseCollector):

    def collect(self) -> dict:
        iam = self.session.client("iam")

        # --- Password policy ---
        try:
            pw_policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            pw_policy = None

        # --- Account summary (high-level counts) ---
        summary = iam.get_account_summary()["SummaryMap"]

        # --- Credential report (covers all users in one API call) ---
        cred_report = self._get_credential_report(iam)

        # Parse credential report into per-user signals
        users_summary = []
        root_signals = {}
        mfa_disabled_users = []
        active_key_older_than_90d = []
        console_no_mfa = []

        for row in cred_report:
            username = row.get("user", "")

            if username == "<root_account>":
                root_signals = {
                    "root_mfa_active": row.get("mfa_active") == "true",
                    "root_access_key_1_active": row.get("access_key_1_active") == "true",
                    "root_access_key_2_active": row.get("access_key_2_active") == "true",
                }
                continue

            has_console = row.get("password_enabled") == "true"
            mfa_active = row.get("mfa_active") == "true"
            key1_active = row.get("access_key_1_active") == "true"
            key2_active = row.get("access_key_2_active") == "true"
            key1_last_rotated = row.get("access_key_1_last_rotated", "N/A")
            key2_last_rotated = row.get("access_key_2_last_rotated", "N/A")

            if has_console and not mfa_active:
                mfa_disabled_users.append(username)
                console_no_mfa.append(username)

            # Flag keys not rotated in 90 days
            for rotated, active in [
                (key1_last_rotated, key1_active),
                (key2_last_rotated, key2_active),
            ]:
                if active and rotated not in ("N/A", "not_supported"):
                    try:
                        from datetime import datetime, timezone
                        rotated_dt = datetime.fromisoformat(
                            rotated.replace("Z", "+00:00")
                        )
                        age_days = (
                            datetime.now(timezone.utc) - rotated_dt
                        ).days
                        if age_days > 90:
                            active_key_older_than_90d.append(
                                {"user": username, "age_days": age_days}
                            )
                    except ValueError:
                        pass

            users_summary.append({
                "username": username,
                "has_console_access": has_console,
                "mfa_active": mfa_active,
                "access_key_1_active": key1_active,
                "access_key_2_active": key2_active,
                "key1_last_rotated": key1_last_rotated,
                "key2_last_rotated": key2_last_rotated,
                "password_last_used": row.get("password_last_used"),
            })

        # --- Password policy signals ---
        pw_signals = {}
        if pw_policy:
            pw_signals = {
                "min_length_gte_8": pw_policy.get("MinimumPasswordLength", 0) >= 8,
                "requires_uppercase": pw_policy.get("RequireUppercaseCharacters", False),
                "requires_lowercase": pw_policy.get("RequireLowercaseCharacters", False),
                "requires_numbers": pw_policy.get("RequireNumbers", False),
                "requires_symbols": pw_policy.get("RequireSymbols", False),
                "max_age_lte_90": pw_policy.get("MaxPasswordAge", 999) <= 90,
                "reuse_prevention_gte_5": pw_policy.get("PasswordReusePrevention", 0) >= 5,
            }
        else:
            # No policy means all are false
            pw_signals = {k: False for k in [
                "min_length_gte_8", "requires_uppercase", "requires_lowercase",
                "requires_numbers", "requires_symbols",
                "max_age_lte_90", "reuse_prevention_gte_5",
            ]}

        return {
            "account_summary": {
                "users": summary.get("Users", 0),
                "roles": summary.get("Roles", 0),
                "groups": summary.get("Groups", 0),
                "policies": summary.get("Policies", 0),
                "mfa_devices": summary.get("MFADevices", 0),
            },
            "password_policy": pw_policy,
            "password_policy_signals": pw_signals,
            "root_signals": root_signals,
            "users": users_summary,
            "compliance_signals": {
                "root_mfa_enabled": root_signals.get("root_mfa_active", False),
                "root_has_no_access_keys": (
                    not root_signals.get("root_access_key_1_active", True)
                    and not root_signals.get("root_access_key_2_active", True)
                ),
                "all_console_users_have_mfa": len(mfa_disabled_users) == 0,
                "no_stale_access_keys_over_90d": len(active_key_older_than_90d) == 0,
                "password_policy_configured": pw_policy is not None,
                "password_policy_meets_pci": all(pw_signals.values()),
                "mfa_disabled_users": mfa_disabled_users,
                "stale_keys": active_key_older_than_90d,
            },
        }

    def _get_credential_report(self, iam) -> list[dict]:
        """Generate and retrieve the IAM credential report as a list of dicts."""
        # Trigger generation (may take a few seconds)
        while True:
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
            time.sleep(2)

        report = iam.get_credential_report()
        content = report["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect IAM posture evidence")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    result = IAMCollector("aws_iam_posture", session).run()

    signals = result.get("data", {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            print(f"  ℹ  {k}: {v if v else '(none)'}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
