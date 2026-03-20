"""
base.py — shared collector base class
All collectors inherit from this to ensure consistent output format.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class BaseCollector:
    """
    Standardised evidence artifact format:
    {
        "evidence_id":   str   — unique ID matching controls.yaml
        "collector":     str   — script filename
        "collected_at":  str   — ISO 8601 UTC timestamp
        "aws_account":   str   — account ID from STS
        "aws_region":    str   — region queried
        "status":        str   — "ok" | "error"
        "data":          any   — collector-specific payload
        "error":         str   — present only if status == "error"
    }
    """

    EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "evidence"))

    def __init__(self, evidence_id: str, session):
        self.evidence_id = evidence_id
        self.session = session
        self.collected_at = datetime.now(timezone.utc).isoformat()
        self.account_id = self._get_account_id()
        self.region = session.region_name or "us-east-1"

    def _get_account_id(self) -> str:
        try:
            return self.session.client("sts").get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def collect(self) -> dict:
        """Override in each collector. Return the data payload."""
        raise NotImplementedError

    def run(self) -> dict:
        """Run collect(), wrap in standard envelope, save to disk."""
        try:
            data = self.collect()
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "aws_account": self.account_id,
                "aws_region": self.region,
                "status": "ok",
                "data": data,
            }
        except Exception as exc:
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "aws_account": self.account_id,
                "aws_region": self.region,
                "status": "error",
                "error": str(exc),
                "data": None,
            }

        self._save(artifact)
        return artifact

    def _save(self, artifact: dict):
        """Write artifact to evidence/<evidence_id>/latest.json
        and a timestamped copy for history."""
        folder = self.EVIDENCE_DIR / self.evidence_id
        folder.mkdir(parents=True, exist_ok=True)

        # Always overwrite latest for quick status checks
        (folder / "latest.json").write_text(
            json.dumps(artifact, indent=2, default=str)
        )

        # Keep a dated snapshot for audit trail
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        (folder / f"{date_str}.json").write_text(
            json.dumps(artifact, indent=2, default=str)
        )

        status = artifact["status"].upper()
        print(f"[{status}] {self.evidence_id} → {folder}/latest.json")
