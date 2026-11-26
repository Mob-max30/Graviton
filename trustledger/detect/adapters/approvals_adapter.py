"""Adapter for parsing approvals.json into change control context."""
import json
from pathlib import Path
from typing import NamedTuple


class ApprovalRecord(NamedTuple):
    approval_id: str
    approved_by: str
    subject: str
    operation: str
    role: str
    scope: list[str]
    valid_from_utc: str | None
    valid_until_utc: str | None
    effective_at_utc: str | None


class ApprovalsAdapter:
    """Parses and indexes authorized change control records."""

    @classmethod
    def load_approvals(cls, path: Path) -> dict[str, ApprovalRecord]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Approvals file not found: {path}")

        data = json.loads(path.read_text(encoding="utf-8"))
        records: dict[str, ApprovalRecord] = {}

        for item in data.get("changes", []):
            rec = ApprovalRecord(
                approval_id=item["approval_id"],
                approved_by=item.get("approved_by", ""),
                subject=item.get("subject", ""),
                operation=item.get("operation", ""),
                role=item.get("role", ""),
                scope=item.get("scope", []),
                valid_from_utc=item.get("valid_from_utc"),
                valid_until_utc=item.get("valid_until_utc"),
                effective_at_utc=item.get("effective_at_utc"),
            )
            records[rec.approval_id] = rec

        return records
