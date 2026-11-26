"""Adapter for parsing and normalizing event logs from CSV or JSONL, quarantining malformed records."""
import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from trustledger.detect.clock import ClockAligner
from trustledger.detect.models import NormalizedEvent

ALLOW_OUTCOMES = frozenset({"allow", "allowed", "success", "ok"})
DENY_OUTCOMES = frozenset({"deny", "denied", "reject", "rejected", "fail", "failed"})


def normalize_outcome(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val in ALLOW_OUTCOMES:
        return "allow"
    if val in DENY_OUTCOMES:
        return "deny"
    return "unknown"


def normalize_action(raw: Any) -> str:
    return str(raw or "").strip().lower()


class EventAdapter:
    """Parses events CSV or JSONL files into NormalizedEvents; malformed rows are quarantined, never raised."""

    def __init__(self, clock_aligner: ClockAligner | None = None):
        self.aligner = clock_aligner or ClockAligner()
        self.rejected_events: List[Dict[str, Any]] = []

    def load_events(self, file_path: Path) -> List[NormalizedEvent]:
        self.rejected_events = []
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Event file not found: {path}")

        if path.suffix == ".csv":
            return self._load_csv(path)
        return self._load_jsonl(path)

    def _load_csv(self, path: Path) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                ev = self._try_parse_dict(row, idx)
                if ev is not None:
                    events.append(ev)
        return events

    def _load_jsonl(self, path: Path) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as err:
                    self.rejected_events.append({"receipt_index": idx, "raw": stripped, "reason": f"invalid_json: {err}"})
                    continue
                if not isinstance(row, dict):
                    self.rejected_events.append({"receipt_index": idx, "raw": row, "reason": "row_not_object"})
                    continue
                ev = self._try_parse_dict(row, idx)
                if ev is not None:
                    events.append(ev)
        return events

    def _try_parse_dict(self, row: dict[str, Any], idx: int) -> NormalizedEvent | None:
        required = ("event_id", "event_time_utc", "received_time_utc", "actor", "source_service", "target_service", "action", "outcome")
        for field in required:
            val = row.get(field)
            if val is None or not str(val).strip():
                self.rejected_events.append({"receipt_index": idx, "raw": row, "reason": f"missing_or_empty_{field}"})
                return None

        try:
            offset_raw = row.get("source_clock_offset_ms", 0)
            offset_ms = int(offset_raw) if offset_raw not in (None, "") else 0
        except (ValueError, TypeError) as err:
            self.rejected_events.append({"receipt_index": idx, "raw": row, "reason": f"invalid_offset: {err}"})
            return None

        event_time = str(row["event_time_utc"]).strip()
        recv_time = str(row["received_time_utc"]).strip()
        try:
            corrected_ms, _delay_ms, uncertainty_ms, out_of_range = self.aligner.align(
                event_time, recv_time, offset_ms
            )
        except (ValueError, TypeError, OverflowError) as err:
            self.rejected_events.append({"receipt_index": idx, "raw": row, "reason": f"invalid_timestamp: {err}"})
            return None

        return NormalizedEvent(
            event_id=str(row["event_id"]).strip(),
            event_time_utc=event_time,
            received_time_utc=recv_time,
            source_clock_offset_ms=offset_ms,
            corrected_time_epoch_ms=corrected_ms,
            actor=str(row["actor"]).strip(),
            source_service=str(row["source_service"]).strip(),
            target_service=str(row["target_service"]).strip(),
            action=normalize_action(row["action"]),
            role_before=str(row.get("role_before") or "").strip(),
            role_after=str(row.get("role_after") or "").strip(),
            outcome=normalize_outcome(row["outcome"]),
            approval_id=str(row["approval_id"]).strip() if row.get("approval_id") else None,
            session_id=str(row["session_id"]).strip() if row.get("session_id") else None,
            correlation_id=str(row["correlation_id"]).strip() if row.get("correlation_id") else None,
            receipt_index=idx,
            order_uncertain=False,
            offset_out_of_range=out_of_range,
            uncertainty_ms=uncertainty_ms,
        )
