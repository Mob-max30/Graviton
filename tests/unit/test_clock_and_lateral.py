"""Tests for B3 (clock offset bounds, uncertainty_ms, corrected-time ordering) and B4 (lateral threshold)."""
import json
from pathlib import Path

from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.clock import DEFAULT_MAX_CLOCK_OFFSET_MS, parse_iso_to_epoch_ms
from trustledger.detect.engine import DetectionPipeline
from trustledger.detect.models import NormalizedEvent
from trustledger.detect.rules import LATERAL_MIN_EDGES


def _write_approvals(path: Path) -> Path:
    path.write_text(json.dumps({"synthetic": True, "changes": []}), encoding="utf-8")
    return path


def test_out_of_range_clock_offset_flagged_and_propagated(tmp_path: Path) -> None:
    """B3: Offset beyond DEFAULT_MAX_CLOCK_OFFSET_MS sets out_of_range=True and attaches uncertainty metadata."""
    events_file = tmp_path / "events.jsonl"
    oversize_offset = int(DEFAULT_MAX_CLOCK_OFFSET_MS) + 1000
    events_file.write_text(
        json.dumps({
            "event_id": "evt-skew",
            "event_time_utc": "2026-01-15T09:10:00.000Z",
            "received_time_utc": "2026-01-15T09:00:00.000Z",
            "source_clock_offset_ms": oversize_offset,
            "actor": "user-x",
            "source_service": "admin-console",
            "target_service": "identity",
            "action": "role_change",
            "role_before": "viewer",
            "role_after": "operator",
            "outcome": "success",
        }) + "\n",
        encoding="utf-8",
    )
    events = EventAdapter().load_events(events_file)
    assert len(events) == 1
    assert events[0].offset_out_of_range is True
    assert events[0].uncertainty_ms > 0.0

    appr_file = _write_approvals(tmp_path / "approvals.json")
    alerts = DetectionPipeline(appr_file).process_events(events)
    assert len(alerts) == 1
    assert alerts[0].timestamps_with_uncertainty["source_offset_out_of_range"] is True
    assert alerts[0].timestamps_with_uncertainty["uncertainty_ms"] == events[0].uncertainty_ms


def test_out_of_order_events_evaluated_in_corrected_time_order(tmp_path: Path) -> None:
    """B3: Events arriving out of corrected-time order are still evaluated in corrected order (R-PRIV-5)."""
    appr_file = _write_approvals(tmp_path / "approvals.json")
    # Read arrives first in receipt order (09:05:00) but role_change occurred earlier (09:01:00)
    ev_read = NormalizedEvent(
        event_id="evt-late-read",
        event_time_utc="2026-01-15T09:05:00.000Z",
        received_time_utc="2026-01-15T09:05:01.000Z",
        source_clock_offset_ms=0,
        corrected_time_epoch_ms=parse_iso_to_epoch_ms("2026-01-15T09:05:00.000Z"),
        actor="user-z",
        source_service="portal",
        target_service="reports",
        action="read",
        role_before="operator",
        role_after="operator",
        outcome="allow",
        approval_id=None,
        session_id="sess-z",
        correlation_id="flow-z",
        receipt_index=0,
    )
    ev_priv = NormalizedEvent(
        event_id="evt-early-priv",
        event_time_utc="2026-01-15T09:01:00.000Z",
        received_time_utc="2026-01-15T09:05:02.000Z",
        source_clock_offset_ms=0,
        corrected_time_epoch_ms=parse_iso_to_epoch_ms("2026-01-15T09:01:00.000Z"),
        actor="user-z",
        source_service="admin-console",
        target_service="identity",
        action="role_change",
        role_before="viewer",
        role_after="operator",
        outcome="success",
        approval_id=None,
        session_id="sess-z",
        correlation_id="flow-z",
        receipt_index=1,
    )
    alerts = DetectionPipeline(appr_file).process_events([ev_read, ev_priv])
    rule_ids = {a.rule_id for a in alerts}
    assert "R-PRIV-1" in rule_ids
    assert "R-PRIV-5" in rule_ids


def test_lateral_movement_threshold_fires_once_at_min_edges(tmp_path: Path) -> None:
    """B4: 2 denied edges -> 0 alerts; 3 edges -> 1 alert; 4th edge -> no duplicate alert."""
    appr_file = _write_approvals(tmp_path / "approvals.json")
    edges = [
        ("reports", "billing"),
        ("billing", "archive"),
        ("archive", "identity"),
        ("identity", "secrets"),
    ]
    events = [
        NormalizedEvent(
            event_id=f"evt-lat-{i}",
            event_time_utc=f"2026-01-15T09:00:0{i}.000Z",
            received_time_utc=f"2026-01-15T09:00:0{i}.100Z",
            source_clock_offset_ms=0,
            corrected_time_epoch_ms=parse_iso_to_epoch_ms(f"2026-01-15T09:00:0{i}.000Z"),
            actor="svc-worker",
            source_service=src,
            target_service=dst,
            action="read",
            role_before="service-reader",
            role_after="service-reader",
            outcome="deny",
            approval_id=None,
            session_id="sess-w",
            correlation_id="flow-w",
            receipt_index=i,
        )
        for i, (src, dst) in enumerate(edges)
    ]

    # 2 edges -> no alert
    assert len(DetectionPipeline(appr_file).process_events(events[: LATERAL_MIN_EDGES - 1])) == 0
    # 3 edges -> 1 alert
    alerts3 = DetectionPipeline(appr_file).process_events(events[:LATERAL_MIN_EDGES])
    assert len(alerts3) == 1
    assert alerts3[0].rule_id == "R-LAT-2"
    assert len(alerts3[0].event_ids) == LATERAL_MIN_EDGES
    # 4th edge -> still 1 alert (no duplicate spam)
    alerts4 = DetectionPipeline(appr_file).process_events(events)
    assert len(alerts4) == 1
