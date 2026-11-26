"""Golden regression test against the official 22-event Track 4 practice dataset.

Asserts exact alignment with public labels:
- Approved promotion + in-window read -> no alert
- Unapproved role change (evt-008) -> flagged with "missing authorization"
- Read following unapproved change (evt-009) -> flagged with both event IDs
- 3 unexpected denied edges in flow-005 (evt-010..012) -> candidate lateral movement sequence
- Isolated denial (evt-020) -> no sequence alert
- Offset event (evt-015) -> corrected time equals labeled time
- Receipt inversion (evt-013 vs evt-014) -> flagged as ordering uncertainty, not replay
"""
from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.engine import DetectionPipeline
from trustledger.fixtures import get_practice_dir


def test_practice_golden_dataset():
    practice_dir = get_practice_dir()
    events_csv = practice_dir / "events.csv"
    approvals_json = practice_dir / "approvals.json"

    assert events_csv.exists(), f"events.csv not found at {events_csv}"

    # 1. Load events via adapter
    adapter = EventAdapter()
    events = adapter.load_events(events_csv)
    assert len(events) == 22

    # 2. Check clock offset alignment on evt-015
    e15 = next(e for e in events if e.event_id == "evt-015")
    assert e15.source_clock_offset_ms == 2000
    # Corrected timestamp: 09:06:03 - 2000ms = 09:06:01.000Z
    # 2026-01-15T09:06:01.000Z epoch ms
    import datetime
    dt = datetime.datetime.fromtimestamp(e15.corrected_time_epoch_ms / 1000.0, tz=datetime.timezone.utc)
    assert dt.strftime("%H:%M:%S") == "09:06:01"

    # 3. Process events through detection pipeline
    pipeline = DetectionPipeline(approvals_json)
    alerts = pipeline.process_events(events)

    alert_rules = {a.rule_id for a in alerts}
    assert "R-PRIV-1" in alert_rules
    assert "R-PRIV-5" in alert_rules
    assert "R-LAT-2" in alert_rules

    # Check evt-008 unapproved change alert
    a_priv = next(a for a in alerts if a.rule_id == "R-PRIV-1")
    assert a_priv.identity == "user-blair"
    assert "evt-008" in a_priv.event_ids
    assert "No matching authorization" in a_priv.explanation

    # Check evt-009 read alert references both evt-008 and evt-009
    a_priv5 = next(a for a in alerts if a.rule_id == "R-PRIV-5")
    assert "evt-008" in a_priv5.event_ids
    assert "evt-009" in a_priv5.event_ids

    # Check candidate lateral movement sequence covers evt-010, evt-011, evt-012
    a_lat = next(a for a in alerts if a.rule_id == "R-LAT-2")
    assert a_lat.identity == "svc-report-worker"
    assert set(a_lat.event_ids) == {"evt-010", "evt-011", "evt-012"}
    assert a_lat.candidate_sequence is True
    assert "Does not indicate successful compromise" in a_lat.explanation

    # Check isolated denial (evt-020) produces no alert
    assert not any("evt-020" in a.event_ids for a in alerts)

    # Check approved promotion (evt-003, evt-004, evt-005) produces no alert
    for approved_id in ("evt-003", "evt-004", "evt-005"):
        assert not any(approved_id in a.event_ids for a in alerts)

    # 4. Check arrival disorder flagged on inverted receipt order
    # evt-014 arrives at receipt index 13, evt-013 at receipt index 14
    e14 = next(e for e in events if e.event_id == "evt-014")
    e13 = next(e for e in events if e.event_id == "evt-013")
    assert e14.receipt_index < e13.receipt_index
    assert e13.corrected_time_epoch_ms < e14.corrected_time_epoch_ms
    assert e14.order_uncertain is True  # Inversion detected and flagged
