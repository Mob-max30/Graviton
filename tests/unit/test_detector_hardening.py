"""Tests for data-driven detector hardening (Part 2.1-2.7)."""

import json
from pathlib import Path

from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.engine import DetectionPipeline


def _write_approvals(path: Path, changes: list[dict] | None = None) -> Path:
    path.write_text(
        json.dumps({"synthetic": True, "changes": changes or []}),
        encoding="utf-8",
    )
    return path


def test_track4_baseline_env_config(tmp_path: Path, monkeypatch) -> None:
    """2.1: TRACK4_BASELINE loads authorized edges from file without hardcoded topology."""
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(
        json.dumps({"allowed_edges": [["gw", "svc-a"], ["svc-a", "svc-b"]]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("TRACK4_BASELINE", str(baseline_file))

    appr_file = _write_approvals(tmp_path / "approvals.json")
    events_file = tmp_path / "events.jsonl"
    # Two allowed events using the configured edges -> should NOT trigger R-LAT-1
    events_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "e1",
                        "event_time_utc": "2026-01-15T10:00:00Z",
                        "received_time_utc": "2026-01-15T10:00:00Z",
                        "actor": "alice",
                        "source_service": "gw",
                        "target_service": "svc-a",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "e2",
                        "event_time_utc": "2026-01-15T10:01:00Z",
                        "received_time_utc": "2026-01-15T10:01:00Z",
                        "actor": "alice",
                        "source_service": "svc-a",
                        "target_service": "svc-b",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    pipeline = DetectionPipeline(appr_file)
    alerts = pipeline.run_file(events_file)
    assert not any(a.rule_id.startswith("R-LAT") for a in alerts)


def test_baseline_unavailable_notice_when_no_benign_warmup(tmp_path: Path, monkeypatch) -> None:
    """2.1: When no baseline is configured and no benign warm-up events exist, emit notice."""
    monkeypatch.delenv("TRACK4_BASELINE", raising=False)
    appr_file = _write_approvals(tmp_path / "approvals.json")
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        json.dumps(
            {
                "event_id": "e1",
                "event_time_utc": "2026-01-15T10:00:00Z",
                "received_time_utc": "2026-01-15T10:00:00Z",
                "actor": "bob",
                "source_service": "alpha",
                "target_service": "beta",
                "action": "read",
                "outcome": "deny",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    pipeline = DetectionPipeline(appr_file)
    pipeline.run_file(events_file)
    assert any("baseline unavailable" in n.lower() for n in pipeline.notices)


def test_renamed_privilege_verbs_detected_via_role_rank(tmp_path: Path) -> None:
    """2.2: Renamed privilege actions (elevate/promote) trigger privilege change alert."""
    appr_file = _write_approvals(tmp_path / "approvals.json")
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "e-elev",
                        "event_time_utc": "2026-01-15T10:00:00Z",
                        "received_time_utc": "2026-01-15T10:00:00Z",
                        "actor": "carol",
                        "source_service": "cli",
                        "target_service": "iam",
                        "action": "elevate",
                        "role_before": "viewer",
                        "role_after": "admin",
                        "outcome": "allow",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "e-prom",
                        "event_time_utc": "2026-01-15T10:01:00Z",
                        "received_time_utc": "2026-01-15T10:01:00Z",
                        "actor": "dave",
                        "source_service": "cli",
                        "target_service": "iam",
                        "action": "promote",
                        "role_before": "member",
                        "role_after": "operator",
                        "outcome": "allow",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    alerts = DetectionPipeline(appr_file).run_file(events_file)
    priv_actors = {a.identity for a in alerts if a.rule_id.startswith("R-PRIV")}
    assert {"carol", "dave"}.issubset(priv_actors)


def test_malformed_events_quarantined_into_rejected_events(tmp_path: Path) -> None:
    """2.4: Malformed timestamps, missing fields, and non-numeric offsets are quarantined."""
    events_file = tmp_path / "bad_events.jsonl"
    events_file.write_text(
        "\n".join(
            [
                "{not-json",
                json.dumps({"event_id": "missing-ts", "actor": "a"}),
                json.dumps(
                    {
                        "event_id": "bad-ts",
                        "event_time_utc": "not-a-timestamp",
                        "actor": "a",
                        "source_service": "s1",
                        "target_service": "s2",
                        "action": "read",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "bad-offset",
                        "event_time_utc": "2026-01-15T10:00:00Z",
                        "source_clock_offset_ms": "NaN-ish",
                        "actor": "a",
                        "source_service": "s1",
                        "target_service": "s2",
                        "action": "read",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "valid-1",
                        "event_time_utc": "2026-01-15T10:00:00Z",
                        "received_time_utc": "2026-01-15T10:00:00Z",
                        "actor": "a",
                        "source_service": "s1",
                        "target_service": "s2",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    adapter = EventAdapter()
    events = adapter.load_events(events_file)
    assert len(events) == 1
    assert events[0].event_id == "valid-1"
    assert len(adapter.rejected_events) == 4


def test_unknown_outcome_triggers_r_norm_1(tmp_path: Path) -> None:
    """2.3: Unknown/unrecognized outcome values normalize to 'unknown' and emit R-NORM-1."""
    appr_file = _write_approvals(tmp_path / "approvals.json")
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        json.dumps(
            {
                "event_id": "e-unk",
                "event_time_utc": "2026-01-15T10:00:00Z",
                "received_time_utc": "2026-01-15T10:00:00Z",
                "actor": "eve",
                "source_service": "web",
                "target_service": "db",
                "action": "read",
                "outcome": "maybe_ok",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    alerts = DetectionPipeline(appr_file).run_file(events_file)
    assert any(a.rule_id == "R-NORM-1" and a.identity == "eve" for a in alerts)


def test_cross_session_lateral_movement_detected(tmp_path: Path, monkeypatch) -> None:
    """2.5: Lateral movement across different session_ids within LATERAL_WINDOW_MS triggers R-LAT-1."""
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"allowed_edges": [["portal", "catalog"]]}), encoding="utf-8")
    monkeypatch.setenv("TRACK4_BASELINE", str(baseline_file))

    appr_file = _write_approvals(tmp_path / "approvals.json")
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "e1",
                        "event_time_utc": "2026-01-15T10:00:00Z",
                        "received_time_utc": "2026-01-15T10:00:00Z",
                        "session_id": "sess-1",
                        "actor": "mallory",
                        "source_service": "catalog",
                        "target_service": "vault",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "e2",
                        "event_time_utc": "2026-01-15T10:02:00Z",
                        "received_time_utc": "2026-01-15T10:02:00Z",
                        "session_id": "sess-2",
                        "actor": "mallory",
                        "source_service": "vault",
                        "target_service": "ledger",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    alerts = DetectionPipeline(appr_file).run_file(events_file)
    assert any(a.rule_id == "R-LAT-1" and a.identity == "mallory" for a in alerts)


def test_approval_unexpected_source_service_triggers_r_lat_3(tmp_path: Path, monkeypatch) -> None:
    """2.5: Approval for specific source_service flags access from an unexpected source (R-LAT-3)."""
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"allowed_edges": [["bastion", "billing-db"]]}), encoding="utf-8")
    monkeypatch.setenv("TRACK4_BASELINE", str(baseline_file))

    appr_file = _write_approvals(
        tmp_path / "approvals.json",
        changes=[
            {
                "approval_id": "CHG-1",
                "subject": "ops-user",
                "operation": "read",
                "role": "reader",
                "scope": ["billing-db"],
                "source_service": "bastion",
                "valid_from_utc": "2026-01-15T09:00:00Z",
                "valid_until_utc": "2026-01-15T11:00:00Z",
                "approved_by": "sec-lead",
            }
        ],
    )
    events_file = tmp_path / "events.jsonl"
    events_file.write_text(
        json.dumps(
            {
                "event_id": "e-src",
                "event_time_utc": "2026-01-15T10:00:00Z",
                "received_time_utc": "2026-01-15T10:00:00Z",
                "actor": "ops-user",
                "source_service": "compromised-printer",
                "target_service": "billing-db",
                "action": "read",
                "outcome": "allow",
                "approval_id": "CHG-1",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    alerts = DetectionPipeline(appr_file).run_file(events_file)
    assert any(a.rule_id == "R-LAT-3" and a.identity == "ops-user" for a in alerts)
