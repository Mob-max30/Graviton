"""Tests for Objective 7: Lateral movement graph detection."""
from __future__ import annotations

import unittest

from graviton.detect import DetectionEngine


class TestLateralMovement(unittest.TestCase):
    def test_unusual_path_flagged_even_with_valid_credentials(self) -> None:
        events = [
            {
                "event_id": "lat-1",
                "event_time_utc": "2026-01-15T09:04:00Z",
                "received_time_utc": "2026-01-15T09:04:00.1Z",
                "source_clock_offset_ms": 0,
                "actor": "svc-worker",
                "source_service": "reports",
                "target_service": "billing",
                "action": "read",
                "outcome": "allow",  # valid credentials do not suppress lateral movement alert
                "session_id": "sess-w",
            },
            {
                "event_id": "lat-2",
                "event_time_utc": "2026-01-15T09:04:01Z",
                "received_time_utc": "2026-01-15T09:04:01.1Z",
                "source_clock_offset_ms": 0,
                "actor": "svc-worker",
                "source_service": "billing",
                "target_service": "archive",
                "action": "read",
                "outcome": "allow",
                "session_id": "sess-w",
            },
        ]
        _, alerts = DetectionEngine().analyze(events)
        lat_alerts = [a for a in alerts if a.category == "lateral_movement"]
        self.assertEqual(len(lat_alerts), 1)
        a = lat_alerts[0]
        self.assertEqual(a.identity, "svc-worker")
        self.assertEqual(a.services, ["reports", "billing", "archive"])
        self.assertEqual(a.event_ids, ["lat-1", "lat-2"])
        self.assertIn("reports -> billing -> archive", a.rule_or_path)

    def test_isolated_single_denial_does_not_trigger_lateral_movement(self) -> None:
        events = [
            {
                "event_id": "iso-1",
                "event_time_utc": "2026-01-15T09:08:00Z",
                "received_time_utc": "2026-01-15T09:08:00.1Z",
                "source_clock_offset_ms": 0,
                "actor": "user-casey",
                "source_service": "portal",
                "target_service": "billing",
                "action": "read",
                "outcome": "deny",
                "session_id": "sess-c",
            }
        ]
        _, alerts = DetectionEngine().analyze(events)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
