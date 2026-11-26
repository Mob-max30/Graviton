"""Tests for Objective 6: Routine vs suspicious detection and evaluation metrics."""
from __future__ import annotations

import unittest

from graviton.detect import DetectionEngine, evaluate_detection


class TestDetectionEval(unittest.TestCase):
    def test_approved_vs_unapproved_role_change(self) -> None:
        approvals = [
            {
                "approval_id": "chg-1",
                "subject": "alice",
                "role": "report-reader",
                "valid_from_utc": "2026-01-15T09:01:00Z",
                "valid_until_utc": "2026-01-15T09:07:00Z",
            }
        ]
        events = [
            {
                "event_id": "e1",
                "event_time_utc": "2026-01-15T09:02:00Z",
                "received_time_utc": "2026-01-15T09:02:00.1Z",
                "source_clock_offset_ms": 0,
                "actor": "alice",
                "source_service": "admin-console",
                "target_service": "identity",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "report-reader",
                "outcome": "success",
                "approval_id": "chg-1",
                "session_id": "s-alice",
            },
            {
                "event_id": "e2",
                "event_time_utc": "2026-01-15T09:03:00Z",
                "received_time_utc": "2026-01-15T09:03:00.1Z",
                "source_clock_offset_ms": 0,
                "actor": "blair",
                "source_service": "admin-console",
                "target_service": "identity",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "outcome": "success",
                "approval_id": "",
                "session_id": "s-blair",
            },
        ]
        _, alerts = DetectionEngine(approvals=approvals).analyze(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "unexpected_privilege_change")
        self.assertEqual(alerts[0].identity, "blair")
        self.assertEqual(alerts[0].event_ids, ["e2"])

    def test_labelled_dataset_metrics(self) -> None:
        metrics = evaluate_detection(benign_count=1000, attack_count=20, seed=42)
        self.assertGreaterEqual(metrics["f1"], 0.95)
        self.assertEqual(metrics["false_alerts_per_1000_benign"], 0.0)
        self.assertGreaterEqual(metrics["median_time_to_alert_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
