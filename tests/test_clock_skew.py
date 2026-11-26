"""Tests for Objective 8: Clock skew and out-of-order event handling."""
from __future__ import annotations

import unittest

from graviton.detect import DetectionEngine


class TestClockSkew(unittest.TestCase):
    def test_in_range_skew_and_reordering_produce_same_alerts(self) -> None:
        clean = [
            {
                "event_id": "ev-1",
                "event_time_utc": "2026-01-15T09:03:00.000Z",
                "received_time_utc": "2026-01-15T09:03:00.200Z",
                "source_clock_offset_ms": 0,
                "actor": "blair",
                "source_service": "admin-console",
                "target_service": "identity",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "outcome": "success",
                "session_id": "s1",
            },
            {
                "event_id": "ev-2",
                "event_time_utc": "2026-01-15T09:03:04.000Z",
                "received_time_utc": "2026-01-15T09:03:04.200Z",
                "source_clock_offset_ms": 0,
                "actor": "blair",
                "source_service": "portal",
                "target_service": "reports",
                "action": "read",
                "outcome": "allow",
                "session_id": "s1",
            },
        ]
        # Shuffled arrival order + +2000 ms clock skew + 5000 ms arrival delay (within +/-5s skew, 10s delay)
        skewed_shuffled = [
            {
                **clean[1],
                "event_time_utc": "2026-01-15T09:03:06.000Z",
                "received_time_utc": "2026-01-15T09:03:04.500Z",
                "source_clock_offset_ms": 2000,
            },
            {
                **clean[0],
                "received_time_utc": "2026-01-15T09:03:05.000Z",
            },
        ]
        _, alerts_clean = DetectionEngine().analyze(clean)
        _, alerts_skewed = DetectionEngine().analyze(skewed_shuffled)

        self.assertEqual([a.category for a in alerts_clean], [a.category for a in alerts_skewed])
        self.assertEqual([a.event_ids for a in alerts_clean], [a.event_ids for a in alerts_skewed])
        self.assertTrue(all(not a.order_uncertain for a in alerts_skewed))

    def test_out_of_range_and_uncertainty_emit_order_uncertain(self) -> None:
        events = [
            {
                "event_id": "ev-late",
                "event_time_utc": "2026-01-15T09:03:00.000Z",
                "received_time_utc": "2026-01-15T09:03:25.000Z",  # 25s delay > 10s MAX_DELAY_MS
                "source_clock_offset_ms": 0,
                "actor": "blair",
                "source_service": "admin-console",
                "target_service": "identity",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "outcome": "success",
                "session_id": "s1",
            },
            {
                "event_id": "ev-read",
                "event_time_utc": "2026-01-15T09:03:01.000Z",
                "received_time_utc": "2026-01-15T09:03:01.200Z",
                "source_clock_offset_ms": 0,
                "actor": "blair",
                "source_service": "portal",
                "target_service": "reports",
                "action": "read",
                "outcome": "allow",
                "session_id": "s1",
            },
        ]
        _, alerts = DetectionEngine(offset_uncertainty_ms=2000).analyze(events)
        uncertain_alerts = [a for a in alerts if a.order_uncertain]
        self.assertTrue(len(uncertain_alerts) >= 2)
        self.assertTrue(any(a.category == "order_uncertain" for a in alerts))
        access_alert = [a for a in alerts if a.category == "access_after_unexpected_privilege"][0]
        self.assertTrue(access_alert.order_uncertain)


if __name__ == "__main__":
    unittest.main()
