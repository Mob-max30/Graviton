"""Phase 3.4: Clock skew and arrival delay boundary tests."""
from __future__ import annotations

import unittest

from graviton.detect.clock import MAX_DELAY_MS, MAX_SKEW_MS
from graviton.detect.engine import DetectionEngine


class TestClockBoundaries(unittest.TestCase):
    def test_just_inside_and_just_outside_skew_and_delay_bounds(self) -> None:
        base = 1_770_000_000_000
        eng = DetectionEngine()

        inside_ev = {
            "event_id": "clk-in-1",
            "event_time_utc": base,
            "received_time_utc": base - MAX_SKEW_MS + 1 + 100,
            "source_clock_offset_ms": MAX_SKEW_MS - 1,
            "actor": "user-a",
            "source_service": "portal",
            "target_service": "catalog",
            "action": "read",
            "outcome": "allow",
        }
        ordered_in, alerts_in = eng.analyze([inside_ev])
        self.assertFalse(ordered_in[0].order_uncertain)
        self.assertEqual(alerts_in, [])

        outside_ev = {
            "event_id": "clk-out-1",
            "event_time_utc": base,
            "received_time_utc": base - (MAX_SKEW_MS + 1) + 100,
            "source_clock_offset_ms": MAX_SKEW_MS + 1,
            "actor": "user-a",
            "source_service": "portal",
            "target_service": "catalog",
            "action": "read",
            "outcome": "allow",
        }
        ordered_out, alerts_out = eng.analyze([outside_ev])
        self.assertTrue(ordered_out[0].order_uncertain)
        self.assertEqual(len(alerts_out), 1)
        self.assertEqual(alerts_out[0].category, "order_uncertain")

        delay_out = {
            "event_id": "del-out-1",
            "event_time_utc": base,
            "received_time_utc": base + MAX_DELAY_MS + 1,
            "source_clock_offset_ms": 0,
            "actor": "user-a",
            "source_service": "portal",
            "target_service": "catalog",
            "action": "read",
            "outcome": "allow",
        }
        ordered_del, alerts_del = eng.analyze([delay_out])
        self.assertTrue(ordered_del[0].order_uncertain)
        self.assertEqual(alerts_del[0].category, "order_uncertain")


if __name__ == "__main__":
    unittest.main()
