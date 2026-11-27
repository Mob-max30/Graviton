"""Phase 2.3: Verify revocation probe uses monotonic clock and measures to the LAST node."""
from __future__ import annotations

import inspect
import unittest

from graviton import probe


class TestProbeMonotonicAndLastNode(unittest.TestCase):
    def test_probe_uses_monotonic_clock_and_tracks_last_node(self) -> None: 
        src = inspect.getsource(probe.probe_revocation_once)
        self.assertIn("monotonic_ns", src)
        self.assertNotIn("time.time()", src)
        self.assertIn("max(per_node_ms.values()", src)


if __name__ == "__main__":
    unittest.main()
