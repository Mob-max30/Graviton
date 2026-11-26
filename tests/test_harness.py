"""Tests for graviton.harness multi-node measurement scenarios (Step 5)."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from graviton.harness.runner import (
    run_device_loss_scenario,
    run_freshness_scenario,
    run_revocation_scenario,
    run_rotation_scenario,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestHarness(unittest.TestCase):
    def test_revocation_scenario_and_last_node_max(self) -> None:
        res = run_revocation_scenario(node_count=4, delay_ms=(0, 10), seed=42)
        self.assertTrue(res["all_nodes_denied"])
        per_node_max = max(item["enforced_ms"] for item in res["per_node"])
        self.assertEqual(res["last_node_enforcement_ms"], per_node_max)

    def test_rotation_scenario_lagging_node(self) -> None:
        res = run_rotation_scenario(node_count=4, delay_ms=(0, 5), seed=7)
        self.assertTrue(res["pre_cutoff_v1_all_allow"])
        self.assertTrue(res["pre_cutoff_v2_all_allow"])
        self.assertEqual(res["lagging_node_v1_before_catchup"], "allow")
        self.assertTrue(res["post_cutoff_v2_all_allow"])
        self.assertTrue(all(r == "KEY_RETIRED" for r in res["post_cutoff_v1_reasons"]))

    def test_device_loss_and_freshness_scenarios(self) -> None:
        loss = run_device_loss_scenario(node_count=3, delay_ms=(0, 5), seed=3)
        self.assertTrue(loss["lost_device_denied_everywhere"])
        self.assertTrue(loss["new_device_allowed_everywhere"])
        self.assertTrue(loss["peer_unaffected_everywhere"])

        fresh = run_freshness_scenario(node_count=3, delay_ms=(0, 5), seed=5, freshness_window=30)
        self.assertEqual(fresh["stale_node_reason"], "STALE_STATE")
        self.assertTrue(fresh["fresh_nodes_allowed"])
        self.assertEqual(fresh["recovered_decision"], "allow")
        self.assertTrue(fresh["revoked_stays_revoked"])

    def test_cli_outputs_json_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="graviton-cli-harness-") as tmp:
            out_path = Path(tmp) / "results.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "graviton.harness",
                    "--scenario",
                    "all",
                    "--nodes",
                    "3",
                    "--delay-ms",
                    "0:5",
                    "--seed",
                    "1",
                    "--out",
                    str(out_path),
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(out_path.is_file())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn("metadata", data)
            self.assertEqual(len(data["scenarios"]), 4)


if __name__ == "__main__":
    unittest.main()
