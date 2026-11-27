"""Stage 6: Packaging, graviton doctor, and real graviton demo tests."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from graviton.crypto.aead import aead_available
from graviton.demo import run_demo
from graviton.doctor import run_doctor

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class Stage6PackagingAndDoctorTests(unittest.TestCase):
    def test_01_doctor_core_checks_pass(self) -> None:
        checks = run_doctor()
        by_name = {c["name"]: c for c in checks}
        for required in ("python", "pqcrypto", "sqlite_returning", "state_dir", "loopback_port"):
            self.assertTrue(by_name[required]["ok"], f"Doctor check failed: {by_name[required]}")

    @unittest.skipUnless(aead_available(), "Stage 6 demo requires the 'app' extra (cryptography)")
    def test_02_real_demo_runs_end_to_end(self) -> None:
        res = run_demo()
        self.assertTrue(res["audit_valid"])
        self.assertEqual(len(res["revocation_ms"]), 2)
        self.assertGreaterEqual(res["last_node_ms"], 0.0)
        self.assertEqual(len(res["redteam"]), 9)
        self.assertTrue(all(item["denied"] and item["node_alive"] for item in res["redteam"]))
        self.assertGreaterEqual(res["alerts"], 2)


if __name__ == "__main__":
    unittest.main()
