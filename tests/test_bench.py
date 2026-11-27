"""Tests for graviton.bench unified benchmark CLI."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestBench(unittest.TestCase):
    def test_bench_cli_outputs_all_sections(self) -> None:
        with tempfile.TemporaryDirectory(prefix="graviton-bench-cli-") as tmp:
            out_path = Path(tmp) / "bench.json"
            proc = subprocess.run(
                [sys.executable, "-m", "graviton.bench", "--iterations", "3", "--out", str(out_path)],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(out_path.read_text(encoding="utf-8"))
            for key in ("metadata", "detection", "revocation", "rotation", "messaging", "overhead"):
                self.assertIn(key, data)


if __name__ == "__main__":
    unittest.main()
