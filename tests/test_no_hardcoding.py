"""Hard Rule 7E: Automated no-hardcoding, path, test-detection, and determinism enforcement."""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import unittest

from graviton.adapter_store import derive_and_save_keys
from graviton.config import load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_PASSWORDS = ("changeme", "secret123", "test-key")
SECRET_ASSIGN_RE = re.compile(
    r"""(?i)\b(password|secret|token|api_key|passphrase|private_key)\b\s*=\s*["'][A-Za-z0-9+/=_-]{16,}["']"""
)
FORBIDDEN_PATHS = ("C:\\\\", "/home/", "/Users/", "file:///", "e:/My Projects", "E:\\My Projects")
TEST_DETECT_MARKERS = ("PYTEST_CURRENT_TEST", "Track-4-Toolkit", "validate.py")


class TestNoHardcoding(unittest.TestCase):
    def test_01_no_forbidden_paths_or_secrets_in_tracked_sources(self) -> None:
        scan_dirs = [REPO_ROOT / "graviton", REPO_ROOT / "docs", REPO_ROOT / "bench"]
        top_files = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "graviton_app.py",
            REPO_ROOT / "team_app.py",
            REPO_ROOT / "track4_service.py",
        ]
        files: list[Path] = list(top_files)
        for d in scan_dirs:
            if d.is_dir():
                files.extend(p for p in d.rglob("*") if p.is_file() and p.suffix in (".py", ".md", ".txt", ".json"))

        for p in files:
            text = p.read_text(encoding="utf-8", errors="replace")
            rel = str(p.relative_to(REPO_ROOT)).replace("\\", "/")
            for marker in FORBIDDEN_PATHS:
                self.assertNotIn(marker, text, f"Forbidden path {marker!r} in {rel}")
            if p.suffix == ".py":
                self.assertNotIn("BEGIN PRIVATE KEY", text, f"PEM key in {rel}")
                for bad in FORBIDDEN_PASSWORDS:
                    self.assertNotIn(bad, text.lower(), f"Forbidden credential {bad!r} in {rel}")
                self.assertIsNone(SECRET_ASSIGN_RE.search(text), f"Suspicious secret literal in {rel}")
                if not rel.startswith("tests/"):
                    for td in TEST_DETECT_MARKERS:
                        self.assertNotIn(td, text, f"Test-detection marker {td!r} in {rel}")

    def test_02_determinism_guard_fresh_keys_never_match(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="graviton_det_"))
        try:
            km = secrets.token_hex(12)
            k1 = derive_and_save_keys(tmp / "k1", km)
            k2 = derive_and_save_keys(tmp / "k2", km)
            for name in ("k_state", "k_audit", "k_head"):
                self.assertNotEqual(k1[name], k2[name])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_03_config_overrides_and_invalid_values_fail_closed(self) -> None:
        old = os.environ.get("GRAVITON_LOCK_TIMEOUT_S")
        try:
            os.environ["GRAVITON_LOCK_TIMEOUT_S"] = "7.5"
            cfg = load_config()
            self.assertEqual(cfg.lock_timeout_s, 7.5)

            os.environ["GRAVITON_LOCK_TIMEOUT_S"] = "-1"
            with self.assertRaises(ValueError):
                load_config()
        finally:
            if old is None:
                os.environ.pop("GRAVITON_LOCK_TIMEOUT_S", None)
            else:
                os.environ["GRAVITON_LOCK_TIMEOUT_S"] = old


if __name__ == "__main__":
    unittest.main()
