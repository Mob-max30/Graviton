"""Automated regression running the official Track 4 Toolkit validator when available."""
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _find_validator() -> Path | None:
    env_toolkit = os.environ.get("TRACK4_TOOLKIT")
    if env_toolkit:
        candidate = Path(env_toolkit) / "validate.py"
        if candidate.is_file():
            return candidate
    repo_root = Path(__file__).resolve().parent.parent.parent
    sibling = repo_root.parent / "Track-4-Toolkit" / "validate.py"
    if sibling.is_file():
        return sibling
    return None


def test_official_toolkit_validator() -> None:
    validator = _find_validator()
    if validator is None:
        pytest.skip("External Track-4-Toolkit validate.py not present; set TRACK4_TOOLKIT to run.")

    repo_root = Path(__file__).resolve().parent.parent.parent
    entry = repo_root / "track4_service.py"

    cmd = [sys.executable, str(validator), "--entry", str(entry), "--timeout", "8"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)

    assert res.returncode == 0, f"Validator failed with exit code {res.returncode}:\n{res.stdout}\n{res.stderr}"
    assert "Local scenario passed." in res.stdout
