"""Fixture discovery for public Track 4 practice data without hardcoded absolute paths."""
import os
from pathlib import Path


def get_practice_dir() -> Path:
    """Resolve the practice fixtures directory from TRACK4_TOOLKIT or vendored fixtures."""
    env_toolkit = os.environ.get("TRACK4_TOOLKIT")
    if env_toolkit:
        candidate = Path(env_toolkit) / "practice"
        if candidate.is_dir():
            return candidate

    repo_root = Path(__file__).resolve().parent.parent
    vendored = repo_root / "fixtures" / "practice"
    if vendored.is_dir():
        return vendored

    sibling = repo_root.parent / "Track-4-Toolkit" / "practice"
    if sibling.is_dir():
        return sibling

    raise FileNotFoundError(
        "Practice fixtures directory not found in TRACK4_TOOLKIT, vendored fixtures/, or sibling Track-4-Toolkit."
    )
