"""Cross-platform task runner (setup, test, validate, demo, eval, bench, brief, verify-clean)."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> int:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=str(REPO_ROOT)).returncode


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    target = args[0] if args else "test"
    py = sys.executable

    if target == "test":
        return _run([py, "-m", "unittest", "discover", "-s", "tests", "-v"])
    if target == "validate":
        tk = REPO_ROOT.parent / "Track-4-Toolkit" / "validate.py"
        if not tk.is_file():
            print(f"Toolkit validator not found at {tk}", file=sys.stderr)
            return 1
        return _run([py, str(tk), "--entry", str(REPO_ROOT / "track4_service.py")])
    if target == "demo":
        return _run([py, "-m", "graviton.demo"])
    if target == "eval":
        return _run([py, "-m", "graviton", "detect-eval", "--out", "build/detect-metrics.json"])
    if target == "bench":
        return _run([py, "bench/benchmark.py"])
    if target == "brief":
        return _run([py, "docs/brief/generate_brief.py"])
    if target == "verify-clean":
        for step in ("test", "eval", "bench"):
            rc = main([step])
            if rc != 0:
                return rc
        if (REPO_ROOT.parent / "Track-4-Toolkit" / "validate.py").is_file():
            return main(["validate"])
        return 0

    print(f"Unknown target: {target}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
