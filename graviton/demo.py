"""One-command 12-objective demo walkthrough (`python -m graviton.demo`)."""
from __future__ import annotations

import subprocess
import sys

OBJECTIVE_TESTS = [
    ("1. Key rotation", "tests/test_node_authorize.py"),
    ("2. Revocation + device loss", "tests/test_harness.py"),
    ("3. Crash recovery", "tests/test_crash_recovery.py"),
    ("4. Backup integrity", "tests/test_backup_integrity.py"),
    ("5. Log integrity", "tests/test_log_integrity.py"),
    ("6. Routine vs suspicious", "tests/test_detection_eval.py"),
    ("7. Lateral movement", "tests/test_lateral_movement.py"),
    ("8. Clock differences", "tests/test_clock_skew.py"),
    ("9. Replay + recipient binding", "tests/test_replay_binding.py"),
    ("10. Forward secrecy", "tests/test_forward_secrecy.py"),
    ("11. Delivery under loss/reordering", "tests/test_lossy_delivery.py"),
    ("12. Session resumption", "tests/test_resumption.py"),
]


def main() -> int:
    for label, path in OBJECTIVE_TESTS:
        print(f"=== {label} ({path}) ===", flush=True)
        proc = subprocess.run([sys.executable, "-m", "unittest", path, "-v"], check=False)
        if proc.returncode != 0:
            return proc.returncode
    print("All 12 objective demonstrations passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
