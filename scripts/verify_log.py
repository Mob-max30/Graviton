"""Standalone CLI to verify an AuditLog JSONL file on disk."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.audit_log import AuditLog


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Graviton AuditLog integrity")
    parser.add_argument("log_path", help="Path to audit.jsonl")
    args = parser.parse_args()

    log = AuditLog(args.log_path)
    ok, err = log.verify_log(from_disk=True)
    if ok:
        print(f"VERIFIED: {len(log.entries)} entries intact and ML-DSA-65 signed.")
        return 0
    print(f"FAILED: {err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
