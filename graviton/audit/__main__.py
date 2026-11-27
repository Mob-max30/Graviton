"""CLI for operator audit log verification (`python -m graviton.audit verify`)."""
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys

from graviton.audit.log import AuditLog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graviton audit log operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_p = sub.add_parser("verify", help="Verify audit log hash chain, checkpoints, and external head hash")
    verify_p.add_argument("--db", required=True, type=Path, help="Path to audit SQLite database")
    verify_p.add_argument("--head", required=True, type=Path, help="Path to external head hash JSON")
    verify_p.add_argument("--pubkey-b64", default=None, help="Optional Base64 ML-DSA-65 public key for checkpoints")

    args = parser.parse_args(argv)
    if args.command == "verify":
        pk = base64.b64decode(args.pubkey_b64, validate=True) if args.pubkey_b64 else None
        log = AuditLog(args.db, args.head)
        res = log.verify(verifier_public_key=pk)
        if res.valid:
            print(
                f"AUDIT LOG OK: events={res.event_count} checkpoints={res.checkpoint_count} "
                f"head_seq={res.head_seq} head_hash={res.head_hash_hex}"
            )
            return 0
        print(
            f"AUDIT LOG INVALID: first_bad_seq={res.first_bad_seq} reason={res.reason}",
            file=sys.stderr,
        )
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
