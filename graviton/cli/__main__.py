"""Plain cross-platform management CLI (`python -m graviton.cli`)."""
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import sys

from graviton.audit import AuditLog
from graviton.bench.suite import run_benchmarks
from graviton.daemon.node import init_node_daemon, run_node_cli
from graviton.detect import evaluate_detection
from graviton.lifecycle import BackupVerificationError, verify_and_load_backup
from graviton.net.protocol import DEFAULT_MAX_FRAME_BYTES
from graviton.nodes import Node


def _parse_host_port(spec: str) -> tuple[str, int]:
    host, port_str = spec.rsplit(":", 1)
    return host, int(port_str)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graviton management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_node = sub.add_parser("node", help="Manage or run an enforcement node daemon")
    node_sub = p_node.add_subparsers(dest="node_cmd", required=True)
    pn_init = node_sub.add_parser("init", help="Initialise node state and ML-DSA-65 node identity")
    pn_init.add_argument("--dir", required=True, type=Path)
    pn_init.add_argument("--node-id", required=True)
    pn_init.add_argument("--feed-id", required=True)
    pn_init.add_argument("--admin-pubkey-b64", required=True)

    pn_run = node_sub.add_parser("run", help="Run the TCP enforcement node daemon")
    pn_run.add_argument("--dir", required=True, type=Path)
    pn_run.add_argument("--listen", default="127.0.0.1:0", help="HOST:PORT (default 127.0.0.1:0)")
    pn_run.add_argument("--max-frame-bytes", type=int, default=DEFAULT_MAX_FRAME_BYTES)
    pn_run.add_argument("--read-timeout", type=float, default=5.0)
    pn_run.add_argument("--idle-timeout", type=float, default=30.0)
    pn_run.add_argument("--max-connections", type=int, default=64)
    pn_run.add_argument("--operator", action="append", default=[])
    pn_run.add_argument("--tls-cert", default=None)
    pn_run.add_argument("--tls-key", default=None)
    pn_run.add_argument("--ready-file", type=Path, default=None)

    pn_stat = node_sub.add_parser("status", help="Inspect local node state")
    pn_stat.add_argument("--dir", required=True, type=Path)

    p_init = sub.add_parser("node-init", help="Initialise an enforcement node directory")
    p_init.add_argument("--dir", required=True, type=Path)
    p_init.add_argument("--feed-id", required=True)
    p_init.add_argument("--admin-pubkey-b64", required=True)

    p_stat = sub.add_parser("node-status", help="Verify node integrity and print applied epoch")
    p_stat.add_argument("--dir", required=True, type=Path)

    p_log = sub.add_parser("log-verify", help="Verify audit log hash chain and external head hash")
    p_log.add_argument("--db", required=True, type=Path)
    p_log.add_argument("--head", required=True, type=Path)
    p_log.add_argument("--pubkey-b64", default=None)

    p_bak = sub.add_parser("backup-verify", help="Verify a signed key backup before loading")
    p_bak.add_argument("--file", required=True, type=Path)
    p_bak.add_argument("--pubkey-b64", required=True)
    p_bak.add_argument("--min-version", type=int, default=1)

    sub.add_parser("detect-eval", help="Run deterministic detection evaluation")
    sub.add_parser("bench", help="Run unified benchmark suite")

    args = parser.parse_args(argv)

    if args.command == "node":
        if args.node_cmd == "init":
            pk = base64.b64decode(args.admin_pubkey_b64, validate=True)
            nid, npk, fp = init_node_daemon(args.dir, args.node_id, args.feed_id, pk)
            print(f"Node initialised: id={nid} fingerprint={fp} pk_b64={base64.b64encode(npk).decode('ascii')}")
            return 0
        if args.node_cmd == "run":
            host, port = _parse_host_port(args.listen)
            args.host = host
            args.port = port
            return run_node_cli(args)
        if args.node_cmd == "status":
            node = Node(args.dir)
            if not node.verify_integrity():
                print(f"NODE CORRUPT: {args.dir}", file=sys.stderr)
                return 1
            print(f"NODE OK: applied_epoch={node.applied_epoch()}")
            return 0

    if args.command == "node-init":
        pk = base64.b64decode(args.admin_pubkey_b64, validate=True)
        Node.initialise(args.dir, args.feed_id, pk)
        print(f"Node initialised at {args.dir} (feed_id={args.feed_id})")
        return 0

    if args.command == "node-status":
        node = Node(args.dir)
        ok = node.verify_integrity()
        if not ok:
            print(f"NODE CORRUPT: {args.dir}", file=sys.stderr)
            return 1
        print(f"NODE OK: applied_epoch={node.applied_epoch()}")
        return 0

    if args.command == "log-verify":
        pk = base64.b64decode(args.pubkey_b64, validate=True) if args.pubkey_b64 else None
        res = AuditLog(args.db, args.head).verify(verifier_public_key=pk)
        if not res.valid:
            print(f"AUDIT LOG INVALID: first_bad_seq={res.first_bad_seq} reason={res.reason}", file=sys.stderr)
            return 1
        print(f"AUDIT LOG OK: events={res.event_count} head_seq={res.head_seq}")
        return 0

    if args.command == "backup-verify":
        pk = base64.b64decode(args.pubkey_b64, validate=True)
        try:
            ver, _ = verify_and_load_backup(args.file, pk, expected_min_version=args.min_version)
        except BackupVerificationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"BACKUP OK: version={ver}")
        return 0

    if args.command == "detect-eval":
        m = evaluate_detection()
        print(f"F1={m['f1']} median_tta_ms={m['median_time_to_alert_ms']} false_alerts/1k={m['false_alerts_per_1000_benign']}")
        return 0

    if args.command == "bench":
        r = run_benchmarks(iterations=10)
        print(f"Detection F1={r['detection']['f1']} Revocation last_node_ms={r['revocation']['last_node_enforcement_ms']}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
