"""CLI entrypoint for `python -m graviton.bench`."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from graviton.bench.suite import run_benchmarks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graviton unified benchmark suite")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    report = run_benchmarks(iterations=args.iterations)
    m = report["metadata"]
    d = report["detection"]
    r = report["revocation"]
    rot = report["rotation"]
    msg = report["messaging"]
    ov = report["overhead"]

    print(f"Graviton Benchmark | Python {m['python']} | pqcrypto {m['pqcrypto']} | {m['platform']}")
    print(
        f"  Detection : F1={d['f1']} median_tta={d['median_time_to_alert_ms']}ms "
        f"false_alerts/1k={d['false_alerts_per_1000_benign']}"
    )
    print(
        f"  Revocation: nodes={r['node_count']} delay_ms={r['delay_ms']} "
        f"last_node_ms={r['last_node_enforcement_ms']} max_compute_ms={r['max_compute_ms']}"
    )
    print(
        f"  Rotation  : pre_v1_allow={rot['pre_cutoff_v1_all_allow']} "
        f"post_v2_allow={rot['post_cutoff_v2_all_allow']} catchup_ms={rot['catchup_ms']}"
    )
    print(
        f"  Messaging : setup_median={msg['session_setup_median_ms']}ms "
        f"encrypt_median={msg['encrypt_median_ms']}ms decrypt_median={msg['decrypt_median_ms']}ms"
    )
    print(
        f"  Overhead  : log_append_median={ov['log_append_median_ms']}ms "
        f"verify_50={ov['log_verify_50_events_ms']}ms storage={ov['storage_bytes']}B"
    )

    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
