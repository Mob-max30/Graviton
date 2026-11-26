"""CLI entrypoint for `python -m graviton.harness`."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from graviton.harness.runner import (
    _runtime_metadata,
    run_device_loss_scenario,
    run_freshness_scenario,
    run_revocation_scenario,
    run_rotation_scenario,
)


def _parse_delay(spec: str) -> tuple[int, int]:
    parts = spec.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("delay-ms must be MIN:MAX (e.g. 0:50)")
    lo, hi = int(parts[0]), int(parts[1])
    if lo < 0 or hi < lo:
        raise argparse.ArgumentTypeError("Invalid delay-ms range")
    return lo, hi


def _print_summary(report: dict) -> None:
    meta = report["metadata"]
    print(f"Graviton Harness | Python {meta['python']} | pqcrypto {meta['pqcrypto']} | {meta['platform']}")
    print(f"Note: {meta['simulation_note']}")
    for sc in report["scenarios"]:
        name = sc["scenario"]
        if name == "revocation":
            print(
                f"[revocation] nodes={sc['node_count']} delay_ms={sc['delay_ms']} "
                f"all_denied={sc['all_nodes_denied']} last_node_ms={sc['last_node_enforcement_ms']} "
                f"max_compute_ms={sc['max_compute_ms']}"
            )
        elif name == "rotation":
            print(
                f"[rotation] nodes={sc['node_count']} pre_v1_allow={sc['pre_cutoff_v1_all_allow']} "
                f"lagging={sc['lagging_node']}({sc['lagging_node_v1_before_catchup']}) "
                f"post_v2_allow={sc['post_cutoff_v2_all_allow']} catchup_ms={sc['catchup_ms']}"
            )
        elif name == "device_loss":
            print(
                f"[device_loss] nodes={sc['node_count']} lost_denied={sc['lost_device_denied_everywhere']} "
                f"new_allowed={sc['new_device_allowed_everywhere']} peer_ok={sc['peer_unaffected_everywhere']} "
                f"revoke_last_ms={sc['revoke_last_node_ms']}"
            )
        elif name == "freshness":
            print(
                f"[freshness] nodes={sc['node_count']} window_s={sc['freshness_window_s']} "
                f"stale_reason={sc['stale_node_reason']} fresh_ok={sc['fresh_nodes_allowed']} "
                f"recovered={sc['recovered_decision']} revoked_stays={sc['revoked_stays_revoked']}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graviton multi-node simulation harness")
    parser.add_argument(
        "--scenario",
        choices=["revocation", "rotation", "device_loss", "freshness", "all"],
        default="all",
    )
    parser.add_argument("--nodes", type=int, default=5)
    parser.add_argument("--delay-ms", type=_parse_delay, default=(0, 50))
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    selected = (
        ["revocation", "rotation", "device_loss", "freshness"]
        if args.scenario == "all"
        else [args.scenario]
    )
    runners = {
        "revocation": lambda: run_revocation_scenario(node_count=args.nodes, delay_ms=args.delay_ms, seed=args.seed),
        "rotation": lambda: run_rotation_scenario(node_count=args.nodes, delay_ms=args.delay_ms, seed=args.seed),
        "device_loss": lambda: run_device_loss_scenario(node_count=args.nodes, delay_ms=args.delay_ms, seed=args.seed),
        "freshness": lambda: run_freshness_scenario(node_count=args.nodes, delay_ms=args.delay_ms, seed=args.seed),
    }

    report = {
        "metadata": _runtime_metadata(),
        "scenarios": [runners[name]() for name in selected],
    }
    _print_summary(report)
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
