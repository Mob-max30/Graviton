"""Subprocess latency benchmark for track4_service.py (stdlib + pqcrypto only)."""
from __future__ import annotations

import argparse
import base64
from importlib.metadata import version as pkg_version
import json
import math
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import tempfile
import time

from pqcrypto.kem import ml_kem_768

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_POINT = REPO_ROOT / "track4_service.py"


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, math.ceil((pct / 100.0) * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def _invoke(payload: dict, state_dir: Path) -> tuple[float, dict]:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    stdin_bytes = json.dumps(payload).encode("utf-8")
    t0 = time.perf_counter_ns()
    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRY_POINT)],
        input=stdin_bytes,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=15,
        check=True,
    )
    dt_ms = (time.perf_counter_ns() - t0) / 1_000_000
    return dt_ms, json.loads(proc.stdout.decode("utf-8"))


def measure_operations(n: int) -> dict:
    timings: dict[str, list[float]] = {
        "setup": [],
        "read": [],
        "revoke": [],
        "audit": [],
        "protected_read": [],
    }
    pk, _ = ml_kem_768.generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")

    with tempfile.TemporaryDirectory(prefix="graviton-bench-") as tmp:
        state_dir = Path(tmp)

        # Measure setup (N fresh setups)
        for i in range(n):
            dt, res = _invoke(
                {
                    "op": "setup",
                    "owners": {"brief": "maya", "doc": "peer"},
                    "contents": {"brief": "demo note", "doc": "peer note"},
                    "disabled": [],
                    "key_material": secrets.token_hex(16),
                },
                state_dir,
            )
            assert res.get("ready") is True
            timings["setup"].append(dt)

        # Measure read (N authorised reads)
        req_ids: list[str] = []
        for i in range(n):
            rid = f"r_{i}"
            req_ids.append(rid)
            dt, res = _invoke(
                {"op": "read", "actor": "maya", "asset": "brief", "request_id": rid},
                state_dir,
            )
            assert res.get("decision") == "allow"
            timings["read"].append(dt)

        # Measure audit (N lookups)
        for rid in req_ids:
            dt, res = _invoke({"op": "audit", "request_id": rid}, state_dir)
            assert res.get("decision") == "allow"
            timings["audit"].append(dt)

        # Measure protected_read (N ML-KEM-768 reads)
        for i in range(n):
            dt, res = _invoke(
                {
                    "op": "protected_read",
                    "actor": "maya",
                    "asset": "brief",
                    "challenge": secrets.token_hex(16),
                    "public_key": pk_b64,
                },
                state_dir,
            )
            assert "ciphertext" in res and "proof" in res
            timings["protected_read"].append(dt)

        # Measure revoke (N distinct actors so each revoke is real work)
        for i in range(n):
            dt, _ = _invoke({"op": "revoke", "actor": f"actor_{i}"}, state_dir)
            timings["revoke"].append(dt)

    summary = {}
    for op, vals in timings.items():
        s = sorted(vals)
        summary[op] = {
            "n": len(s),
            "p50_ms": round(_percentile(s, 50), 2),
            "p95_ms": round(_percentile(s, 95), 2),
            "max_ms": round(max(s), 2),
        }

    try:
        pqc_ver = pkg_version("pqcrypto")
    except Exception:
        pqc_ver = "unknown"

    return {
        "metadata": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pqcrypto": pqc_ver,
        },
        "operations": summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure per-process adapter latency")
    parser.add_argument("--n", type=int, default=100, help="Requests per operation (default: 100)")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    result = measure_operations(args.n)
    meta = result["metadata"]
    print(f"Adapter Latency | N={args.n} | Python {meta['python']} | pqcrypto {meta['pqcrypto']} | {meta['platform']}")
    print(f"{'operation':<16} {'n':>5} {'p50_ms':>10} {'p95_ms':>10} {'max_ms':>10}")
    for op, stats in result["operations"].items():
        print(f"{op:<16} {stats['n']:>5} {stats['p50_ms']:>10.2f} {stats['p95_ms']:>10.2f} {stats['max_ms']:>10.2f}")

    if args.out is not None:
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
