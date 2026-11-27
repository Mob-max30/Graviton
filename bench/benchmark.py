"""Phase 6: Comprehensive performance benchmark writing build/bench.json."""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import platform
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pqcrypto.kem import ml_kem_768

from graviton.audit import AuditLog, AuthenticatedSession
from graviton.comms.session import encrypt_message, establish_session
from graviton.crypto.signatures import generate_signing_keypair
from graviton.detect.engine import DetectionEngine
from graviton.detect.eval import generate_labelled_dataset

ENTRY = REPO_ROOT / "track4_service.py"


def _pct(sorted_vals: list[float], p: float) -> float:
    idx = min(len(sorted_vals) - 1, max(0, math.ceil((p / 100.0) * len(sorted_vals)) - 1))
    return round(sorted_vals[idx], 3)


def _stats(vals: list[float]) -> dict:
    s = sorted(vals)
    return {
        "runs": len(s),
        "p50_ms": round(statistics.median(s), 3),
        "p95_ms": _pct(s, 95),
        "p99_ms": _pct(s, 99),
    }


def run_all_benchmarks(*, adapter_runs: int = 50, out_path: Path | None = None) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="graviton_bench_"))
    try:
        # 1. Adapter cold-start per op (setup, read, revoke, audit, protected_read)
        state_dir = tmp / "state"
        key_dir = tmp / "keys"
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(state_dir)
        env["TRACK4_KEY_DIR"] = str(key_dir)

        def _call(payload: dict) -> float:
            t0 = time.perf_counter()
            p = subprocess.run(
                [sys.executable, str(ENTRY)],
                input=json.dumps(payload).encode("utf-8"),
                capture_output=True,
                env=env,
                cwd=str(REPO_ROOT),
                timeout=15,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode("utf-8", errors="replace"))
            return dt

        km = secrets.token_hex(16)
        setup_lat = [
            _call({"op": "setup", "owners": {"doc": "alice"}, "contents": {"doc": "body"}, "key_material": km})
            for _ in range(adapter_runs)
        ]
        read_lat = [
            _call({"op": "read", "actor": "alice", "asset": "doc", "request_id": f"r-{i}"})
            for i in range(adapter_runs)
        ]
        audit_lat = [
            _call({"op": "audit", "request_id": f"r-{i}"})
            for i in range(adapter_runs)
        ]
        pk, _ = ml_kem_768.generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        pread_lat = [
            _call({
                "op": "protected_read",
                "actor": "alice",
                "asset": "doc",
                "challenge": f"c-{i}",
                "public_key": pk_b64,
                "request_id": f"pr-{i}",
            })
            for i in range(adapter_runs)
        ]
        revoke_lat = [
            _call({"op": "revoke", "actor": f"u-{i}"})
            for i in range(adapter_runs)
        ]

        # 2. ML-KEM-768 encapsulation & signed handshake
        kem_lat: list[float] = []
        for _ in range(100):
            t0 = time.perf_counter()
            ml_kem_768.encrypt(pk)
            kem_lat.append((time.perf_counter() - t0) * 1000.0)

        a_pk, a_sk = generate_signing_keypair()
        b_pk, b_sk = generate_signing_keypair()
        hs_lat: list[float] = []
        for _ in range(20):
            t0 = time.perf_counter()
            s_a, _, _ = establish_session("a", a_sk, a_pk, "b", b_sk, b_pk)
            hs_lat.append((time.perf_counter() - t0) * 1000.0)

        # 3. E2EE message throughput
        t0 = time.perf_counter()
        n_msgs = 200
        for i in range(n_msgs):
            encrypt_message(s_a, "a", "b", i, b"benchmark-payload-128bytes-" * 4)
        e2ee_dt = time.perf_counter() - t0

        # 4. Audit append+fsync rate & 1000-record verify
        alog = AuditLog(tmp / "audit.db", tmp / "audit_head.json")
        t0 = time.perf_counter()
        for i in range(200):
            alog.append_event(AuthenticatedSession(actor="a"), "READ", "doc", "allow", f"i={i}")
        append_dt = time.perf_counter() - t0
        for i in range(200, 1000):
            alog.append_event(AuthenticatedSession(actor="a"), "READ", "doc", "allow", f"i={i}")
        t0 = time.perf_counter()
        ver = alog.verify()
        assert ver.valid
        verify_1k_ms = (time.perf_counter() - t0) * 1000.0

        # 5. Detector events/sec
        raw_evs, approvals, _ = generate_labelled_dataset(seed=1)
        eng = DetectionEngine(approvals=approvals)
        t0 = time.perf_counter()
        eng.analyze(raw_evs)
        det_dt = time.perf_counter() - t0

        result = {
            "environment": {
                "os": f"{platform.system()} {platform.release()}",
                "python": platform.python_version(),
                "cpu_count": os.cpu_count(),
            },
            "adapter_cold_start_ms": {
                "setup": _stats(setup_lat),
                "read": _stats(read_lat),
                "revoke": _stats(revoke_lat),
                "audit": _stats(audit_lat),
                "protected_read": _stats(pread_lat),
            },
            "crypto_and_messaging": {
                "ml_kem_768_encap_ms": _stats(kem_lat),
                "signed_handshake_ms": _stats(hs_lat),
                "e2ee_msgs_per_sec": round(n_msgs / max(e2ee_dt, 1e-6), 2),
            },
            "audit_log": {
                "append_fsync_per_sec": round(200 / max(append_dt, 1e-6), 2),
                "verify_1000_records_ms": round(verify_1k_ms, 3),
            },
            "detector": {
                "events": len(raw_evs),
                "events_per_sec": round(len(raw_evs) / max(det_dt, 1e-6), 2),
            },
        }
        target = out_path or (REPO_ROOT / "build" / "bench.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    print(json.dumps(run_all_benchmarks(), indent=2))
