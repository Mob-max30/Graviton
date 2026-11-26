"""Unified benchmark suite covering Section 20."""
from __future__ import annotations

from importlib.metadata import version as pkg_version
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

from graviton.audit import AuditLog, AuthenticatedSession
from graviton.comms import decrypt_message, encrypt_message, establish_session
from graviton.crypto.signatures import generate_signing_keypair
from graviton.detect import evaluate_detection
from graviton.harness.runner import run_revocation_scenario, run_rotation_scenario


def run_benchmarks(*, iterations: int = 20) -> dict:
    try:
        pqc_ver = pkg_version("pqcrypto")
    except Exception:
        pqc_ver = "unknown"

    metadata = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pqcrypto": pqc_ver,
    }

    detection = evaluate_detection(benign_count=1000, attack_count=20, seed=42)
    revocation = run_revocation_scenario(node_count=5, delay_ms=(0, 50), seed=1)
    rotation = run_rotation_scenario(node_count=5, delay_ms=(0, 50), seed=1)

    a_pk, a_sk = generate_signing_keypair()
    b_pk, b_sk = generate_signing_keypair()
    setup_ms: list[float] = []
    enc_ms: list[float] = []
    dec_ms: list[float] = []
    for i in range(iterations):
        t0 = time.perf_counter_ns()
        sa, sb, _ = establish_session("alice", a_sk, a_pk, "bob", b_sk, b_pk)
        setup_ms.append((time.perf_counter_ns() - t0) / 1_000_000)

        t1 = time.perf_counter_ns()
        env = encrypt_message(sa, "alice", "bob", i, b"benchmark-payload-128B" * 5)
        enc_ms.append((time.perf_counter_ns() - t1) / 1_000_000)

        t2 = time.perf_counter_ns()
        pt = decrypt_message(sb, env, "bob")
        dec_ms.append((time.perf_counter_ns() - t2) / 1_000_000)
        assert pt.startswith(b"benchmark-payload-128B")

    messaging = {
        "iterations": iterations,
        "session_setup_median_ms": round(statistics.median(setup_ms), 3),
        "encrypt_median_ms": round(statistics.median(enc_ms), 3),
        "decrypt_median_ms": round(statistics.median(dec_ms), 3),
    }

    with tempfile.TemporaryDirectory(prefix="graviton-bench-log-") as tmp:
        base = Path(tmp)
        db_path = base / "audit.db"
        head_path = base / "audit_head.json"
        log = AuditLog(db_path, head_path)
        sess = AuthenticatedSession("alice", "bench")
        append_ms: list[float] = []
        for i in range(50):
            t0 = time.perf_counter_ns()
            log.append_event(sess, "read", f"asset_{i}", "allow", "ok")
            append_ms.append((time.perf_counter_ns() - t0) / 1_000_000)
        log.create_checkpoint(a_sk, "admin")

        t_ver = time.perf_counter_ns()
        res = log.verify(verifier_public_key=a_pk)
        verify_ms = (time.perf_counter_ns() - t_ver) / 1_000_000
        assert res.valid
        storage_bytes = db_path.stat().st_size + head_path.stat().st_size

    overhead = {
        "events_logged": 50,
        "log_append_median_ms": round(statistics.median(append_ms), 3),
        "log_verify_50_events_ms": round(verify_ms, 3),
        "storage_bytes": storage_bytes,
    }

    return {
        "metadata": metadata,
        "detection": detection,
        "revocation": {
            "node_count": revocation["node_count"],
            "delay_ms": revocation["delay_ms"],
            "last_node_enforcement_ms": revocation["last_node_enforcement_ms"],
            "max_compute_ms": revocation["max_compute_ms"],
            "all_nodes_denied": revocation["all_nodes_denied"],
        },
        "rotation": {
            "node_count": rotation["node_count"],
            "pre_cutoff_v1_all_allow": rotation["pre_cutoff_v1_all_allow"],
            "post_cutoff_v2_all_allow": rotation["post_cutoff_v2_all_allow"],
            "catchup_ms": rotation["catchup_ms"],
        },
        "messaging": messaging,
        "overhead": overhead,
    }
