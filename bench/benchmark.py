"""Performance benchmark reporting cold start, crypto latency, throughput, and memory."""
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.audit.logger import SignedAuditLogger
from trustledger.audit.verifier import verify_log
from trustledger.cluster.gossip import GossipCluster
from trustledger.crypto.keys import HybridIdentityKeypair, TrustedPeerStore
from trustledger.crypto.suites import CipherSuite
from trustledger.detect.engine import DetectionPipeline
from trustledger.protocol.handshake import HandshakeInitiator, HandshakeResponder
from trustledger.protocol.ratchet import SymmetricRatchetSession


def bench_adapter_cold_start(n_runs: int = 15) -> tuple[float, float]:
    """Measure adapter cold-start process spawn latency (p50 and p95)."""
    latencies: list[float] = []
    repo_root = Path(__file__).resolve().parent.parent
    entry = repo_root / "track4_service.py"

    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as key_dir:
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = tmp_dir
        env["TRACK4_KEY_DIR"] = key_dir
        setup_req = json.dumps({"op": "setup", "owners": {"a1": "u1"}, "contents": {"a1": "v1"}, "disabled": [], "key_material": "k1"})
        read_req = json.dumps({"op": "read", "actor": "u1", "asset": "a1", "request_id": "r1"})

        subprocess.run([sys.executable, "-B", str(entry)], input=setup_req, text=True, capture_output=True, env=env, check=False)

        for _ in range(n_runs):
            t0 = time.monotonic()
            subprocess.run([sys.executable, "-B", str(entry)], input=read_req, text=True, capture_output=True, env=env, check=False)
            t1 = time.monotonic()
            latencies.append((t1 - t0) * 1000.0)

    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    return p50, p95


def run_all_benchmarks(out_path: Path | None = None) -> dict[str, Any]:
    specs = f"{platform.system()} {platform.machine()} - Python {platform.python_version()}"
    print(f"Running benchmarks on: {specs}...")

    p50_adapter, p95_adapter = bench_adapter_cold_start(10)

    c_key = HybridIdentityKeypair.generate()
    s_key = HybridIdentityKeypair.generate()
    trust = TrustedPeerStore()
    trust.register_peer("c", c_key, CipherSuite.SUITE_PQ)
    trust.register_peer("s", s_key, CipherSuite.SUITE_PQ)

    t0 = time.monotonic()
    for _ in range(20):
        init = HandshakeInitiator("c", "client", c_key, CipherSuite.SUITE_PQ, trusted_peers=trust)
        resp = HandshakeResponder("s", "server", s_key, trusted_peers=trust)
        s_nonce, kem_ct, s_x, s_sig, _ = resp.process_client_hello_and_reply(
            init.identity, init.role, CipherSuite.SUITE_PQ, init.client_nonce, init.ephemeral_key.kem_pk, None
        )
        c_sig, _c_keys = init.process_server_hello_and_authenticate("s", "server", s_key.dsa_pk, None, s_nonce, kem_ct, s_x, s_sig)
        resp.complete_handshake(c_key.dsa_pk, None, c_sig)
    hs_pq_ms = ((time.monotonic() - t0) / 20.0) * 1000.0

    alice = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "a", "b", "fp", b"1" * 32, b"2" * 32)
    bob = SymmetricRatchetSession("s1", CipherSuite.SUITE_PQ, "b", "a", "fp", b"2" * 32, b"1" * 32)
    t0 = time.monotonic()
    for i in range(1000):
        ct = alice.encrypt_message(b"Benchmark test payload 1234567890", f"m-{i}")
        bob.decrypt_message(ct, i, f"m-{i}", "a", "b", "fp", 1, total_length=33)
    ratchet_msgs_sec = 1000.0 / (time.monotonic() - t0)

    cluster = GossipCluster([f"node-{i}" for i in range(10)])
    gossip_stats = cluster.measure_propagation_distribution(20)

    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "bench.log"
        pk, sk = ml_dsa.generate_keypair()
        logger = SignedAuditLogger(log_file, "k1", sk, checkpoint_interval=50)
        t0 = time.monotonic()
        for _ in range(200):
            logger.append_entry("u1", "read", "a1", "allow")
        logger.finalize()
        audit_append_sec = 200.0 / (time.monotonic() - t0)

        t0 = time.monotonic()
        verify_log(log_file, pk)
        audit_verify_ms = (time.monotonic() - t0) * 1000.0

    from eval.generate import SyntheticLogGenerator

    gen = SyntheticLogGenerator(seed=42)
    events_raw, approvals_doc, _ = gen.generate_workload(num_benign=2000, num_attacks=50)
    with tempfile.TemporaryDirectory() as tmp_dir:
        ef = Path(tmp_dir) / "ev.jsonl"
        with open(ef, "w", encoding="utf-8") as f:
            for ev in events_raw:
                f.write(json.dumps(ev) + "\n")
        af = Path(tmp_dir) / "appr.json"
        af.write_text(json.dumps(approvals_doc), encoding="utf-8")

        pipeline = DetectionPipeline(af)
        t0 = time.monotonic()
        pipeline.run_file(ef)
        detect_events_sec = len(events_raw) / (time.monotonic() - t0)

    results: dict[str, Any] = {
        "platform": specs,
        "cpu_count": os.cpu_count(),
        "adapter_cold_start_p50_ms": round(p50_adapter, 2),
        "adapter_cold_start_p95_ms": round(p95_adapter, 2),
        "pq_handshake_latency_ms": round(hs_pq_ms, 2),
        "ratchet_msgs_per_sec": round(ratchet_msgs_sec, 1),
        "revocation_gossip_p50_ms": round(gossip_stats.p50_ms, 3),
        "audit_append_entries_per_sec": round(audit_append_sec, 1),
        "audit_verify_200_ms": round(audit_verify_ms, 2),
        "detector_events_per_sec": round(detect_events_sec, 1),
    }

    target = out_path or (Path(__file__).resolve().parent.parent / "build" / "bench-metrics.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


if __name__ == "__main__":
    res = run_all_benchmarks()
    print("\nBenchmark Results Summary:")
    print("---------------------------------------------------------------------")
    for k, v in res.items():
        print(f"{k:35s}: {v}")
    print("---------------------------------------------------------------------")
