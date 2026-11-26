"""Performance & overhead benchmark for Graviton PQC primitives and 10k-event detection."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.crypto import (
    aead_decrypt,
    aead_encrypt,
    generate_hybrid_kem_keypair,
    generate_sign_keypair,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    sign_message,
    verify_signature,
)
from graviton.detector import AccessEvent, TrustDetector


def main() -> None:
    # 1. Hybrid KEM + ML-DSA-65 + AES-256-GCM microbenchmarks
    t0 = time.perf_counter()
    for _ in range(50):
        kp = generate_hybrid_kem_keypair()
        ct, xpk, ss1 = hybrid_kem_encapsulate(kp.mlkem_pk, kp.x25519_pk)
        ss2 = hybrid_kem_decapsulate(kp.mlkem_sk, kp.x25519_sk, ct, xpk)
        assert ss1 == ss2
    kem_ms = (time.perf_counter() - t0) * 1000.0 / 50

    skp = generate_sign_keypair()
    msg = b"graviton-benchmark-payload"
    t0 = time.perf_counter()
    for _ in range(100):
        sig = sign_message(skp.secret_key, msg)
        assert verify_signature(skp.public_key, msg, sig)
    sig_ms = (time.perf_counter() - t0) * 1000.0 / 100

    key = b"k" * 32
    t0 = time.perf_counter()
    for _ in range(1000):
        n, c = aead_encrypt(key, msg, b"aad")
        assert aead_decrypt(key, n, c, b"aad") == msg
    aead_us = (time.perf_counter() - t0) * 1_000_000.0 / 1000

    # 2. 10,000-event detector scale benchmark
    events = [
        AccessEvent(f"ev-{i}", float(i), f"user-{i % 50}", "read", "vault" if i % 2 else "auth", label="benign")
        for i in range(10_000)
    ]
    det = TrustDetector()
    t0 = time.perf_counter()
    alerts = det.analyze(events)
    det_ms = (time.perf_counter() - t0) * 1000.0

    print(
        json.dumps(
            {
                "hybrid_kem_roundtrip_ms": round(kem_ms, 3),
                "mldsa65_sign_verify_ms": round(sig_ms, 3),
                "aes256gcm_roundtrip_us": round(aead_us, 2),
                "detector_10k_events_ms": round(det_ms, 2),
                "detector_alerts": len(alerts),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
