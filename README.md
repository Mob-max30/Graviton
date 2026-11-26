# Graviton — Track 4: "Trust, but verify"

Post-Quantum Cryptography (`ML-KEM-768 + X25519` Hybrid KEM, `ML-DSA-65`, `AES-256-GCM`), Atomic Key Lifecycle Management, Injection-Safe Audit Logging, and Explainable Lateral-Movement Detection.

## Clean-Machine Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -v
```

## Architecture

- `graviton/crypto.py`: Post-quantum `ML-KEM-768` & `ML-DSA-65` (`pqcrypto==0.4.0`) + `X25519` Hybrid KEM + `AES-256-GCM` + `HKDF-SHA256` (fails closed if PQC libraries are absent).
- `graviton/messaging.py`: True ephemeral forward-secret E2EE sessions, replay & recipient AAD binding, out-of-order delivery with loss reporting, and ML-DSA-65-bound session resumption.
- `graviton/lifecycle.py`: Key rotation with grace-period cutoff, multi-node revocation propagation, device-loss re-enrollment, checksummed WAL crash recovery, and AES-GCM + ML-DSA-65 + anti-rollback backups.
- `graviton/audit_log.py`: Hash-chained, ML-DSA-65-signed append-only audit log with control-character/ANSI sanitization against log injection.
- `graviton/detector.py`: Explainable rule + service-graph detector with clock-skew normalization (`±300s`) reporting F1, median time-to-alert, and false alerts per 1,000 benign events.
- `graviton/dashboard.py`: FastAPI operator console (`uvicorn graviton.dashboard:app --port 8000`).

## CLI & Verification Scripts

```bash
python scripts/chaos_demo.py          # Full Track 4 end-to-end walkthrough
python scripts/evaluate_detection.py  # 1,050-event labelled evaluation (F1, TTA, FA/1k)
python scripts/explain.py             # Human-readable alert explanations
python scripts/timeline.py            # Clock-skew-normalized event timeline
python scripts/bench.py               # PQC & 10k-event performance benchmark
```

## Documentation

- [2-Page Project Brief & Threat Model](docs/two-page-brief.md)
- [Track 4 Evidence Matrix](docs/evidence-matrix.md)
