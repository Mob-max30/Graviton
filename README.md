# Graviton — Post-Quantum Identity, E2EE & Explainable Detection

Track 4 prototype protecting organization files and messages using vetted post-quantum cryptography (`pqcrypto` ML-KEM-768 + ML-DSA-65) and hybrid X25519 + AES-256-GCM, paired with tamper-evident logging and a non-ML rule/graph detector.

## Clean-Machine Setup & Terminal CLI

```bash
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .
```

### Terminal Commands
```bash
gt -register <company-name>
gt use <company-name>
gt ls
gt -add <file-or-folder-path>
gt -add-people
gt -chat
```

## Run Verification Tests

```bash
python -m pytest -v
```

## Security & Operational Policies

- **Post-Quantum & Hybrid Cryptography:** `ML-DSA-65` for identity, authority, backup, and audit-log signatures; hybrid `ML-KEM-768 + X25519` with `HKDF-SHA256` for ephemeral forward-secret sessions; `AES-256-GCM` with strict AAD binding.
- **Key Rotation & Grace Period:** Two-phase WAL rotation (`PREPARE` -> `COMMIT`). Every node rejects **new** requests using the old key immediately after `cutoff_at`. When `grace_seconds > 0`, only in-flight transfers started before `cutoff_at` may complete until `grace_until`.
- **Clock Skew Support:** Detector supports out-of-order events within `±30.0` seconds (`supported_skew_range_sec = [-30.0, 30.0]`) and flags `uncertain_order = true` when consecutive events fall within the overlapping uncertainty window.
- **Non-ML Detection:** Uses deterministic contextual rules, statistical thresholds, and `networkx` directed service graphs (no AI/ML components).
