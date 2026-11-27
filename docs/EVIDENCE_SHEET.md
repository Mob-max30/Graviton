# Graviton Evidence Sheet (Track 4)

- **Repository**: Graviton (`pranav` branch)
- **Adapter Entry**: `track4_service.py` -> `team_app.py` -> `graviton_app.py` -> `graviton/adapter_store.py`
- **Dependencies**:
  - Core / Adapter: Python 3.12 + `pqcrypto==0.4.0` (`ML-KEM-768`, `ML-DSA-65`)
  - Full Engine Extra: `cryptography==50.0.2` (`AES-256-GCM`, `scrypt` keystores)
- **Adapter Security Controls**:
  - Key separation (`TRACK4_KEY_DIR` separate from `TRACK4_STATE_DIR`, `0700`/`0600` POSIX permissions)
  - RFC 5869 HKDF-SHA256 (`k_state`, `k_audit`, `k_head`) derived from `secrets.token_bytes(32)` + `key_material`; raw `key_material` never persisted
  - `state_mac` (HMAC-SHA256) on canonical state + anti-rollback `.head.json`
  - Hash-chained + HMAC'd `audit_log.jsonl` with `O_APPEND` + `os.fsync` and single-use `request_id` (first-write-wins)
  - Bounded exclusive advisory file lock (`4.0s` timeout)
- **Generated Evidence Files**:
  - `build/probe.json`: 3-node (30 runs) and 5-node (10 runs) real-process revocation propagation
  - `build/detect-metrics.json`: synthetic, Track-4-Toolkit `practice/`, and 10-seed held-out family metrics
  - `build/bench.json`: adapter cold-start, ML-KEM-768, E2EE throughput, audit append/verify, and detector benchmarks
  - `build/evidence/demo_evidence.json`: 3-node E2EE, rotation cutoff, revocation, backup corruption, red-team, and audit verify run
  - `build/FINAL_REPORT.md`: full verification gate outputs and hard-coding audit
