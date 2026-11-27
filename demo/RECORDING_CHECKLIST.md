# Graviton 5-Minute Demo Recording Checklist

- **0:00 — Problem & USP**: Explain separation of post-quantum policy (`ML-DSA-65`) from untrusted SQLite storage (`relay_vault.db` ciphertext only) and hardened Track 4 adapter (`track4_service.py`).
- **0:45 — Adapter & Toolkit Validator**: Run `python ../Track-4-Toolkit/validate.py --entry ../Graviton/track4_service.py` (22/22 PASS) and `python -m unittest tests/adapter/test_adapter_hardening.py -v` (rollback, audit delete/truncate, `key_material` absent, `request_id` reuse, import guard).
- **1:30 — Rotation & Revocation Across 3 Live Nodes**: Run `python -m graviton.demo`; highlight old key rejected across all 3 nodes after cutoff and lost-device revocation measured to the LAST node (`build/probe.json`).
- **2:30 — Crash & Backup Corruption Recovery**: Show `test_crash_recovery.py` (`kill -9` mid-rotation) and `create_backup` / `verify_and_load_backup` rejecting tampered version/bytes.
- **3:15 — Tamper-Evident Audit & Log Injection**: Show `graviton audit verify` passing and newline/JSON log-injection attempts escaped and inert.
- **4:00 — Detection Alerts & Clock Skew Uncertainty**: Run `python -m graviton detect-eval --out build/detect-metrics.json` (practice + 10-seed held-out families) and show `order_uncertain` beyond `MAX_SKEW_MS=5000ms`.
- **4:40 — Limits & Honesty**: State plain-TCP metadata visibility, plaintext-in-state adapter trade-off (host-root MAC forgery), single-hub data plane, and local loopback scope.
