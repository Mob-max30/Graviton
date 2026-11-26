# Trust, but verify: Official Repository Evidence Sheet

Team: DevForge | Date/time: 2026-11-26 | Environment: Windows AMD64 (8 CPUs, Python 3.13.14) and Linux python:3.12-slim container.

All 12 goals have automated, reproducible demonstrations. Status values: `measured`. Evidence links are repository-relative.

| Goal | Public Demonstration & Evidence to Collect | Expected Behavior Defined Before Run | Actual Result / Status / Evidence Link |
|---|---|---|---|
| **1. Key rotation** | Documented two-phase commit rotation. Record version IDs, activation epochs, and dual-key acceptance across live traffic. | Atomically commit epoch bump via WAL; dual-accept old key during 300s grace; reject new requests on old key after cutoff. | **measured**<br/>Verified in [`tests/fault_injection/test_key_rotation.py`](tests/fault_injection/test_key_rotation.py). Phase 1 PREPARE -> Phase 2 COMMIT. Epoch 1 -> 2. |
| **2. Revocation across nodes** | Anti-entropy gossip revocation across simulated cluster nodes. Measure propagation time from node 0 to all peers. | All nodes converge to latest revocation version; access denied at use-time on all nodes post-convergence. | **measured**<br/>Verified in [`tests/fault_injection/test_cluster_revocation.py`](tests/fault_injection/test_cluster_revocation.py). p50 propagation 0.025 ms across 10 nodes. |
| **3. Crash recovery** | Inject crash at named points during rotation and revocation. Restart and replay WAL. | Deterministically roll forward committed changes; roll back uncommitted changes; assert exactly 1 ACTIVE key. | **measured**<br/>Verified in [`tests/fault_injection/test_crash_recovery.py`](tests/fault_injection/test_crash_recovery.py). Invariants hold after crash in PREPARE and COMMIT. |
| **4. Backup integrity** | Encrypted AEAD backup bundle with signed Merkle root manifest. Test restore, tampering, and rollback. | Restore validates signature, Merkle root, and backup counter before decrypting; rejects rollback to older backups. | **measured**<br/>Verified in [`tests/fault_injection/test_backup_integrity.py`](tests/fault_injection/test_backup_integrity.py). Bit-flip, entry swap, forged sig, and rollback caught. |
| **5. Log integrity** | Canonical JSONL append-only audit log with SHA-256 hash chains, ML-DSA-65 signatures, and periodic + terminal Merkle checkpoints. | Offline verification CLI `trustledger verify-log` detects deletion, tail truncation, empty logs, and record modification. | **measured**<br/>Verified in [`tests/unit/test_audit_log.py`](tests/unit/test_audit_log.py). CLI verified 200 records in 81.7 ms; tail truncation and empty logs fail with `TRUNCATED`. |
| **6. Routine vs suspicious activity** | Process public practice events. Compare explanations with `labels.csv`. Flag unapproved changes and access. | Approved change-100 (evt-003..005) produces no alert; unexpected change evt-008 flagged with missing authorization. | **measured**<br/>Verified in [`tests/unit/test_practice_golden.py`](tests/unit/test_practice_golden.py). 100% agreement with public worked examples. |
| **7. Lateral movement** | Graph analysis grouping unexpected denied service edges in flow-005 into a candidate sequence. | Group evt-010..012 by actor, session, and flow into candidate sequence; isolated denial evt-020 produces no sequence alert. | **measured**<br/>Verified in [`tests/unit/test_practice_golden.py`](tests/unit/test_practice_golden.py). Emits R-LAT-2 candidate sequence; avoids false compromise claim. |
| **8. Clock differences** | Process evt-015 (+2000ms offset) and evt-013/014 (inverted arrival). Correct timeline and flag uncertainty. | Corrected timestamp for evt-015 matches 09:06:01; arrival disorder flagged as order_uncertain, not replay. | **measured**<br/>Verified in [`tests/unit/test_practice_golden.py`](tests/unit/test_practice_golden.py). Corrected time computed; order uncertainty recorded. |
| **9. Replay & recipient binding** | Verify bounded skipped-key reorder buffer, replay guard, and 12-field Associated Data (AD) binding in symmetric ratcheting session. | Out-of-order 0,2,1 succeeds; replayed sequences or duplicate message IDs rejected; modifying any AD field fails authentication. | **measured**<br/>Verified in [`tests/unit/test_ratchet.py`](tests/unit/test_ratchet.py) and [`tests/adversarial/test_adversarial_suite.py`](tests/adversarial/test_adversarial_suite.py). |
| **10. Forward secrecy** | Ephemeral ML-KEM-768 + X25519 key exchange with `TrustedPeerStore` pinning. Record session, leak long-term private keys, attempt decryption. | Past recorded session traffic cannot be decrypted despite full leakage of long-term identity keys; unpinned keys rejected. | **measured**<br/>Verified in [`tests/unit/test_suites.py`](tests/unit/test_suites.py). Ephemeral secrets deleted immediately after derivation. |
| **11. Delivery under loss/reordering** | Transmit chunked messages with keyed HMAC-SHA256 tags and full-length message IDs through network impairment simulator. | Reed-Solomon FEC recovers erasures and bit-flips under 8% loss; forged chunks and prefix-colliding IDs rejected. | **measured**<br/>Verified in [`tests/property/test_fec_and_delivery.py`](tests/property/test_fec_and_delivery.py). 205/205 seeds passed; forged chunk rejected. |
| **12. Session resumption** | Issue AEAD-sealed resumption ticket with durable atomic single-use store. Test resumption across simulated restart. | Valid ticket resumes session with fresh keys; replayed (including across restarts), expired, or wrong-identity tickets rejected. | **measured**<br/>Verified in [`tests/unit/test_tickets.py`](tests/unit/test_tickets.py). Durable replay guard verified across restart. |

---

## Measurement Records

### Record 1: Official Toolkit Adapter Compliance
- **Claim**: `track4_service.py` satisfies all lost-device setup, read, revocation, peer isolation, and audit requirements without secret leakage.
- **Setup & Input**: Official Track-4-Toolkit `validate.py` (v1.0.0, commit 8901dfb). Random 16-hex actors, 12-hex assets, 24-hex bodies.
- **Procedure**: `python ../Track-4-Toolkit/validate.py --entry track4_service.py --timeout 8`
- **Expected**: Exit code 0, all format, setup, and behavior checks PASS.
- **Observed**: 22/22 checks PASS, Exit status 0. Cold start p50=193.2 ms / p95=203.19 ms on Windows Python 3.13.14.
- **Evidence**: [`tests/adapter/test_toolkit_validator.py`](tests/adapter/test_toolkit_validator.py), [`build/bench-metrics.json`](build/bench-metrics.json)

### Record 2: Explainable Detector Metrics (10-Seed, Held-Out Families & Practice Evaluation)
- **Claim**: Detector evaluates synthetic workloads across 10 seeds, 6 held-out scenario families, and `fixtures/practice` with full precision/recall/F1/FAR/TTA reporting.
- **Setup & Input**: Synthetic event generator across 10 random seeds (1,500 benign events, 60 injected attack events per seed), 6 held-out families, and 22-event `fixtures/practice`.
- **Procedure**: `python -m eval.evaluate` (or `python tasks.py metrics`)
- **Expected**: Measured precision, recall, F1, false alerts per 1,000 benign events, event-time TTA, processing latency, and throughput written to `build/eval-metrics.json`.
- **Observed**: 10-seed Precision=0.8849, Recall=0.3333, F1=0.4838, FAR/1k=1.8, Event TTA=100.0 ms, Proc latency=0.0179 ms, Throughput=91,885.31 events/sec; `fixtures/practice` & 6/6 held-out families P=1.0, R=1.0, F1=1.0, FAR/1k=0.0.
- **Evidence**: [`eval/evaluate.py`](eval/evaluate.py), [`build/eval-metrics.json`](build/eval-metrics.json)

### Record 3: Adversarial Red-Team Resilience
- **Claim**: TrustLedger defends against all 28 adversarial & red-team regression test cases without unhandled exceptions or state corruption.
- **Setup & Input**: 28 adversarial, fuzz, and red-team regression test cases covering replay, reflection, KCI, UKS, downgrade, ticket reuse, nonce reuse, TOCTOU, state/head rollback, log injection, forged WAL, and detector evasion.
- **Procedure**: `python -m trustledger.cli selftest-attack`
- **Expected**: 28/28 attacks defended and handled with fail-closed rejections.
- **Observed**: 28/28 PASS.
- **Evidence**: [`tests/adversarial/test_adversarial_suite.py`](tests/adversarial/test_adversarial_suite.py), [`tests/adversarial/test_redteam_regressions.py`](tests/adversarial/test_redteam_regressions.py)
