# Track 4 Evidence Matrix — Graviton

| # | Track 4 Requirement | Implementation | Verification / Test |
|---|---|---|---|
| 1 | **Key rotation** | `KeyLifecycleManager.rotate_key()`, `NodeVerifier.set_cutoff()` (`graviton/lifecycle.py`) | `test_key_rotation_revocation_crash_recovery_and_backup` |
| 2 | **Revocation across nodes** | `KeyLifecycleManager.revoke_and_propagate()`, `reenroll_after_device_loss()` (`graviton/lifecycle.py`) | `test_key_rotation_revocation_crash_recovery_and_backup` |
| 3 | **Crash recovery** | `KeyLifecycleManager._append_wal()`, `_load_or_recover()` (`graviton/lifecycle.py`) | `test_key_rotation_revocation_crash_recovery_and_backup`, `test_redteam_truncated_wal_crash_recovery` |
| 4 | **Backup integrity** | `create_backup()`, `restore_backup()` with AES-GCM + SHA-256 + ML-DSA-65 + epoch check | `test_key_rotation_revocation_crash_recovery_and_backup`, `test_redteam_path_traversal_and_rollback_blocked` |
| 5 | **Log integrity** | `AuditLog.append()`, `_sanitize_text()`, `verify_log(from_disk=True)` (`graviton/audit_log.py`) | `test_audit_log_integrity_and_injection_resistance`, `test_redteam_log_injection_and_clock_skew_uncertainty` |
| 6 | **Routine & suspicious activity** | `TrustDetector.analyze()`, `evaluate()` (`graviton/detector.py`) | `test_detector_routine_lateral_movement_and_clock_skew`, `scripts/evaluate_detection.py` |
| 7 | **Lateral movement** | `TrustDetector` service-transition graph + `Alert.path` & `explanation` | `test_detector_routine_lateral_movement_and_clock_skew`, `scripts/explain.py` |
| 8 | **Clock differences** | `SUPPORTED_CLOCK_SKEW_S = 300.0`, `order_uncertain` flag (`graviton/detector.py`) | `test_redteam_log_injection_and_clock_skew_uncertainty`, `scripts/timeline.py` |
| 9 | **Replay & recipient binding** | `MessagingEndpoint.send()`, `receive()` AAD + `seen_seqs` (`graviton/messaging.py`) | `test_messaging_pqc_reordering_replay_recipient_resumption_and_close` |
| 10 | **Forward secrecy** | Ephemeral Hybrid KEM (`ML-KEM-768 + X25519`) + `erase_secret_keys()` (`graviton/messaging.py`) | `test_redteam_true_forward_secrecy_after_longterm_key_compromise` |
| 11 | **Delivery under loss/reordering** | `reorder_buffer`, `report_incomplete_deliveries()`, `discard_incomplete()` | `test_messaging_pqc_reordering_replay_recipient_resumption_and_close`, `test_redteam_delivery_under_loss_and_corruption_discarded` |
| 12 | **Session resumption** | `make_resumption_proof()`, `resume_session()` with HMAC + ML-DSA-65 signature | `test_redteam_session_resumption_hijack_blocked` |
