# TrustLedger System Architecture

TrustLedger is designed for high-assurance post-quantum zero-trust data access, identity control, and explainable log-based detection.

```
                           +----------------------------------------+
                           |       Untrusted Client Invocations     |
                           +----------------------------------------+
                                              |
                                              v
+==================================================================================+
|  LAYER A: JUDGED CORE (track4_service.py -> team_app.py -> trustledger/core/)     |
|                                                                                  |
|  - Strictly Standard Library + Lazy pqcrypto (ML-KEM-768)                        |
|  - Bounded cold start: < 45 ms per invocation (target < 150 ms)                  |
|  - Advisory Cross-Platform File Lock (fcntl on POSIX / msvcrt on Windows)        |
|  - Atomic Write-Temp-Fsync-Replace State Store (state.json + .head.json)       |
|  - Isolated Key Dir (.tl-keys-<hash> / TRACK4_KEY_DIR, 0700, symlink checks)   |
|  - Append-only Hash-Chained Audit Logging (audit.log with fsync per change)      |
|  - Pure Operations: setup, read, revoke, audit, protected_read                   |
+==================================================================================+
                                              |
                                              v
+==================================================================================+
|  LAYER B: FULL SECURITY PLATFORM (trustledger/{crypto, protocol, keys, ...})     |
|                                                                                  |
|  1. Cryptographic Suites:                                                        |
|     - SUITE_PQ: ML-KEM-768 + ML-DSA-65 via pqcrypto==0.4.0                       |
|     - SUITE_HYBRID: ML-KEM-768/X25519 + ML-DSA-65/Ed25519                        |
|     - AEAD: ChaCha20-Poly1305 with per-key counter nonces & 12-field AD binding  |
|                                                                                  |
|  2. Resilient Protocol & Channels:                                               |
|     - Ephemeral Authenticated Handshake with Forward Secrecy                     |
|     - Symmetric Ratchet with 128-bit Replay Window & Bounded ID Cache            |
|     - 16 KiB Chunking + Byte-Slice Reed-Solomon Forward Error Correction (FEC)   |
|     - AEAD-Sealed Resumption Tickets with Single-Use Replay Guards               |
|                                                                                  |
|  3. Key Lifecycle & Cluster Coordination:                                        |
|     - States: PENDING -> ACTIVE -> GRACE (300s) -> RETIRED; any -> REVOKED      |
|     - Two-Phase Commit Rotation via HMAC-authenticated Write-Ahead Log (WAL)     |
|     - Monotonically Versioned Revocation via Simulated In-Process Gossip         |
|     - Encrypted Backups with Signed Merkle Root Manifest & Anti-Rollback Guard   |
|                                                                                  |
|  4. Explainable Detection Pipeline (NO AI / NO ML):                              |
|     - Streaming Ingest -> Clock Alignment & Malformed-Event Quarantine           |
|     - Approvals Context Join (valid_from/valid_until_utc exclusive window)       |
|     - Data-Driven BaselineProvider (TRACK4_BASELINE / warm-up, no hard-coding) |
|     - Robust Non-Parametric Statistics: Median & Median Absolute Deviation (MAD) |
|     - Rules: R-PRIV-1/2/3/5, R-CRED-1, R-LAT-1/2/3, R-NORM-1, and R-STAT-1       |
|     - Directed Service-Graph Path Traversal & Active Containment Overlay         |
+==================================================================================+
```

## Data Flows & State Durability
1. **Request Reception:** Client JSON is read from stdin (capped at 1 MiB).
2. **Lock Acquisition:** Exclusive lock acquired on `state.lock` with a `4.0`-second timeout (`FileLock(store.lock_file, timeout_seconds=4.0)` in `trustledger/core/service.py`).
3. **Integrity Check:** `state.json` loaded; HMAC-SHA256 verified against derived `k_state`. Mismatch immediately aborts with fail-closed integrity error.
4. **Authorization & Revocation:** Current identity evaluated against `disabled` and `revoked_tombstones`.
5. **Audit Event Generation:** Canonical JSON record constructed, hash-chained with `prev_hash`, authenticated with `k_audit`, appended to `audit.log`, and fsynced.
6. **State Atomic Replace:** If state changed, written to unique temp file, fsynced, and atomically replaced (`os.replace`).
7. **Response Emission:** Exact JSON response encoded (no NaN) and flushed to stdout.
