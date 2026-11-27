# Graviton Threat Model

## 1. Protected Assets
1. **Group Policy & Trust Root**: The admin `ML-DSA-65` public key, `feed_id`, and hash-chained policy entries (`REGISTER_KEY`, `ROTATE_KEY`, `REVOKE_DEVICE`, `REVOKE_ACTOR`) stored on every enforcement node.
2. **Member & Admin Private Keys**: `ML-DSA-65` signing keys stored in `scrypt` + `AES-256-GCM` keystores (`admin.keystore.json`, `member.keystore.json`) and unlocked only in memory via runtime passphrase.
3. **E2EE Message & File Confidentiality**: Plaintext messages and files encrypted end-to-end (`ML-KEM-768` + `HKDF-SHA256` + `AES-256-GCM`) before leaving the sender; node SQLite (`relay_vault.db`) stores only opaque ciphertext JSON.
4. **Session Forward Secrecy**: Ephemeral `ML-KEM-768` secret keys (`eph_sk`) are deleted immediately upon `decapsulate()`, and session keys are stored only inside the member's `AES-256-GCM`-encrypted `sessions.enc.json`.
5. **Audit Log Integrity**: Per-node SQLite `audit.db` protected by SHA-256 hash chaining, SQLite `UPDATE`/`DELETE` triggers, external head files, and signed checkpoints.

## 2. Threat Actors & Capabilities
- **Database Thief (`Mallory` with read/copy access to `relay_vault.db`)**: Can read or copy SQLite files from a node. Cannot recover plaintext, private keys, or session keys because none are stored on the node.
- **Database Tamperer (`Mallory` with write access to `relay_vault.db`)**: Can modify, truncate, or reorder rows. Recipients detect tampering via `AES-256-GCM` tag and associated data `(recipient_id, sender_id, session_id, counter)` and discard incomplete or corrupt chunked transfers.
- **Network Active Attacker**: Can replay captured `MSG_REQUEST` frames, tamper with wire bytes, send oversized frames, or forge `MSG_FEED_PUSH` entries. Denied by per-connection `server_nonce` + `seq`, `ML-DSA-65` signatures, pre-allocation frame bounds, and feed chain verification.
- **Revoked or Compromised Member Device**: A lost or revoked device key is rejected independently by every node once the `REVOKE_*` feed entry propagates.
- **Insider / Lateral Movement**: A valid member attempting `admin` operations or unexpected `relay -> vault -> admin` paths is denied at the node and alerted by Sentinel (`DetectionEngine`).

## 3. Trust Assumptions
1. **Admin Key & Admin Machine**: The group admin `ML-DSA-65` key is a single point of failure, and the admin workstation is trusted.
2. **Member Endpoints**: Sender and recipient devices are assumed uncompromised while unlocked.
3. **Out-of-Band Fingerprint Verification**: Admin and member verify short SHA-256 fingerprints out-of-band before completing `join` and `approve`.
4. **Adapter Trust Domain**: On the Track 4 competition adapter path (`track4_service.py`), admin key and node state share one host directory.

## 4. Explicit Limitations (Out of Scope in v1)
- **Transport Metadata**: Plaintext TCP is used by default (optional classical `--tls-cert`/`--tls-key`); handles, sizes, and timing are visible to the network and nodes.
- **Single-Hub Data Plane**: Policy feeds replicate across nodes, while `relay` and `vault` ciphertexts live on the target node only.
- **Clock Synchronisation**: Nodes do not run a distributed clock protocol; Sentinel flags skew outside `MAX_SKEW_MS` (`5000ms`) as `order_uncertain`.
- **Research Prototype**: Not independently audited; multi-machine operation across separate physical hosts was not tested.
