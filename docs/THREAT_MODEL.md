# Graviton Threat Model

## 1. Protected Assets
1. **Policy Feed and Trust Root**: Admin `ML-DSA-65` public key, `feed_id`, and hash-chained policy entries (`REGISTER_KEY`, `ROTATE_KEY`, `REVOKE_DEVICE`, `REVOKE_ACTOR`) replicated across enforcement nodes.
2. **Identity and Signing Keys**: `ML-DSA-65` keys stored in `scrypt` + `AES-256-GCM` keystores (`admin.keystore.json`, `member.keystore.json`) and unlocked only in memory via runtime passphrase.
3. **E2EE Messages and File Chunks**: Plaintext messages and chunked files encrypted end-to-end (`ML-KEM-768` + `HKDF-SHA256` + `AES-256-GCM`) before leaving the sender; node SQLite (`relay_vault.db`) stores opaque ciphertext JSON only.
4. **Audit Logs and Key Backups**: Hash-chained SQLite `audit.db` (with SQLite triggers and signed checkpoints), adapter `audit_log.jsonl` (hash-chained + `k_audit` HMAC), and `ML-DSA-65`-signed key backups.
5. **Adapter State**: Track 4 adapter state (`owners`, `contents`, `disabled`, `revoked` tombstones) authenticated with `k_state` HMAC and anti-rollback `.head.json` in a separate `TRACK4_KEY_DIR`.

## 2. Threat Actors
- **Network Attacker**: Captures, replays, tampers with, or floods TCP frames or sends forged `FEED_PUSH` entries. Denied by per-connection nonces/sequences, `ML-DSA-65` signatures, pre-allocation frame limits, and feed chain verification.
- **Malicious or Revoked Insider**: Uses a revoked key, probes another member's envelopes, or attempts privilege escalation / `relay -> vault -> admin` lateral movement. Denied by every node and alerted by Sentinel.
- **Lost-Device Finder**: Possesses a stolen device keystore or key; once revoked, every node rejects it after feed convergence.
- **Database Thief / Host-File Tamperer**: Copies or edits `relay_vault.db`, `adapter_state.json`, or `audit_log.jsonl`. `relay_vault.db` contains zero plaintext or keys; adapter state/log tampering or snapshot rollback triggers `integrity_violation`.
- **Malicious Log Author**: Injects newlines, quotes, or fake JSON in `actor` or `request_id`; neutralized by canonical JSON escaping.

## 3. Trust Assumptions
- The group admin workstation and admin `ML-DSA-65` key are trusted (admin key is a single point of failure).
- Sender and recipient endpoints are uncompromised while unlocked; OS CSPRNG (`secrets`) and `pqcrypto==0.4.0` are sound.
- Admin and members verify short SHA-256 fingerprints out-of-band before `join` and `approve`.

## 4. Honest Limitations
- **Transport Metadata**: TCP traffic is plaintext unless optional classical TLS (`--tls-cert`/`--tls-key`) is enabled; handles, sizes, and timing are visible.
- **Adapter Confidentiality**: Track 4 adapter `adapter_state.json` stores asset contents in plaintext (integrity-protected by `k_state` HMAC, not encrypted) because the adapter path is stdlib + `pqcrypto` only and refuses custom ciphers.
- **Host Root**: A host-root attacker with read/write access to both `TRACK4_STATE_DIR` and `TRACK4_KEY_DIR` can forge MACs.
- **Architecture Scope**: Single-hub `relay`/`vault` data plane in v1; local loopback clusters only (multi-machine not tested); Python code is not guaranteed constant-time; not independently audited.
