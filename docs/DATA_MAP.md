# Graviton Data Map

This document inventories every directory, file, and SQLite database created by Graviton, based directly on the source code.

---

## 1. Adapter State Area (`TRACK4_STATE_DIR` or `<os_temp>/graviton_state`)

Resolved by `get_state_dir()` in `graviton_app.py`. Directories are created with mode `0o700` via `ensure_state_dir()` and files with mode `0o600` via `atomic_write_text()` or `os.open()` in `graviton/storage.py` (where supported by the OS).

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<state_dir>/` | Root adapter state directory (`0o700`) | `ensure_state_dir()` (`graviton/storage.py`) | `graviton_app.py` | Contains all adapter generation dirs & lock | Lists active generation names | Delete/corrupt denies all `read`/`protected_read` (fail-closed) |
| `<state_dir>/.state.lock` | Cross-process exclusive lock file (`0o600`, 0B POSIX / 1B Windows) | `state_lock()` (`graviton/storage.py`) | `state_lock()` (`graviton/storage.py`) | None | None | Holding exclusive lock causes DoS/timeout on adapter ops |
| `<state_dir>/current_generation.json` | JSON `{"version":2,"generation":"gen_<24hex>"}` (`0o600`) | `_handle_setup()` via `atomic_write_text()` (`graviton_app.py`) | `_resolve_generation_dir()` (`graviton_app.py`) | None | Reveals active generation directory name | Corrupt/delete/point to missing dir causes fail-closed `deny` on `read`/`protected_read` and errors on `revoke`/`audit` |
| `<state_dir>/gen_<24hex>/` | Isolated state directory for one `setup` generation (`0o700`) | `_handle_setup()` (`graviton_app.py`) | `_resolve_generation_dir()` (`graviton_app.py`) | Contains `adapter_state.json`, `admin_key.json`, `node/` | Exposes generation contents if OS permissions bypassed | Deleting active generation causes fail-closed `deny` |
| `<state_dir>/gen_<24hex>/adapter_state.json` | JSON `{"version":2,"owners":{...},"contents":{...},"key_material":"..."}` (`0o600`) | `_handle_setup()` (`graviton_app.py`) | `_load_adapter_state()` (`graviton_app.py`) | **`key_material`** (synthetic secret string, plaintext on disk, `0o600`, owner-only) and protected asset **`contents`** (plaintext on disk) | **Critical**: discloses `key_material`, all asset `contents`, and `owners` | Corrupt/delete causes fail-closed `deny`; tampering `owners`/`contents` alters served data/ownership |
| `<state_dir>/gen_<24hex>/admin_key.json` | JSON `{"version":2,"feed_id":"...","admin_secret_key_b64":"...","epoch":N,"last_hash_hex":"..."}` (`0o600`) | `_handle_setup()`, `_handle_revoke()` (`graviton_app.py`) | `_handle_revoke()` (`graviton_app.py`) | **Adapter Admin ML-DSA-65 secret key** (`admin_secret_key_b64`, 4032 B raw, ML-DSA-65, secret, on disk, **plaintext**, `0o600`, owner-only) | **Critical**: attacker can forge valid `REVOKE_ACTOR` (or other feed entries) for that `feed_id` | Corrupt/delete breaks `revoke` (`state_corrupt`/`revoke_author_failed`); overwriting key breaks feed signing continuity |
| `<state_dir>/gen_<24hex>/audit_log.jsonl` | Append-only JSON-lines decision log (`request_id`, `op`, `actor`, `asset`, `decision`, internal `reason`) (`0o600`) | `_handle_setup()` (empty init), `_append_audit_record()` (`graviton_app.py`) | `_find_audit_record()` via `_handle_audit()` (`graviton_app.py`) | None (no `key_material` or `contents`) | Reveals actors, asset IDs, request IDs, and internal deny reasons | Tampering alters `audit` lookup responses (Phase 1/4 adapter log is not hash-chained; see `graviton/audit/log.py` for hash-chained log) |
| `<state_dir>/gen_<24hex>/.tmp_*.part` | Transient atomic-write staging file (`0o600`, deleted on `os.replace` or error) | `atomic_write_text()` (`graviton/storage.py`) | Never read by application | Transient copy of file being written | Brief exposure window during write if host compromised | Ignored on crash; unlinked on exception |

---

## 2. Independent Enforcement Node Directory (`<node_dir>`, or `<gen_dir>/node/`)

Managed by `Node` in `graviton/nodes/node.py`.

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<node_dir>/` | Node state directory (`0o700`) | `Node.initialise()` (`graviton/nodes/node.py`), `ensure_state_dir()` | `Node` (`graviton/nodes/node.py`) | None | None | Delete causes `STATE_CORRUPT` (`deny` everywhere) |
| `<node_dir>/.state.lock` | Node-level cross-process lock (`0o600`) | `state_lock()` (`graviton/storage.py`) | `Node` methods via `_state_lock()` | None | None | Holding lock causes DoS/timeout |
| `<node_dir>/node_state.json` | JSON `{"version":1,"feed_id":...,"admin_public_key_b64":...,"applied_epoch":N,"last_entry_hash_hex":...,"applied_entries":[b64...],"last_issued_at":T,"registry":{...},"revoked_actors":[...]}` (`0o600`) | `Node.initialise()`, `Node.apply_entry()` (`graviton/nodes/node.py`) | `Node._load_raw_state()`, `Node.verify_integrity()`, `Node.authorize()`, `Node.authenticate_request()`, `Node.check_actor()` | **Admin ML-DSA-65 public key** (`admin_public_key_b64`, 1952 B, public, plaintext) and **Device ML-DSA-65 public keys** (`registry[actor][dev].versions[v].public_key_b64`, public, plaintext) | Reveals registered actors, devices, public keys, revocation status, and feed history | Any tampering with `registry`, `applied_entries`, or schema fails `verify_integrity()` -> node fails closed with `STATE_CORRUPT` (`deny`). Replacing `admin_public_key_b64` + entire `applied_entries` with attacker-signed chain requires full write access to node disk |

---

## 3. Tamper-Evident Audit Log (`graviton/audit/log.py`)

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<db_path>` (e.g. `audit.db`, SQLite) | Tables `audit_events` (hash-chained events) and `audit_checkpoints` (ML-DSA-65 signed heads), protected by `BEFORE UPDATE`/`DELETE` abort triggers | `AuditLog._init_storage()`, `append_event()`, `create_checkpoint()` (`graviton/audit/log.py`) | `AuditLog.fetch_events()`, `AuditLog.verify()` (`graviton/audit/log.py`), `graviton/audit/__main__.py`, `graviton/cli/__main__.py` | None (checkpoint signatures are public signatures) | Reveals actors, actions, targets, decisions, details | `UPDATE`/`DELETE` aborted by SQLite triggers; dropping triggers + editing rows is detected by `AuditLog.verify()` (`record_hash`/`prev_hash` mismatch); wholesale DB rewrite is detected against `<external_head_path>` |
| `<external_head_path>` (e.g. `audit_head.json`) | JSON `{"version":1,"seq":N,"head_hash_hex":"..."}` (`0o600`) | `AuditLog._write_external_head()` (`graviton/audit/log.py`) | `AuditLog.verify()` (`graviton/audit/log.py`) | None | Reveals latest log sequence number and SHA-256 head hash | Tampering causes `AuditLog.verify()` to report external head mismatch; attacker who controls *both* DB and external head file can rewrite history unless checkpoint `verifier_public_key` is also checked |

---

## 4. Key Lifecycle, WAL & Signed Backups (`graviton/lifecycle/`)

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<lifecycle_dir>/lifecycle_state.json` | JSON `{"version":1,"active_version":V,"keys":{ver:{"public_key_b64":...,"status":...}},"revoked_versions":[...]}` (`0o600`) | `RotationManager.initialise()`, `rotate()`, `revoke_version()`, `recover()` (`graviton/lifecycle/rotation.py`) | `RotationManager._load()`, `get_state_snapshot()`, `recover()` | **Key version public keys** (`public_key_b64`, public, plaintext) | Reveals key versions, statuses, and revocations | Corrupt/delete breaks rotation/recovery; un-revoking a version in file would allow use if attacker has host write access |
| `<lifecycle_dir>/rotation_wal.json` | JSON `{"version":1,"step":"IDLE\|PREPARE\|COMMIT\|ACTIVATE\|RETIRE","pending":{...}}` (`0o600`) | `RotationManager.initialise()`, `rotate()`, `recover()` (`graviton/lifecycle/rotation.py`) | `RotationManager._load()`, `recover()` | Pending rotation **public key** (`new_public_key_b64`, public, plaintext) | Reveals in-flight rotation state | Corrupting WAL disrupts recovery |
| `<backup_path>` (e.g. `keys.bak`) | JSON envelope `{"format_version":1,"backup_version":V,"payload_b64":"...","signature_b64":"..."}` (`0o600`) | `create_backup()` (`graviton/lifecycle/backup.py`) | `verify_and_load_backup()` (`graviton/lifecycle/backup.py`) | Backup payload (e.g. key material map, plaintext inside `payload_b64`, authenticated by ML-DSA-65 signature) | Discloses backed-up key material if read | Any byte flip, truncation, or version swap fails `verify_and_load_backup()` (`BackupVerificationError`) and is logged to `AuditLog` |

---

## 5. Encrypted Keystore (`graviton/crypto/keystore.py`)

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<keystore_path>` (e.g. `alice.keystore.json`) | JSON `{"version":1,"identity_id":...,"kdf":"scrypt","scrypt":{n,r,p,salt_b64},"public_key_b64":...,"nonce_b64":...,"ciphertext_b64":...}` (`0o600`) | `save_keystore()` (`graviton/crypto/keystore.py`) | `load_keystore()` (`graviton/crypto/keystore.py`) | **Identity secret key** (ML-DSA-65 or ML-KEM-768, **encrypted at rest** with `hashlib.scrypt` + `AES-256-GCM`, bound to `identity_id` AAD) + **public key** (plaintext) | Cannot recover secret key without brute-forcing user password against `scrypt` (`n=16384, r=8, p=1`) | Any modification fails AES-256-GCM tag verification (`KeystoreError`) |

---

## 6. Messaging Replay Cache & Offline Queue (`graviton/comms/`)

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `<cache_path>` (e.g. `replay_cache.json`) | JSON `{"version":1,"sessions":{sid:{"seen":[...],"floor":N}}}` (`0o600`) | `ReplayCache._save()` via `check_and_record()` (`graviton/comms/session.py`) | `ReplayCache._load()` (`graviton/comms/session.py`) | None | Reveals session IDs and seen message counters | Deleting/resetting cache could allow replay of previously seen messages |
| `<queue_path>` (e.g. `queue.json`) | JSON `{"version":1,"items":[{"recipient_id":...,"envelope":{...},"delivered":bool}]}` (`0o600`) | `OfflineQueue.enqueue()` (`graviton/comms/delivery.py`) | `OfflineQueue.pending_for()` (`graviton/comms/delivery.py`) | None (stores encrypted/authenticated message envelopes only) | Reveals queue metadata (sender, recipient, session ID, counter, size); in `hmac-sha256-fallback` mode (without `cryptography`), payload is base64-encoded rather than encrypted | Dropping items causes message loss; modifying envelopes fails recipient-bound AEAD/HMAC verification on `decrypt_message()` |

---

## 7. Benchmark / Harness Optional Output Files

| Path pattern | Contents | Writers | Readers | Keys / Secrets stored | Attacker **read** impact | Attacker **write / delete** impact |
| --- | --- | --- | --- | --- | --- | --- |
| `--out <path>` (e.g. `results.json`) | JSON benchmark/harness timing & detection metrics | `graviton/harness/__main__.py:main()`, `graviton/bench/__main__.py:main()` | Operator | None | Reveals latency & metric measurements only | Corrupts local report file only |

---

## 8. Cryptographic Keys & Secrets Summary

| Key / Secret | Algorithm | Public / Secret | Storage | Encryption at Rest | Who Can Read |
| --- | --- | --- | --- | --- | --- |
| Adapter `admin_secret_key` | ML-DSA-65 (4032 B) | **Secret** | On disk (`<gen_dir>/admin_key.json`) | **Plaintext** (`0o600`) | Local OS user / adapter process |
| Adapter `key_material` | Synthetic string | **Secret** | On disk (`<gen_dir>/adapter_state.json`) | **Plaintext** (`0o600`) | Local OS user / adapter process (never logged/returned) |
| `protected_read` `shared_secret` | ML-KEM-768 (32 B) | **Secret** | **In memory only** (`_handle_protected_read`) | N/A (never written to disk) | Single request process only |
| FeedAuthor `admin_secret_key` | ML-DSA-65 (4032 B) | **Secret** | **In memory only** (`FeedAuthor._admin_secret_key`) | N/A | Authoring process only |
| Device / Identity `secret_key` | ML-DSA-65 / ML-KEM-768 | **Secret** | Keystore file (`save_keystore`) | **Encrypted** (`scrypt` + `AES-256-GCM`, `0o600`) | Holder of keystore password |
| Ephemeral KEM `eph_sk` & `ss` | ML-KEM-768 | **Secret** | **In memory only** (`establish_session`), deleted immediately | N/A | Handshake function scope only |
| `SessionContext.session_key` | HKDF-SHA-256 (32 B) | **Secret** | **In memory only** (`SessionContext`), zeroed by `erase()` | N/A | Session endpoints only |
| `ResumptionManager._ticket_secret` | HMAC-SHA-256 (32 B) | **Secret** | **In memory only** (`ResumptionManager`) | N/A | Resumption server process |
| Admin / Device `public_key` | ML-DSA-65 (1952 B) | **Public** | On disk (`node_state.json`, `lifecycle_state.json`, keystore) | Plaintext | Anyone with node/state access |

---

## 9. Exact State Directory Contents After One Adapter `setup` Plus One `revoke`

Observed by running `setup` followed by `revoke` against `track4_service.py` with `TRACK4_STATE_DIR` set to a fresh directory:

```text
<TRACK4_STATE_DIR>/                           (dir, 0o700)
├── .state.lock                               (1 B on Windows / 0 B on POSIX, 0o600)
├── current_generation.json                   (57 B, 0o600) -> {"version":2,"generation":"gen_<24hex>"}
└── gen_<24hex>/                              (dir, 0o700)
    ├── adapter_state.json                    (0o600) -> owners, contents, key_material
    ├── admin_key.json                        (5553 B, 0o600) -> feed_id, admin_secret_key_b64, epoch=2, last_hash_hex
    ├── audit_log.jsonl                       (0 B until first read, 0o600)
    └── node/                                 (dir, 0o700)
        ├── .state.lock                       (0o600)
        └── node_state.json                   (0o600) -> GENESIS (epoch 1) + REVOKE_ACTOR (epoch 2)
```
