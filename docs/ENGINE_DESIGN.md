# Graviton Real Terminal Security Engine — Design Document (Phase 11, Stage 0)

## 1. Process Model

Every node, sentinel, and CLI invocation is a real OS process started from the terminal:

| Component | Entrypoint / Command | Lifecycle | State Directory |
| --- | --- | --- | --- |
| **Enforcement Node** | `graviton node run` (`graviton/daemon/node.py`) | Long-running TCP daemon | `--dir <node_dir>` (contains `node_state.json`, `node_key.keystore.json` or `0600` key, `relay_vault.db`, `audit.db`, `audit_head.json`, `invites.db`) |
| **Detection Sentinel** | `graviton sentinel run` (`graviton/daemon/sentinel.py`) | Long-running polling daemon | `--dir <sentinel_dir>` (contains `cursors.json`, `alerts.jsonl`) |
| **Admin CLI** | `graviton admin ...` | Short-lived per command | `$GRAVITON_HOME/admin/` (`%APPDATA%\graviton\admin\` on Windows, `~/.config/graviton/admin/` on POSIX) |
| **Member Client CLI** | `graviton <cmd>` | Short-lived / interactive `cmd.Cmd` shell | `$GRAVITON_HOME/client/` (`keystore.json`, `config.json`, `replay_cache.json`, `resumption_tickets.json`) |

- Sample personas used across docs, tests, and demos: **Kavya** (group admin), **Arjun** & **Neel** (members), **Mallory** (attacker).
- **Single-hub data plane (v1)**: Policy feed (`Node` state) is replicated and independently enforced by every node. Ciphertext envelopes (`relay`) and file chunks (`vault`) live on each node's local SQLite DB (default home node: the hub); cross-node envelope replication is out of scope for v1.

---

## 2. Existing Code Inventory & Conflicts

| Module | Key Public API | Data Format | Conflicts / Adaptation Needed |
| --- | --- | --- | --- |
| `graviton/crypto/` | `generate_kem_keypair`, `encapsulate`, `decapsulate`, `generate_signing_keypair`, `sign_message`, `verify_signature`, `hkdf`, `build_associated_data`, `seal`, `open_sealed`, `save_keystore`, `load_keystore` | Raw ML-KEM-768 (1184/2400/1088/32 B), ML-DSA-65 (1952/4032/3309 B), `scrypt`+AES-256-GCM JSON keystore | None; Stage 4/keystore commands must fail closed if `cryptography` is absent |
| `graviton/feed/` | `enc_u8/u32/u64/bytes/str/id`, `Reader`, `FeedAuthor`, `verify_entry`, `EntryType` | Big-endian length-prefixed binary (`MAX_ID_LEN=256`, `MAX_ENTRY_LEN=16384`), ML-DSA-65 (`domain=b"feed"`) | None; `graviton/net/protocol.py` reuses `encoding.py` primitives |
| `graviton/nodes/` | `Node.initialise`, `apply_entry`, `apply_entries`, `authorize`, `authenticate_request`, `check_actor`, `verify_integrity`, `applied_epoch` | `node_state.json` (v1) | Add `entries_after(epoch)` for `FEED_PULL` and `get_device_public_key(actor, device_id, ver)` for wire-protocol `REQUEST` verification (keeping `authenticate_request` unchanged) |
| `graviton/audit/` | `AuditLog(db_path, external_head_path)`, `AuthenticatedSession`, `append_event`, `create_checkpoint`, `verify` | SQLite `audit_events` + `audit_checkpoints` (append-only triggers) + `audit_head.json` | Schema differs from `DetectionEngine` input dict; Stage 5 adds a thin mapper reading structured JSON in `detail` |
| `graviton/lifecycle/` | `RotationManager`, `create_backup`, `verify_and_load_backup` | `lifecycle_state.json`, `rotation_wal.json`, signed `.bak` | Reused directly |
| `graviton/comms/` | `establish_session`, `encrypt_message`, `decrypt_message`, `ReplayCache`, `split_into_chunks`, `ChunkedReceiver`, `OfflineQueue`, `ResumptionManager` | JSON envelope (`aes-256-gcm` or `hmac-sha256-fallback`) | Network data-plane must require `aead_available() == True` and fail closed otherwise |
| `graviton/detect/` | `DetectionEngine.analyze`, `order_events`, `evaluate_detection` | Normalized event dicts + `Alert` objects | Add `audit_event_to_detector_event()` mapper + `service` edge tracking |
| `graviton_app.py` / `track4_service.py` | `dispatch(request)` | Toolkit JSON adapter v1 | Untouched; never imports `net`, `daemon`, or `cli` |

---

## 3. Wire Protocol (`graviton/net/protocol.py`)

### Framing
```text
+--------------------+------------------------------------------+
| length (u32, 4 B)  | body (length bytes, <= MAX_FRAME_BYTES)  |
+--------------------+------------------------------------------+
```
- `MAX_FRAME_BYTES = 1_048_576` (1 MiB, configurable). `length` is checked **before** allocating/reading `body`.
- All integers are big-endian; all strings are strict UTF-8 via `graviton/feed/encoding.py`.

### Message Types
| Type | ID (`u8`) | Direction | Body Layout |
| --- | --- | --- | --- |
| `HELLO` | `1` | Server -> Client | `u8 proto_ver(1) | u8 type(1) | str feed_id | str node_id | u64 node_epoch | bytes[32] server_nonce | bytes[32] node_pk_sha256` |
| `REQUEST` | `2` | Client -> Server | `u8 proto_ver(1) | u8 type(2) | str actor | str device_id | u32 key_version | u32 seq | u8 op | bytes payload | bytes sig` |
| `RESPONSE` | `3` | Server -> Client | `u8 proto_ver(1) | u8 type(3) | u32 seq | u8 status | bytes payload | bytes sig` |
| `FEED_PUSH` | `4` | Client -> Server | `u8 proto_ver(1) | u8 type(4) | u32 count | [bytes entry_1 ...]` (pre-auth, self-authenticating) |
| `JOIN_REQUEST` | `5` | Client -> Server | `u8 proto_ver(1) | u8 type(5) | str invite_id | bytes invite_secret | str handle | str device_id | bytes device_pk | bytes pop_sig` (pre-auth, `domain=b"join"`) |

### Signature Constructions
- **`REQUEST` signature** (`domain=b"request"`):
  `enc_u8(1) + enc_id(feed_id) + enc_bytes(server_nonce) + enc_u32(seq) + enc_u8(op) + enc_bytes(sha256(payload))`
  Verified against `Node` registered ML-DSA-65 public key for `(actor, device_id, key_version)` **before** parsing `payload`.
- **`RESPONSE` signature** (`domain=b"response"`):
  `enc_u8(1) + enc_bytes(sha256(request_frame_body)) + enc_u8(status) + enc_bytes(sha256(payload))`
  Signed by the node's own ML-DSA-65 identity key; verified by the client against its pinned node public key.
- **`JOIN_REQUEST` proof of possession** (`domain=b"join"`):
  `enc_u8(1) + enc_id(invite_id) + enc_bytes(invite_secret) + enc_id(handle) + enc_id(device_id) + enc_bytes(device_pk)`

### Operations & Services Table
| Op Code | Name | Service | Who May Call |
| --- | --- | --- | --- |
| `1` | `STATUS` | `directory` | Pre-auth or any registered member |
| `2` | `FEED_PULL` | `directory` | Registered member or registered node |
| `10` | `PUT_ENVELOPE` | `relay` | Registered member (sender) |
| `11` | `LIST_INBOX` | `relay` | Registered member (recipient) |
| `12` | `FETCH_ENVELOPE` | `relay` | Registered member (recipient) |
| `13` | `ACK` | `relay` | Registered member (recipient) |
| `20` | `PUT_CHUNK` | `vault` | Registered member |
| `21` | `GET_CHUNK` | `vault` | Registered member |
| `30` | `AUDIT_PULL` | `admin` | Operator (`--operator HANDLE`) |
| `31` | `JOIN_LIST` | `admin` | Operator (`--operator HANDLE`) |
| `32` | `JOIN_RESOLVE` | `admin` | Operator (`--operator HANDLE`) |

Status codes: `0 = OK`, `1 = DENIED` (generic, no reason leaked), `2 = BAD_REQUEST`, `3 = RATE_LIMITED`.

---

## 4. SQLite Schemas (Node Data Plane, Parameterised Queries Only)

SQLite `3.50.4` is bundled and verified to support `DELETE ... RETURNING` inside `BEGIN IMMEDIATE`.

```sql
CREATE TABLE IF NOT EXISTS relay_envelopes (
    envelope_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    burn_after_read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_relay_recipient ON relay_envelopes(recipient, expires_at);

CREATE TABLE IF NOT EXISTS vault_chunks (
    chunk_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    recipient TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    invite_id TEXT PRIMARY KEY,
    secret_sha256 TEXT NOT NULL,
    handle_hint TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pending_joins (
    invite_id TEXT PRIMARY KEY,
    handle TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_pk_b64 TEXT NOT NULL,
    device_fp TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
);
```

---

## 5. Invitation Sequence Diagram

```text
Kavya (Admin)                     Hub Node                         Arjun (Member)
     |                                |                                  |
     |-- graviton admin invite arjun ->| (stores invite_id, sha256(sec)) |
     |   writes arjun.invite          |                                  |
     |                                |                                  |
     |======== out-of-band: Kavya shares arjun.invite + admin FP =======>|
     |                                |                                  |
     |                                |                 graviton init --handle arjun
     |                                |                 graviton join arjun.invite
     |                                |                 [HARD STOP: confirm admin FP]
     |                                |<-- JOIN_REQUEST (secret, pk, PoP)|
     |                                | (verifies sha256(secret), PoP,   |
     |                                |  marks invite used, stores pend) |
     |                                |                                  |
     |<- graviton admin pending ------|                                  |
     |   (displays Arjun's device FP) |                                  |
     |======== out-of-band: Arjun reads device FP to Kavya =============>|
     |-- graviton admin approve arjun |                                  |
     |   (signs REGISTER_KEY, pushes) |                                  |
     |-- FEED_PUSH(REGISTER_KEY) ---->| (verifies & applies to Node)     |
```

---

## 6. Limits, Rate Limits & Quotas

| Constant | Default | Purpose |
| --- | --- | --- |
| `MAX_FRAME_BYTES` | `1_048_576` (1 MiB) | Max TCP frame size |
| `READ_TIMEOUT_S` | `5.0` | Slow-client socket read timeout |
| `IDLE_TIMEOUT_S` | `30.0` | Idle connection timeout |
| `MAX_CONNECTIONS` | `64` | Concurrent client connection cap |
| `RATE_LIMIT_PER_SOURCE` | `60 req / 10s` | Per-IP token bucket |
| `RATE_LIMIT_PER_IDENTITY` | `120 req / 10s` | Per-actor token bucket |
| `MAX_ENVELOPES_PER_USER` | `500` | Relay quota per recipient |
| `MAX_STORAGE_BYTES_PER_USER` | `10_485_760` (10 MiB) | Relay + vault quota per user |
| `DEFAULT_ENVELOPE_TTL_S` | `3600` (1 hour) | Purge expired envelopes |
| `DEFAULT_SYNC_INTERVAL_S` | `1.0` | `--upstream` poll interval |

---

## 7. Failure, Crash Recovery & What Is NOT Protected

- **Graceful shutdown**: `SIGINT`/`SIGTERM` stops accepting new connections, drains active handlers cleanly, and closes SQLite/sockets without partial writes.
- **Crash safety (`kill -9`)**: All state files use `atomic_write_text()` (`mkstemp` + `fsync` + `os.replace`); SQLite uses `BEGIN IMMEDIATE` transactions; nodes recover from disk and catch up from `--upstream` on restart.
- **Fail closed**: Any parse error, bad signature, corrupt state (`STATE_CORRUPT`), unknown identity, or missing AEAD extra (`cryptography`) results in denial/error.
- **Explicitly NOT protected in v1**:
  1. **No transport encryption by default** (metadata: who talks to whom, when, sizes, and non-encrypted protocol headers are visible on the network; optional `--tls-cert`/`--tls-key` provides classical TLS only).
  2. **Single-hub data plane**: Envelopes are stored on the receiving node only; no cross-node envelope replication.
  3. **Trusted admin key & machine**: Admin ML-DSA-65 key is a single point of failure; compromised endpoints or host root are out of scope.
  4. **Adapter path trust domain**: On the Stage 1 adapter path, admin key and node share one host trust domain.
  5. **Unsynchronised clocks**: Real machines may have clock skew; sentinel flags `order_uncertain` outside supported bounds.
  6. **Research prototype**: Not independently audited.
