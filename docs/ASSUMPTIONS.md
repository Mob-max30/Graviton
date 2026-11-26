# Assumptions & Architecture Choices

Differences, assumptions, and specific implementation choices aligned with the toolkit contract.

## 1. Storage & State Management
- In accordance with the toolkit specification, state is stored under `TRACK4_STATE_DIR` (or a secure temp directory).
- To support both POSIX (production/judging) and Windows (development/testing), cross-platform file locking is implemented using `msvcrt` on Windows and `fcntl.flock` on POSIX systems.
- State writes use write-to-temp-and-atomic-rename (`os.replace`) with directory fsync where supported.

## 2. Key Derivation & Protection
- `key_material` provided in `setup` is never written in plaintext to disk or stdout/stderr.
- Instead, a cryptographic master key is derived via HKDF-SHA256 with a freshly generated 32-byte salt:
  - `K_state`: Used to compute an HMAC-SHA256 integrity tag over `state.json`.
  - `K_audit`: Used to authenticate audit records.
- At-rest confidentiality of data bodies in the judged core relies on OS permissions (0600 file / 0700 dir) because the judged core is constrained to the Python standard library and cannot import third-party AEAD ciphers. This is an explicit, documented design trade-off.

## 3. Logging & Audit
- The audit log is stored as an append-only canonical JSON lines (`.jsonl`) file alongside `state.json`.
- Each record forms a SHA-256 hash chain with the previous record to detect deletion, reordering, and tail truncation.

## 4. Judged Core Isolation
- The judged core (`trustledger/core/`) imports **only** the Python standard library plus `pqcrypto.kem.ml_kem_768` (imported lazily inside `protected_read`).
- No heavy libraries (`cryptography`, `hypothesis`, `reedsolo`, `reportlab`) are imported in the judged path, guaranteeing sub-150ms cold starts.
