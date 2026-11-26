# Toolkit Ground Truth Notes

Summary and verification of the official Track 4 Toolkit (`v1.0.0`, commit `8901dfb`).

## 1. Adapter Contract & Execution Model
- **Entry point**: Exactly one entry point at repo root: `track4_service.py`, paired with `team_app.py` defining `dispatch(request: dict) -> dict`. No Node.js scripts in Python submission.
- **Process model**: A fresh process is spawned per request (`subprocess.Popen([sys.executable, "-B", entry])`).
- **Input/Output**: Reads one UTF-8 JSON object from `stdin` to EOF. Writes exactly one JSON object + newline to `stdout`. On error, prints generic diagnostic to `stderr` and exits 1 with empty `stdout`.
- **Stream caps**: Stdout and stderr capped at 64 KiB each.
- **Per-operation timeout**: 8.0 seconds timeout per invocation.
- **Child processes**: Must not leave background child processes or open file descriptors/streams alive at process exit.

## 2. Supported Operations
1. `setup`:
   - Inputs: `owners` (asset_id -> actor_id), `contents` (asset_id -> body_str), `disabled` (list of actor_ids), `key_material` (sensitive marker string).
   - Expected Output: `{"ready": true}`.
   - Constraint: `key_material` must never leak to `stdout`, `stderr`, or plaintext disk.
2. `read`:
   - Inputs: `actor`, `asset`, `request_id`.
   - Output (authorized owner): `{"decision": "allow", "body": "<exact stored body>"}`.
   - Output (unauthorized / disabled / revoked / unknown): `{"decision": "deny"}`.
   - Constraint: Denied responses must never disclose body or key material.
   - Audit requirement: The decision must be recorded against `request_id`.
3. `revoke`:
   - Inputs: `actor`.
   - Output: `{}` (or empty JSON dict).
   - Effect: Actor is added to disabled/revoked tombstones, persisting across process runs. Unaffected peers maintain access.
4. `audit`:
   - Inputs: `request_id`.
   - Output: `{"request_id": "<id>", "decision": "allow" | "deny"}`.
   - For unknown request_id, returns `{"error": "unknown_request"}`.
5. `protected_read`:
   - Inputs: `actor`, `asset`, `challenge`, `public_key`.
   - Authorized Output: `{"ciphertext": "<base64 ML-KEM-768 ct>", "proof": "<hex hmac-sha256>"}`.
   - Proof specification: HMAC-SHA256 keyed by KEM shared secret over UTF-8 bytes of `challenge + stored_body` (concatenated without separator).
   - Denied Output: `{"decision": "deny"}`.

## 3. Runtime Environment & State Isolation
- Judging environment: Offline Linux container, Python 3.12, `pqcrypto==0.4.0`.
- Root filesystem is read-only.
- Writable state dir provided via `TRACK4_STATE_DIR`, fallback to `tempfile.gettempdir()`.
- State must be persisted to disk before acknowledging operations.
- State isolation: Each test run / state directory must start fresh without residual state from previous runs.

## 4. Installed `pqcrypto==0.4.0` API Verification
- `pqcrypto.kem.ml_kem_768`:
  - `generate_keypair()` -> `(public_key: bytes [1184], secret_key: bytes [2400])`
  - `encrypt(public_key: bytes)` -> `(ciphertext: bytes [1088], shared_secret: bytes [32])`
  - `decrypt(secret_key: bytes, ciphertext: bytes)` -> `shared_secret: bytes [32]`
  *(Note: API uses `encrypt`/`decrypt`, not `encapsulate`/`decapsulate`)*.
- `pqcrypto.sign.ml_dsa_65`:
  - `generate_keypair()` -> `(public_key: bytes [1952], secret_key: bytes [4032])`
  - `sign(secret_key: bytes, message: bytes)` -> `signature: bytes [3309]`
  - `verify(public_key: bytes, message: bytes, signature: bytes)` -> `bool`
- `pqcrypto.sign.sphincs_shake_128s_simple`:
  - `generate_keypair()` -> `(pk [32], sk [64])`
  - `sign(sk, msg)` -> `sig [7856]`
  - `verify(pk, msg, sig)` -> `bool`
