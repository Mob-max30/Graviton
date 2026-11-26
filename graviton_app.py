"""Graviton Phase 1 security engine for the Track 4 adapter contract."""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile

from pqcrypto.kem import ml_kem_768

STATE_VERSION = 1
STATE_FILENAME = "state.json"
AUDIT_LOG_FILENAME = "audit_log.jsonl"
LOCK_FILENAME = ".state.lock"


def get_state_dir() -> Path:
    """Return the writable state directory from TRACK4_STATE_DIR or OS temp."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / "graviton_state"


def _ensure_state_dir(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except OSError:
        pass


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


@contextmanager
def _state_lock(state_dir: Path):
    """Cross-process exclusive file lock using only Python standard library."""
    _ensure_state_dir(state_dir)
    lock_path = state_dir / LOCK_FILENAME
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _atomic_write_text(target: Path, content: str) -> None:
    """Write content atomically via temp file + flush + fsync + os.replace."""
    parent = target.parent
    _ensure_state_dir(parent)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp_", suffix=".part", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
        _fsync_dir(parent)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _append_audit_record(state_dir: Path, record: dict) -> None:
    """Append a single canonical JSON-lines audit record durably."""
    log_path = state_dir / AUDIT_LOG_FILENAME
    line = json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n"
    fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(state_dir)


def _load_state(state_dir: Path) -> dict | None:
    state_path = state_dir / STATE_FILENAME
    if not state_path.is_file():
        return None
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        raise ValueError("Unsupported or corrupted state schema")
    return data


def _save_state(state_dir: Path, state: dict) -> None:
    state_path = state_dir / STATE_FILENAME
    payload = json.dumps(state, allow_nan=False, separators=(",", ":"))
    _atomic_write_text(state_path, payload)


def _find_audit_record(state_dir: Path, request_id: str) -> dict | None:
    log_path = state_dir / AUDIT_LOG_FILENAME
    if not log_path.is_file():
        return None
    found = None
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if record.get("request_id") == request_id:
                found = record
    return found


def _is_authorized(state: dict, actor: str, asset: str) -> bool:
    disabled = set(state.get("disabled", []))
    if actor in disabled:
        return False
    owners = state.get("owners", {})
    contents = state.get("contents", {})
    if asset not in owners or asset not in contents:
        return False
    return owners[asset] == actor


def _handle_setup(state_dir: Path, request: dict) -> dict:
    owners = request.get("owners")
    contents = request.get("contents")
    disabled = request.get("disabled", [])
    key_material = request.get("key_material")

    if not isinstance(owners, dict) or not isinstance(contents, dict):
        return {"error": "invalid_setup_fields"}
    if not isinstance(disabled, list) or not all(isinstance(x, str) for x in disabled):
        return {"error": "invalid_disabled_list"}
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in owners.items()):
        return {"error": "invalid_owners_map"}
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in contents.items()):
        return {"error": "invalid_contents_map"}
    if key_material is not None and not isinstance(key_material, str):
        return {"error": "invalid_key_material"}

    state = {
        "version": STATE_VERSION,
        "owners": dict(owners),
        "contents": dict(contents),
        "disabled": list(dict.fromkeys(disabled)),
        "key_material": key_material if key_material is not None else "",
    }
    _save_state(state_dir, state)
    _atomic_write_text(state_dir / AUDIT_LOG_FILENAME, "")
    return {"ready": True}


def _handle_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    request_id = request.get("request_id")
    if not all(isinstance(x, str) for x in (actor, asset, request_id)):
        return {"error": "missing_or_invalid_fields"}

    state = _load_state(state_dir)
    if state is None:
        return {"error": "not_initialized"}

    allowed = _is_authorized(state, actor, asset)
    decision = "allow" if allowed else "deny"
    _append_audit_record(
        state_dir,
        {
            "version": STATE_VERSION,
            "request_id": request_id,
            "op": "read",
            "actor": actor,
            "asset": asset,
            "decision": decision,
        },
    )
    if allowed:
        return {"decision": "allow", "body": state["contents"][asset]}
    return {"decision": "deny"}


def _handle_revoke(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    if not isinstance(actor, str):
        return {"error": "missing_or_invalid_actor"}

    state = _load_state(state_dir)
    if state is None:
        return {"error": "not_initialized"}

    if actor not in state["disabled"]:
        state["disabled"].append(actor)
        _save_state(state_dir, state)
    return {}


def _handle_audit(state_dir: Path, request: dict) -> dict:
    request_id = request.get("request_id")
    if not isinstance(request_id, str):
        return {"error": "missing_or_invalid_request_id"}

    state = _load_state(state_dir)
    if state is None:
        return {"error": "not_initialized"}

    record = _find_audit_record(state_dir, request_id)
    if record is None:
        return {"error": "unknown_request"}
    return {"request_id": record["request_id"], "decision": record["decision"]}


def _handle_protected_read(state_dir: Path, request: dict) -> dict:
    actor = request.get("actor")
    asset = request.get("asset")
    challenge = request.get("challenge")
    public_key_b64 = request.get("public_key")
    if not all(isinstance(x, str) for x in (actor, asset, challenge, public_key_b64)):
        return {"error": "missing_or_invalid_fields"}

    state = _load_state(state_dir)
    if state is None:
        return {"error": "not_initialized"}

    if not _is_authorized(state, actor, asset):
        return {"decision": "deny"}

    try:
        public_key = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return {"error": "invalid_public_key"}

    if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        return {"error": "invalid_public_key_length"}

    try:
        ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    except Exception:
        return {"error": "kem_encapsulation_failed"}

    body = state["contents"][asset]
    message = (challenge + body).encode("utf-8")
    proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    return {
        "decision": "allow",
        "ciphertext": ciphertext_b64,
        "proof": proof,
    }


def dispatch(request: dict) -> dict:
    """Dispatch one adapter request against persisted state."""
    op = request.get("op")
    if not isinstance(op, str):
        return {"error": "missing_op"}

    state_dir = get_state_dir()
    with _state_lock(state_dir):
        if op == "setup":
            return _handle_setup(state_dir, request)
        if op == "read":
            return _handle_read(state_dir, request)
        if op == "revoke":
            return _handle_revoke(state_dir, request)
        if op == "audit":
            return _handle_audit(state_dir, request)
        if op == "protected_read":
            return _handle_protected_read(state_dir, request)
        return {"error": "unsupported_operation"}
