"""Stdlib-only integrity, key-separation, anti-rollback, and MAC'd audit store for Track 4 adapter."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]

ZERO_HASH_HEX = "0" * 64
STORE_VERSION = 2
DEFAULT_LOCK_TIMEOUT_S = 4.0

# Public HKDF domain-separation labels (non-secret by design, RFC 5869).
HKDF_INFO_STATE = b"graviton-adapter-k-state-v1"
HKDF_INFO_AUDIT = b"graviton-adapter-k-audit-v1"
HKDF_INFO_HEAD = b"graviton-adapter-k-head-v1"


class LockTimeoutError(TimeoutError):
    """Raised when the bounded exclusive state lock cannot be acquired in time."""


class KeyDirSeparationError(ValueError):
    """Raised when TRACK4_KEY_DIR overlaps with TRACK4_STATE_DIR."""


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 implemented strictly on Python stdlib hmac + hashlib."""
    actual_salt = salt if salt else b"\x00" * 32
    prk = hmac.new(actual_salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def fsync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def atomic_write_json(path: Path, data: dict) -> None:
    ensure_private_dir(path.parent)
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        if os.name != "nt":
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        fsync_dir(path.parent)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def get_key_dir(state_dir: Path) -> Path:
    """Resolve TRACK4_KEY_DIR (separate from TRACK4_STATE_DIR) and enforce separation."""
    state_abs = state_dir.resolve()
    env_key_dir = os.environ.get("TRACK4_KEY_DIR")
    if env_key_dir:
        key_dir = Path(env_key_dir)
    else:
        digest = hashlib.sha256(str(state_abs).encode("utf-8")).hexdigest()[:16]
        tmp_abs = Path(tempfile.gettempdir()).resolve()
        if tmp_abs != state_abs and state_abs not in tmp_abs.parents:
            key_dir = tmp_abs / f"graviton_keys_{digest}"
        else:
            key_dir = state_abs.parent / f".graviton_keys_{digest}"

    key_abs = key_dir.resolve()
    if key_abs == state_abs or state_abs in key_abs.parents or key_abs in state_abs.parents:
        raise KeyDirSeparationError("TRACK4_KEY_DIR must be separate from TRACK4_STATE_DIR")
    ensure_private_dir(key_dir)
    return key_dir


def derive_and_save_keys(key_dir: Path, key_material: str) -> dict[str, bytes]:
    """Derive k_state, k_audit, k_head from fresh CSPRNG + key_material; store ONLY derived keys."""
    ensure_private_dir(key_dir)
    salt = secrets.token_bytes(32)
    ikm = secrets.token_bytes(32) + key_material.encode("utf-8")
    keys = {
        "k_state": hkdf_sha256(salt, ikm, HKDF_INFO_STATE, 32),
        "k_audit": hkdf_sha256(salt, ikm, HKDF_INFO_AUDIT, 32),
        "k_head": hkdf_sha256(salt, ikm, HKDF_INFO_HEAD, 32),
    }
    del ikm
    import base64

    atomic_write_json(
        key_dir / "keys.json",
        {
            "version": STORE_VERSION,
            "k_state_b64": base64.b64encode(keys["k_state"]).decode("ascii"),
            "k_audit_b64": base64.b64encode(keys["k_audit"]).decode("ascii"),
            "k_head_b64": base64.b64encode(keys["k_head"]).decode("ascii"),
        },
    )
    return keys


def load_keys(key_dir: Path) -> dict[str, bytes] | None:
    import base64

    kp = key_dir / "keys.json"
    if not kp.is_file():
        return None
    try:
        data = json.loads(kp.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != STORE_VERSION:
            return None
        return {
            "k_state": base64.b64decode(data["k_state_b64"], validate=True),
            "k_audit": base64.b64decode(data["k_audit_b64"], validate=True),
            "k_head": base64.b64decode(data["k_head_b64"], validate=True),
        }
    except Exception:
        return None


def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sign_state(state_body: dict, k_state: bytes) -> dict:
    payload = dict(state_body)
    payload.pop("state_mac", None)
    mac = hmac.new(k_state, _canonical_bytes(payload), hashlib.sha256).hexdigest()
    payload["state_mac"] = mac
    return payload


def verify_state(state: dict, k_state: bytes) -> bool:
    if not isinstance(state, dict):
        return False
    mac = state.get("state_mac")
    if not isinstance(mac, str):
        return False
    payload = {k: v for k, v in state.items() if k != "state_mac"}
    expected = hmac.new(k_state, _canonical_bytes(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def sign_head(head_body: dict, k_head: bytes) -> dict:
    payload = dict(head_body)
    payload.pop("head_mac", None)
    mac = hmac.new(k_head, _canonical_bytes(payload), hashlib.sha256).hexdigest()
    payload["head_mac"] = mac
    return payload


def verify_head(head: dict, k_head: bytes) -> bool:
    if not isinstance(head, dict):
        return False
    mac = head.get("head_mac")
    if not isinstance(mac, str):
        return False
    payload = {k: v for k, v in head.items() if k != "head_mac"}
    expected = hmac.new(k_head, _canonical_bytes(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def load_head(key_dir: Path, k_head: bytes) -> dict | None:
    hp = key_dir / ".head.json"
    if not hp.is_file():
        return None
    try:
        data = json.loads(hp.read_text(encoding="utf-8"))
        if not verify_head(data, k_head):
            return None
        return data
    except Exception:
        return None


def save_head(key_dir: Path, head_body: dict, k_head: bytes) -> None:
    atomic_write_json(key_dir / ".head.json", sign_head(head_body, k_head))


def append_audit_record(
    log_path: Path,
    k_audit: bytes,
    *,
    seq: int,
    prev_hash: str,
    request_id: str,
    actor: str,
    asset: str,
    op: str,
    decision: str,
    reason: str,
    ts: int | None = None,
) -> dict:
    """Append a single hash-chained, HMAC-authenticated JSON line durably."""
    body = {
        "seq": seq,
        "prev_hash": prev_hash,
        "request_id": request_id,
        "actor": actor,
        "asset": asset,
        "op": op,
        "decision": decision,
        "reason": reason,
        "ts": int(time.time()) if ts is None else int(ts),
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    record_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    mac = hmac.new(k_audit, record_hash.encode("ascii"), hashlib.sha256).hexdigest()
    full = dict(body)
    full["record_hash"] = record_hash
    full["mac"] = mac
    line = json.dumps(full, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"

    ensure_private_dir(log_path.parent)
    fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        if os.name != "nt":
            try:
                os.chmod(log_path, 0o600)
            except OSError:
                pass
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(log_path.parent)
    return full


def verify_and_read_audit_log(log_path: Path, k_audit: bytes) -> tuple[bool, list[dict]]:
    """Verify full hash chain and per-record HMACs; fail closed on deletion/truncation/tamper."""
    if not log_path.is_file():
        return False, []
    try:
        raw = log_path.read_bytes()
        if raw and not raw.endswith(b"\n"):
            return False, []
        lines = raw.decode("utf-8").splitlines()
        records: list[dict] = []
        expected_seq = 1
        expected_prev = ZERO_HASH_HEX
        for line in lines:
            if not line:
                return False, []
            rec = json.loads(line)
            if not isinstance(rec, dict):
                return False, []
            if rec.get("seq") != expected_seq or rec.get("prev_hash") != expected_prev:
                return False, []
            body = {
                k: rec[k]
                for k in ("seq", "prev_hash", "request_id", "actor", "asset", "op", "decision", "reason", "ts")
            }
            canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
            exp_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(str(rec.get("record_hash", "")), exp_hash):
                return False, []
            exp_mac = hmac.new(k_audit, exp_hash.encode("ascii"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(rec.get("mac", "")), exp_mac):
                return False, []
            records.append(rec)
            expected_seq += 1
            expected_prev = exp_hash
        return True, records
    except Exception:
        return False, []


def check_consistency_and_anti_rollback(
    state: dict,
    head: dict,
    records: list[dict],
) -> tuple[bool, bool]:
    """Verify state, head, and audit log match; returns (valid, needs_head_heal)."""
    if state.get("generation") != head.get("generation"):
        return False, False
    st_seq = int(state.get("last_seq", -1))
    st_hash = str(state.get("last_hash", ""))
    st_rev = len(state.get("revoked", []))
    hd_seq = int(head.get("last_seq", -1))
    hd_hash = str(head.get("last_hash", ""))
    hd_rev = int(head.get("revoked_count", -1))

    log_seq = len(records)
    log_hash = records[-1]["record_hash"] if records else ZERO_HASH_HEX

    if st_seq != log_seq or st_hash != log_hash:
        return False, False
    if st_seq < hd_seq or st_rev < hd_rev:
        return False, False
    if st_seq == hd_seq:
        return st_hash == hd_hash, False
    # Crash recovery case: state + audit log committed ahead of .head.json (st_seq == hd_seq + 1)
    if st_seq == hd_seq + 1:
        return True, True
    return False, False


@contextmanager
def bounded_lock(state_dir: Path, *, timeout_s: float = DEFAULT_LOCK_TIMEOUT_S):
    """Exclusive advisory file lock with bounded timeout (fails closed with LockTimeoutError)."""
    ensure_private_dir(state_dir)
    lock_path = state_dir / ".adapter.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout_s
    acquired = False
    try:
        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                elif msvcrt is not None:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise LockTimeoutError("Timed out waiting for adapter state lock")
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(fd)
