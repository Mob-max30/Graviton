"""Core state storage, constant-time string comparison, anti-rollback head, and isolated key storage.

Guarantees:
- Strict state isolation
- Separate private key storage directory (TRACK4_KEY_DIR or per-state-dir 0700 dir), symlink/uid checked
- Anti-rollback head record stored in key_dir (0600, atomic write + fsync)
- HKDF key derivation from key_material with random salt (domain-separated k_state, k_audit, k_head)
- HMAC-SHA256 integrity verification on load (fail closed)
- Zero plaintext storage of raw key_material
"""
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1
GENESIS_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def ct_equal(a: str, b: str) -> bool:
    """Constant-time UTF-8 byte comparison safe for non-ASCII and surrogate strings."""
    return hmac.compare_digest(
        a.encode("utf-8", errors="surrogatepass"),
        b.encode("utf-8", errors="surrogatepass"),
    )


def canonical_json_bytes(data: Any) -> bytes:
    """Format dictionary or list into canonical UTF-8 JSON bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def hkdf_extract_and_expand_sha256(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF using stdlib hmac and hashlib.sha256."""
    if not salt:
        salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    n = (length + 31) // 32
    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


class IntegrityError(RuntimeError):
    """Raised when state, audit, head, or directory integrity violation is detected."""


def _check_safe_dir(path: Path, label: str) -> None:
    """Reject symlinks, non-directories, wrong-owner dirs, and group/world-accessible dirs."""
    try:
        st = os.lstat(str(path))
    except OSError as err:
        raise IntegrityError(f"Cannot stat {label}: {err}") from err

    if stat.S_ISLNK(st.st_mode):
        raise IntegrityError(f"Unsafe {label}: symlink rejected")
    if not stat.S_ISDIR(st.st_mode):
        raise IntegrityError(f"Unsafe {label}: not a directory")

    if sys.platform != "win32":
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise IntegrityError(f"Unsafe {label}: owned by unexpected uid {st.st_uid}")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise IntegrityError(f"Unsafe permissions on {label}: {oct(mode)}")


def _ensure_private_dir(path: Path, label: str) -> None:
    """Create directory with mode 0700 without following symlinks, then verify ownership/mode."""
    if not os.path.lexists(str(path)):
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(str(path), 0o700)
        except FileExistsError:
            pass
    _check_safe_dir(path, label)


def get_state_dir() -> Path:
    """Determine writable state directory from environment or private fallback."""
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        path = Path(env_dir)
    else:
        path = Path(tempfile.gettempdir()) / "track4-trustledger-core"
    _ensure_private_dir(path, "state_dir")
    return path


def get_key_dir(state_dir: Path) -> Path:
    """Determine isolated per-state-dir key directory outside state_dir; fail closed on symlinks/unsafe perms."""
    if os.path.lexists(str(state_dir)):
        _check_safe_dir(state_dir, "state_dir")

    resolved_state = state_dir.resolve()
    state_tag = hashlib.sha256(str(resolved_state).encode("utf-8", errors="surrogatepass")).hexdigest()[:16]

    env_key_dir = os.environ.get("TRACK4_KEY_DIR")
    if env_key_dir:
        key_dir = Path(env_key_dir)
    else:
        # Derive a per-state-dir private directory outside state_dir (never a shared predictable /tmp/keys)
        parent_candidate = resolved_state.parent / f".tl-keys-{state_tag}"
        try:
            _ensure_private_dir(parent_candidate, "key_dir")
            key_dir = parent_candidate
        except (OSError, IntegrityError):
            key_dir = Path.home() / f".tl-keys-{state_tag}"

    _ensure_private_dir(key_dir, "key_dir")

    resolved_key = key_dir.resolve()
    if resolved_key == resolved_state or resolved_state in resolved_key.parents:
        raise IntegrityError("Key directory must be strictly separate from state directory")

    return key_dir


class StateStore:
    """Durable state storage with HMAC integrity verification, anti-rollback head, and isolated key storage."""

    def __init__(self, state_dir: Optional[Path] = None, key_dir: Optional[Path] = None):
        self.state_dir = state_dir or get_state_dir()
        _ensure_private_dir(self.state_dir, "state_dir")
        self.key_dir = key_dir or get_key_dir(self.state_dir)
        _ensure_private_dir(self.key_dir, "key_dir")

        if self.key_dir.resolve() == self.state_dir.resolve():
            raise IntegrityError("Key directory must be strictly separate from state directory")

        state_id = hashlib.sha256(
            str(self.state_dir.resolve()).encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:16]
        self.keys_file = self.key_dir / f"{state_id}.keys.blob"
        self.head_file = self.key_dir / f"{state_id}.head.json"
        self.state_file = self.state_dir / "state.json"
        self.lock_file = self.state_dir / "state.lock"
        self.audit_file = self.state_dir / "audit.log"

    def compute_mac(self, k_state: bytes, state_data: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 hex string over canonical state excluding state_mac."""
        copy_data = {k: v for k, v in state_data.items() if k != "state_mac"}
        return hmac.new(k_state, canonical_json_bytes(copy_data), hashlib.sha256).hexdigest()

    def _compute_head_mac(self, k_head: bytes, head_data: Dict[str, Any]) -> str:
        copy_data = {k: v for k, v in head_data.items() if k != "head_mac"}
        return hmac.new(k_head, canonical_json_bytes(copy_data), hashlib.sha256).hexdigest()

    def derive_keys(self, salt: bytes, key_material: str) -> Tuple[bytes, bytes, bytes]:
        """Derive (k_state, k_audit, k_head) from raw key_material via HKDF."""
        ikm = key_material.encode("utf-8", errors="surrogatepass")
        k_state = hkdf_extract_and_expand_sha256(salt, ikm, b"trustledger:state:v1", 32)
        k_audit = hkdf_extract_and_expand_sha256(salt, ikm, b"trustledger:audit:v1", 32)
        k_head = hkdf_extract_and_expand_sha256(salt, ikm, b"trustledger:head:v1", 32)
        return k_state, k_audit, k_head

    def _write_head(self, k_head: bytes, version: int, last_seq: int, last_hash: str, revoked_count: int) -> None:
        head_data: Dict[str, Any] = {
            "version": version,
            "last_seq": last_seq,
            "last_hash": last_hash,
            "revoked_count": revoked_count,
        }
        head_data["head_mac"] = self._compute_head_mac(k_head, head_data)
        self._atomic_write(self.head_file, canonical_json_bytes(head_data))

    def _load_head(self, k_head: bytes) -> Dict[str, Any]:
        if not self.head_file.exists():
            raise IntegrityError("Missing anti-rollback head record in key directory.")
        if sys.platform != "win32":
            mode = stat.S_IMODE(os.lstat(str(self.head_file)).st_mode)
            if mode & 0o077:
                raise IntegrityError(f"Unsafe permissions on head file: {oct(mode)}")
        head_data: Dict[str, Any] = json.loads(self.head_file.read_bytes().decode("utf-8"))
        recorded_mac = str(head_data.get("head_mac", ""))
        expected_mac = self._compute_head_mac(k_head, head_data)
        if not ct_equal(recorded_mac, expected_mac):
            raise IntegrityError("Anti-rollback head MAC verification failed.")
        return head_data

    def initialize(
        self,
        owners: Dict[str, str],
        contents: Dict[str, str],
        disabled: List[str],
        key_material: str,
    ) -> None:
        """Initialize fresh state, reset audit log, and reset anti-rollback head."""
        salt = secrets.token_bytes(32)
        k_state, k_audit, k_head = self.derive_keys(salt, key_material)

        keys_blob = {
            "salt_hex": salt.hex(),
            "k_state_hex": k_state.hex(),
            "k_audit_hex": k_audit.hex(),
            "k_head_hex": k_head.hex(),
        }
        self._atomic_write(self.keys_file, canonical_json_bytes(keys_blob))

        legacy_keys = self.state_dir / "keys.blob"
        if legacy_keys.exists():
            legacy_keys.unlink()

        disabled_sorted = sorted(set(disabled))
        state_data: Dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "version": 1,
            "salt_hex": salt.hex(),
            "owners": dict(owners),
            "contents": dict(contents),
            "disabled": disabled_sorted,
            "revoked_tombstones": list(disabled_sorted),
            "last_seq": 0,
            "last_hash": GENESIS_HASH,
        }
        state_data["state_mac"] = self.compute_mac(k_state, state_data)
        self._atomic_write(self.state_file, canonical_json_bytes(state_data))
        self._write_head(k_head, 1, 0, GENESIS_HASH, len(disabled_sorted))

        if self.audit_file.exists():
            self.audit_file.unlink()
        self.audit_file.touch(mode=0o600, exist_ok=True)

    def load_all_keys(self) -> Tuple[bytes, bytes, bytes]:
        """Load (k_state, k_audit, k_head) from isolated keys_file."""
        if not self.keys_file.exists():
            raise FileNotFoundError("Keys blob not found in key directory; state uninitialized.")
        if sys.platform != "win32":
            st = os.lstat(str(self.keys_file))
            if stat.S_ISLNK(st.st_mode):
                raise IntegrityError("Keys file must not be a symlink.")
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o077:
                raise IntegrityError(f"Unsafe permissions on keys file: {oct(mode)}")
        data = json.loads(self.keys_file.read_bytes().decode("utf-8"))
        k_state = bytes.fromhex(data["k_state_hex"])
        k_audit = bytes.fromhex(data["k_audit_hex"])
        k_head = bytes.fromhex(data["k_head_hex"]) if "k_head_hex" in data else hkdf_extract_and_expand_sha256(
            bytes.fromhex(data["salt_hex"]), k_state, b"trustledger:head:v1", 32
        )
        return k_state, k_audit, k_head

    def load_keys(self) -> Tuple[bytes, bytes]:
        """Load (k_state, k_audit) from isolated keys_file."""
        k_state, k_audit, _ = self.load_all_keys()
        return k_state, k_audit

    def load_state(self) -> Dict[str, Any]:
        """Load state, verify state MAC, and enforce anti-rollback against head record in key_dir."""
        if not self.state_file.exists():
            raise FileNotFoundError("State file not found.")
        k_state, k_audit, k_head = self.load_all_keys()
        raw_bytes = self.state_file.read_bytes()
        state_data: Dict[str, Any] = json.loads(raw_bytes.decode("utf-8"))

        recorded_mac = str(state_data.get("state_mac", ""))
        expected_mac = self.compute_mac(k_state, state_data)
        if not ct_equal(recorded_mac, expected_mac):
            raise IntegrityError("State integrity violation: HMAC mismatch.")

        head_data = self._load_head(k_head)
        state_ver = int(state_data.get("version", 0))
        head_ver = int(head_data.get("version", 0))
        state_seq = int(state_data.get("last_seq", 0))
        head_seq = int(head_data.get("last_seq", 0))
        state_hash = str(state_data.get("last_hash", ""))
        head_hash = str(head_data.get("last_hash", ""))
        state_rev_count = len(set(state_data.get("revoked_tombstones", [])))
        head_rev_count = int(head_data.get("revoked_count", 0))

        if state_ver < head_ver:
            raise IntegrityError(f"State rollback detected: state version {state_ver} < head {head_ver}")
        if state_seq < head_seq:
            raise IntegrityError(f"State rollback detected: state seq {state_seq} < head {head_seq}")
        if state_rev_count < head_rev_count:
            raise IntegrityError(f"Revocation rollback detected: {state_rev_count} < head {head_rev_count}")
        if state_seq == head_seq and not ct_equal(state_hash, head_hash):
            raise IntegrityError("State hash mismatch against anti-rollback head at equal sequence.")

        # Crash-window recovery rule: save_state writes state.json before head.json.
        # If a crash occurred between the two writes, state.version == head.version + 1.
        # Tolerate this ONLY when the authenticated audit log tail proves state.last_seq/last_hash is genuine.
        if state_ver == head_ver + 1:
            from trustledger.core.audit import AuditLog

            AuditLog(self.audit_file).verify_chain(
                k_audit=k_audit,
                expected_last_seq=state_seq,
                expected_last_hash=state_hash,
            )
            self._write_head(k_head, state_ver, state_seq, state_hash, state_rev_count)
        elif state_ver > head_ver + 1:
            raise IntegrityError(f"Unexpected state/head version gap: state={state_ver}, head={head_ver}")

        return state_data

    def save_state(self, state_data: Dict[str, Any]) -> None:
        """Save updated state first, then update anti-rollback head in key_dir."""
        k_state, _, k_head = self.load_all_keys()
        new_ver = int(state_data.get("version", 1)) + 1
        state_data["version"] = new_ver
        state_data["state_mac"] = self.compute_mac(k_state, state_data)
        self._atomic_write(self.state_file, canonical_json_bytes(state_data))

        rev_count = len(set(state_data.get("revoked_tombstones", [])))
        self._write_head(
            k_head,
            new_ver,
            int(state_data.get("last_seq", 0)),
            str(state_data.get("last_hash", GENESIS_HASH)),
            rev_count,
        )

    def _atomic_write(self, target_path: Path, data: bytes) -> None:
        """Write to temp file, fsync, and replace atomically."""
        tmp_path = target_path.with_name(f"{target_path.name}.tmp.{secrets.token_hex(8)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if sys.platform != "win32":
            fd = os.open(str(tmp_path), flags, 0o600)
        else:
            fd = os.open(str(tmp_path), flags)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp_path, target_path)

        if sys.platform != "win32":
            try:
                dir_fd = os.open(str(target_path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
