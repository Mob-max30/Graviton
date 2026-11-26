"""Two-phase commit key rotation with dual-key grace acceptance and durable fsynced WAL."""
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Optional

from trustledger.core.store import hkdf_extract_and_expand_sha256
from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState

DEFAULT_GRACE_PERIOD_SECONDS = 300.0  # 5 minutes


class WALIntegrityError(RuntimeError):
    """Raised when a WAL record is forged, truncated, or missing a valid HMAC."""


class WALPhase(str):
    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"


class RotationCoordinator:
    """Orchestrates 2-Phase Commit key rotation with durable fsynced, HMAC-authenticated WAL."""

    def __init__(
        self,
        wal_dir: Path,
        lifecycle: KeyLifecycleManager,
        grace_period_seconds: float = DEFAULT_GRACE_PERIOD_SECONDS,
        wal_key: Optional[bytes] = None,
    ):
        self.wal_dir = Path(wal_dir)
        self.wal_dir.mkdir(parents=True, exist_ok=True)
        self.wal_file = self.wal_dir / "rotation.wal"
        self.lifecycle = lifecycle
        self.grace_period_seconds = grace_period_seconds
        self._wal_mac_key = self._init_wal_mac_key(wal_key)

    def _init_wal_mac_key(self, wal_key: Optional[bytes]) -> bytes:
        if wal_key is not None:
            ikm = wal_key
        else:
            env_key = os.environ.get("TRACK4_WAL_KEY")
            if env_key:
                ikm = env_key.encode("utf-8")
            else:
                key_path = self.wal_dir / ".wal.key"
                if key_path.exists():
                    ikm = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
                else:
                    ikm = secrets.token_bytes(32)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                    fd = os.open(str(key_path), flags, 0o600) if sys.platform != "win32" else os.open(str(key_path), flags)
                    try:
                        os.write(fd, ikm.hex().encode("ascii"))
                        os.fsync(fd)
                    finally:
                        os.close(fd)
        return hkdf_extract_and_expand_sha256(
            salt=b"trustledger:wal:salt:v1",
            ikm=ikm,
            info=b"trustledger:wal:hmac:v1",
            length=32,
        )

    @staticmethod
    def _canonical_wal_bytes(data: dict[str, Any]) -> bytes:
        payload = {k: v for k, v in data.items() if k != "wal_mac"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _sign_wal(self, data: dict[str, Any]) -> dict[str, Any]:
        signed = {k: v for k, v in data.items() if k != "wal_mac"}
        mac = hmac.new(self._wal_mac_key, self._canonical_wal_bytes(signed), hashlib.sha256).hexdigest()
        signed["wal_mac"] = mac
        return signed

    def prepare_rotation(self, new_key_id: str, new_key_alg: str, new_key_pub_hex: str) -> dict[str, Any]:
        """Phase 1: Register new key in PENDING state and write PREPARE record to WAL."""
        new_epoch = self.lifecycle.current_epoch + 1
        self.lifecycle.register_key(new_key_id, new_key_alg, new_key_pub_hex)
        active_rec = self.lifecycle.get_active_key()
        old_id = active_rec.key_id if active_rec is not None else None

        wal_entry: dict[str, Any] = {
            "phase": WALPhase.PREPARED,
            "old_key_id": old_id,
            "new_key_id": new_key_id,
            "target_epoch": new_epoch,
        }
        self._atomic_wal_write(wal_entry)
        return wal_entry

    def commit_rotation(self, new_key_id: str, now: Optional[float] = None) -> dict[str, Any]:
        """Phase 2: Transition old key to GRACE (with cutoff timestamp), new key to ACTIVE, bump epoch."""
        wal_data = self.read_wal()
        if not wal_data or wal_data.get("phase") != WALPhase.PREPARED:
            raise RuntimeError("Cannot commit: No PREPARED rotation in WAL")
        if wal_data.get("new_key_id") != new_key_id:
            raise RuntimeError("WAL target key mismatch")

        current_time = time.time() if now is None else now
        grace_until = current_time + self.grace_period_seconds

        old_key_id = wal_data.get("old_key_id")
        if old_key_id:
            self.lifecycle.transition_state(old_key_id, KeyState.GRACE, grace_until=grace_until)

        self.lifecycle.current_epoch = wal_data["target_epoch"]
        self.lifecycle.transition_state(new_key_id, KeyState.ACTIVE)

        wal_entry = {
            "phase": WALPhase.COMMITTED,
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "active_epoch": self.lifecycle.current_epoch,
            "grace_until": grace_until,
        }
        self._atomic_wal_write(wal_entry)
        return wal_entry

    def abort_rotation(self, new_key_id: str) -> None:
        """Roll back prepared rotation."""
        rec = self.lifecycle.get_key(new_key_id)
        if rec and rec.state != KeyState.REVOKED:
            self.lifecycle.transition_state(new_key_id, KeyState.REVOKED)
        self._atomic_wal_write({"phase": WALPhase.ABORTED, "new_key_id": new_key_id})

    def read_wal(self) -> dict[str, Any] | None:
        if not self.wal_file.exists():
            return None
        try:
            data: Any = json.loads(self.wal_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WALIntegrityError(f"Corrupt or truncated WAL: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("wal_mac"), str):
            raise WALIntegrityError("WAL record missing wal_mac")
        expected_mac = hmac.new(self._wal_mac_key, self._canonical_wal_bytes(data), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(data["wal_mac"].encode("utf-8"), expected_mac.encode("utf-8")):
            raise WALIntegrityError("WAL HMAC verification failed")
        return data

    def _atomic_wal_write(self, data: dict[str, Any]) -> None:
        signed = self._sign_wal(data)
        raw = json.dumps(signed).encode("utf-8")
        tmp = self.wal_file.with_name(f"rotation.wal.tmp.{secrets.token_hex(4)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(tmp), flags, 0o600) if sys.platform != "win32" else os.open(str(tmp), flags)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.wal_file)
