"""Cryptographic key lifecycle state machine enforcing monotonic epochs, grace cutoffs, and disk durability."""
import json
import os
import secrets
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional, Set, Tuple


class KeyState(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    GRACE = "GRACE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


VALID_TRANSITIONS = {
    KeyState.PENDING: {KeyState.ACTIVE, KeyState.REVOKED},
    KeyState.ACTIVE: {KeyState.GRACE, KeyState.RETIRED, KeyState.REVOKED},
    KeyState.GRACE: {KeyState.RETIRED, KeyState.REVOKED},
    KeyState.RETIRED: {KeyState.REVOKED},
    KeyState.REVOKED: set(),  # Terminal tombstone
}


class KeyLifecycleRecord(NamedTuple):
    key_id: str
    epoch: int
    state: KeyState
    algorithm: str
    public_key_hex: str
    created_at_epoch: int
    revoked_at_epoch: Optional[int] = None
    grace_until: Optional[float] = None


class KeyLifecycleManager:
    """Enforces monotonic epoch transitions, grace-period cutoffs, and optional atomic disk persistence."""

    def __init__(self, initial_epoch: int = 1, state_path: Optional[Path] = None):
        self.current_epoch = initial_epoch
        self.state_path = Path(state_path) if state_path is not None else None
        self._keys: Dict[str, KeyLifecycleRecord] = {}
        self._active_key_id: Optional[str] = None
        self._seen_key_ids: Set[str] = set()
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def _load(self) -> None:
        if self.state_path is None:
            raise RuntimeError("state_path is not configured")
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.current_epoch = int(data["current_epoch"])
        self._active_key_id = data.get("active_key_id")
        self._seen_key_ids = set(data.get("seen_key_ids", []))
        self._keys = {}
        for k_id, item in data.get("keys", {}).items():
            self._keys[k_id] = KeyLifecycleRecord(
                key_id=item["key_id"],
                epoch=int(item["epoch"]),
                state=KeyState(item["state"]),
                algorithm=item["algorithm"],
                public_key_hex=item["public_key_hex"],
                created_at_epoch=int(item["created_at_epoch"]),
                revoked_at_epoch=item.get("revoked_at_epoch"),
                grace_until=item.get("grace_until"),
            )

    def save(self) -> None:
        """Persist lifecycle state atomically with fsync."""
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "current_epoch": self.current_epoch,
            "active_key_id": self._active_key_id,
            "seen_key_ids": sorted(self._seen_key_ids),
            "keys": {
                k_id: {
                    "key_id": rec.key_id,
                    "epoch": rec.epoch,
                    "state": rec.state.value,
                    "algorithm": rec.algorithm,
                    "public_key_hex": rec.public_key_hex,
                    "created_at_epoch": rec.created_at_epoch,
                    "revoked_at_epoch": rec.revoked_at_epoch,
                    "grace_until": rec.grace_until,
                }
                for k_id, rec in self._keys.items()
            },
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        tmp = self.state_path.with_name(f"{self.state_path.name}.tmp.{secrets.token_hex(4)}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(tmp), flags, 0o600) if sys.platform != "win32" else os.open(str(tmp), flags)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.state_path)

    def register_key(self, key_id: str, algorithm: str, public_key_hex: str) -> KeyLifecycleRecord:
        """Register a brand-new key in PENDING state. Key IDs cannot be reused."""
        if key_id in self._seen_key_ids:
            raise ValueError(f"Key ID {key_id} has already been used and cannot be reused")

        rec = KeyLifecycleRecord(
            key_id=key_id,
            epoch=self.current_epoch,
            state=KeyState.PENDING,
            algorithm=algorithm,
            public_key_hex=public_key_hex,
            created_at_epoch=self.current_epoch,
        )
        self._keys[key_id] = rec
        self._seen_key_ids.add(key_id)
        self.save()
        return rec

    def transition_state(
        self,
        key_id: str,
        new_state: KeyState,
        grace_until: Optional[float] = None,
    ) -> KeyLifecycleRecord:
        """Transition key state according to monotonic lifecycle rules."""
        if key_id not in self._keys:
            raise KeyError(f"Key ID {key_id} not found")

        curr = self._keys[key_id]
        if new_state not in VALID_TRANSITIONS[curr.state]:
            raise ValueError(f"Illegal key state transition from {curr.state} to {new_state}")

        revoked_epoch = self.current_epoch if new_state == KeyState.REVOKED else curr.revoked_at_epoch
        effective_grace = grace_until if new_state == KeyState.GRACE else None
        updated = KeyLifecycleRecord(
            key_id=curr.key_id,
            epoch=self.current_epoch,
            state=new_state,
            algorithm=curr.algorithm,
            public_key_hex=curr.public_key_hex,
            created_at_epoch=curr.created_at_epoch,
            revoked_at_epoch=revoked_epoch,
            grace_until=effective_grace,
        )
        self._keys[key_id] = updated

        if new_state == KeyState.ACTIVE:
            self._active_key_id = key_id

        self.save()
        return updated

    def verify_key_for_request(self, key_id: str, now: Optional[float] = None) -> Tuple[bool, str]:
        """Verify whether key_id is valid for serving a request at timestamp `now`."""
        rec = self._keys.get(key_id)
        if rec is None:
            return False, "KEY_UNKNOWN"
        if rec.state == KeyState.REVOKED:
            return False, "KEY_REVOKED"
        if rec.state == KeyState.RETIRED:
            return False, "KEY_RETIRED"
        if rec.state == KeyState.PENDING:
            return False, "KEY_PENDING"
        if rec.state == KeyState.ACTIVE:
            return True, "ACTIVE_KEY"
        if rec.state == KeyState.GRACE:
            check_now = time.time() if now is None else now
            if rec.grace_until is not None and check_now >= rec.grace_until:
                self.transition_state(key_id, KeyState.RETIRED)
                return False, "KEY_EXPIRED_AFTER_GRACE"
            return True, "GRACE_KEY"
        return False, "KEY_INVALID"

    def is_key_acceptable(self, key_id: str, now: Optional[float] = None) -> bool:
        """Return True if key_id is currently acceptable (ACTIVE or within GRACE deadline)."""
        ok, _ = self.verify_key_for_request(key_id, now=now)
        return ok

    def get_key(self, key_id: str) -> Optional[KeyLifecycleRecord]:
        return self._keys.get(key_id)

    def get_active_key(self) -> Optional[KeyLifecycleRecord]:
        if self._active_key_id:
            return self._keys.get(self._active_key_id)
        return None
