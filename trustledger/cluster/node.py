"""Cluster node model with local state, per-device key enrollment, and use-time revocation checks."""
import time
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from trustledger.keys.lifecycle import KeyLifecycleManager


class RevocationEntry(NamedTuple):
    version: int
    kind: str  # "actor" or "device_key"
    target: str


class ClusterNode:
    """Individual cluster node with localized key lifecycle, device keys, and revocation tombstones."""

    def __init__(self, node_id: str, lifecycle: Optional[KeyLifecycleManager] = None):
        self.node_id = node_id
        self.lifecycle = lifecycle or KeyLifecycleManager()
        self.revoked_actors: Set[str] = set()
        self.revoked_device_keys: Set[str] = set()
        self.enrolled_devices: Dict[str, str] = {}  # device_key_id -> actor
        self.revocation_log: List[RevocationEntry] = []
        self.revocation_version = 0
        self.last_updated_time = time.monotonic()

    def enroll_device(self, actor: str, device_key_id: str) -> None:
        """Register an active device key for an actor (cannot reuse a revoked key)."""
        if device_key_id in self.revoked_device_keys:
            raise ValueError(f"Device key {device_key_id} is permanently revoked")
        self.enrolled_devices[device_key_id] = actor

    def apply_revocation_entry(self, entry: RevocationEntry) -> bool:
        """Apply a single monotonically versioned revocation entry."""
        if entry.version <= self.revocation_version:
            return False
        if entry.kind == "actor":
            self.revoked_actors.add(entry.target)
        elif entry.kind == "device_key":
            self.revoked_device_keys.add(entry.target)
        else:
            raise ValueError(f"Unknown revocation kind: {entry.kind}")
        self.revocation_log.append(entry)
        self.revocation_version = entry.version
        self.last_updated_time = time.monotonic()
        return True

    def sync_revocation_delta(self, remote_log: List[RevocationEntry]) -> int:
        """Apply all missing revocation entries from a peer's log in version order."""
        applied = 0
        for entry in sorted(remote_log, key=lambda e: e.version):
            if self.apply_revocation_entry(entry):
                applied += 1
        return applied

    def apply_revocation(self, actor: str, version: int) -> bool:
        """Compatibility helper for actor revocation."""
        return self.apply_revocation_entry(RevocationEntry(version=version, kind="actor", target=actor))

    def can_access(
        self,
        actor: str,
        asset_owner: str,
        device_key_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Use-time permission, device-key, and revocation check."""
        if actor in self.revoked_actors:
            return False, "ACTOR_REVOKED"
        if device_key_id is not None:
            if device_key_id in self.revoked_device_keys:
                return False, "DEVICE_KEY_REVOKED"
            if self.enrolled_devices.get(device_key_id) != actor:
                return False, "DEVICE_NOT_ENROLLED"
        if actor != asset_owner:
            return False, "NOT_OWNER"
        return True, "AUTHORIZED"
