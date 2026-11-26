"""Crash point fault injection framework and idempotent recovery manager."""
from typing import Optional

from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator, WALPhase


class CrashInjectedError(RuntimeError):
    """Exception raised by a simulated crash point."""


class CrashPointManager:
    """Configures named crash injection points for testing fault tolerance."""

    _active_crash_point: Optional[str] = None

    @classmethod
    def arm(cls, point_name: str) -> None:
        cls._active_crash_point = point_name

    @classmethod
    def disarm(cls) -> None:
        cls._active_crash_point = None

    @classmethod
    def trigger(cls, point_name: str) -> None:
        if cls._active_crash_point == point_name:
            cls._active_crash_point = None
            raise CrashInjectedError(f"Simulated crash at point: {point_name}")


class RecoveryManager:
    """Deterministic, idempotent recovery from crashed WAL states and invariant verification."""

    def __init__(self, coordinator: RotationCoordinator, lifecycle: KeyLifecycleManager):
        self.coordinator = coordinator
        self.lifecycle = lifecycle

    def recover(self) -> str:
        """Replay WAL, resolve half-done operations idempotently, and restore state."""
        wal_data = self.coordinator.read_wal()
        if not wal_data:
            return "NOOP: Clean state, nothing to recover"

        phase = wal_data.get("phase")
        new_key_id = wal_data.get("new_key_id")

        if phase == WALPhase.PREPARED and new_key_id:
            self.coordinator.abort_rotation(str(new_key_id))
            return f"ROLLED_BACK: Aborted half-prepared key {new_key_id}"

        if phase == WALPhase.COMMITTED:
            old_key_id = wal_data.get("old_key_id")
            if old_key_id:
                old_rec = self.lifecycle.get_key(str(old_key_id))
                if old_rec is not None and old_rec.state in (KeyState.ACTIVE, KeyState.GRACE):
                    self.lifecycle.transition_state(str(old_key_id), KeyState.RETIRED)

            if new_key_id:
                new_rec = self.lifecycle.get_key(str(new_key_id))
                if new_rec is not None and new_rec.state == KeyState.PENDING:
                    self.lifecycle.current_epoch = int(wal_data.get("active_epoch", self.lifecycle.current_epoch))
                    self.lifecycle.transition_state(str(new_key_id), KeyState.ACTIVE)

            return f"ROLLED_FORWARD: Confirmed committed active key {new_key_id}"

        return "CLEAN: WAL in terminal phase"

    def assert_invariants(self) -> None:
        """Verify core safety invariants hold true post-recovery."""
        active_keys = [
            k for k, rec in self.lifecycle._keys.items() if rec.state == KeyState.ACTIVE
        ]
        if len(active_keys) > 1:
            raise AssertionError(f"Multiple ACTIVE keys found post-recovery: {active_keys}")

        for k, rec in self.lifecycle._keys.items():
            if rec.revoked_at_epoch is not None and rec.state != KeyState.REVOKED:
                raise AssertionError(f"Revoked key {k} resurrected into state {rec.state}")
