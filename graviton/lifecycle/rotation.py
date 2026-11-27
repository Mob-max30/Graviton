"""Write-ahead rotation state machine and crash recovery (Section 10)."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
from typing import Callable

from graviton.audit.log import AuditLog, AuthenticatedSession
from graviton.lifecycle.backup import BackupVerificationError, verify_and_load_backup
from graviton.storage import atomic_write_text, ensure_state_dir, state_lock

LIFECYCLE_VERSION = 1
STATE_FILENAME = "lifecycle_state.json"
WAL_FILENAME = "rotation_wal.json"


class RotationStep(str, Enum):
    IDLE = "IDLE"
    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    ACTIVATE = "ACTIVATE"
    RETIRE = "RETIRE"


class RotationError(RuntimeError):
    """Raised on invalid rotation request or inconsistent lifecycle state."""


@dataclass(frozen=True)
class RecoveryReport:
    recovered_from_step: RotationStep
    active_version: int
    usable_versions: list[int]
    revoked_versions: list[int]
    backup_verified: bool | None = None
    backup_error: str | None = None


class RotationManager:
    """Durable write-ahead rotation state machine: PREPARE -> COMMIT -> ACTIVATE -> RETIRE."""

    def __init__(self, state_dir: str | Path, *, audit_log: AuditLog | None = None) -> None:
        self.state_dir = Path(state_dir)
        self.audit_log = audit_log
        ensure_state_dir(self.state_dir)

    def _state_path(self) -> Path:
        return self.state_dir / STATE_FILENAME

    def _wal_path(self) -> Path:
        return self.state_dir / WAL_FILENAME

    def initialise(self, initial_version: int, public_key: bytes) -> None:
        with state_lock(self.state_dir):
            state = {
                "version": LIFECYCLE_VERSION,
                "active_version": initial_version,
                "keys": {
                    str(initial_version): {
                        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
                        "status": "ACTIVE",
                    }
                },
                "revoked_versions": [],
            }
            wal = {"version": LIFECYCLE_VERSION, "step": RotationStep.IDLE.value, "pending": None}
            atomic_write_text(self._state_path(), json.dumps(state, allow_nan=False, separators=(",", ":")))
            atomic_write_text(self._wal_path(), json.dumps(wal, allow_nan=False, separators=(",", ":")))

    def _load(self) -> tuple[dict, dict]:
        state = json.loads(self._state_path().read_text(encoding="utf-8"))
        wal = json.loads(self._wal_path().read_text(encoding="utf-8"))
        return state, wal

    def _save_state(self, state: dict) -> None:
        atomic_write_text(self._state_path(), json.dumps(state, allow_nan=False, separators=(",", ":")))

    def _save_wal(self, wal: dict) -> None:
        atomic_write_text(self._wal_path(), json.dumps(wal, allow_nan=False, separators=(",", ":")))

    def revoke_version(self, key_version: int) -> None:
        with state_lock(self.state_dir):
            state, _ = self._load()
            if key_version not in state["revoked_versions"]:
                state["revoked_versions"].append(key_version)
            k = state["keys"].get(str(key_version))
            if k is not None:
                k["status"] = "REVOKED"
            self._save_state(state)

    def get_state_snapshot(self) -> dict:
        with state_lock(self.state_dir):
            state, _ = self._load()
            return state

    def rotate(
        self,
        to_version: int,
        new_public_key: bytes,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> int:
        """Execute PREPARE -> COMMIT -> ACTIVATE -> RETIRE with durable WAL per step."""
        hook = fault_hook or (lambda _stage: None)
        with state_lock(self.state_dir):
            state, wal = self._load()
            if wal["step"] != RotationStep.IDLE.value:
                raise RotationError("Cannot start rotation while WAL is not IDLE; run recover() first")
            from_version = int(state["active_version"])
            if to_version <= from_version:
                raise RotationError("to_version must be greater than active_version")
            if from_version in state["revoked_versions"]:
                raise RotationError("Cannot rotate from a revoked active version")

            pending = {
                "from_version": from_version,
                "to_version": to_version,
                "new_public_key_b64": base64.b64encode(new_public_key).decode("ascii"),
            }

            # 1. PREPARE
            wal = {"version": LIFECYCLE_VERSION, "step": RotationStep.PREPARE.value, "pending": pending}
            self._save_wal(wal)
            hook("after_wal_prepare")
            state["keys"][str(to_version)] = {
                "public_key_b64": pending["new_public_key_b64"],
                "status": "PREPARED",
            }
            self._save_state(state)
            hook("after_apply_prepare")

            # 2. COMMIT
            wal = {"version": LIFECYCLE_VERSION, "step": RotationStep.COMMIT.value, "pending": pending}
            self._save_wal(wal)
            hook("after_wal_commit")
            state["keys"][str(to_version)]["status"] = "COMMITTED"
            self._save_state(state)
            hook("after_apply_commit")

            # 3. ACTIVATE
            wal = {"version": LIFECYCLE_VERSION, "step": RotationStep.ACTIVATE.value, "pending": pending}
            self._save_wal(wal)
            hook("after_wal_activate")
            state["active_version"] = to_version
            state["keys"][str(to_version)]["status"] = "ACTIVE"
            self._save_state(state)
            hook("after_apply_activate")

            # 4. RETIRE
            wal = {"version": LIFECYCLE_VERSION, "step": RotationStep.RETIRE.value, "pending": pending}
            self._save_wal(wal)
            hook("after_wal_retire")
            if from_version not in state["revoked_versions"]:
                state["keys"][str(from_version)]["status"] = "RETIRED"
            self._save_state(state)
            hook("after_apply_retire")

            self._save_wal({"version": LIFECYCLE_VERSION, "step": RotationStep.IDLE.value, "pending": None})
            return to_version

    def recover(
        self,
        *,
        backup_path: str | Path | None = None,
        backup_public_key: bytes | None = None,
        expected_min_backup_version: int = 1,
    ) -> RecoveryReport:
        """Recover to a single consistent, authorised key version after a crash."""
        backup_verified: bool | None = None
        backup_error: str | None = None

        if backup_path is not None:
            if backup_public_key is None:
                raise RotationError("backup_public_key is required when backup_path is given")
            try:
                verify_and_load_backup(
                    backup_path,
                    backup_public_key,
                    expected_min_version=expected_min_backup_version,
                    audit_log=self.audit_log,
                    session=AuthenticatedSession(actor="system-recovery"),
                )
                backup_verified = True
            except BackupVerificationError as exc:
                backup_verified = False
                backup_error = str(exc)

        with state_lock(self.state_dir):
            state, wal = self._load()
            step = RotationStep(wal["step"])
            pending = wal.get("pending")

            if step == RotationStep.PREPARE and pending is not None:
                # Uncommitted rotation: roll back cleanly
                to_ver_str = str(pending["to_version"])
                if int(pending["to_version"]) not in state["revoked_versions"]:
                    state["keys"].pop(to_ver_str, None)
                from_ver = int(pending["from_version"])
                state["active_version"] = from_ver
                if from_ver not in state["revoked_versions"] and str(from_ver) in state["keys"]:
                    state["keys"][str(from_ver)]["status"] = "ACTIVE"
                self._save_state(state)
                self._save_wal({"version": LIFECYCLE_VERSION, "step": RotationStep.IDLE.value, "pending": None})

            elif step in (RotationStep.COMMIT, RotationStep.ACTIVATE, RotationStep.RETIRE) and pending is not None:
                # Committed rotation: roll forward to completion
                from_ver = int(pending["from_version"])
                to_ver = int(pending["to_version"])
                to_ver_str = str(to_ver)
                if to_ver_str not in state["keys"]:
                    state["keys"][to_ver_str] = {
                        "public_key_b64": pending["new_public_key_b64"],
                        "status": "ACTIVE",
                    }
                if to_ver not in state["revoked_versions"]:
                    state["active_version"] = to_ver
                    state["keys"][to_ver_str]["status"] = "ACTIVE"
                if from_ver not in state["revoked_versions"] and str(from_ver) in state["keys"]:
                    state["keys"][str(from_ver)]["status"] = "RETIRED"
                self._save_state(state)
                self._save_wal({"version": LIFECYCLE_VERSION, "step": RotationStep.IDLE.value, "pending": None})

            # Enforce revocation permanence on all keys
            revoked = list(state["revoked_versions"])
            for rv in revoked:
                if str(rv) in state["keys"]:
                    state["keys"][str(rv)]["status"] = "REVOKED"
            self._save_state(state)

            usable = [
                int(ver)
                for ver, info in state["keys"].items()
                if int(ver) not in revoked and info["status"] in ("ACTIVE", "COMMITTED")
            ]
            return RecoveryReport(
                recovered_from_step=step,
                active_version=int(state["active_version"]),
                usable_versions=sorted(usable),
                revoked_versions=sorted(revoked),
                backup_verified=backup_verified,
                backup_error=backup_error,
            )
