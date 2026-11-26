"""Crash point fault injection, recovery, and invariant assertion tests."""
import tempfile
from pathlib import Path

import pytest

from trustledger.cluster.crash import (
    CrashInjectedError,
    CrashPointManager,
    RecoveryManager,
)
from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator, WALIntegrityError


def test_crash_during_prepare_rolls_back():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(1)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        rec_mgr = RecoveryManager(coord, lifecycle)

        # Prepare rotation
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")

        # Simulate crash before commit
        CrashPointManager.arm("PRE_COMMIT")
        try:
            CrashPointManager.trigger("PRE_COMMIT")
        except CrashInjectedError:
            pass  # Crash simulated

        # Perform recovery
        status = rec_mgr.recover()
        assert "ROLLED_BACK" in status
        rec_mgr.assert_invariants()

        # k1 is still ACTIVE, k2 is revoked
        assert lifecycle.get_active_key().key_id == "k1"
        assert lifecycle.get_key("k2").state == KeyState.REVOKED


def test_crash_during_commit_rolls_forward():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "lifecycle.json"
        lifecycle = KeyLifecycleManager(1, state_path=state_file)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")
        coord.commit_rotation("k2")

        # Simulate process restart: load a brand-new KeyLifecycleManager from disk
        restarted_lifecycle = KeyLifecycleManager(state_path=state_file)
        restarted_coord = RotationCoordinator(Path(tmp_dir), restarted_lifecycle)
        rec_mgr = RecoveryManager(restarted_coord, restarted_lifecycle)

        status = rec_mgr.recover()
        assert "ROLLED_FORWARD" in status
        # Idempotent second recovery call does not crash
        status2 = rec_mgr.recover()
        assert "ROLLED_FORWARD" in status2
        rec_mgr.assert_invariants()

        assert restarted_lifecycle.get_active_key().key_id == "k2"
        assert restarted_lifecycle.get_key("k1").state == KeyState.RETIRED


def test_crash_before_prepare_preserves_active_key():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(1)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        rec_mgr = RecoveryManager(coord, lifecycle)

        CrashPointManager.arm("BEFORE_PREPARE")
        with pytest.raises(CrashInjectedError):
            CrashPointManager.trigger("BEFORE_PREPARE")

        status = rec_mgr.recover()
        assert status.startswith("NOOP:")
        rec_mgr.assert_invariants()
        assert lifecycle.get_active_key().key_id == "k1"


def test_crash_mid_commit_before_committed_wal_rolls_back():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(1)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")

        # Simulate crash mid-commit before COMMITTED WAL record is written
        CrashPointManager.arm("MID_COMMIT")
        with pytest.raises(CrashInjectedError):
            CrashPointManager.trigger("MID_COMMIT")

        rec_mgr = RecoveryManager(coord, lifecycle)
        status = rec_mgr.recover()
        assert "ROLLED_BACK" in status
        rec_mgr.assert_invariants()
        assert lifecycle.get_active_key().key_id == "k1"
        assert lifecycle.get_key("k2").state == KeyState.REVOKED


def test_forged_and_truncated_wal_fail_closed():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(1)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle)
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")
        wal_data = coord.read_wal()
        assert wal_data is not None and "wal_mac" in wal_data

        # Tamper with target_epoch without updating wal_mac
        wal_data["target_epoch"] = 999
        coord.wal_file.write_text('{"phase": "PREPARED", "old_key_id": "k1", "new_key_id": "k2", "target_epoch": 999, "wal_mac": "' + wal_data["wal_mac"] + '"}', encoding="utf-8")
        with pytest.raises(WALIntegrityError, match="HMAC"):
            coord.read_wal()

        # Truncate WAL file
        coord.wal_file.write_text('{"phase": "PREPARED"', encoding="utf-8")
        with pytest.raises(WALIntegrityError, match="Corrupt"):
            coord.read_wal()
