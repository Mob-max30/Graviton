"""Key rotation, two-phase commit, and dual-key acceptance tests."""
import tempfile
from pathlib import Path

from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator


def test_two_phase_commit_key_rotation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lifecycle = KeyLifecycleManager(initial_epoch=1)
        coordinator = RotationCoordinator(Path(tmp_dir), lifecycle)

        # 1. Setup initial active key
        lifecycle.register_key("key-v1", "ML-DSA-65", "pub1")
        lifecycle.transition_state("key-v1", KeyState.ACTIVE)
        assert lifecycle.get_active_key().key_id == "key-v1"

        # 2. Phase 1: Prepare rotation to key-v2
        prep = coordinator.prepare_rotation("key-v2", "ML-DSA-65", "pub2")
        assert prep["new_key_id"] == "key-v2"
        assert prep["target_epoch"] == 2
        assert lifecycle.get_key("key-v2").state == KeyState.PENDING

        # 3. Phase 2: Commit rotation at t=1000 with 300s grace
        coord_t0 = 1000.0
        commit = coordinator.commit_rotation("key-v2", now=coord_t0)
        assert commit["new_key_id"] == "key-v2"
        assert commit["active_epoch"] == 2

        # Verify new key is ACTIVE and old key transitioned to GRACE
        assert lifecycle.get_active_key().key_id == "key-v2"
        assert lifecycle.get_key("key-v1").state == KeyState.GRACE
        assert lifecycle.current_epoch == 2

        # Dual-key acceptance within grace window (injected clock before deadline)
        deadline = commit["grace_until"]
        assert lifecycle.is_key_acceptable("key-v2", now=deadline - 1.0) is True
        assert lifecycle.is_key_acceptable("key-v1", now=deadline - 1.0) is True

        # Cutoff enforcement after grace period expires (monotonic GRACE -> RETIRED)
        assert lifecycle.is_key_acceptable("key-v1", now=deadline + 1.0) is False
        ok_old_after, reason_after = lifecycle.verify_key_for_request("key-v1", now=deadline + 1.0)
        assert ok_old_after is False
        assert reason_after == "KEY_RETIRED"
        assert lifecycle.get_key("key-v1").state == KeyState.RETIRED
        assert lifecycle.is_key_acceptable("key-v2", now=deadline + 1.0) is True


def test_grace_cutoff_persists_across_restart():
    """B1: Recreate coordinator and lifecycle from disk after grace deadline and assert rejection."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "lifecycle.json"
        lifecycle = KeyLifecycleManager(initial_epoch=1, state_path=state_file)
        lifecycle.register_key("k1", "ML-DSA-65", "p1")
        lifecycle.transition_state("k1", KeyState.ACTIVE)

        coord = RotationCoordinator(Path(tmp_dir), lifecycle, grace_period_seconds=0.05)
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")
        commit = coord.commit_rotation("k2", now=1000.0)
        deadline = commit["grace_until"]

        # Restart from disk
        restarted = KeyLifecycleManager(state_path=state_file)
        assert restarted.is_key_acceptable("k1", now=deadline - 0.01) is True
        assert restarted.is_key_acceptable("k1", now=deadline + 0.01) is False
        assert restarted.is_key_acceptable("k2", now=deadline + 0.01) is True


def test_key_id_cannot_be_reused():
    lifecycle = KeyLifecycleManager()
    lifecycle.register_key("unique-key", "ML-DSA-65", "pub")
    lifecycle.transition_state("unique-key", KeyState.REVOKED)

    import pytest
    with pytest.raises(ValueError, match="cannot be reused"):
        lifecycle.register_key("unique-key", "ML-DSA-65", "pub")
