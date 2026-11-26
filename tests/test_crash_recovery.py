"""Tests for Objective 3: Rotation crash recovery & fault injection (graviton.lifecycle)."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from graviton.audit import AuditLog
from graviton.crypto.kem import decapsulate, encapsulate, generate_kem_keypair
from graviton.crypto.signatures import generate_signing_keypair
from graviton.lifecycle import RotationManager, RotationStep, create_backup


class _InjectedCrash(RuntimeError):
    pass


FAULT_POINTS = (
    "after_wal_prepare",
    "after_apply_prepare",
    "after_wal_commit",
    "after_apply_commit",
    "after_wal_activate",
    "after_apply_activate",
    "after_wal_retire",
    "after_apply_retire",
)


class TestCrashRecovery(unittest.TestCase):
    def test_fault_injection_at_every_rotation_step(self) -> None:
        for stage in FAULT_POINTS:
            with self.subTest(stage=stage):
                with tempfile.TemporaryDirectory(prefix="graviton-crash-") as tmp:
                    base = Path(tmp)
                    mgr = RotationManager(base / "lifecycle")
                    pk0, _ = generate_kem_keypair()
                    pk1, sk1 = generate_kem_keypair()
                    pk2, sk2 = generate_kem_keypair()

                    # v1 active, v2 rotated in, then v1 revoked so we also verify revocations persist
                    mgr.initialise(1, pk0)
                    mgr.rotate(2, pk1)
                    mgr.revoke_version(1)

                    # Encapsulate protected data under v2 (committed before crash) and v3 (target)
                    ct_v2, ss_v2 = encapsulate(pk1)
                    ct_v3, ss_v3 = encapsulate(pk2)

                    def hook(current_stage: str, target: str = stage) -> None:
                        if current_stage == target:
                            raise _InjectedCrash(f"Simulated crash at {current_stage}")

                    with self.assertRaises(_InjectedCrash):
                        mgr.rotate(3, pk2, fault_hook=hook)

                    # Fresh manager instance simulates process restart + recovery
                    restarted = RotationManager(base / "lifecycle")
                    report = restarted.recover()

                    self.assertIn(1, report.revoked_versions)
                    if "prepare" in stage:
                        self.assertEqual(report.recovered_from_step, RotationStep.PREPARE)
                        self.assertEqual(report.active_version, 2)
                        self.assertEqual(decapsulate(sk1, ct_v2), ss_v2)
                    else:
                        self.assertEqual(report.active_version, 3)
                        self.assertEqual(decapsulate(sk2, ct_v3), ss_v3)
                        # v1 stays revoked, v2 is retired
                        snap = restarted.get_state_snapshot()
                        self.assertEqual(snap["keys"]["1"]["status"], "REVOKED")
                        self.assertEqual(snap["keys"]["2"]["status"], "RETIRED")
                        self.assertEqual(snap["keys"]["3"]["status"], "ACTIVE")

    def test_recovery_rejects_corrupt_backup_but_keeps_committed_keys(self) -> None:
        with tempfile.TemporaryDirectory(prefix="graviton-rec-bak-") as tmp:
            base = Path(tmp)
            audit = AuditLog(base / "audit.db", base / "audit_head.json")
            mgr = RotationManager(base / "lifecycle", audit_log=audit)
            pk1, sk1 = generate_kem_keypair()
            mgr.initialise(1, pk1)
            ct, ss = encapsulate(pk1)

            b_pk, b_sk = generate_signing_keypair()
            bak_path = create_backup(base / "keys.bak", 1, {"1": "committed"}, b_sk)
            # Corrupt the backup file
            raw = bak_path.read_text(encoding="utf-8")
            bak_path.write_text(raw[:-5] + "XXXXX", encoding="utf-8")

            report = mgr.recover(backup_path=bak_path, backup_public_key=b_pk)
            self.assertFalse(report.backup_verified)
            self.assertIsNotNone(report.backup_error)
            # Committed key v1 remains usable
            self.assertEqual(report.active_version, 1)
            self.assertEqual(decapsulate(sk1, ct), ss)
            # Failure was logged in AuditLog
            events = audit.fetch_events()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["action"], "backup_verify")
            self.assertEqual(events[0]["decision"], "deny")


if __name__ == "__main__":
    unittest.main()
