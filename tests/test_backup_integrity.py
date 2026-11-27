"""Tests for Objective 4: Backup integrity verification (graviton.lifecycle.backup)."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import tempfile
import unittest

from graviton.audit import AuditLog
from graviton.crypto.signatures import generate_signing_keypair
from graviton.lifecycle import BackupVerificationError, create_backup, verify_and_load_backup


class TestBackupIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-backup-")
        self.base = Path(self._tmp.name)
        self.pk, self.sk = generate_signing_keypair()
        self.audit = AuditLog(self.base / "audit.db", self.base / "audit_head.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_valid_backup_verifies_and_loads(self) -> None:
        payload = {"k1": secrets.token_hex(16)}
        bak = create_backup(self.base / "valid.bak", 2, payload, self.sk)
        ver, loaded = verify_and_load_backup(bak, self.pk, expected_min_version=2, audit_log=self.audit)
        self.assertEqual(ver, 2)
        self.assertEqual(loaded, payload)
        self.assertEqual(self.audit.fetch_events()[-1]["decision"], "allow")

    def test_flipped_bytes_truncated_and_version_swap_detected(self) -> None:
        payload = {"k1": secrets.token_hex(16)}
        bak = create_backup(self.base / "keys.bak", 3, payload, self.sk)
        env = json.loads(bak.read_text(encoding="utf-8"))

        # 1. Flip byte in payload_b64
        tampered_payload = dict(env)
        p = tampered_payload["payload_b64"]
        tampered_payload["payload_b64"] = ("B" if p[0] == "A" else "A") + p[1:]
        bad1 = self.base / "bad_payload.bak"
        bad1.write_text(json.dumps(tampered_payload), encoding="utf-8")
        with self.assertRaises(BackupVerificationError):
            verify_and_load_backup(bad1, self.pk, audit_log=self.audit)

        # 2. Flip byte in signature_b64
        tampered_sig = dict(env)
        s = tampered_sig["signature_b64"]
        tampered_sig["signature_b64"] = ("B" if s[0] == "A" else "A") + s[1:]
        bad2 = self.base / "bad_sig.bak"
        bad2.write_text(json.dumps(tampered_sig), encoding="utf-8")
        with self.assertRaises(BackupVerificationError):
            verify_and_load_backup(bad2, self.pk, audit_log=self.audit)

        # 3. Truncated backup
        bad3 = self.base / "truncated.bak"
        bad3.write_text(bak.read_text(encoding="utf-8")[:40], encoding="utf-8")
        with self.assertRaises(BackupVerificationError):
            verify_and_load_backup(bad3, self.pk, audit_log=self.audit)

        # 4. Version swap / rollback (valid v1 backup presented when v3 is required)
        old_bak = create_backup(self.base / "old.bak", 1, payload, self.sk)
        with self.assertRaises(BackupVerificationError):
            verify_and_load_backup(old_bak, self.pk, expected_min_version=3, audit_log=self.audit)

        # 5. Version field swapped in envelope without re-signing
        swapped = dict(env)
        swapped["backup_version"] = 4
        bad5 = self.base / "swapped.bak"
        bad5.write_text(json.dumps(swapped), encoding="utf-8")
        with self.assertRaises(BackupVerificationError):
            verify_and_load_backup(bad5, self.pk, audit_log=self.audit)

        events = self.audit.fetch_events()
        self.assertEqual(len(events), 5)
        self.assertTrue(all(e["decision"] == "deny" for e in events))


if __name__ == "__main__":
    unittest.main()
