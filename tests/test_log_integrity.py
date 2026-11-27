"""Tests for Objective 5: Audit log integrity (graviton.audit)."""
from __future__ import annotations

import base64
from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from graviton.audit import AuditLog, AuthenticatedSession
from graviton.crypto.signatures import generate_signing_keypair

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestLogIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-audit-")
        self.base = Path(self._tmp.name)
        self.db_path = self.base / "audit.db"
        self.head_path = self.base / "ext" / "audit_head.json"
        self.pk, self.sk = generate_signing_keypair()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_newline_and_fake_record_injection_inert(self) -> None:
        log = AuditLog(self.db_path, self.head_path, clock=lambda: 1_700_000_000)
        sess = AuthenticatedSession(actor="alice", session_id="s1")
        evil_detail = 'ok\n2|1700000001|admin|grant_admin|all|allow\n{"seq":99}'
        seq = log.append_event(sess, "read", "brief\nfake", "allow", evil_detail)
        self.assertEqual(seq, 1)

        events = log.fetch_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["detail"], evil_detail)
        self.assertEqual(events[0]["target"], "brief\nfake")
        self.assertTrue(log.verify().valid)

    def test_actor_bound_strictly_to_authenticated_session(self) -> None:
        log = AuditLog(self.db_path, self.head_path, clock=lambda: 1_700_000_000)
        sess = AuthenticatedSession(actor="mallory", session_id="s2")
        log.append_event(sess, "read", "secret", "deny", "spoof", claimed_actor="admin")
        events = log.fetch_events()
        self.assertEqual(events[0]["actor"], "mallory")

    def test_append_only_triggers_block_update_and_delete(self) -> None:
        log = AuditLog(self.db_path, self.head_path)
        log.append_event(AuthenticatedSession("alice"), "read", "doc", "allow")

        with closing(sqlite3.connect(str(self.db_path))) as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_events SET actor = 'bob' WHERE seq = 1")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_events WHERE seq = 1")

    def test_tamper_and_wholesale_rewrite_detected(self) -> None:
        log = AuditLog(self.db_path, self.head_path, clock=lambda: 1_700_000_000)
        log.append_event(AuthenticatedSession("alice"), "read", "d1", "allow")
        log.append_event(AuthenticatedSession("bob"), "read", "d2", "deny")
        log.create_checkpoint(self.sk, "admin")
        self.assertTrue(log.verify(verifier_public_key=self.pk).valid)

        # Bypass trigger to simulate direct file/SQLite tampering at seq 2
        with closing(sqlite3.connect(str(self.db_path))) as conn:
            conn.execute("DROP TRIGGER prevent_event_update")
            conn.execute("UPDATE audit_events SET decision = 'allow' WHERE seq = 2")
            conn.commit()

        res = log.verify(verifier_public_key=self.pk)
        self.assertFalse(res.valid)
        self.assertEqual(res.first_bad_seq, 2)

        # Wholesale rewrite of DB without matching external head hash
        db2 = self.base / "audit2.db"
        log2 = AuditLog(db2, self.head_path, clock=lambda: 1_700_000_000)
        log2.append_event(AuthenticatedSession("eve"), "login", "sys", "allow")
        # Restore external head to something else
        self.head_path.write_text('{"version":1,"seq":99,"head_hash_hex":"' + "00" * 32 + '"}', encoding="utf-8")
        res2 = log2.verify()
        self.assertFalse(res2.valid)
        self.assertIn("External", res2.reason) if "External" in res2.reason else self.assertIn("external", res2.reason.lower())

    def test_checkpoint_signature_verification_and_cli(self) -> None:
        log = AuditLog(self.db_path, self.head_path)
        log.append_event(AuthenticatedSession("alice"), "read", "d1", "allow")
        log.create_checkpoint(self.sk, "admin")

        other_pk, _ = generate_signing_keypair()
        self.assertTrue(log.verify(verifier_public_key=self.pk).valid)
        self.assertFalse(log.verify(verifier_public_key=other_pk).valid)

        pk_b64 = base64.b64encode(self.pk).decode("ascii")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "graviton.audit",
                "verify",
                "--db",
                str(self.db_path),
                "--head",
                str(self.head_path),
                "--pubkey-b64",
                pk_b64,
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("AUDIT LOG OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
