"""Tests for Objective 12: Identity-bound session resumption (graviton.comms.resumption)."""
from __future__ import annotations

from pathlib import Path
import secrets
import tempfile
import unittest

from graviton.audit import AuditLog
from graviton.comms import ResumptionError, ResumptionManager
from graviton.crypto.signatures import generate_signing_keypair


class TestSessionResumption(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-resume-")
        base = Path(self._tmp.name)
        self.audit = AuditLog(base / "audit.db", base / "audit_head.json")
        self.now = [1_700_000_000]
        self.mgr = ResumptionManager(
            ticket_lifetime_s=3600,
            clock=lambda: self.now[0],
            audit_log=self.audit,
        )
        self.alice_pk, self.alice_sk = generate_signing_keypair()
        self.mallory_pk, self.mallory_sk = generate_signing_keypair()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_legitimate_resume_succeeds_and_impostor_rejected_and_logged(self) -> None:
        sid = "sess-" + secrets.token_hex(8)
        ticket = self.mgr.issue_ticket(sid, "alice", self.alice_pk)

        nonce = secrets.token_bytes(16)
        sig_alice = self.mgr.sign_resume_challenge(self.alice_sk, sid, "alice", nonce)
        self.assertTrue(self.mgr.verify_resumption(ticket, "alice", nonce, sig_alice))

        # Different identity presenting the same session ID (even with its own valid key) is rejected
        sig_mallory = self.mgr.sign_resume_challenge(self.mallory_sk, sid, "mallory", nonce)
        with self.assertRaises(ResumptionError):
            self.mgr.verify_resumption(ticket, "mallory", nonce, sig_mallory)

        # Presenting "alice" with mallory's signature is also rejected
        with self.assertRaises(ResumptionError):
            self.mgr.verify_resumption(ticket, "alice", nonce, sig_mallory)

        events = self.audit.fetch_events()
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["action"] == "session_resume" and e["decision"] == "deny" for e in events))

    def test_expiry_and_revocation_invalidate_ticket(self) -> None:
        sid = "sess-" + secrets.token_hex(8)
        ticket = self.mgr.issue_ticket(sid, "alice", self.alice_pk)
        nonce = secrets.token_bytes(16)
        sig = self.mgr.sign_resume_challenge(self.alice_sk, sid, "alice", nonce)

        # Advance past lifetime
        self.now[0] += 3601
        with self.assertRaises(ResumptionError):
            self.mgr.verify_resumption(ticket, "alice", nonce, sig)

        # Revocation invalidates active ticket immediately
        self.now[0] = 1_700_000_000
        ticket2 = self.mgr.issue_ticket("sess-2", "alice", self.alice_pk)
        self.mgr.revoke_peer_tickets("alice")
        sig2 = self.mgr.sign_resume_challenge(self.alice_sk, "sess-2", "alice", nonce)
        with self.assertRaises(ResumptionError):
            self.mgr.verify_resumption(ticket2, "alice", nonce, sig2)


if __name__ == "__main__":
    unittest.main()
