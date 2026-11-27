"""Tests for Objective 11: Delivery under loss or reordering (graviton.comms.delivery)."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from graviton.audit import AuditLog
from graviton.comms import ChunkedReceiver, OfflineQueue, establish_session, split_into_chunks
from graviton.crypto.signatures import generate_signing_keypair


class TestLossyDelivery(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-delivery-")
        self.base = Path(self._tmp.name)
        a_pk, a_sk = generate_signing_keypair()
        b_pk, b_sk = generate_signing_keypair()
        self.s_alice, self.s_bob, _ = establish_session("alice", a_sk, a_pk, "bob", b_sk, b_pk)
        self.audit = AuditLog(self.base / "audit.db", self.base / "audit_head.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_reordering_and_loss_recovery_succeeds(self) -> None:
        payload = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        chunks = split_into_chunks(self.s_alice, "alice", "bob", payload, chunk_size=10)
        self.assertEqual(len(chunks), 4)

        rx = ChunkedReceiver(self.s_bob, "bob", max_retries=3, audit_log=self.audit)
        # Deliver out of order, dropping chunk 1 initially
        r3 = rx.receive_chunk(chunks[3])
        self.assertFalse(r3.delivered)
        r0 = rx.receive_chunk(chunks[0])
        self.assertFalse(r0.delivered)
        r2 = rx.receive_chunk(chunks[2])
        self.assertFalse(r2.delivered)
        self.assertEqual(r2.missing_indices, [1])

        # Retransmit missing chunk 1
        retrans = rx.request_retransmit(chunks[0].msg_id)
        self.assertEqual(retrans.missing_indices, [1])
        r1 = rx.receive_chunk(chunks[1])
        self.assertTrue(r1.delivered)
        self.assertEqual(r1.payload, payload)

    def test_retry_exhaustion_and_tampered_chunk_discard_and_log(self) -> None:
        chunks = split_into_chunks(self.s_alice, "alice", "bob", b"abcdefghijklmnop", chunk_size=4)
        rx = ChunkedReceiver(self.s_bob, "bob", max_retries=2, audit_log=self.audit)

        rx.receive_chunk(chunks[0])
        self.assertIsNone(rx.request_retransmit(chunks[0].msg_id).error)
        self.assertIsNone(rx.request_retransmit(chunks[0].msg_id).error)
        # 3rd retry exceeds max_retries=2 -> partial message discarded and logged
        failed = rx.request_retransmit(chunks[0].msg_id)
        self.assertFalse(failed.delivered)
        self.assertIsNotNone(failed.error)
        self.assertEqual(self.audit.fetch_events()[-1]["decision"], "deny")

        # Tampered chunk also discards immediately
        chunks2 = split_into_chunks(self.s_alice, "alice", "bob", b"secret-msg", chunk_size=5, base_counter=10)
        bad_env = dict(chunks2[0].envelope)
        bad_env["sender_id"] = "mallory"
        from graviton.comms import Chunk

        res_bad = rx.receive_chunk(Chunk(chunks2[0].msg_id, 0, 2, bad_env))
        self.assertFalse(res_bad.delivered)
        self.assertIsNotNone(res_bad.error)

    def test_offline_queue_stores_encrypted_envelopes(self) -> None:
        q = OfflineQueue(self.base / "queue.json")
        chunks = split_into_chunks(self.s_alice, "alice", "bob", b"offline-hello", chunk_size=20)
        q.enqueue("bob", chunks[0].envelope)
        pending = q.pending_for("bob")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["session_id"], self.s_alice.session_id)


if __name__ == "__main__":
    unittest.main()
