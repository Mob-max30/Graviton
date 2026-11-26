"""Tests for Node.authorize and Node.authenticate_request (Step 4)."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from graviton.crypto.signatures import generate_signing_keypair, sign_message
from graviton.feed.author import FeedAuthor
from graviton.feed.entries import FEED_SIGN_DOMAIN
from graviton.nodes.node import Node, ReasonCode, build_request_signing_bytes


class TestNodeAuthorize(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-auth-")
        self.base = Path(self._tmp.name)
        self.admin_pk, self.admin_sk = generate_signing_keypair()
        self.now = 1_700_000_000
        self.author = FeedAuthor("feed-1", self.admin_sk, clock=lambda: self.now)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rotation_cutoff_and_lagging_node(self) -> None:
        n1 = Node.initialise(self.base / "n1", "feed-1", self.admin_pk)
        n2 = Node.initialise(self.base / "n2", "feed-1", self.admin_pk)
        pk1, _ = generate_signing_keypair()
        pk2, _ = generate_signing_keypair()

        e1 = self.author.genesis()
        e2 = self.author.register_key("alice", "dev-1", pk1)
        e3 = self.author.rotate_key("alice", "dev-1", 2, pk2, cutoff_epoch=5)
        e4 = self.author.head()
        e5 = self.author.head()

        # Before cutoff (epoch 4): both v1 and v2 allowed
        n1.apply_entries([e1, e2, e3, e4])
        n2.apply_entries([e1, e2, e3, e4])
        self.assertEqual(n1.authorize("alice", "dev-1", 1).decision, "allow")
        self.assertEqual(n1.authorize("alice", "dev-1", 2).decision, "allow")

        # n1 applies epoch 5 (cutoff); n2 lags at epoch 4
        n1.apply_entry(e5)
        d1_v1 = n1.authorize("alice", "dev-1", 1)
        self.assertEqual((d1_v1.decision, d1_v1.reason), ("deny", ReasonCode.KEY_RETIRED))
        self.assertEqual(n1.authorize("alice", "dev-1", 2).decision, "allow")
        # Lagging n2 still accepts v1 until it catches up
        self.assertEqual(n2.authorize("alice", "dev-1", 1).decision, "allow")

    def test_device_and_actor_revocation_and_device_loss_reenrol(self) -> None:
        node = Node.initialise(self.base / "n", "feed-1", self.admin_pk)
        pk_a1, _ = generate_signing_keypair()
        pk_a2, _ = generate_signing_keypair()
        pk_a3, _ = generate_signing_keypair()
        pk_b1, _ = generate_signing_keypair()

        node.apply_entries([
            self.author.genesis(),
            self.author.register_key("alice", "dev-1", pk_a1),
            self.author.register_key("alice", "dev-2", pk_a2),
            self.author.register_key("bob", "bob-1", pk_b1),
            self.author.revoke_device("alice", "dev-1"),
        ])

        d = node.authorize("alice", "dev-1", 1)
        self.assertEqual((d.decision, d.reason), ("deny", ReasonCode.REVOKED_DEVICE))
        self.assertEqual(node.authorize("alice", "dev-2", 1).decision, "allow")
        self.assertEqual(node.authorize("bob", "bob-1", 1).decision, "allow")

        # Re-enrol with a new device_id works; re-registering revoked dev-1 is rejected
        res_new = node.apply_entry(self.author.register_key("alice", "dev-3", pk_a3))
        self.assertTrue(res_new.applied)
        self.assertEqual(node.authorize("alice", "dev-3", 1).decision, "allow")

        dup_author = FeedAuthor("feed-1", self.admin_sk, clock=lambda: self.now)
        dup_author.epoch = self.author.epoch
        dup_author.last_hash = self.author.last_hash
        res_dup = node.apply_entry(dup_author.register_key("alice", "dev-1", pk_a1))
        self.assertFalse(res_dup.applied)

        # Revoking actor denies all their devices permanently
        node.apply_entry(self.author.revoke_actor("alice"))
        self.assertEqual(node.authorize("alice", "dev-2", 1).reason, ReasonCode.REVOKED_ACTOR)
        self.assertEqual(node.authorize("alice", "dev-3", 1).reason, ReasonCode.REVOKED_ACTOR)
        self.assertEqual(node.authorize("bob", "bob-1", 1).decision, "allow")

        # Survives restart and later entries
        node.apply_entry(self.author.head())
        reloaded = Node(self.base / "n")
        self.assertEqual(reloaded.authorize("alice", "dev-3", 1).reason, ReasonCode.REVOKED_ACTOR)

    def test_freshness_window_and_none(self) -> None:
        fake_now = [1_700_000_000]
        node_strict = Node.initialise(
            self.base / "strict", "feed-1", self.admin_pk, freshness_window=10, clock=lambda: fake_now[0]
        )
        node_none = Node.initialise(
            self.base / "none", "feed-1", self.admin_pk, freshness_window=None, clock=lambda: fake_now[0]
        )
        pk, _ = generate_signing_keypair()
        entries = [self.author.genesis(), self.author.register_key("alice", "dev-1", pk)]
        node_strict.apply_entries(entries)
        node_none.apply_entries(entries)

        self.assertEqual(node_strict.authorize("alice", "dev-1", 1).decision, "allow")
        fake_now[0] += 15
        self.assertEqual(node_strict.authorize("alice", "dev-1", 1).reason, ReasonCode.STALE_STATE)
        self.assertEqual(node_none.authorize("alice", "dev-1", 1).decision, "allow")

        # New HEAD at current time restores freshness
        self.now = fake_now[0]
        node_strict.apply_entry(self.author.head())
        self.assertEqual(node_strict.authorize("alice", "dev-1", 1).decision, "allow")

    def test_authenticate_request_signatures_and_domains(self) -> None:
        node = Node.initialise(self.base / "auth", "feed-1", self.admin_pk)
        pk1, sk1 = generate_signing_keypair()
        pk2, sk2 = generate_signing_keypair()
        _, wrong_sk = generate_signing_keypair()

        node.apply_entries([
            self.author.genesis(),
            self.author.register_key("alice", "dev-1", pk1),
            self.author.rotate_key("alice", "dev-1", 2, pk2, cutoff_epoch=10),
        ])

        payload = b"GET /resource/42"
        msg_v1 = build_request_signing_bytes("feed-1", "alice", "dev-1", 1, payload)
        sig_v1 = sign_message(sk1, msg_v1, domain=b"request")
        self.assertEqual(node.authenticate_request("alice", "dev-1", 1, payload, sig_v1).decision, "allow")

        # Wrong version (v2 is known, sig is from v1), wrong key, tampered payload, wrong domain -> INVALID_SIGNATURE; unknown actor -> UNKNOWN_KEY
        self.assertEqual(node.authenticate_request("alice", "dev-1", 2, payload, sig_v1).reason, ReasonCode.INVALID_SIGNATURE)
        sig_wrong = sign_message(wrong_sk, msg_v1, domain=b"request")
        self.assertEqual(node.authenticate_request("alice", "dev-1", 1, payload, sig_wrong).reason, ReasonCode.INVALID_SIGNATURE)
        self.assertEqual(node.authenticate_request("alice", "dev-1", 1, payload + b"!", sig_v1).reason, ReasonCode.INVALID_SIGNATURE)
        self.assertEqual(node.authenticate_request("bob", "dev-1", 1, payload, sig_v1).reason, ReasonCode.UNKNOWN_KEY)

        sig_feed_domain = sign_message(sk1, msg_v1, domain=FEED_SIGN_DOMAIN)
        self.assertEqual(node.authenticate_request("alice", "dev-1", 1, payload, sig_feed_domain).reason, ReasonCode.INVALID_SIGNATURE)

        # Revoked device denied even with valid signature
        node.apply_entry(self.author.revoke_device("alice", "dev-1"))
        self.assertEqual(node.authenticate_request("alice", "dev-1", 1, payload, sig_v1).reason, ReasonCode.REVOKED_DEVICE)

    def test_preemptive_revoke_unregistered_actor(self) -> None:
        node = Node.initialise(self.base / "pre", "feed-1", self.admin_pk)
        pk, _ = generate_signing_keypair()
        node.apply_entries([
            self.author.genesis(),
            self.author.revoke_actor("disabled-user"),
        ])
        self.assertEqual(node.authorize("disabled-user", "any-dev", 1).reason, ReasonCode.REVOKED_ACTOR)
        res = node.apply_entry(self.author.register_key("disabled-user", "dev-1", pk))
        self.assertFalse(res.applied)


if __name__ == "__main__":
    unittest.main()
