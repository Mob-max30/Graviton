"""Tests for Node.check_actor (Phase 4 Step 1)."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.nodes.node import Node, ReasonCode


class TestNodeCheckActor(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-check-actor-")
        self.node_dir = Path(self._tmp.name) / "node"
        self.admin_pk, self.admin_sk = generate_signing_keypair()
        self.author = FeedAuthor("feed-ca", self.admin_sk, clock=lambda: 1_700_000_000)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_fresh_actor_and_revoke_and_preemptive_revoke(self) -> None:
        node = Node.initialise(self.node_dir, "feed-ca", self.admin_pk)
        pk, _ = generate_signing_keypair()
        node.apply_entries([
            self.author.genesis(),
            self.author.register_key("alice", "dev-1", pk),
        ])
        self.assertEqual(node.check_actor("alice").reason, ReasonCode.OK)
        self.assertEqual(node.check_actor("unregistered-actor").reason, ReasonCode.OK)

        # Pre-emptive revoke of unregistered actor
        node.apply_entry(self.author.revoke_actor("disabled-user"))
        self.assertEqual(node.check_actor("disabled-user").reason, ReasonCode.REVOKED_ACTOR)
        self.assertEqual(node.check_actor("alice").reason, ReasonCode.OK)

        # Revoke registered actor
        node.apply_entry(self.author.revoke_actor("alice"))
        self.assertEqual(node.check_actor("alice").reason, ReasonCode.REVOKED_ACTOR)
        # Existing authorize() unchanged
        self.assertEqual(node.authorize("alice", "dev-1", 1).reason, ReasonCode.REVOKED_ACTOR)

    def test_state_corrupt_on_missing_or_tampered(self) -> None:
        node = Node.initialise(self.node_dir, "feed-ca", self.admin_pk)
        node.apply_entry(self.author.genesis())
        state_file = self.node_dir / "node_state.json"

        state_file.write_text("{corrupt", encoding="utf-8")
        d = node.check_actor("alice")
        self.assertEqual((d.decision, d.reason), ("deny", ReasonCode.STATE_CORRUPT))

        state_file.unlink()
        d2 = node.check_actor("alice")
        self.assertEqual((d2.decision, d2.reason), ("deny", ReasonCode.STATE_CORRUPT))


if __name__ == "__main__":
    unittest.main()
