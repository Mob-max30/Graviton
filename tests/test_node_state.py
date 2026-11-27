"""Tests for graviton.nodes.Node state persistence, atomicity, concurrency, and integrity (Step 3)."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.nodes.node import Node, NodeInitError, ReasonCode

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestNodeState(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-node-")
        self.node_dir = Path(self._tmp.name) / "node1"
        self.admin_pk, self.admin_sk = generate_signing_keypair()
        self.author = FeedAuthor("feed-alpha", self.admin_sk, clock=lambda: 1_700_000_000)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_state_survives_fresh_node_and_subprocess(self) -> None:
        Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        dev_pk, _ = generate_signing_keypair()
        g = self.author.genesis()
        r = self.author.register_key("alice", "dev-1", dev_pk)

        node = Node(self.node_dir)
        res = node.apply_entries([g, r])
        self.assertEqual(res.applied_count, 2)
        self.assertIsNone(res.stopped_reason)

        # Fresh subprocess reads the persisted state
        code = (
            "from graviton.nodes import Node\n"
            f"n = Node({str(self.node_dir)!r})\n"
            "d = n.authorize('alice', 'dev-1', 1)\n"
            "assert d.decision == 'allow', d\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_atomicity_mid_write_kill(self) -> None:
        node = Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        dev_pk, _ = generate_signing_keypair()
        node.apply_entries([self.author.genesis(), self.author.register_key("alice", "dev-1", dev_pk)])

        killer = (
            "import os, tempfile\n"
            "from pathlib import Path\n"
            "d = Path(os.environ['NODE_DIR'])\n"
            "fd, _ = tempfile.mkstemp(prefix='.tmp_', suffix='.part', dir=str(d))\n"
            "os.write(fd, b'{\"corrupted\":')\n"
            "os.close(fd)\n"
            "os._exit(1)\n"
        )
        env = os.environ.copy()
        env["NODE_DIR"] = str(self.node_dir)
        subprocess.run([sys.executable, "-c", killer], env=env, check=False)

        self.assertEqual(Node(self.node_dir).authorize("alice", "dev-1", 1).decision, "allow")

    def test_concurrent_apply_two_subprocesses(self) -> None:
        node = Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        node.apply_entry(self.author.genesis())
        dev_pk, _ = generate_signing_keypair()
        reg_b64 = base64.b64encode(self.author.register_key("alice", "dev-1", dev_pk)).decode("ascii")

        worker_code = (
            "import base64, os\n"
            "from graviton.nodes import Node\n"
            "n = Node(os.environ['NODE_DIR'])\n"
            "res = n.apply_entry(base64.b64decode(os.environ['ENTRY_B64']))\n"
            "print(res.status)\n"
        )
        env = os.environ.copy()
        env["NODE_DIR"] = str(self.node_dir)
        env["ENTRY_B64"] = reg_b64

        p1 = subprocess.Popen([sys.executable, "-c", worker_code], cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, text=True)
        p2 = subprocess.Popen([sys.executable, "-c", worker_code], cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, text=True)
        out1, _ = p1.communicate(timeout=10)
        out2, _ = p2.communicate(timeout=10)
        self.assertEqual(p1.returncode, 0)
        self.assertEqual(p2.returncode, 0)
        statuses = {out1.strip(), out2.strip()}
        self.assertEqual(statuses, {"applied", "already_applied"})
        self.assertTrue(Node(self.node_dir).verify_integrity())

    def test_rollback_fork_gap_idempotent(self) -> None:
        node = Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        e1 = self.author.genesis()
        e2 = self.author.head()
        e3 = self.author.head()

        self.assertEqual(node.apply_entry(e1).status, "applied")
        # Gap (epoch 3 before epoch 2)
        self.assertEqual(node.apply_entry(e3).status, "gap")
        self.assertEqual(node.applied_epoch(), 1)

        self.assertEqual(node.apply_entry(e2).status, "applied")
        # Idempotent re-delivery
        self.assertEqual(node.apply_entry(e1).status, "already_applied")
        self.assertEqual(node.apply_entry(e2).status, "already_applied")

        # Fork at epoch 2
        fork_author = FeedAuthor("feed-alpha", self.admin_sk, clock=lambda: 1_700_000_999)
        fork_e1 = fork_author.genesis()
        fork_e2 = fork_author.head()
        self.assertEqual(node.apply_entry(fork_e2).status, "fork_rejected")

        # Rollback at epoch 1 with different entry
        self.assertEqual(node.apply_entry(fork_e1).status, "rollback_rejected")

    def test_corrupt_state_and_verify_integrity(self) -> None:
        node = Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        dev_pk, _ = generate_signing_keypair()
        node.apply_entries([self.author.genesis(), self.author.register_key("alice", "dev-1", dev_pk)])
        self.assertTrue(node.verify_integrity())

        # Tamper with stored registry
        state_file = self.node_dir / "node_state.json"
        original = state_file.read_text(encoding="utf-8")
        data = json.loads(original)
        data["registry"]["mallory"] = data["registry"]["alice"]
        state_file.write_text(json.dumps(data), encoding="utf-8")

        self.assertFalse(node.verify_integrity())
        decision = node.authorize("alice", "dev-1", 1)
        self.assertEqual(decision.decision, "deny")
        self.assertEqual(decision.reason, ReasonCode.STATE_CORRUPT)

        # Unparseable state file
        state_file.write_text("{broken", encoding="utf-8")
        decision2 = node.authorize("alice", "dev-1", 1)
        self.assertEqual(decision2.decision, "deny")
        self.assertEqual(decision2.reason, ReasonCode.STATE_CORRUPT)

    def test_refuse_reinitialise_with_different_trust_root(self) -> None:
        Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        # Same parameters succeed
        Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        # Different feed_id refused
        with self.assertRaises(NodeInitError):
            Node.initialise(self.node_dir, "feed-beta", self.admin_pk)
        # Different admin key refused
        other_pk, _ = generate_signing_keypair()
        with self.assertRaises(NodeInitError):
            Node.initialise(self.node_dir, "feed-alpha", other_pk)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not enforced on Windows")
    def test_posix_permissions(self) -> None:
        Node.initialise(self.node_dir, "feed-alpha", self.admin_pk)
        self.assertEqual(self.node_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.node_dir / "node_state.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
