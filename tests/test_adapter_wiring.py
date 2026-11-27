"""Subprocess tests for Phase 4 adapter wiring to the signed feed and node."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.nodes import Node, ReasonCode

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_POINT = REPO_ROOT / "track4_service.py"


def run_adapter(payload: dict, state_dir: Path, timeout: float = 15.0) -> tuple[int, dict, str, str]:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRY_POINT)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=timeout,
    )
    return proc.returncode, json.loads(proc.stdout), proc.stdout, proc.stderr


def _active_gen_dir(state_dir: Path) -> Path:
    pointer = json.loads((state_dir / "current_generation.json").read_text(encoding="utf-8"))
    return state_dir / pointer["generation"]


class TestAdapterWiring(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-wire-")
        self.state_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_01_and_02_round_trip_and_feed_advance_and_idempotent_revoke(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"brief": "maya"},
                "contents": {"brief": "demo note"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        node_dir = _active_gen_dir(self.state_dir) / "node"
        self.assertEqual(Node(node_dir).applied_epoch(), 1)

        _, res, _, _ = run_adapter(
            {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r01"},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "allow", "body": "demo note"})

        run_adapter({"op": "revoke", "actor": "maya"}, self.state_dir)
        self.assertEqual(Node(node_dir).applied_epoch(), 2)
        self.assertEqual(Node(node_dir).check_actor("maya").reason, ReasonCode.REVOKED_ACTOR)

        # Idempotent revoke does not append a new feed entry
        run_adapter({"op": "revoke", "actor": "maya"}, self.state_dir)
        self.assertEqual(Node(node_dir).applied_epoch(), 2)

        _, denied, _, _ = run_adapter(
            {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r02"},
            self.state_dir,
        )
        self.assertEqual(denied, {"decision": "deny"})
        _, audited, _, _ = run_adapter({"op": "audit", "request_id": "r02"}, self.state_dir)
        self.assertEqual(audited, {"request_id": "r02", "decision": "deny"})

    def test_03_disabled_at_setup_creates_revoke_entries(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"d1": "u1", "d2": "u2"},
                "contents": {"d1": "s1", "d2": "s2"},
                "disabled": ["u1", "u_extra"],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        node_dir = _active_gen_dir(self.state_dir) / "node"
        node = Node(node_dir)
        self.assertEqual(node.applied_epoch(), 3)  # GENESIS + 2 REVOKE_ACTOR
        self.assertEqual(node.check_actor("u1").reason, ReasonCode.REVOKED_ACTOR)
        self.assertEqual(node.check_actor("u_extra").reason, ReasonCode.REVOKED_ACTOR)
        _, res, _, _ = run_adapter(
            {"op": "read", "actor": "u1", "asset": "d1", "request_id": "r1"},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "deny"})

    def test_04_and_05_peer_unaffected_and_preemptive_revoke(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"a1": "alice", "b1": "bob"},
                "contents": {"a1": "alpha", "b1": "bravo"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        # Pre-emptive revoke of actor owning nothing
        run_adapter({"op": "revoke", "actor": "eve"}, self.state_dir)
        node = Node(_active_gen_dir(self.state_dir) / "node")
        self.assertEqual(node.check_actor("eve").reason, ReasonCode.REVOKED_ACTOR)

        # Revoke alice; bob keeps access
        run_adapter({"op": "revoke", "actor": "alice"}, self.state_dir)
        _, res_a, _, _ = run_adapter(
            {"op": "read", "actor": "alice", "asset": "a1", "request_id": "ra"},
            self.state_dir,
        )
        _, res_b, _, _ = run_adapter(
            {"op": "read", "actor": "bob", "asset": "b1", "request_id": "rb"},
            self.state_dir,
        )
        self.assertEqual(res_a, {"decision": "deny"})
        self.assertEqual(res_b, {"decision": "allow", "body": "bravo"})

    def test_06_fail_closed_on_missing_or_corrupt_node_or_pointer(self) -> None:
        pk, _ = ml_kem_768.generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")

        def assert_all_fail_closed() -> None:
            _, r1, _, _ = run_adapter(
                {"op": "read", "actor": "alice", "asset": "doc", "request_id": "rx"},
                self.state_dir,
            )
            self.assertEqual(r1, {"decision": "deny"})
            _, r2, _, _ = run_adapter(
                {
                    "op": "protected_read",
                    "actor": "alice",
                    "asset": "doc",
                    "challenge": secrets.token_hex(8),
                    "public_key": pk_b64,
                },
                self.state_dir,
            )
            self.assertEqual(r2, {"decision": "deny"})
            _, r3, _, _ = run_adapter({"op": "revoke", "actor": "alice"}, self.state_dir)
            self.assertIn("error", r3)

        # Case A: deleted node directory
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc": "alice"},
                "contents": {"doc": "secret"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        shutil.rmtree(_active_gen_dir(self.state_dir) / "node")
        assert_all_fail_closed()

        # Case B: corrupted node_state.json
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc": "alice"},
                "contents": {"doc": "secret"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        (_active_gen_dir(self.state_dir) / "node" / "node_state.json").write_text("{corrupt", encoding="utf-8")
        assert_all_fail_closed()

        # Case C: corrupted pointer file
        (self.state_dir / "current_generation.json").write_text("{corrupt", encoding="utf-8")
        assert_all_fail_closed()

    def test_07_crash_safe_setup_before_and_after_pointer_switch(self) -> None:
        # Initial valid generation (OLD)
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc": "alice"},
                "contents": {"doc": "old-body"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        old_gen = _active_gen_dir(self.state_dir)

        # Simulate crash after writing a new generation directory, BEFORE pointer switch
        uncommitted = self.state_dir / ("gen_" + secrets.token_hex(12))
        uncommitted.mkdir(parents=True)
        (uncommitted / "adapter_state.json").write_text('{"version":2,"owners":{"doc":"alice"},"contents":{"doc":"partial"}}', encoding="utf-8")

        _, res_old, _, _ = run_adapter(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r_old"},
            self.state_dir,
        )
        self.assertEqual(res_old, {"decision": "allow", "body": "old-body"})

        # Simulate crash AFTER pointer switch to new valid generation, BEFORE old-gen cleanup
        new_gen = self.state_dir / ("gen_" + secrets.token_hex(12))
        new_gen.mkdir(parents=True)
        admin_pk, admin_sk = generate_signing_keypair()
        feed_id = secrets.token_hex(16)
        node = Node.initialise(new_gen / "node", feed_id, admin_pk)
        author = FeedAuthor(feed_id, admin_sk)
        node.apply_entry(author.genesis())
        (new_gen / "adapter_state.json").write_text(
            json.dumps({"version": 2, "owners": {"doc": "alice"}, "contents": {"doc": "new-body"}, "key_material": ""}),
            encoding="utf-8",
        )
        (new_gen / "admin_key.json").write_text(
            json.dumps(
                {
                    "version": 2,
                    "feed_id": feed_id,
                    "admin_secret_key_b64": base64.b64encode(admin_sk).decode("ascii"),
                    "epoch": author.epoch,
                    "last_hash_hex": author.last_hash.hex(),
                }
            ),
            encoding="utf-8",
        )
        (new_gen / "audit_log.jsonl").write_text("", encoding="utf-8")
        (self.state_dir / "current_generation.json").write_text(
            json.dumps({"version": 2, "generation": new_gen.name}),
            encoding="utf-8",
        )
        self.assertTrue(old_gen.exists())

        _, res_new, _, _ = run_adapter(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r_new"},
            self.state_dir,
        )
        # Un-MAC'd / un-registered generation must fail closed with integrity_violation
        self.assertEqual(res_new, {"error": "integrity_violation"})

    def test_08_concurrent_revokes_and_reads_no_deadlock(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {f"doc_{i}": f"user_{i}" for i in range(6)},
                "contents": {f"doc_{i}": f"val_{i}" for i in range(6)},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )

        tasks = [{"op": "revoke", "actor": f"user_{i}"} for i in range(4)] + [
            {"op": "read", "actor": f"user_{i}", "asset": f"doc_{i}", "request_id": f"cr_{i}"}
            for i in range(6)
        ]

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda req: run_adapter(req, self.state_dir, timeout=15.0), tasks))

        for rc, res, _, _ in results:
            self.assertEqual(rc, 0)
            self.assertIsInstance(res, dict)

        node = Node(_active_gen_dir(self.state_dir) / "node")
        self.assertTrue(node.verify_integrity())
        self.assertEqual(node.applied_epoch(), 5)  # GENESIS + 4 revokes

    def test_09_hygiene_no_secrets_or_reason_codes_in_output(self) -> None:
        km = "km_" + secrets.token_hex(24)
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc": "alice"},
                "contents": {"doc": "body-secret-" + secrets.token_hex(8)},
                "disabled": [],
                "key_material": km,
            },
            self.state_dir,
        )
        admin_data = json.loads((_active_gen_dir(self.state_dir) / "admin_key.json").read_text(encoding="utf-8"))
        admin_sk_b64 = admin_data["admin_secret_key_b64"]
        admin_sk_hex = base64.b64decode(admin_sk_b64).hex()

        ops = [
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r1"},
            {"op": "revoke", "actor": "alice"},
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r2"},
            {"op": "audit", "request_id": "r2"},
        ]
        for payload in ops:
            _, _, out, err = run_adapter(payload, self.state_dir)
            for forbidden in (km, admin_sk_b64, admin_sk_hex, "REVOKED_ACTOR", "STATE_CORRUPT", "UNKNOWN_KEY"):
                self.assertNotIn(forbidden, out)
                self.assertNotIn(forbidden, err)

    def test_10_audit_exact_two_fields_and_boundary_injection(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc": "alice"},
                "contents": {"doc": "hello"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        evil_id = 'r1\n{"request_id":"forged","decision":"allow"}\n"'
        evil_actor = 'mallory"\n{"decision":"allow"}'
        run_adapter({"op": "read", "actor": evil_actor, "asset": "doc", "request_id": evil_id}, self.state_dir)
        _, audited, _, _ = run_adapter({"op": "audit", "request_id": evil_id}, self.state_dir)
        self.assertEqual(set(audited.keys()), {"request_id", "decision"})
        self.assertEqual(audited, {"request_id": evil_id, "decision": "deny"})
        _, forged, _, _ = run_adapter({"op": "audit", "request_id": "forged"}, self.state_dir)
        self.assertIn("error", forged)

    def test_11_protected_read_unchanged_and_revoked_denied(self) -> None:
        body = "vault-" + secrets.token_hex(10)
        run_adapter(
            {
                "op": "setup",
                "owners": {"vault": "alice"},
                "contents": {"vault": body},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        pk, sk = ml_kem_768.generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        challenge = secrets.token_hex(16)
        _, res, _, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault",
                "challenge": challenge,
                "public_key": pk_b64,
            },
            self.state_dir,
        )
        ss = ml_kem_768.decrypt(sk, base64.b64decode(res["ciphertext"], validate=True))
        expected = hmac.new(ss, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(res["proof"], expected))

        run_adapter({"op": "revoke", "actor": "alice"}, self.state_dir)
        _, denied, _, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault",
                "challenge": challenge,
                "public_key": pk_b64,
            },
            self.state_dir,
        )
        self.assertEqual(denied, {"decision": "deny"})


if __name__ == "__main__":
    unittest.main()
