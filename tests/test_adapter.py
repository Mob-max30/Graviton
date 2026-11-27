"""Subprocess-based unittest suite for the Graviton Phase 1 adapter."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_POINT = REPO_ROOT / "track4_service.py"


def run_adapter(payload: dict | str, state_dir: Path) -> tuple[int, dict | None, str, str]:
    """Invoke track4_service.py as a fresh subprocess with JSON or raw stdin."""
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    stdin_text = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        [sys.executable, "-B", str(ENTRY_POINT)],
        input=stdin_text,
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=10,
    )
    parsed = None
    if proc.stdout.strip():
        parsed = json.loads(proc.stdout)
    return proc.returncode, parsed, proc.stdout, proc.stderr


class TestTrack4Adapter(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-test-")
        self.state_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_01_contract_round_trip(self) -> None:
        km = secrets.token_hex(16)
        rc, res, _, _ = run_adapter(
            {
                "op": "setup",
                "owners": {"brief": "maya"},
                "contents": {"brief": "demo note"},
                "disabled": [],
                "key_material": km,
            },
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"ready": True})

        rc, res, _, _ = run_adapter(
            {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r01"},
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"decision": "allow", "body": "demo note"})

        rc, res, _, _ = run_adapter({"op": "revoke", "actor": "maya"}, self.state_dir)
        self.assertEqual(rc, 0)
        self.assertIsInstance(res, dict)

        rc, res, _, _ = run_adapter(
            {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r02"},
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"decision": "deny"})
        self.assertNotIn("body", res)

        rc, res, _, _ = run_adapter({"op": "audit", "request_id": "r02"}, self.state_dir)
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"request_id": "r02", "decision": "deny"})

    def test_02_peer_unaffected_after_revoke(self) -> None:
        km = secrets.token_hex(16)
        run_adapter(
            {
                "op": "setup",
                "owners": {"asset_a": "alice", "asset_b": "bob"},
                "contents": {"asset_a": "alpha", "asset_b": "bravo"},
                "disabled": [],
                "key_material": km,
            },
            self.state_dir,
        )
        run_adapter({"op": "revoke", "actor": "alice"}, self.state_dir)

        _, res_a, _, _ = run_adapter(
            {"op": "read", "actor": "alice", "asset": "asset_a", "request_id": "req_a"},
            self.state_dir,
        )
        self.assertEqual(res_a, {"decision": "deny"})

        _, res_b, _, _ = run_adapter(
            {"op": "read", "actor": "bob", "asset": "asset_b", "request_id": "req_b"},
            self.state_dir,
        )
        self.assertEqual(res_b, {"decision": "allow", "body": "bravo"})

    def test_03_non_owner_and_unknown_denied(self) -> None:
        secret_body = "classified-" + secrets.token_hex(8)
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc1": "alice"},
                "contents": {"doc1": secret_body},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        for idx, (actor, asset) in enumerate(
            [("bob", "doc1"), ("alice", "unknown_doc"), ("unknown_actor", "unknown_doc")]
        ):
            _, res, out, _ = run_adapter(
                {"op": "read", "actor": actor, "asset": asset, "request_id": f"r_{idx}"},
                self.state_dir,
            )
            self.assertEqual(res, {"decision": "deny"})
            self.assertNotIn(secret_body, out)

    def test_04_disabled_at_setup_denied(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"doc1": "carol"},
                "contents": {"doc1": "secret"},
                "disabled": ["carol"],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        _, res, _, _ = run_adapter(
            {"op": "read", "actor": "carol", "asset": "doc1", "request_id": "r_disabled"},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "deny"})

    def test_05_persistence_and_setup_reset(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"d1": "u1"},
                "contents": {"d1": "v1"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        run_adapter({"op": "revoke", "actor": "u1"}, self.state_dir)
        _, res, _, _ = run_adapter(
            {"op": "read", "actor": "u1", "asset": "d1", "request_id": "r1"},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "deny"})

        # New setup resets previous state and revocations
        run_adapter(
            {
                "op": "setup",
                "owners": {"d1": "u1"},
                "contents": {"d1": "v2"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        _, res, _, _ = run_adapter(
            {"op": "read", "actor": "u1", "asset": "d1", "request_id": "r2"},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "allow", "body": "v2"})

    def test_06_atomic_write_survives_mid_write_kill(self) -> None:
        run_adapter(
            {
                "op": "setup",
                "owners": {"d1": "u1"},
                "contents": {"d1": "intact"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            },
            self.state_dir,
        )
        # Simulate a process killed after creating a temp file but before os.replace
        killer_code = (
            "import os, signal, tempfile\n"
            "from pathlib import Path\n"
            "d = Path(os.environ['TARGET_DIR'])\n"
            "fd, p = tempfile.mkstemp(prefix='.tmp_', suffix='.part', dir=str(d))\n"
            "os.write(fd, b'{\"corrupted\": ')\n"
            "os.close(fd)\n"
            "os._exit(1)\n"
        )
        env = os.environ.copy()
        env["TARGET_DIR"] = str(self.state_dir)
        subprocess.run([sys.executable, "-c", killer_code], env=env, check=False)

        rc, res, _, _ = run_adapter(
            {"op": "read", "actor": "u1", "asset": "d1", "request_id": "after_crash"},
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"decision": "allow", "body": "intact"})

    def test_07_stdout_stderr_hygiene(self) -> None:
        km = "km_" + secrets.token_hex(24)
        body = "body_" + secrets.token_hex(24)
        ops = [
            {
                "op": "setup",
                "owners": {"a": "alice"},
                "contents": {"a": body},
                "disabled": [],
                "key_material": km,
            },
            {"op": "read", "actor": "alice", "asset": "a", "request_id": "r1"},
            {"op": "revoke", "actor": "alice"},
            {"op": "read", "actor": "alice", "asset": "a", "request_id": "r2"},
            {"op": "audit", "request_id": "r2"},
        ]
        for idx, payload in enumerate(ops):
            rc, res, out, err = run_adapter(payload, self.state_dir)
            self.assertEqual(rc, 0)
            self.assertNotIn(km, out)
            self.assertNotIn(km, err)
            if idx == 3:  # denied read
                self.assertEqual(res, {"decision": "deny"})
                self.assertNotIn(body, out)
                self.assertNotIn(body, err)

    def test_08_malformed_inputs(self) -> None:
        for raw in ("{not valid json", "", "   ", "[1, 2, 3]"):
            rc, res, out, _ = run_adapter(raw, self.state_dir)
            self.assertEqual(rc, 0)
            self.assertNotIn("Traceback", out)
            self.assertIsInstance(res, dict)
            self.assertIn("error", res)

        for payload in (
            {"op": "unknown_op"},
            {"no_op": True},
            {"op": "read", "actor": "a"},
            {"op": "revoke"},
            {"op": "audit"},
        ):
            rc, res, out, _ = run_adapter(payload, self.state_dir)
            self.assertEqual(rc, 0)
            self.assertNotIn("Traceback", out)
            self.assertIsInstance(res, dict)
            self.assertIn("error", res)

    def test_09_log_record_boundary_injection(self) -> None:
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
        _, res, _, _ = run_adapter(
            {"op": "read", "actor": evil_actor, "asset": "doc", "request_id": evil_id},
            self.state_dir,
        )
        self.assertEqual(res, {"decision": "deny"})

        _, audit_evil, _, _ = run_adapter({"op": "audit", "request_id": evil_id}, self.state_dir)
        self.assertEqual(audit_evil, {"request_id": evil_id, "decision": "deny"})

        _, audit_forged, _, _ = run_adapter({"op": "audit", "request_id": "forged"}, self.state_dir)
        self.assertIn("error", audit_forged)

    def test_10_protected_read_ml_kem_768(self) -> None:
        body = "top-secret-" + secrets.token_hex(12)
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

        rc, res, _, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault",
                "challenge": challenge,
                "public_key": pk_b64,
            },
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertIn("ciphertext", res)
        self.assertIn("proof", res)

        ct = base64.b64decode(res["ciphertext"], validate=True)
        shared_secret = ml_kem_768.decrypt(sk, ct)
        expected_proof = hmac.new(
            shared_secret, (challenge + body).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        self.assertTrue(hmac.compare_digest(res["proof"], expected_proof))

        # Malformed public key for authorized actor -> clean error
        rc, bad_res, out, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault",
                "challenge": challenge,
                "public_key": "not-valid-base64!!!",
            },
            self.state_dir,
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("Traceback", out)
        self.assertIn("error", bad_res)

        # Non-owner gets deny with no ciphertext/proof
        _, deny_res, _, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "bob",
                "asset": "vault",
                "challenge": challenge,
                "public_key": pk_b64,
            },
            self.state_dir,
        )
        self.assertEqual(deny_res, {"decision": "deny"})
        self.assertNotIn("ciphertext", deny_res)
        self.assertNotIn("proof", deny_res)

        # Revoked owner gets deny with no ciphertext/proof
        run_adapter({"op": "revoke", "actor": "alice"}, self.state_dir)
        _, rev_res, _, _ = run_adapter(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault",
                "challenge": challenge,
                "public_key": pk_b64,
            },
            self.state_dir,
        )
        self.assertEqual(rev_res, {"decision": "deny"})
        self.assertNotIn("ciphertext", rev_res)
        self.assertNotIn("proof", rev_res)


if __name__ == "__main__":
    unittest.main()
