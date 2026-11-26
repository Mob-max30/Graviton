"""Tests for Objective 9: Replay protection and recipient binding (graviton.comms.session)."""
from __future__ import annotations

from pathlib import Path
import secrets
import tempfile
import unittest

from graviton.comms import MessageError, ReplayCache, decrypt_message, encrypt_message, establish_session
from graviton.crypto.signatures import generate_signing_keypair


class TestReplayAndBinding(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="graviton-replay-")
        self.cache_path = Path(self._tmp.name) / "replay_cache.json"
        self.alice_pk, self.alice_sk = generate_signing_keypair()
        self.bob_pk, self.bob_sk = generate_signing_keypair()
        self.eve_pk, self.eve_sk = generate_signing_keypair()
        self.s_alice, self.s_bob, _ = establish_session(
            "alice", self.alice_sk, self.alice_pk, "bob", self.bob_sk, self.bob_pk
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_recipient_binding_and_third_party_cannot_read(self) -> None:
        msg = b"confidential-" + secrets.token_bytes(12)
        env = encrypt_message(self.s_alice, "alice", "bob", 1, msg)
        cache = ReplayCache(self.cache_path)

        # Intended recipient reads
        self.assertEqual(decrypt_message(self.s_bob, env, "bob", replay_cache=cache), msg)

        # Altered recipient field fails authentication
        tampered = dict(env)
        tampered["recipient_id"] = "eve"
        with self.assertRaises(MessageError):
            decrypt_message(self.s_bob, tampered, "eve")

        # Wrong expected recipient fails
        with self.assertRaises(MessageError):
            decrypt_message(self.s_bob, env, "eve")

        # Third party with their own session cannot decrypt/verify
        _, s_eve, _ = establish_session(
            "alice", self.alice_sk, self.alice_pk, "eve", self.eve_sk, self.eve_pk
        )
        with self.assertRaises(MessageError):
            decrypt_message(s_eve, env, "bob")

    def test_replay_rejected_across_restart_and_cache_eviction(self) -> None:
        env1 = encrypt_message(self.s_alice, "alice", "bob", 1, b"msg-1")
        cache1 = ReplayCache(self.cache_path, max_per_session=3)
        self.assertEqual(decrypt_message(self.s_bob, env1, "bob", replay_cache=cache1), b"msg-1")

        # Immediate duplicate rejected
        with self.assertRaises(MessageError):
            decrypt_message(self.s_bob, env1, "bob", replay_cache=cache1)

        # Fresh ReplayCache instance (simulating restart) still rejects counter 1
        cache_restarted = ReplayCache(self.cache_path, max_per_session=3)
        with self.assertRaises(MessageError):
            decrypt_message(self.s_bob, env1, "bob", replay_cache=cache_restarted)

        # Bounded retention: counters 2, 3, 4 evict 1 (floor=1), so 1 remains rejected
        for c in (2, 3, 4):
            env_c = encrypt_message(self.s_alice, "alice", "bob", c, f"msg-{c}".encode())
            decrypt_message(self.s_bob, env_c, "bob", replay_cache=cache_restarted)
        with self.assertRaises(MessageError):
            decrypt_message(self.s_bob, env1, "bob", replay_cache=cache_restarted)


if __name__ == "__main__":
    unittest.main()
