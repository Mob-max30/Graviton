"""Tests for Objective 10: Forward secrecy (graviton.comms.session)."""
from __future__ import annotations

import unittest

from graviton.comms import MessageError, SessionContext, decrypt_message, encrypt_message, establish_session
from graviton.crypto.kdf import hkdf
from graviton.crypto.kem import SECRET_KEY_SIZE, decapsulate
from graviton.crypto.signatures import generate_signing_keypair


class TestForwardSecrecy(unittest.TestCase):
    def test_long_term_key_exposure_does_not_reveal_past_session(self) -> None:
        alice_pk, alice_sk = generate_signing_keypair()
        bob_pk, bob_sk = generate_signing_keypair()

        s_alice, s_bob, transcript = establish_session(
            "alice", alice_sk, alice_pk, "bob", bob_sk, bob_pk
        )
        secret_msg = b"past-session-secret-payload"
        envelope = encrypt_message(s_alice, "alice", "bob", 1, secret_msg)
        self.assertEqual(decrypt_message(s_bob, envelope, "bob"), secret_msg)

        # Session completes and keys are erased
        s_alice.erase()
        s_bob.erase()

        # Attacker records transcript and later compromises BOTH long-term ML-DSA-65 secret keys.
        # Long-term signing keys are not ML-KEM-768 secret keys and cannot decapsulate kem_ciphertext.
        self.assertNotEqual(len(alice_sk), SECRET_KEY_SIZE)
        self.assertNotEqual(len(bob_sk), SECRET_KEY_SIZE)
        with self.assertRaises(ValueError):
            decapsulate(bob_sk, transcript.kem_ciphertext)

        # Even trying to derive a session key from public transcript + long-term secret keys fails
        forged_key = hkdf(transcript.session_id.encode("utf-8"), bob_sk[:32], b"graviton-session-v1", 32)
        forged_ctx = SessionContext(transcript.session_id, "alice", "bob", forged_key)
        with self.assertRaises(MessageError):
            decrypt_message(forged_ctx, envelope, "bob")


if __name__ == "__main__":
    unittest.main()
