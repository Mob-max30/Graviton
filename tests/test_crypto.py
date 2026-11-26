"""Unit tests for graviton.crypto (Phase 2 cryptographic core)."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import tempfile
import unittest

from graviton.crypto.aead import (
    AeadUnavailableError,
    aead_available,
    build_associated_data,
    open_sealed,
    seal,
)
from graviton.crypto.kdf import hkdf, hkdf_expand, hkdf_extract
from graviton.crypto.kem import (
    CIPHERTEXT_SIZE,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    SHARED_SECRET_SIZE,
    decapsulate,
    encapsulate,
    generate_kem_keypair,
)
from graviton.crypto.keystore import (
    KeystoreError,
    derive_keystore_key,
    load_keystore,
    save_keystore,
)
from graviton.crypto.signatures import (
    DSA_PUBLIC_KEY_SIZE,
    DSA_SECRET_KEY_SIZE,
    DSA_SIGNATURE_SIZE,
    generate_signing_keypair,
    sign_message,
    verify_signature,
)


class TestCryptoCore(unittest.TestCase):
    def test_hkdf_rfc5869_vector_a1(self) -> None:
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(prk, expected_prk)
        okm = hkdf_expand(prk, info, 42)
        self.assertEqual(okm, expected_okm)
        self.assertEqual(hkdf(salt, ikm, info, 42), expected_okm)

    def test_ml_kem_768_round_trip_and_validation(self) -> None:
        pk, sk = generate_kem_keypair()
        self.assertEqual(len(pk), PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), SECRET_KEY_SIZE)

        ct, ss_sender = encapsulate(pk)
        self.assertEqual(len(ct), CIPHERTEXT_SIZE)
        self.assertEqual(len(ss_sender), SHARED_SECRET_SIZE)

        ss_receiver = decapsulate(sk, ct)
        self.assertEqual(ss_sender, ss_receiver)

        with self.assertRaises(ValueError):
            encapsulate(pk[:-1])
        with self.assertRaises(ValueError):
            decapsulate(sk[:-1], ct)
        with self.assertRaises(ValueError):
            decapsulate(sk, ct[:-1])

    def test_ml_dsa_65_sign_verify_and_tamper(self) -> None:
        pk, sk = generate_signing_keypair()
        self.assertEqual(len(pk), DSA_PUBLIC_KEY_SIZE)
        self.assertEqual(len(sk), DSA_SECRET_KEY_SIZE)

        msg = b"policy-epoch:1:revoke:device-42"
        sig = sign_message(sk, msg)
        self.assertEqual(len(sig), DSA_SIGNATURE_SIZE)
        self.assertTrue(verify_signature(pk, msg, sig))

        # Tampered message, signature, domain, or wrong key must fail
        self.assertFalse(verify_signature(pk, msg + b"x", sig))
        tampered_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        self.assertFalse(verify_signature(pk, msg, tampered_sig))
        self.assertFalse(verify_signature(pk, msg, sig, domain=b"other-domain:"))

        other_pk, _ = generate_signing_keypair()
        self.assertFalse(verify_signature(other_pk, msg, sig))

    def test_associated_data_unambiguous_encoding(self) -> None:
        aad1 = build_associated_data("bob", "alice", "sess1", 1)
        aad2 = build_associated_data("bo", "balice", "sess1", 1)
        aad3 = build_associated_data("bob", "alice", "sess1", 2)
        self.assertNotEqual(aad1, aad2)
        self.assertNotEqual(aad1, aad3)

    def test_scrypt_and_keystore_behavior(self) -> None:
        pw = secrets.token_hex(16)
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        k1 = derive_keystore_key(pw, salt1)
        k1_again = derive_keystore_key(pw, salt1)
        k2 = derive_keystore_key(pw, salt2)
        self.assertEqual(k1, k1_again)
        self.assertNotEqual(k1, k2)
        self.assertEqual(len(k1), 32)

        pk, sk = generate_signing_keypair()
        with tempfile.TemporaryDirectory(prefix="graviton-ks-") as tmp:
            ks_path = Path(tmp) / "alice.keystore.json"
            if aead_available():
                save_keystore(ks_path, "alice", pk, sk, pw)
                ident, loaded_pk, loaded_sk = load_keystore(ks_path, pw)
                self.assertEqual(ident, "alice")
                self.assertEqual(loaded_pk, pk)
                self.assertEqual(loaded_sk, sk)

                with self.assertRaises(KeystoreError):
                    load_keystore(ks_path, secrets.token_hex(16))

                aad = build_associated_data("bob", "alice", "s1", 0)
                nonce, ct = seal(k1, b"secret-msg", aad)
                self.assertEqual(open_sealed(k1, nonce, ct, aad), b"secret-msg")
            else:
                with self.assertRaises(AeadUnavailableError):
                    seal(k1, b"secret-msg", b"aad")
                with self.assertRaises(AeadUnavailableError):
                    save_keystore(ks_path, "alice", pk, sk, pw)
                self.assertFalse(ks_path.exists())


if __name__ == "__main__":
    unittest.main()
