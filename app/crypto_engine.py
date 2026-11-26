"""Post-quantum and hybrid cryptographic primitives using vetted libraries."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65


class CryptoError(Exception):
    """Raised when cryptographic verification or decryption fails."""


@dataclass
class KeyPair:
    public_key: bytes
    secret_key: bytes


def generate_signing_keypair() -> KeyPair:
    """Generate an ML-DSA-65 signing keypair."""
    pk, sk = ml_dsa_65.keygen()
    return KeyPair(public_key=bytes(pk), secret_key=bytes(sk))


def sign_data(secret_key: bytes, data: bytes) -> bytes:
    """Sign arbitrary bytes with ML-DSA-65."""
    return bytes(ml_dsa_65.sign(secret_key, data))


def verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns False on any failure."""
    try:
        ml_dsa_65.verify(public_key, data, signature)
        return True
    except Exception:
        return False


def generate_kem_keypair() -> KeyPair:
    """Generate an ML-KEM-768 key encapsulation keypair."""
    pk, sk = ml_kem_768.keygen()
    return KeyPair(public_key=bytes(pk), secret_key=bytes(sk))


def generate_x25519_keypair() -> KeyPair:
    """Generate an ephemeral X25519 keypair for hybrid key exchange."""
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return KeyPair(public_key=pub_bytes, secret_key=priv_bytes)


def hybrid_encapsulate(
    peer_mlkem_pk: bytes,
    peer_x25519_pk: bytes,
    context: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    Perform hybrid X25519 + ML-KEM-768 encapsulation.

    Returns (kem_ciphertext, initiator_x25519_pk, shared_session_key_32b).
    Ephemeral X25519 secret is discarded immediately after derivation.
    """
    kem_ct, kem_ss = ml_kem_768.encaps(peer_mlkem_pk)
    eph = generate_x25519_keypair()
    try:
        priv = x25519.X25519PrivateKey.from_private_bytes(eph.secret_key)
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pk)
        ecdh_ss = priv.exchange(peer_pub)
        combined = bytes(kem_ss) + ecdh_ss
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"graviton-hybrid-kem-v1|" + context,
        ).derive(combined)
        return bytes(kem_ct), eph.public_key, session_key
    finally:
        # Best-effort zeroization of ephemeral secret material in mutable buffer
        eph.secret_key = b"\x00" * len(eph.secret_key)


def hybrid_decapsulate(
    mlkem_sk: bytes,
    x25519_sk: bytes,
    kem_ct: bytes,
    initiator_x25519_pk: bytes,
    context: bytes,
) -> bytes:
    """Decapsulate hybrid X25519 + ML-KEM-768 into a 32-byte session key."""
    try:
        kem_ss = ml_kem_768.decaps(mlkem_sk, kem_ct)
        priv = x25519.X25519PrivateKey.from_private_bytes(x25519_sk)
        peer_pub = x25519.X25519PublicKey.from_public_bytes(initiator_x25519_pk)
        ecdh_ss = priv.exchange(peer_pub)
        combined = bytes(kem_ss) + ecdh_ss
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"graviton-hybrid-kem-v1|" + context,
        ).derive(combined)
    except Exception as exc:
        raise CryptoError(f"Hybrid decapsulation failed: {exc}") from exc


def derive_subkey(master_key: bytes, label: bytes, length: int = 32) -> bytes:
    """Derive a domain-separated subkey via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=label,
    ).derive(master_key)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM and return (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt with AES-256-GCM and verify AAD."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("AEAD authentication failed (tampered payload or AAD mismatch)") from exc


def canonical_json(obj: Any) -> bytes:
    """Deterministic canonical JSON encoding for signing and hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def key_fingerprint(public_key: bytes) -> str:
    """Short 16-byte hex fingerprint of a public key."""
    return hashlib.sha256(public_key).hexdigest()[:32]


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison."""
    return hmac.compare_digest(a, b)
