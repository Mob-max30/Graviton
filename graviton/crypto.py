"""Post-Quantum & Hybrid Cryptography primitives for Graviton.

Implements:
- ML-KEM-768 (FIPS 203) via pqcrypto==0.4.0
- Hybrid ML-KEM-768 + X25519 key encapsulation
- ML-DSA-65 (FIPS 204) digital signatures via pqcrypto==0.4.0
- AES-256-GCM authenticated encryption via cryptography
- RFC 5869 HKDF-SHA256 key derivation

Fails closed if PQC or AEAD libraries are unavailable (no insecure fallbacks).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

try:
    from pqcrypto.kem import ml_kem_768  # type: ignore
    from pqcrypto.sign import ml_dsa_65  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "pqcrypto==0.4.0 is required for ML-KEM-768 and ML-DSA-65; insecure fallback is disabled."
    ) from exc

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "cryptography is required for X25519, AES-256-GCM, and HKDF-SHA256."
    ) from exc


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive key material using RFC 5869 HKDF-SHA256."""
    actual_salt = salt if salt else (b"\x00" * 32)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=actual_salt,
        info=info,
    ).derive(ikm)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM and bind AAD."""
    if len(key) < 32:
        raise ValueError("AEAD key must be at least 32 bytes")
    nonce = os.urandom(12)
    ct = AESGCM(key[:32]).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify AAD."""
    if len(key) < 32:
        raise ValueError("AEAD key must be at least 32 bytes")
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key[:32]).decrypt(nonce, ciphertext, aad)


@dataclass
class KEMKeyPair:
    public_key: bytes
    secret_key: bytes
    algorithm: str = "ML-KEM-768"


@dataclass
class HybridKEMKeyPair:
    mlkem_pk: bytes
    mlkem_sk: bytes
    x25519_pk: bytes
    x25519_sk: bytes
    algorithm: str = "ML-KEM-768+X25519"

    def erase_secret_keys(self) -> None:
        """Overwrite secret key references on session completion for forward secrecy."""
        self.mlkem_sk = b""
        self.x25519_sk = b""


def generate_kem_keypair() -> KEMKeyPair:
    pk, sk = ml_kem_768.generate_keypair()
    return KEMKeyPair(pk, sk, "ML-KEM-768")


def generate_hybrid_kem_keypair() -> HybridKEMKeyPair:
    ml_pk, ml_sk = ml_kem_768.generate_keypair()
    x_priv = x25519.X25519PrivateKey.generate()
    x_pk = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_sk = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return HybridKEMKeyPair(ml_pk, ml_sk, x_pk, x_sk)


def kem_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    ct, ss = ml_kem_768.encrypt(public_key)
    return ct, ss


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    return ml_kem_768.decrypt(secret_key, ciphertext)


def hybrid_kem_encapsulate(
    peer_mlkem_pk: bytes, peer_x25519_pk: bytes
) -> Tuple[bytes, bytes, bytes]:
    """Perform hybrid ML-KEM-768 + X25519 key encapsulation.

    Returns (mlkem_ct, eph_x25519_pk, combined_shared_secret).
    """
    ml_ct, ml_ss = ml_kem_768.encrypt(peer_mlkem_pk)
    eph_x = x25519.X25519PrivateKey.generate()
    eph_x_pk = eph_x.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    peer_x = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pk)
    x_ss = eph_x.exchange(peer_x)
    combined = hkdf_sha256(
        ikm=ml_ss + x_ss,
        salt=eph_x_pk + ml_ct,
        info=b"graviton-hybrid-kem-v1",
        length=32,
    )
    return ml_ct, eph_x_pk, combined


def hybrid_kem_decapsulate(
    mlkem_sk: bytes,
    x25519_sk: bytes,
    mlkem_ct: bytes,
    eph_x25519_pk: bytes,
) -> bytes:
    """Decapsulate hybrid ML-KEM-768 + X25519 ciphertext."""
    if not mlkem_sk or not x25519_sk:
        raise ValueError("Ephemeral or secret KEM key has been erased")
    ml_ss = ml_kem_768.decrypt(mlkem_sk, mlkem_ct)
    priv_x = x25519.X25519PrivateKey.from_private_bytes(x25519_sk)
    peer_x = x25519.X25519PublicKey.from_public_bytes(eph_x25519_pk)
    x_ss = priv_x.exchange(peer_x)
    return hkdf_sha256(
        ikm=ml_ss + x_ss,
        salt=eph_x25519_pk + mlkem_ct,
        info=b"graviton-hybrid-kem-v1",
        length=32,
    )


@dataclass(frozen=True)
class SignKeyPair:
    public_key: bytes
    secret_key: bytes
    algorithm: str = "ML-DSA-65"


def generate_sign_keypair() -> SignKeyPair:
    pk, sk = ml_dsa_65.generate_keypair()
    return SignKeyPair(pk, sk, "ML-DSA-65")


def sign_message(secret_key: bytes, message: bytes) -> bytes:
    return ml_dsa_65.sign(secret_key, message)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        return bool(ml_dsa_65.verify(public_key, message, signature))
    except Exception:
        return False
