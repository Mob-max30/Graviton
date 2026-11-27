"""Ephemeral ML-KEM-768 key establishment wrapper around pqcrypto."""
from __future__ import annotations

from pqcrypto.kem import ml_kem_768

PUBLIC_KEY_SIZE: int = ml_kem_768.PUBLIC_KEY_SIZE
SECRET_KEY_SIZE: int = ml_kem_768.SECRET_KEY_SIZE
CIPHERTEXT_SIZE: int = ml_kem_768.CIPHERTEXT_SIZE
SHARED_SECRET_SIZE: int = ml_kem_768.PLAINTEXT_SIZE


def generate_kem_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ephemeral ML-KEM-768 (public_key, secret_key) pair."""
    return ml_kem_768.generate_keypair()


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret against a raw ML-KEM-768 public key."""
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError("public_key must be bytes")
    pk_bytes = bytes(public_key)
    if len(pk_bytes) != PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-KEM-768 public key must be {PUBLIC_KEY_SIZE} bytes")
    return ml_kem_768.encrypt(pk_bytes)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using a raw ML-KEM-768 secret key."""
    if not isinstance(secret_key, (bytes, bytearray)):
        raise TypeError("secret_key must be bytes")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    sk_bytes = bytes(secret_key)
    ct_bytes = bytes(ciphertext)
    if len(sk_bytes) != SECRET_KEY_SIZE:
        raise ValueError(f"ML-KEM-768 secret key must be {SECRET_KEY_SIZE} bytes")
    if len(ct_bytes) != CIPHERTEXT_SIZE:
        raise ValueError(f"ML-KEM-768 ciphertext must be {CIPHERTEXT_SIZE} bytes")
    return ml_kem_768.decrypt(sk_bytes, ct_bytes)
