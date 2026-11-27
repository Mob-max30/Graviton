"""ML-DSA-65 identity signature wrapper around pqcrypto."""
from __future__ import annotations

from pqcrypto.sign import ml_dsa_65

DSA_PUBLIC_KEY_SIZE: int = ml_dsa_65.PUBLIC_KEY_SIZE
DSA_SECRET_KEY_SIZE: int = ml_dsa_65.SECRET_KEY_SIZE
DSA_SIGNATURE_SIZE: int = ml_dsa_65.SIGNATURE_SIZE

_DEFAULT_DOMAIN = b"graviton-v1:"


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate a long-term ML-DSA-65 (public_key, secret_key) identity pair."""
    return ml_dsa_65.generate_keypair()


def sign_message(
    secret_key: bytes,
    message: bytes,
    domain: bytes = _DEFAULT_DOMAIN,
) -> bytes:
    """Sign a domain-separated message with an ML-DSA-65 secret key."""
    if not isinstance(secret_key, (bytes, bytearray)):
        raise TypeError("secret_key must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    sk_bytes = bytes(secret_key)
    if len(sk_bytes) != DSA_SECRET_KEY_SIZE:
        raise ValueError(f"ML-DSA-65 secret key must be {DSA_SECRET_KEY_SIZE} bytes")
    return ml_dsa_65.sign(sk_bytes, bytes(domain) + bytes(message))


def verify_signature(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    domain: bytes = _DEFAULT_DOMAIN,
) -> bool:
    """Verify an ML-DSA-65 signature; returns False on invalid/tampered inputs."""
    if not isinstance(public_key, (bytes, bytearray)):
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False
    if not isinstance(signature, (bytes, bytearray)):
        return False
    pk_bytes = bytes(public_key)
    sig_bytes = bytes(signature)
    if len(pk_bytes) != DSA_PUBLIC_KEY_SIZE or len(sig_bytes) != DSA_SIGNATURE_SIZE:
        return False
    try:
        return bool(ml_dsa_65.verify(pk_bytes, bytes(domain) + bytes(message), sig_bytes))
    except Exception:
        return False
