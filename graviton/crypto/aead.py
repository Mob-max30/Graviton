"""Authenticated Encryption with Associated Data (AEAD) and canonical AAD binding.

Uses standard AES-256-GCM via `cryptography` when available. When `cryptography`
is not installed (e.g., a pqcrypto-only judging container), raises
`AeadUnavailableError` instead of inventing a custom cipher.
"""
from __future__ import annotations

import os
import struct

AEAD_KEY_SIZE = 32
AEAD_NONCE_SIZE = 12


class AeadUnavailableError(RuntimeError):
    """Raised when no vetted AEAD library (e.g. cryptography) is installed."""


def aead_available() -> bool:
    """Return True if a vetted AES-256-GCM implementation is importable."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except ImportError:
        return False


def build_associated_data(
    recipient_id: str,
    sender_id: str,
    session_id: str,
    counter: int,
) -> bytes:
    """Build unambiguous length-prefixed AEAD associated data for message binding."""
    if counter < 0:
        raise ValueError("counter must be non-negative")
    parts = [recipient_id, sender_id, session_id]
    encoded = bytearray(b"graviton-aad-v1")
    for item in parts:
        raw = item.encode("utf-8")
        encoded.extend(struct.pack(">I", len(raw)))
        encoded.extend(raw)
    encoded.extend(struct.pack(">Q", counter))
    return bytes(encoded)


def seal(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt and authenticate plaintext with AES-256-GCM; returns (nonce, ciphertext)."""
    if len(key) != AEAD_KEY_SIZE:
        raise ValueError(f"AEAD key must be {AEAD_KEY_SIZE} bytes")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise AeadUnavailableError(
            "AES-256-GCM requires the 'cryptography' package; "
            "no custom cipher fallback is permitted."
        ) from exc

    nonce = os.urandom(AEAD_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def open_sealed(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt and verify AES-256-GCM ciphertext; raises on tampering or wrong AAD."""
    if len(key) != AEAD_KEY_SIZE:
        raise ValueError(f"AEAD key must be {AEAD_KEY_SIZE} bytes")
    if len(nonce) != AEAD_NONCE_SIZE:
        raise ValueError(f"AEAD nonce must be {AEAD_NONCE_SIZE} bytes")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise AeadUnavailableError(
            "AES-256-GCM requires the 'cryptography' package; "
            "no custom cipher fallback is permitted."
        ) from exc

    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
