"""RFC 5869 HKDF implementation using Python standard library hmac and hashlib."""
from __future__ import annotations

import hashlib
import hmac


def hkdf_extract(salt: bytes | None, ikm: bytes, hash_name: str = "sha256") -> bytes:
    """RFC 5869 Section 2.2: Extract a pseudorandom key (PRK)."""
    hash_len = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * hash_len
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """RFC 5869 Section 2.3: Expand a PRK into output keying material."""
    hash_len = hashlib.new(hash_name).digest_size
    if length < 0 or length > 255 * hash_len:
        raise ValueError(f"HKDF output length must be between 0 and {255 * hash_len}")
    if len(prk) < hash_len:
        raise ValueError("PRK length must be at least hash digest size")
    if length == 0:
        return b""

    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hash_name).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def hkdf(
    salt: bytes | None,
    ikm: bytes,
    info: bytes,
    length: int,
    hash_name: str = "sha256",
) -> bytes:
    """RFC 5869 Extract-then-Expand key derivation."""
    prk = hkdf_extract(salt, ikm, hash_name=hash_name)
    return hkdf_expand(prk, info, length, hash_name=hash_name)
