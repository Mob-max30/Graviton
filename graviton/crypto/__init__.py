"""Post-quantum cryptographic primitives for Graviton.

All primitives use vetted implementations:
- ML-KEM-768 via pqcrypto.kem.ml_kem_768
- ML-DSA-65 via pqcrypto.sign.ml_dsa_65
- HKDF (RFC 5869) and scrypt via Python 3.12 standard library
"""

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
from graviton.crypto.signatures import (
    DSA_PUBLIC_KEY_SIZE,
    DSA_SECRET_KEY_SIZE,
    DSA_SIGNATURE_SIZE,
    generate_signing_keypair,
    sign_message,
    verify_signature,
)

__all__ = [
    "CIPHERTEXT_SIZE",
    "DSA_PUBLIC_KEY_SIZE",
    "DSA_SECRET_KEY_SIZE",
    "DSA_SIGNATURE_SIZE",
    "PUBLIC_KEY_SIZE",
    "SECRET_KEY_SIZE",
    "SHARED_SECRET_SIZE",
    "decapsulate",
    "encapsulate",
    "generate_kem_keypair",
    "generate_signing_keypair",
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
    "sign_message",
    "verify_signature",
]
