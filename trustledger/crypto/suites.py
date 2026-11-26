"""Cipher suite constants and definitions for TrustLedger."""
from enum import IntEnum


class CipherSuite(IntEnum):
    SUITE_PQ = 1       # Pure post-quantum: ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305
    SUITE_HYBRID = 2   # Hybrid: (ML-KEM-768 + X25519) + (ML-DSA-65 + Ed25519) + ChaCha20-Poly1305


SUITE_NAMES = {
    CipherSuite.SUITE_PQ: "ML-KEM-768+ML-DSA-65",
    CipherSuite.SUITE_HYBRID: "ML-KEM-768/X25519+ML-DSA-65/Ed25519",
}
