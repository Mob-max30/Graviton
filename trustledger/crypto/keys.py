"""Cryptographic keys, trusted peer store, and zeroization helpers for TrustLedger."""
import hashlib
import hmac
import json
from pathlib import Path
from typing import Dict, NamedTuple, Optional

import pqcrypto.kem.ml_kem_768 as ml_kem
import pqcrypto.sign.ml_dsa_65 as ml_dsa
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from trustledger.crypto.suites import CipherSuite


def zeroize_bytearray(b: bytearray) -> None:
    """Best-effort zeroization of sensitive mutable memory buffers."""
    for i in range(len(b)):
        b[i] = 0


def compute_fingerprint(public_key_bytes: bytes) -> str:
    """Compute full 64-hex (256-bit) fingerprint from SHA-256 of public key."""
    return hashlib.sha256(public_key_bytes).hexdigest()


class HybridIdentityKeypair(NamedTuple):
    dsa_pk: bytes
    dsa_sk: bytes
    ed_pk: bytes
    ed_sk: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "HybridIdentityKeypair":
        dsa_pk, dsa_sk = ml_dsa.generate_keypair()
        ed_sk = ed25519.Ed25519PrivateKey.generate()
        ed_pk = ed_sk.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return cls(dsa_pk=dsa_pk, dsa_sk=dsa_sk, ed_pk=ed_pk, ed_sk=ed_sk)

    def fingerprint_for_suite(self, suite: CipherSuite) -> str:
        if suite == CipherSuite.SUITE_PQ:
            return compute_fingerprint(self.dsa_pk)
        return compute_fingerprint(self.dsa_pk + self.ed_pk)

    @property
    def fingerprint(self) -> str:
        return self.fingerprint_for_suite(CipherSuite.SUITE_HYBRID)


class TrustedPeerStore:
    """Out-of-band identity-to-public-key pin store for handshake authentication."""

    def __init__(self, pins: Optional[Dict[str, str]] = None):
        self._pins: Dict[str, str] = dict(pins) if pins else {}

    def register_peer(self, peer_id: str, keypair: HybridIdentityKeypair, suite: CipherSuite) -> None:
        self._pins[f"{peer_id}:{int(suite)}"] = keypair.fingerprint_for_suite(suite)

    def register_fingerprint(self, peer_id: str, suite: CipherSuite, fingerprint: str) -> None:
        self._pins[f"{peer_id}:{int(suite)}"] = fingerprint

    @classmethod
    def from_json_file(cls, path: Path) -> "TrustedPeerStore":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(pins={str(k): str(v) for k, v in data.items()})

    def verify_peer_key(
        self,
        peer_id: str,
        suite: CipherSuite,
        dsa_pk: bytes,
        ed_pk: Optional[bytes],
    ) -> str:
        """Verify supplied public key matches pinned fingerprint; fail closed if unpinned."""
        if not self._pins:
            raise ValueError("TrustedPeerStore has no configured trust anchors")
        key = f"{peer_id}:{int(suite)}"
        expected_fp = self._pins.get(key)
        if not expected_fp:
            raise ValueError(f"No trusted public key pinned for peer '{peer_id}' and suite {int(suite)}")

        actual_fp = compute_fingerprint(
            dsa_pk + (ed_pk if suite == CipherSuite.SUITE_HYBRID and ed_pk else b"")
        )
        if not hmac.compare_digest(actual_fp.encode("utf-8"), expected_fp.encode("utf-8")):
            raise ValueError(f"Peer '{peer_id}' public key fingerprint mismatch (untrusted key)")
        return actual_fp


class EphemeralKEMKeypair(NamedTuple):
    kem_pk: bytes
    kem_sk: bytes
    x25519_pk: Optional[bytes] = None
    x25519_sk: Optional[x25519.X25519PrivateKey] = None

    @classmethod
    def generate(cls, suite: CipherSuite) -> "EphemeralKEMKeypair":
        kem_pk, kem_sk = ml_kem.generate_keypair()
        if suite == CipherSuite.SUITE_HYBRID:
            x_sk = x25519.X25519PrivateKey.generate()
            x_pk = x_sk.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
            return cls(kem_pk=kem_pk, kem_sk=kem_sk, x25519_pk=x_pk, x25519_sk=x_sk)
        return cls(kem_pk=kem_pk, kem_sk=kem_sk)
