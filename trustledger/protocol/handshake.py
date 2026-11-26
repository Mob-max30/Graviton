"""Two-way authenticated post-quantum and hybrid key exchange handshake with mandatory peer key pinning."""
import hashlib
import secrets
import struct
from typing import NamedTuple, Optional, Tuple

import pqcrypto.kem.ml_kem_768 as ml_kem
import pqcrypto.sign.ml_dsa_65 as ml_dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustledger.crypto.keys import (
    EphemeralKEMKeypair,
    HybridIdentityKeypair,
    TrustedPeerStore,
)
from trustledger.crypto.suites import CipherSuite

PROTOCOL_VERSION = 1
ML_DSA_65_SIG_SIZE = 3309
ED25519_SIG_SIZE = 64


def _lp(data: bytes) -> bytes:
    """Length-prefix a byte string with a 4-byte big-endian unsigned length."""
    return struct.pack(">I", len(data)) + data


def _verify_peer_signature(
    suite: CipherSuite,
    dsa_pk: bytes,
    ed_pk: Optional[bytes],
    digest: bytes,
    signature: bytes,
    role_label: str,
) -> None:
    expected_len = ML_DSA_65_SIG_SIZE + (ED25519_SIG_SIZE if suite == CipherSuite.SUITE_HYBRID else 0)
    if len(signature) != expected_len:
        raise HandshakeError(
            f"{role_label} signature length mismatch: expected {expected_len}, got {len(signature)}"
        )
    if not ml_dsa.verify(dsa_pk, digest, signature[:ML_DSA_65_SIG_SIZE]):
        raise HandshakeError(f"{role_label} ML-DSA-65 signature verification failed")
    if suite == CipherSuite.SUITE_HYBRID:
        if not ed_pk:
            raise HandshakeError(f"Missing {role_label.lower()} Ed25519 public key")
        ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(ed_pk)
        try:
            ed_pub.verify(signature[ML_DSA_65_SIG_SIZE:], digest)
        except Exception as err:
            raise HandshakeError(f"{role_label} Ed25519 signature verification failed") from err


class HandshakeError(ValueError):
    """Raised on handshake authentication, trust-anchor, or downgrade failure."""


class SessionKeys(NamedTuple):
    session_id: str
    suite: CipherSuite
    send_key: bytes
    recv_key: bytes
    peer_id: str
    peer_fingerprint: str


class HandshakeInitiator:
    """Initiator state machine for authenticated ephemeral key exchange."""

    def __init__(
        self,
        identity: str,
        role: str,
        identity_key: HybridIdentityKeypair,
        suite: CipherSuite = CipherSuite.SUITE_HYBRID,
        trusted_peers: Optional[TrustedPeerStore] = None,
    ):
        self.identity = identity
        self.role = role
        self.identity_key = identity_key
        self.suite = suite
        self.trusted_peers = trusted_peers
        self.client_nonce = secrets.token_bytes(32)
        self.ephemeral_key: Optional[EphemeralKEMKeypair] = EphemeralKEMKeypair.generate(suite)
        self.transcript = hashlib.sha256()

        self._record_client_hello()

    def _record_client_hello(self) -> bytes:
        if self.ephemeral_key is None:
            raise RuntimeError("Ephemeral key not initialized")
        parts = [
            struct.pack(">BB", PROTOCOL_VERSION, self.suite),
            _lp(self.identity.encode("utf-8")),
            _lp(self.role.encode("utf-8")),
            _lp(self.client_nonce),
            _lp(self.ephemeral_key.kem_pk),
        ]
        if self.suite == CipherSuite.SUITE_HYBRID and self.ephemeral_key.x25519_pk:
            parts.append(_lp(self.ephemeral_key.x25519_pk))
        data = b"".join(parts)
        self.transcript.update(data)
        return data

    def process_server_hello_and_authenticate(
        self,
        server_id: str,
        server_role: str,
        server_identity_dsa_pk: bytes,
        server_identity_ed_pk: Optional[bytes],
        server_nonce: bytes,
        kem_ciphertext: bytes,
        server_x25519_pk: Optional[bytes],
        server_signature: bytes,
    ) -> Tuple[bytes, SessionKeys]:
        """Verify pinned server key, verify signature, and produce client auth signature."""
        if self.trusted_peers is None:
            raise HandshakeError("TrustedPeerStore not configured; failing closed")
        if self.ephemeral_key is None:
            raise HandshakeError("Ephemeral key already consumed")

        try:
            server_fp = self.trusted_peers.verify_peer_key(
                server_id, self.suite, server_identity_dsa_pk, server_identity_ed_pk
            )
        except ValueError as err:
            raise HandshakeError(str(err)) from err

        parts = [
            _lp(server_id.encode("utf-8")),
            _lp(server_role.encode("utf-8")),
            _lp(server_nonce),
            _lp(kem_ciphertext),
        ]
        if self.suite == CipherSuite.SUITE_HYBRID and server_x25519_pk:
            parts.append(_lp(server_x25519_pk))
        self.transcript.update(b"".join(parts))

        kem_secret = ml_kem.decrypt(self.ephemeral_key.kem_sk, kem_ciphertext)

        shared_secrets = [kem_secret]
        if self.suite == CipherSuite.SUITE_HYBRID:
            if not server_x25519_pk or not self.ephemeral_key.x25519_sk:
                raise HandshakeError("Missing X25519 keys for hybrid suite")
            peer_x_pub = x25519.X25519PublicKey.from_public_bytes(server_x25519_pk)
            x_secret = self.ephemeral_key.x25519_sk.exchange(peer_x_pub)
            shared_secrets.append(x_secret)

        ikm = b"".join(shared_secrets)
        transcript_hash = self.transcript.digest()

        _verify_peer_signature(
            self.suite,
            server_identity_dsa_pk,
            server_identity_ed_pk,
            transcript_hash,
            server_signature,
            "Server",
        )

        client_dsa_sig = ml_dsa.sign(self.identity_key.dsa_sk, transcript_hash)
        client_sig = client_dsa_sig
        if self.suite == CipherSuite.SUITE_HYBRID:
            client_ed_sig = self.identity_key.ed_sk.sign(transcript_hash)
            client_sig = client_dsa_sig + client_ed_sig

        client_fp = self.identity_key.fingerprint_for_suite(self.suite)

        info = (
            _lp(transcript_hash)
            + _lp(client_fp.encode("ascii"))
            + _lp(server_fp.encode("ascii"))
            + _lp(self.role.encode("utf-8"))
            + _lp(server_role.encode("utf-8"))
            + struct.pack(">BB", PROTOCOL_VERSION, self.suite)
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=transcript_hash,
            info=info,
        )
        key_material = hkdf.derive(ikm)
        send_key = key_material[:32]
        recv_key = key_material[32:]
        session_id = hashlib.sha256(transcript_hash + self.client_nonce + server_nonce).hexdigest()[:32]

        # Delete ephemeral private key reference immediately after derivation
        self.ephemeral_key = None

        keys = SessionKeys(
            session_id=session_id,
            suite=self.suite,
            send_key=send_key,
            recv_key=recv_key,
            peer_id=server_id,
            peer_fingerprint=server_fp,
        )
        return client_sig, keys


class HandshakeResponder:
    """Responder state machine for authenticated ephemeral key exchange."""

    def __init__(
        self,
        identity: str,
        role: str,
        identity_key: HybridIdentityKeypair,
        trusted_peers: Optional[TrustedPeerStore] = None,
    ):
        self.identity = identity
        self.role = role
        self.identity_key = identity_key
        self.trusted_peers = trusted_peers
        self.server_nonce = secrets.token_bytes(32)
        self.transcript = hashlib.sha256()
        self._ikm: Optional[bytes] = None

    def process_client_hello_and_reply(
        self,
        client_id: str,
        client_role: str,
        suite: CipherSuite,
        client_nonce: bytes,
        client_kem_pk: bytes,
        client_x25519_pk: Optional[bytes],
    ) -> Tuple[bytes, bytes, Optional[bytes], bytes, bytes]:
        """Process ClientHello, encapsulate KEM, sign transcript, and return server hello fields."""
        if suite not in (CipherSuite.SUITE_PQ, CipherSuite.SUITE_HYBRID):
            raise HandshakeError(f"Unsupported or downgraded cipher suite: {suite}")

        self.suite = suite
        self.client_id = client_id
        self.client_role = client_role
        self.client_nonce = client_nonce

        parts = [
            struct.pack(">BB", PROTOCOL_VERSION, suite),
            _lp(client_id.encode("utf-8")),
            _lp(client_role.encode("utf-8")),
            _lp(client_nonce),
            _lp(client_kem_pk),
        ]
        if suite == CipherSuite.SUITE_HYBRID and client_x25519_pk:
            parts.append(_lp(client_x25519_pk))
        self.transcript.update(b"".join(parts))

        kem_ciphertext, kem_secret = ml_kem.encrypt(client_kem_pk)

        shared_secrets = [kem_secret]
        server_x_pk_bytes = None
        if suite == CipherSuite.SUITE_HYBRID:
            if not client_x25519_pk:
                raise HandshakeError("Client missing X25519 public key in hybrid mode")
            server_x_sk = x25519.X25519PrivateKey.generate()
            server_x_pk_bytes = server_x_sk.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
            client_x_pub = x25519.X25519PublicKey.from_public_bytes(client_x25519_pk)
            x_secret = server_x_sk.exchange(client_x_pub)
            shared_secrets.append(x_secret)
            del server_x_sk

        self._ikm = b"".join(shared_secrets)

        resp_parts = [
            _lp(self.identity.encode("utf-8")),
            _lp(self.role.encode("utf-8")),
            _lp(self.server_nonce),
            _lp(kem_ciphertext),
        ]
        if suite == CipherSuite.SUITE_HYBRID and server_x_pk_bytes:
            resp_parts.append(_lp(server_x_pk_bytes))
        self.transcript.update(b"".join(resp_parts))

        transcript_hash = self.transcript.digest()

        dsa_sig = ml_dsa.sign(self.identity_key.dsa_sk, transcript_hash)
        server_sig = dsa_sig
        if suite == CipherSuite.SUITE_HYBRID:
            ed_sig = self.identity_key.ed_sk.sign(transcript_hash)
            server_sig = dsa_sig + ed_sig

        return (
            self.server_nonce,
            kem_ciphertext,
            server_x_pk_bytes,
            server_sig,
            transcript_hash,
        )

    def complete_handshake(
        self,
        client_identity_dsa_pk: bytes,
        client_identity_ed_pk: Optional[bytes],
        client_signature: bytes,
    ) -> SessionKeys:
        """Verify pinned client key, verify client auth signature, and derive final session keys."""
        if self.trusted_peers is None:
            raise HandshakeError("TrustedPeerStore not configured; failing closed")
        if self._ikm is None:
            raise HandshakeError("Handshake IKM already consumed or not initialized")

        try:
            client_fp = self.trusted_peers.verify_peer_key(
                self.client_id, self.suite, client_identity_dsa_pk, client_identity_ed_pk
            )
        except ValueError as err:
            raise HandshakeError(str(err)) from err

        transcript_hash = self.transcript.digest()

        _verify_peer_signature(
            self.suite,
            client_identity_dsa_pk,
            client_identity_ed_pk,
            transcript_hash,
            client_signature,
            "Client",
        )

        server_fp = self.identity_key.fingerprint_for_suite(self.suite)

        info = (
            _lp(transcript_hash)
            + _lp(client_fp.encode("ascii"))
            + _lp(server_fp.encode("ascii"))
            + _lp(self.client_role.encode("utf-8"))
            + _lp(self.role.encode("utf-8"))
            + struct.pack(">BB", PROTOCOL_VERSION, self.suite)
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=transcript_hash,
            info=info,
        )
        key_material = hkdf.derive(self._ikm)
        recv_key = key_material[:32]
        send_key = key_material[32:]
        session_id = hashlib.sha256(transcript_hash + self.client_nonce + self.server_nonce).hexdigest()[:32]

        self._ikm = None

        return SessionKeys(
            session_id=session_id,
            suite=self.suite,
            send_key=send_key,
            recv_key=recv_key,
            peer_id=self.client_id,
            peer_fingerprint=client_fp,
        )
