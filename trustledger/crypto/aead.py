"""ChaCha20-Poly1305 AEAD with strict counter nonces and full Associated Data binding."""
import struct
from typing import NamedTuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAX_MESSAGES_PER_KEY = 1000000  # Conservative safe bound


class AssociatedData(NamedTuple):
    protocol_version: int
    suite_id: int
    sender_id: str
    recipient_id: str
    recipient_key_fingerprint: str
    recipient_epoch: int
    session_id: str
    sequence_number: int
    message_id: str
    chunk_index: int
    chunk_count: int
    total_length: int

    def serialize(self) -> bytes:
        """Canonical binary encoding of all 12 AD fields."""
        sender_b = self.sender_id.encode("utf-8")
        recip_b = self.recipient_id.encode("utf-8")
        recip_fp_b = self.recipient_key_fingerprint.encode("ascii")
        sess_b = self.session_id.encode("utf-8")
        msg_b = self.message_id.encode("utf-8")

        header = struct.pack(
            ">BBHHH",
            self.protocol_version,
            self.suite_id,
            len(sender_b),
            len(recip_b),
            len(recip_fp_b),
        )
        body = struct.pack(
            f">{len(sender_b)}s{len(recip_b)}s{len(recip_fp_b)}sQ",
            sender_b,
            recip_b,
            recip_fp_b,
            self.recipient_epoch,
        )
        tail = struct.pack(
            f">H{len(sess_b)}sQH{len(msg_b)}sIIQ",
            len(sess_b),
            sess_b,
            self.sequence_number,
            len(msg_b),
            msg_b,
            self.chunk_index,
            self.chunk_count,
            self.total_length,
        )
        return header + body + tail


def make_nonce(seq: int) -> bytes:
    """Deterministic 12-byte nonce from 64-bit sequence number with 4 zero prefix bytes."""
    return b"\x00\x00\x00\x00" + struct.pack(">Q", seq)


class AEADCipher:
    """ChaCha20-Poly1305 wrapper enforcing monotonic counter nonces."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"ChaCha20-Poly1305 requires 32-byte key, got {len(key)}")
        self._aead = ChaCha20Poly1305(key)
        self._send_counter = 0

    def encrypt(self, plaintext: bytes, ad: AssociatedData) -> bytes:
        if self._send_counter >= MAX_MESSAGES_PER_KEY:
            raise OverflowError("Maximum messages exceeded for this cipher key; rotation required")
        nonce = make_nonce(self._send_counter)
        self._send_counter += 1
        ad_bytes = ad.serialize()
        return self._aead.encrypt(nonce, plaintext, ad_bytes)

    def decrypt(self, ciphertext: bytes, seq: int, ad: AssociatedData) -> bytes:
        nonce = make_nonce(seq)
        ad_bytes = ad.serialize()
        try:
            return self._aead.decrypt(nonce, ciphertext, ad_bytes)
        except InvalidTag as err:
            raise ValueError("AEAD authentication failed (tag mismatch or corrupted AD)") from err
