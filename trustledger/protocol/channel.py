"""High-level authenticated channel with chunking, Reed-Solomon FEC, and keyed MACs."""
import hashlib
import hmac
import secrets
import struct
from enum import Enum
from typing import Dict, List, Optional, Tuple

from trustledger.crypto.fec import CHUNK_SIZE, ChunkFEC

FRAME_VERSION = 2
FIXED_HEADER_FORMAT = ">BBIIIIQ32s32sH"
FIXED_HEADER_SIZE = struct.calcsize(FIXED_HEADER_FORMAT)  # 92 bytes
MAX_MESSAGE_ID_BYTES = 1024


class DeliveryFailureReason(str, Enum):
    INCOMPLETE = "INCOMPLETE"
    TIMEOUT = "TIMEOUT"
    AUTH_FAIL = "AUTH_FAIL"
    REPLAY = "REPLAY"
    WRONG_RECIPIENT = "WRONG_RECIPIENT"
    STALE_KEY = "STALE_KEY"
    REVOKED = "REVOKED"


class ResilientChannel:
    """Manages chunking, Reed-Solomon FEC, keyed chunk MACs, and whole-message auth."""

    def __init__(
        self,
        k_data: int = 4,
        m_parity: int = 2,
        max_retries: int = 3,
        channel_key: Optional[bytes] = None,
    ):
        self.k = k_data
        self.m = m_parity
        self.fec = ChunkFEC(k_data, m_parity)
        self.max_retries = max_retries
        self._channel_key = channel_key if channel_key is not None else secrets.token_bytes(32)
        if len(self._channel_key) != 32:
            raise ValueError("channel_key must be 32 bytes")

    def _compute_whole_tag(self, message_id_bytes: bytes, total_length: int, payload: bytes) -> bytes:
        mac = hmac.new(self._channel_key, b"trustledger:whole:v2", hashlib.sha256)
        mac.update(struct.pack(">HQ", len(message_id_bytes), total_length))
        mac.update(message_id_bytes)
        mac.update(payload)
        return mac.digest()

    def _compute_chunk_tag(
        self,
        version: int,
        message_id_bytes: bytes,
        group_idx: int,
        chunk_idx: int,
        k: int,
        m: int,
        total_length: int,
        whole_tag: bytes,
        chunk_bytes: bytes,
    ) -> bytes:
        mac = hmac.new(self._channel_key, b"trustledger:chunk:v2", hashlib.sha256)
        mac.update(
            struct.pack(
                ">BBIIIIQH32s",
                version,
                0,
                group_idx,
                chunk_idx,
                k,
                m,
                total_length,
                len(message_id_bytes),
                whole_tag,
            )
        )
        mac.update(message_id_bytes)
        mac.update(chunk_bytes)
        return mac.digest()

    def prepare_message_packets(self, message_id: str, payload: bytes) -> List[bytes]:
        """Split into chunks and encode into FEC-protected packet frames with keyed HMAC tags."""
        msg_id_bytes = message_id.encode("utf-8")
        if not msg_id_bytes or len(msg_id_bytes) > MAX_MESSAGE_ID_BYTES:
            raise ValueError(f"message_id UTF-8 length must be 1..{MAX_MESSAGE_ID_BYTES} bytes")

        chunks = self.fec.chunk_payload(payload)
        packets: List[bytes] = []

        orig_count = len(chunks)
        remainder = orig_count % self.k
        if remainder != 0:
            chunks.extend([b""] * (self.k - remainder))

        whole_tag = self._compute_whole_tag(msg_id_bytes, len(payload), payload)

        for group_idx in range(0, len(chunks), self.k):
            group_data = chunks[group_idx : group_idx + self.k]
            parities = self.fec.encode_group(group_data)

            all_chunks = group_data + parities
            for chunk_idx, chunk_bytes in enumerate(all_chunks):
                chunk_tag = self._compute_chunk_tag(
                    FRAME_VERSION,
                    msg_id_bytes,
                    group_idx // self.k,
                    chunk_idx,
                    self.k,
                    self.m,
                    len(payload),
                    whole_tag,
                    chunk_bytes,
                )

                header = struct.pack(
                    FIXED_HEADER_FORMAT,
                    FRAME_VERSION,
                    0,
                    group_idx // self.k,
                    chunk_idx,
                    self.k,
                    self.m,
                    len(payload),
                    whole_tag,
                    chunk_tag,
                    len(msg_id_bytes),
                )
                packets.append(header + msg_id_bytes + chunk_bytes)

        return packets

    def receive_and_assemble(
        self,
        received_packets: List[bytes],
        expected_message_id: str,
        total_length: int,
    ) -> Tuple[bool, Optional[bytes], Optional[DeliveryFailureReason]]:
        """Reorder, validate header geometry and keyed chunk MACs, decode FEC, and verify whole-message MAC."""
        groups: Dict[int, Dict[int, bytes]] = {}
        expected_whole_tag: Optional[bytes] = None
        saw_any_packet = False
        saw_auth_fail = False

        for p in received_packets:
            if len(p) < FIXED_HEADER_SIZE:
                saw_auth_fail = True
                continue
            (
                version,
                _reserved,
                grp_idx,
                chk_idx,
                k,
                m,
                pkt_total_len,
                whole_tag,
                chunk_tag,
                msg_id_len,
            ) = struct.unpack_from(FIXED_HEADER_FORMAT, p, 0)

            if version != FRAME_VERSION:
                saw_auth_fail = True
                continue
            if k != self.k or m != self.m or pkt_total_len != total_length:
                saw_auth_fail = True
                continue
            if chk_idx >= self.k + self.m:
                saw_auth_fail = True
                continue
            if msg_id_len == 0 or msg_id_len > MAX_MESSAGE_ID_BYTES:
                saw_auth_fail = True
                continue
            if len(p) < FIXED_HEADER_SIZE + msg_id_len:
                saw_auth_fail = True
                continue

            msg_id_bytes = p[FIXED_HEADER_SIZE : FIXED_HEADER_SIZE + msg_id_len]
            try:
                msg_id = msg_id_bytes.decode("utf-8")
            except UnicodeDecodeError:
                saw_auth_fail = True
                continue

            if msg_id != expected_message_id:
                return False, None, DeliveryFailureReason.WRONG_RECIPIENT

            chunk_payload = p[FIXED_HEADER_SIZE + msg_id_len :]
            expected_chunk_tag = self._compute_chunk_tag(
                version,
                msg_id_bytes,
                grp_idx,
                chk_idx,
                k,
                m,
                pkt_total_len,
                whole_tag,
                chunk_payload,
            )
            saw_any_packet = True
            if not hmac.compare_digest(chunk_tag, expected_chunk_tag):
                saw_auth_fail = True
                continue

            if expected_whole_tag is None:
                expected_whole_tag = whole_tag
            elif not hmac.compare_digest(expected_whole_tag, whole_tag):
                saw_auth_fail = True
                continue

            if grp_idx not in groups:
                groups[grp_idx] = {}
            groups[grp_idx][chk_idx] = chunk_payload

        total_chunks_approx = (total_length + CHUNK_SIZE - 1) // CHUNK_SIZE if total_length > 0 else 1
        expected_groups = (total_chunks_approx + self.k - 1) // self.k

        assembled_chunks: List[bytes] = []

        for g in range(expected_groups):
            if g not in groups or len(groups[g]) < self.k:
                reason = DeliveryFailureReason.AUTH_FAIL if (saw_auth_fail and not groups.get(g)) else DeliveryFailureReason.INCOMPLETE
                return False, None, reason

            lengths = [
                max(0, min(CHUNK_SIZE, total_length - (g * self.k + i) * CHUNK_SIZE))
                for i in range(self.k)
            ]
            try:
                rec_group = self.fec.decode_group(groups[g], lengths)
                assembled_chunks.extend(rec_group)
            except Exception:
                return False, None, DeliveryFailureReason.AUTH_FAIL

        full_payload = b"".join(assembled_chunks)[:total_length]
        if expected_whole_tag is None or not saw_any_packet:
            return False, None, DeliveryFailureReason.INCOMPLETE

        actual_whole_tag = self._compute_whole_tag(
            expected_message_id.encode("utf-8"),
            total_length,
            full_payload,
        )
        if not hmac.compare_digest(expected_whole_tag, actual_whole_tag):
            return False, None, DeliveryFailureReason.AUTH_FAIL

        return True, full_payload, None
