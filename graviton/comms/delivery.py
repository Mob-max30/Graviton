"""Chunked message delivery under packet loss/reordering and offline encrypted queue (Section 17)."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import secrets

from graviton.audit.log import AuditLog, AuthenticatedSession
from graviton.comms.session import MessageError, SessionContext, decrypt_message, encrypt_message
from graviton.storage import atomic_write_text, state_lock

DEFAULT_MAX_RETRIES = 3


class DeliveryError(RuntimeError):
    """Raised when chunked delivery fails or receives an invalid chunk."""


@dataclass(frozen=True)
class Chunk:
    msg_id: str
    index: int
    total: int
    envelope: dict


@dataclass(frozen=True)
class DeliveryResult:
    delivered: bool
    msg_id: str
    payload: bytes | None = None
    missing_indices: list[int] | None = None
    error: str | None = None


def split_into_chunks(
    session: SessionContext,
    sender_id: str,
    recipient_id: str,
    payload: bytes,
    *,
    chunk_size: int = 64,
    base_counter: int = 0,
    msg_id: str | None = None,
) -> list[Chunk]:
    """Split payload into numbered, individually authenticated chunks."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    mid = msg_id or secrets.token_hex(8)
    slices = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)] or [b""]
    total = len(slices)
    chunks: list[Chunk] = []
    for idx, part in enumerate(slices):
        env = encrypt_message(
            session,
            sender_id,
            recipient_id,
            base_counter + idx,
            json.dumps({"msg_id": mid, "index": idx, "total": total}, separators=(",", ":")).encode("utf-8")
            + b"\x00"
            + part,
        )
        chunks.append(Chunk(msg_id=mid, index=idx, total=total, envelope=env))
    return chunks


class ChunkedReceiver:
    """Reassembles numbered chunks under reordering/loss, discarding on failure."""

    def __init__(
        self,
        session: SessionContext,
        recipient_id: str,
        *,
        max_retries: int = DEFAULT_MAX_RETRIES,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.session = session
        self.recipient_id = recipient_id
        self.max_retries = max_retries
        self.audit_log = audit_log
        self._buffers: dict[str, dict[int, bytes]] = {}
        self._totals: dict[str, int] = {}
        self._retries: dict[str, int] = {}
        self._failed: set[str] = set()

    def _fail_and_discard(self, msg_id: str, reason: str) -> DeliveryResult:
        self._buffers.pop(msg_id, None)
        self._totals.pop(msg_id, None)
        self._retries.pop(msg_id, None)
        self._failed.add(msg_id)
        if self.audit_log is not None:
            self.audit_log.append_event(
                AuthenticatedSession(actor=self.recipient_id),
                "chunked_delivery",
                msg_id,
                "deny",
                reason,
            )
        return DeliveryResult(delivered=False, msg_id=msg_id, payload=None, error=reason)

    def receive_chunk(self, chunk: Chunk) -> DeliveryResult:
        """Accept and authenticate one chunk; return DeliveryResult."""
        if chunk.msg_id in self._failed:
            return DeliveryResult(delivered=False, msg_id=chunk.msg_id, error="Message already discarded")
        try:
            raw = decrypt_message(self.session, chunk.envelope, self.recipient_id)
            meta_bytes, part = raw.split(b"\x00", 1)
            meta = json.loads(meta_bytes.decode("utf-8"))
            if meta["msg_id"] != chunk.msg_id or meta["index"] != chunk.index or meta["total"] != chunk.total:
                raise MessageError("Chunk metadata mismatch")
        except Exception as exc:
            return self._fail_and_discard(chunk.msg_id, f"Invalid chunk authentication: {exc}")

        if chunk.total < 1 or not (0 <= chunk.index < chunk.total):
            return self._fail_and_discard(chunk.msg_id, "Invalid chunk index or total")

        if chunk.msg_id in self._totals and self._totals[chunk.msg_id] != chunk.total:
            return self._fail_and_discard(chunk.msg_id, "Inconsistent total chunk count")

        self._totals[chunk.msg_id] = chunk.total
        buf = self._buffers.setdefault(chunk.msg_id, {})
        buf[chunk.index] = part

        if len(buf) == chunk.total:
            assembled = b"".join(buf[i] for i in range(chunk.total))
            self._buffers.pop(chunk.msg_id, None)
            self._totals.pop(chunk.msg_id, None)
            self._retries.pop(chunk.msg_id, None)
            return DeliveryResult(delivered=True, msg_id=chunk.msg_id, payload=assembled)

        missing = [i for i in range(chunk.total) if i not in buf]
        return DeliveryResult(delivered=False, msg_id=chunk.msg_id, missing_indices=missing)

    def request_retransmit(self, msg_id: str) -> DeliveryResult:
        """Record a retransmission attempt; discard partial message if retries exceeded."""
        if msg_id in self._failed:
            return DeliveryResult(delivered=False, msg_id=msg_id, error="Message already discarded")
        count = self._retries.get(msg_id, 0) + 1
        self._retries[msg_id] = count
        if count > self.max_retries:
            return self._fail_and_discard(msg_id, f"Retry limit ({self.max_retries}) exceeded")
        total = self._totals.get(msg_id, 0)
        buf = self._buffers.get(msg_id, {})
        missing = [i for i in range(total) if i not in buf]
        return DeliveryResult(delivered=False, msg_id=msg_id, missing_indices=missing)


class OfflineQueue:
    """Persistent queue storing only encrypted message envelopes and delivery state."""

    def __init__(self, queue_path: str | Path) -> None:
        self.queue_path = Path(queue_path)
        self._lock_dir = self.queue_path.parent

    def enqueue(self, recipient_id: str, envelope: dict) -> None:
        with state_lock(self._lock_dir):
            data = (
                json.loads(self.queue_path.read_text(encoding="utf-8"))
                if self.queue_path.is_file()
                else {"version": 1, "items": []}
            )
            data["items"].append({"recipient_id": recipient_id, "envelope": envelope, "delivered": False})
            atomic_write_text(self.queue_path, json.dumps(data, allow_nan=False, separators=(",", ":")))

    def pending_for(self, recipient_id: str) -> list[dict]:
        with state_lock(self._lock_dir):
            if not self.queue_path.is_file():
                return []
            data = json.loads(self.queue_path.read_text(encoding="utf-8"))
            return [
                item["envelope"]
                for item in data["items"]
                if item["recipient_id"] == recipient_id and not item["delivered"]
            ]
