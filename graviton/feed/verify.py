"""Pure verification functions for signed, hash-chained feed entries."""
from __future__ import annotations

from graviton.crypto.signatures import verify_signature
from graviton.feed.encoding import MAX_ENTRY_LEN, FeedFormatError
from graviton.feed.entries import (
    FEED_SIGN_DOMAIN,
    ZERO_HASH,
    EntryType,
    FeedEntry,
    decode_entry_body,
    unpack_signed_entry,
)


class FeedVerificationError(ValueError):
    """Raised when a feed entry fails structural, continuity, or signature checks."""


class FeedContinuityError(FeedVerificationError):
    """Raised when epoch or prev_hash does not match expected chain state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def verify_entry(
    raw_bytes: bytes,
    admin_public_key: bytes,
    pinned_feed_id: str,
    expected_epoch: int,
    expected_prev_hash: bytes,
) -> FeedEntry:
    """Verify raw serialized entry bytes in strict order without re-serialising.

    Check order: size limit, decode, version/type, feed_id, epoch and prev_hash
    continuity, then ML-DSA-65 signature over exact body bytes.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise FeedVerificationError("Entry must be bytes")
    raw = bytes(raw_bytes)
    if len(raw) > MAX_ENTRY_LEN:
        raise FeedVerificationError("Entry exceeds MAX_ENTRY_LEN")

    try:
        body, signature = unpack_signed_entry(raw)
        entry = decode_entry_body(body)
    except FeedFormatError as exc:
        raise FeedVerificationError(str(exc)) from exc

    if entry.feed_id != pinned_feed_id:
        raise FeedVerificationError("feed_id mismatch")

    if entry.epoch != expected_epoch:
        if entry.epoch < expected_epoch:
            raise FeedContinuityError("rollback_or_repeat", f"Expected epoch {expected_epoch}, got {entry.epoch}")
        raise FeedContinuityError("gap", f"Expected epoch {expected_epoch}, got {entry.epoch}")

    if expected_epoch == 1:
        if entry.entry_type != EntryType.GENESIS:
            raise FeedVerificationError("Epoch 1 must be GENESIS")
        if entry.prev_hash != ZERO_HASH:
            raise FeedContinuityError("bad_prev_hash", "Genesis prev_hash must be 32 zero bytes")
    else:
        if entry.entry_type == EntryType.GENESIS:
            raise FeedVerificationError("GENESIS only allowed at epoch 1")
        if entry.prev_hash != expected_prev_hash:
            raise FeedContinuityError("bad_prev_hash", "prev_hash does not match previous entry")

    if not verify_signature(admin_public_key, body, signature, domain=FEED_SIGN_DOMAIN):
        raise FeedVerificationError("Invalid admin ML-DSA-65 signature")

    return entry
