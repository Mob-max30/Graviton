"""Canonical feed entry definitions, encoding, and decoding."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib

from graviton.crypto.signatures import DSA_PUBLIC_KEY_SIZE, DSA_SIGNATURE_SIZE
from graviton.feed.encoding import (
    MAX_ENTRY_LEN,
    MAX_ID_LEN,
    FeedFormatError,
    Reader,
    enc_bytes,
    enc_id,
    enc_u8,
    enc_u32,
    enc_u64,
)

FEED_FORMAT_VERSION = 1
FEED_SIGN_DOMAIN = b"feed"
ZERO_HASH = b"\x00" * 32


class EntryType(IntEnum):
    GENESIS = 1
    REGISTER_KEY = 2
    ROTATE_KEY = 3
    REVOKE_DEVICE = 4
    REVOKE_ACTOR = 5
    HEAD = 6


@dataclass(frozen=True)
class FeedEntry:
    version: int
    entry_type: EntryType
    feed_id: str
    epoch: int
    prev_hash: bytes
    issued_at: int
    actor: str | None = None
    device_id: str | None = None
    key_version: int | None = None
    public_key: bytes | None = None
    cutoff_epoch: int | None = None


def compute_entry_hash(serialized_entry: bytes) -> bytes:
    """Return the SHA-256 hash of a serialized signed feed entry."""
    return hashlib.sha256(serialized_entry).digest()


def encode_entry_body(entry: FeedEntry) -> bytes:
    """Encode a FeedEntry body into canonical big-endian binary form."""
    if entry.version != FEED_FORMAT_VERSION:
        raise FeedFormatError(f"Unsupported feed version: {entry.version}")
    if len(entry.prev_hash) != 32:
        raise FeedFormatError("prev_hash must be exactly 32 bytes")

    buf = bytearray()
    buf.extend(enc_u8(entry.version))
    buf.extend(enc_u8(int(entry.entry_type)))
    buf.extend(enc_id(entry.feed_id))
    buf.extend(enc_u64(entry.epoch))
    buf.extend(enc_bytes(entry.prev_hash))
    buf.extend(enc_u64(entry.issued_at))

    if entry.entry_type in (EntryType.GENESIS, EntryType.HEAD):
        pass
    elif entry.entry_type == EntryType.REGISTER_KEY:
        if entry.actor is None or entry.device_id is None or entry.key_version is None or entry.public_key is None:
            raise FeedFormatError("Missing fields for REGISTER_KEY")
        if len(entry.public_key) != DSA_PUBLIC_KEY_SIZE:
            raise FeedFormatError("Invalid ML-DSA-65 public key size")
        buf.extend(enc_id(entry.actor))
        buf.extend(enc_id(entry.device_id))
        buf.extend(enc_u32(entry.key_version))
        buf.extend(enc_bytes(entry.public_key))
    elif entry.entry_type == EntryType.ROTATE_KEY:
        if (
            entry.actor is None
            or entry.device_id is None
            or entry.key_version is None
            or entry.public_key is None
            or entry.cutoff_epoch is None
        ):
            raise FeedFormatError("Missing fields for ROTATE_KEY")
        if len(entry.public_key) != DSA_PUBLIC_KEY_SIZE:
            raise FeedFormatError("Invalid ML-DSA-65 public key size")
        buf.extend(enc_id(entry.actor))
        buf.extend(enc_id(entry.device_id))
        buf.extend(enc_u32(entry.key_version))
        buf.extend(enc_bytes(entry.public_key))
        buf.extend(enc_u64(entry.cutoff_epoch))
    elif entry.entry_type == EntryType.REVOKE_DEVICE:
        if entry.actor is None or entry.device_id is None:
            raise FeedFormatError("Missing fields for REVOKE_DEVICE")
        buf.extend(enc_id(entry.actor))
        buf.extend(enc_id(entry.device_id))
    elif entry.entry_type == EntryType.REVOKE_ACTOR:
        if entry.actor is None:
            raise FeedFormatError("Missing actor for REVOKE_ACTOR")
        buf.extend(enc_id(entry.actor))
    else:
        raise FeedFormatError(f"Unknown entry_type: {entry.entry_type}")

    return bytes(buf)


def decode_entry_body(body: bytes) -> FeedEntry:
    """Strictly decode a canonical entry body into a FeedEntry."""
    r = Reader(body, max_len=MAX_ENTRY_LEN)
    version = r.read_u8()
    if version != FEED_FORMAT_VERSION:
        raise FeedFormatError(f"Unsupported feed version: {version}")
    raw_type = r.read_u8()
    try:
        entry_type = EntryType(raw_type)
    except ValueError as exc:
        raise FeedFormatError(f"Unknown entry type: {raw_type}") from exc

    feed_id = r.read_id()
    epoch = r.read_u64()
    prev_hash = r.read_bytes(max_len=32)
    if len(prev_hash) != 32:
        raise FeedFormatError("prev_hash must be exactly 32 bytes")
    issued_at = r.read_u64()

    actor = device_id = None
    key_version = cutoff_epoch = None
    public_key = None

    if entry_type in (EntryType.GENESIS, EntryType.HEAD):
        pass
    elif entry_type == EntryType.REGISTER_KEY:
        actor = r.read_id()
        device_id = r.read_id()
        key_version = r.read_u32()
        public_key = r.read_bytes(max_len=DSA_PUBLIC_KEY_SIZE)
        if len(public_key) != DSA_PUBLIC_KEY_SIZE:
            raise FeedFormatError("Invalid ML-DSA-65 public key length")
    elif entry_type == EntryType.ROTATE_KEY:
        actor = r.read_id()
        device_id = r.read_id()
        key_version = r.read_u32()
        public_key = r.read_bytes(max_len=DSA_PUBLIC_KEY_SIZE)
        if len(public_key) != DSA_PUBLIC_KEY_SIZE:
            raise FeedFormatError("Invalid ML-DSA-65 public key length")
        cutoff_epoch = r.read_u64()
    elif entry_type == EntryType.REVOKE_DEVICE:
        actor = r.read_id()
        device_id = r.read_id()
    elif entry_type == EntryType.REVOKE_ACTOR:
        actor = r.read_id()

    r.assert_finished()
    return FeedEntry(
        version=version,
        entry_type=entry_type,
        feed_id=feed_id,
        epoch=epoch,
        prev_hash=prev_hash,
        issued_at=issued_at,
        actor=actor,
        device_id=device_id,
        key_version=key_version,
        public_key=public_key,
        cutoff_epoch=cutoff_epoch,
    )


def unpack_signed_entry(serialized_entry: bytes) -> tuple[bytes, bytes]:
    """Decode serialized_entry into (body_bytes, signature_bytes) without re-serialising."""
    r = Reader(serialized_entry, max_len=MAX_ENTRY_LEN)
    body = r.read_bytes(max_len=MAX_ENTRY_LEN)
    signature = r.read_bytes(max_len=DSA_SIGNATURE_SIZE)
    r.assert_finished()
    if len(signature) != DSA_SIGNATURE_SIZE:
        raise FeedFormatError("Invalid ML-DSA-65 signature length")
    return body, signature


def pack_signed_entry(body: bytes, signature: bytes) -> bytes:
    """Pack body and signature into serialized_entry and enforce MAX_ENTRY_LEN."""
    if len(signature) != DSA_SIGNATURE_SIZE:
        raise FeedFormatError("Invalid ML-DSA-65 signature length")
    serialized = enc_bytes(body) + enc_bytes(signature)
    if len(serialized) > MAX_ENTRY_LEN:
        raise FeedFormatError(f"Serialized entry exceeds MAX_ENTRY_LEN ({MAX_ENTRY_LEN})")
    return serialized
