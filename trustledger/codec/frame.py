"""Canonical binary length-prefixed frame codecs with strict boundary enforcement."""
import struct

PROTOCOL_VERSION = 1
MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MiB hard boundary
MAX_FIELD_SIZE = 1024 * 1024      # 1 MiB


class CodecError(ValueError):
    """Raised when frame parsing or serialization fails boundary checks."""


def encode_bytes(b: bytes) -> bytes:
    """Encode byte string as 4-byte big-endian length + payload."""
    if len(b) > MAX_FIELD_SIZE:
        raise CodecError(f"Field exceeds maximum size: {len(b)} > {MAX_FIELD_SIZE}")
    return struct.pack(">I", len(b)) + b


def decode_bytes(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode 4-byte length + payload from data at offset. Returns (bytes, new_offset)."""
    if offset + 4 > len(data):
        raise CodecError("Unexpected EOF while reading field length")
    (length,) = struct.unpack_from(">I", data, offset)
    if length > MAX_FIELD_SIZE:
        raise CodecError(f"Field length exceeds max allowed: {length} > {MAX_FIELD_SIZE}")
    offset += 4
    if offset + length > len(data):
        raise CodecError("Unexpected EOF while reading field payload")
    val = data[offset : offset + length]
    return val, offset + length


def encode_string(s: str) -> bytes:
    """Encode UTF-8 string with length prefix."""
    return encode_bytes(s.encode("utf-8"))


def decode_string(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Decode UTF-8 string from length-prefixed bytes."""
    raw, new_offset = decode_bytes(data, offset)
    try:
        return raw.decode("utf-8"), new_offset
    except UnicodeDecodeError as err:
        raise CodecError("Invalid UTF-8 sequence") from err


def pack_frame(frame_type: int, payload: bytes) -> bytes:
    """Pack frame with magic, version, frame_type (1 byte), length (4 bytes), and payload."""
    if len(payload) > MAX_FRAME_SIZE:
        raise CodecError("Payload exceeds MAX_FRAME_SIZE")
    header = struct.pack(">4sBBI", b"TL01", PROTOCOL_VERSION, frame_type, len(payload))
    return header + payload


def unpack_frame(data: bytes) -> tuple[int, bytes]:
    """Unpack frame header and validate magic, version, and length."""
    if len(data) < 10:
        raise CodecError("Frame too short for header")
    magic, version, frame_type, length = struct.unpack_from(">4sBBI", data, 0)
    if magic != b"TL01":
        raise CodecError(f"Invalid magic prefix: {magic!r}")
    if version != PROTOCOL_VERSION:
        raise CodecError(f"Unsupported protocol version: {version}")
    if length > MAX_FRAME_SIZE:
        raise CodecError(f"Frame length exceeds limit: {length}")
    if len(data) < 10 + length:
        raise CodecError("Frame data incomplete")
    return frame_type, data[10 : 10 + length]
