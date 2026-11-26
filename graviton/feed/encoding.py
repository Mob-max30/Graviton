"""Canonical big-endian binary encoding and strict Reader for Graviton feeds."""
from __future__ import annotations

import struct

MAX_ID_LEN = 256
MAX_ENTRY_LEN = 16384


class FeedFormatError(ValueError):
    """Raised when binary feed data is malformed, truncated, or violates bounds."""


def enc_u8(x: int) -> bytes:
    if not isinstance(x, int) or isinstance(x, bool) or not (0 <= x <= 0xFF):
        raise FeedFormatError("u8 out of range")
    return struct.pack(">B", x)


def enc_u32(x: int) -> bytes:
    if not isinstance(x, int) or isinstance(x, bool) or not (0 <= x <= 0xFFFFFFFF):
        raise FeedFormatError("u32 out of range")
    return struct.pack(">I", x)


def enc_u64(x: int) -> bytes:
    if not isinstance(x, int) or isinstance(x, bool) or not (0 <= x <= 0xFFFFFFFFFFFFFFFF):
        raise FeedFormatError("u64 out of range")
    return struct.pack(">Q", x)


def enc_bytes(b: bytes | bytearray) -> bytes:
    if not isinstance(b, (bytes, bytearray)):
        raise FeedFormatError("Expected bytes")
    raw = bytes(b)
    return enc_u32(len(raw)) + raw


def enc_str(s: str) -> bytes:
    if not isinstance(s, str):
        raise FeedFormatError("Expected str")
    try:
        raw = s.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FeedFormatError("Invalid UTF-8 string") from exc
    return enc_bytes(raw)


def enc_id(identifier: str) -> bytes:
    """Encode an opaque non-empty identifier within MAX_ID_LEN bytes."""
    if not isinstance(identifier, str):
        raise FeedFormatError("Identifier must be str")
    try:
        raw = identifier.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FeedFormatError("Invalid UTF-8 in identifier") from exc
    if len(raw) == 0:
        raise FeedFormatError("Identifier must not be empty")
    if len(raw) > MAX_ID_LEN:
        raise FeedFormatError(f"Identifier exceeds MAX_ID_LEN ({MAX_ID_LEN})")
    return enc_bytes(raw)


class Reader:
    """Strict sequential decoder for canonical big-endian feed structures."""

    def __init__(self, data: bytes | bytearray, *, max_len: int | None = None) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise FeedFormatError("Input must be bytes")
        self._data = bytes(data)
        if max_len is not None and len(self._data) > max_len:
            raise FeedFormatError(f"Input exceeds maximum length ({max_len})")
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise FeedFormatError("Unexpected end of input")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def read_u8(self) -> int:
        return struct.unpack(">B", self._take(1))[0]

    def read_u32(self) -> int:
        return struct.unpack(">I", self._take(4))[0]

    def read_u64(self) -> int:
        return struct.unpack(">Q", self._take(8))[0]

    def read_bytes(self, *, max_len: int = MAX_ENTRY_LEN) -> bytes:
        length = self.read_u32()
        if length > max_len:
            raise FeedFormatError(f"Field length {length} exceeds limit {max_len}")
        if length > self.remaining:
            raise FeedFormatError("Length prefix exceeds remaining bytes")
        return self._take(length)

    def read_str(self, *, max_len: int = MAX_ENTRY_LEN) -> str:
        raw = self.read_bytes(max_len=max_len)
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FeedFormatError("Invalid UTF-8 bytes") from exc

    def read_id(self) -> str:
        ident = self.read_str(max_len=MAX_ID_LEN)
        if len(ident.encode("utf-8")) == 0:
            raise FeedFormatError("Empty identifier is not allowed")
        return ident

    def assert_finished(self) -> None:
        if self._pos != len(self._data):
            raise FeedFormatError(f"Trailing bytes: {self.remaining}")
