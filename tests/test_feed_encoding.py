"""Tests for graviton.feed.encoding (Step 1 binary encoding & strict Reader)."""
from __future__ import annotations

import unittest

from graviton.feed.encoding import (
    MAX_ID_LEN,
    FeedFormatError,
    Reader,
    enc_bytes,
    enc_id,
    enc_str,
    enc_u8,
    enc_u32,
    enc_u64,
)


class TestFeedEncoding(unittest.TestCase):
    def test_primitives_round_trip(self) -> None:
        blob = (
            enc_u8(0)
            + enc_u8(255)
            + enc_u32(0x01020304)
            + enc_u64(0x0102030405060708)
            + enc_bytes(b"\x00\xffhello")
            + enc_str("graviton-utf8-\u00e9")
            + enc_id("node-1")
        )
        r = Reader(blob)
        self.assertEqual(r.read_u8(), 0)
        self.assertEqual(r.read_u8(), 255)
        self.assertEqual(r.read_u32(), 0x01020304)
        self.assertEqual(r.read_u64(), 0x0102030405060708)
        self.assertEqual(r.read_bytes(), b"\x00\xffhello")
        self.assertEqual(r.read_str(), "graviton-utf8-\u00e9")
        self.assertEqual(r.read_id(), "node-1")
        r.assert_finished()

    def test_truncated_and_overrun_rejected(self) -> None:
        with self.assertRaises(FeedFormatError):
            Reader(b"").read_u8()
        with self.assertRaises(FeedFormatError):
            Reader(b"\x00\x01").read_u32()
        with self.assertRaises(FeedFormatError):
            Reader(enc_u32(10) + b"abc").read_bytes()

    def test_oversized_field_and_empty_identifier_rejected(self) -> None:
        with self.assertRaises(FeedFormatError):
            enc_id("")
        with self.assertRaises(FeedFormatError):
            enc_id("x" * (MAX_ID_LEN + 1))
        with self.assertRaises(FeedFormatError):
            Reader(enc_str("")).read_id()
        with self.assertRaises(FeedFormatError):
            Reader(enc_str("x" * (MAX_ID_LEN + 1))).read_id()

    def test_invalid_utf8_and_trailing_bytes_rejected(self) -> None:
        bad_utf8 = enc_bytes(b"\xff\xfe\xfd")
        with self.assertRaises(FeedFormatError):
            Reader(bad_utf8).read_str()

        r = Reader(enc_u8(1) + b"\x00")
        self.assertEqual(r.read_u8(), 1)
        with self.assertRaises(FeedFormatError):
            r.assert_finished()

    def test_ambiguity_prevention(self) -> None:
        left = enc_str("ab") + enc_str("c")
        right = enc_str("a") + enc_str("bc")
        self.assertNotEqual(left, right)


if __name__ == "__main__":
    unittest.main()
